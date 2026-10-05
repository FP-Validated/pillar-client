// A separate binary avoids tracing callsite-interest races with other tests.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use pillar_api::{router, AppError, ServerApp, SignerInfo};
use pillar_core::{
    PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, ProviderHealthSnapshot,
};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::fmt::MakeWriter;

struct FailingApp {
    error: String,
}

#[async_trait]
impl ServerApp for FailingApp {
    async fn sign_request_v1(
        &self,
        _input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError> {
        Err(AppError::BadRequest(self.error.clone()))
    }

    async fn sign_request_v2(
        &self,
        _input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError> {
        Err(AppError::BadRequest(self.error.clone()))
    }

    async fn get_signer_info(&self, _chain_name: String) -> Result<Vec<SignerInfo>, AppError> {
        Ok(Vec::new())
    }

    fn get_available_chain_names(&self) -> Vec<String> {
        vec!["ethereum".to_string(), "bsc".to_string()]
    }

    fn get_environment(&self) -> String {
        "mainnet".to_string()
    }

    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, AppError> {
        Err(AppError::Internal("unused".to_string()))
    }

    async fn get_provider_health_report(&self) -> Result<Value, AppError> {
        Err(AppError::Internal("unused".to_string()))
    }

    fn public_sign_routes(&self) -> bool {
        true
    }

    fn api_auth_enabled(&self) -> bool {
        false
    }
}

#[derive(Clone)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

struct SharedLogGuard(Arc<Mutex<Vec<u8>>>);

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = SharedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogGuard(self.0.clone())
    }
}

impl Write for SharedLogGuard {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn v2_request(message_hash: &str) -> Value {
    json!({
        "srcTxHash": "0xdeadbeef",
        "lzMessageId": {
            "pathwayId": {
                "srcChainName": "ethereum",
                "dstChainName": "bsc",
                "srcEid": 30101,
                "dstEid": 30102,
                "sender": "0x1111111111111111111111111111111111111111",
                "receiver": "0x2222222222222222222222222222222222222222"
            },
            "nonce": 7,
            "ulnSendVersion": "V302"
        },
        "signingContext": {
            "protocolType": "MESSAGE",
            "expiration": 1900000000,
            "blockConfirmation": 1
        },
        "messageHash": message_hash
    })
}

#[test]
fn caller_error_cannot_expand_logs_and_successful_status_requests_are_quiet() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("pillar_api=info"))
        .with_target(true)
        .compact()
        .with_writer(SharedLogWriter(captured.clone()))
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let caller_hash = format!("0x{}\nAUDIT_PROBE\x1b", "a".repeat(98 * 1024));
            let app = FailingApp {
                error: format!("Message hash mismatch, expected: {caller_hash}, got: 0x{}", "b".repeat(64)),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                axum::serve(listener, router(app, "test"))
                    .with_graceful_shutdown(async { let _ = stopped.await; })
                    .await.unwrap();
            });
            for method in ["GET", "HEAD"] {
                let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
                socket.write_all(format!("{method} / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                let mut response = Vec::new();
                socket.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 200"));
            }
            assert_eq!(captured.lock().unwrap().len(), 0, "successful status requests produced info-level records");
            let request_id = format!("RID_MARKER{}", "r".repeat(8192));
            let post = |payload: String| {
                let request_id = request_id.clone();
                async move {
                    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
                    socket.write_all(format!("POST /v2/resolve-and-sign HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nx-request-id: {request_id}\r\nContent-Length: {}\r\n\r\n{payload}", payload.len()).as_bytes()).await.unwrap();
                    let mut response = Vec::new();
                    socket.read_to_end(&mut response).await.unwrap();
                    response
                }
            };
            let response = post(v2_request(&caller_hash).to_string()).await;
            assert!(response.starts_with(b"HTTP/1.1 400"));
            assert!(response.windows(b"AUDIT_PROBE".len()).any(|bytes| bytes == b"AUDIT_PROBE"));
            // Unknown chains are answered with upstream's unavailable-chain 500, which
            // echoes the name to the caller but never to the log.
            let mut input = v2_request(&caller_hash);
            input["lzMessageId"]["pathwayId"]["srcChainName"] = json!("UNKNOWN_CHAIN_MARKER\nforged");
            let response = post(input.to_string()).await;
            assert!(response.starts_with(b"HTTP/1.1 500"));
            assert!(response.windows(b"UNKNOWN_CHAIN_MARKER".len()).any(|bytes| bytes == b"UNKNOWN_CHAIN_MARKER"));
            let mut input = v2_request(&caller_hash);
            input["lzMessageId"]["pathwayId"]["dstChainName"] = json!("UNKNOWN_DEST_MARKER\nforged");
            let response = post(input.to_string()).await;
            assert!(response.starts_with(b"HTTP/1.1 500"));
            assert!(response.windows(b"UNKNOWN_DEST_MARKER".len()).any(|bytes| bytes == b"UNKNOWN_DEST_MARKER"));
            for query in ["QUERY_MARKER%0Ainjected", "QUERY_MARKER../unsafe", &format!("QUERY_MARKER{}", "q".repeat(129))] {
                let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
                socket.write_all(format!("GET /signer-info?chainName={query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                let mut response = Vec::new();
                socket.read_to_end(&mut response).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 400"));
            }
            stop.send(()).unwrap();
            server.await.unwrap();
        });
    });
    let captured = captured.lock().unwrap();
    let records = String::from_utf8_lossy(&captured);
    assert!(
        records.lines().any(|line| line.contains("WARN")),
        "failure warning was suppressed"
    );
    assert!(
        !records.contains("AUDIT_PROBE")
            && !records.contains("UNKNOWN_CHAIN_MARKER")
            && !records.contains("UNKNOWN_DEST_MARKER")
            && !records.contains("RID_MARKER")
            && !records.contains("QUERY_MARKER"),
        "caller error leaked into the shared log"
    );
    assert!(
        captured.len() < 4096,
        "near-100 KiB caller input amplified log volume to {} bytes",
        captured.len()
    );
    let directory = std::env::var("PILLAR_E2E_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../local/e2e-runs")
        });
    static RUN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let directory = directory.join(RUN.get_or_init(|| {
        format!(
            "run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }));
    std::fs::create_dir_all(&directory).unwrap();
    let evidence = json!({"caller_hash_padding_bytes": 98 * 1024, "info_records_for_get_head": 0, "caller_marker_logged": false, "failure_warning_preserved": true, "failure_log_bytes": captured.len(), "http_status": 400});
    std::fs::write(
        directory.join("bounded-caller-log-e2e.json"),
        evidence.to_string(),
    )
    .unwrap();
    println!("{evidence}");
}
