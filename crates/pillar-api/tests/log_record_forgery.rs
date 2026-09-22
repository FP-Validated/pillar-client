//! A caller must not be able to write a log record.
//!
//! This lives in its own integration binary on purpose. `tracing` caches a
//! callsite's interest globally the first time it is reached, so a sibling unit
//! test emitting the same event while no subscriber is installed poisons that
//! cache and the capture silently loses the record under test - green for the
//! wrong reason, and only under `--test-threads=1` does it pass honestly. One
//! test per process removes the race instead of papering over it.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use http::{Method, Request, StatusCode};
use pillar_api::{router, AppError, ServerApp, SignerInfo};
use pillar_core::{
    PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, ProviderHealthSnapshot,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

/// Fails every v2 request with the text the core would produce, which quotes the
/// caller's `messageHash` back verbatim
/// (`Message hash mismatch, expected: {request}, got: {computed}`,
/// `pillar-core`). That is the route by which caller bytes reach the formatter:
/// the field is compared, never interpolated into an outbound request, so it
/// carries no shape gate of its own and the escaping has to happen where the
/// record is written.
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
fn control_characters_from_a_caller_cannot_forge_a_log_record() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    // Mirrors `init_tracing` in `crates/pillar-cli/src/main.rs`: same formatter,
    // same target rendering, same filter for this crate. Notably it does not
    // disable ANSI, because the binary does not either.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("pillar_api=info"))
        .with_target(true)
        .compact()
        .with_writer(SharedLogWriter(captured.clone()))
        .finish();
    // `with_default` is thread-local, so the request has to run on this thread:
    // a multi-threaded runtime hands the handler to a worker that never sees the
    // subscriber.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    tracing::subscriber::with_default(subscriber, || {
        runtime.block_on(async {
            let forged = format!("0x{}\nAUDIT_PROBE\x1b", "a".repeat(64));
            let app = FailingApp {
                error: format!(
                    "Message hash mismatch, expected: {forged}, got: 0x{}",
                    "b".repeat(64)
                ),
            };
            let request = Request::builder()
                .method(Method::POST)
                .uri("/v2/resolve-and-sign")
                .header("content-type", "application/json")
                .body(Body::from(v2_request(&forged).to_string()))
                .unwrap();

            let response = router(app, "test").oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            // Echoed to the caller who sent it, which is not a forgery vector.
            // Only the shared log is.
            assert!(body["body"].as_str().unwrap().contains("AUDIT_PROBE"));
        });
    });

    let captured = captured.lock().unwrap();
    let contains = |needle: &[u8]| captured.windows(needle.len()).any(|w| w == needle);
    assert!(
        !captured.is_empty(),
        "nothing was captured, so this test proves nothing"
    );
    // The formatter colours its own output, so raw ESC bytes are expected here.
    // A blanket "no control bytes" assertion would only be measuring whether
    // ANSI happened to be on. What must never appear is a control byte the
    // *caller* supplied.
    assert!(
        !contains(b"\nAUDIT_PROBE"),
        "caller text opened a new log line: {:?}",
        String::from_utf8_lossy(&captured)
    );
    assert!(
        !contains(b"AUDIT_PROBE\x1b"),
        "caller text carried a raw terminal escape: {:?}",
        String::from_utf8_lossy(&captured)
    );
    // Present, but inert. Without this, simply not logging the error would pass.
    assert!(
        contains(br"\nAUDIT_PROBE\u{1b}"),
        "the escaped payload is missing, so the error was never logged: {:?}",
        String::from_utf8_lossy(&captured)
    );
}
