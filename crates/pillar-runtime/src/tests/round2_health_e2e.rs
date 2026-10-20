//! Round 2 provider-health findings through the production health source and
//! the production `reqwest` transport against local HTTP providers.
use super::*;
use crate::provider_health::{ReqwestJsonRpcTransport, MAX_HEALTH_RESPONSE_TEXT_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn record(name: &str, value: Value) {
    super::audit_round_artifact("round2", name, value);
}

/// Answers every request with `body` until aborted.
async fn serve_json_forever(body: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = Arc::new(body);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0; 1024];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(count) => request.extend_from_slice(&chunk[..count]),
                    }
                    let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let length = String::from_utf8_lossy(&request[..end])
                        .to_ascii_lowercase()
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(header.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(&body).await;
                }
            });
        }
    });
    (format!("http://{address}"), task)
}

/// A provider answering `eth_chainId` with a ~4 MiB string of URL tokens. Before the
/// fix the redaction rescanned the remainder for each token: 221.7 s in a release build
/// for this size, far past the report's 10 s deadline, which cannot interrupt it. Every
/// URL is `https://`, so the old search for `http://` never stopped early; `httpx http:/`
/// are near-misses the scanner must step over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn round2_m11_hostile_health_response_is_redacted_within_the_probe_deadline() {
    const SECRET: &str = "round2-secret-0123456789abcdef";
    let credential_url = format!("https://user:{SECRET}@rpc.example/v2/{SECRET}?token={SECRET} ");
    let wrapper = r#"{"jsonrpc":"2.0","id":1,"result":""}"#.len();
    let limit = 4 * 1024 * 1024 - wrapper;
    let mut result = String::with_capacity(limit);
    let mut index = 0usize;
    loop {
        let token = match index % 64 {
            0 => credential_url.as_str(),
            1 => "httpx http:/ ",
            _ => "https://a ",
        };
        if result.len() + token.len() > limit {
            break;
        }
        result.push_str(token);
        index += 1;
    }
    let body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "result": result})).unwrap();
    assert!(body.len() <= 4 * 1024 * 1024);
    let (base, server) = serve_json_forever(body.clone()).await;

    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!("{base}/v2/{SECRET}"))],
                1,
            ),
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        ReqwestJsonRpcTransport::new().unwrap(),
        || 1,
        pillar_config::static_chain_type_by_chain_name(&["ethereum".to_string()]).unwrap(),
    );

    let started = std::time::Instant::now();
    let report = source.get_provider_health_report().await.unwrap();
    let elapsed = started.elapsed();
    server.abort();

    let entry = &report["ethereum"].providers[0];
    let response = entry.response.as_str().unwrap();
    let serialized = serde_json::to_string(&report).unwrap();
    record(
        "m11-hostile-health-response",
        json!({
            "response_body_bytes": body.len(),
            "url_tokens": index,
            "report_seconds": elapsed.as_secs_f64(),
            "probe_deadline_seconds": 10,
            "retained_response_bytes": response.len(),
            "retained_cap_bytes": MAX_HEALTH_RESPONSE_TEXT_BYTES,
            "truncated": response.contains("…[truncated "),
            "secret_in_report": serialized.contains(SECRET),
            "userinfo_in_report": serialized.contains("user:"),
            "healthy": entry.healthy,
            "url": entry.url,
        }),
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "the report took {elapsed:?}, past its own 10 s deadline"
    );
    assert!(!entry.healthy);
    assert!(response.starts_with("https://<redacted>@rpc.example/<redacted>?<redacted>"));
    assert!(response.len() <= MAX_HEALTH_RESPONSE_TEXT_BYTES + 64);
    assert!(response.contains("…[truncated "));
    assert!(
        !serialized.contains(SECRET),
        "a credential reached the report"
    );
    assert!(!serialized.contains("user:"), "userinfo reached the report");
}
