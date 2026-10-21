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
/// for this size, far past the report's 10 s deadline, which cannot interrupt it. URL
/// scheme matching and userinfo boundaries must remain linear even with hostile punctuation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn round2_m11_hostile_health_response_is_redacted_within_the_probe_deadline() {
    const SECRET: &str = "round2-secret-0123456789abcdef";
    const PAREN_SECRET: &str = "round2-paren-secret-0123456789";
    const QUOTE_SECRET: &str = "round2-quote-secret-0123456789";
    const UPPER_SECRET: &str = "round2-uppercase-secret-0123456789";
    let credential_url = format!("https://user:{SECRET}@rpc.example/v2/{SECRET}?token={SECRET} ");
    let counterexamples = format!(
        "https://user:{PAREN_SECRET})secret@rpc.example/v2/secret?token=secret \
         https://user:{QUOTE_SECRET}'secret@rpc.example/v2/secret?token=secret \
         HTTPS://user:{UPPER_SECRET}@rpc.example/v2/secret?token=secret \
         retry https://rpc.example/v2/status?region=west, (done)"
    );
    let wrapper = r#"{"jsonrpc":"2.0","id":1,"result":""}"#.len();
    let limit = 4 * 1024 * 1024 - wrapper;
    let mut result = String::with_capacity(limit);
    result.push_str(&counterexamples);
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
    let secrets = [SECRET, PAREN_SECRET, QUOTE_SECRET, UPPER_SECRET];
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
            "secret_in_report": secrets.iter().any(|secret| serialized.contains(secret)),
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
    for secret in secrets {
        assert!(
            !serialized.contains(secret),
            "credential reached the report: {secret}"
        );
    }
    assert!(!serialized.contains("user:"), "userinfo reached the report");
    assert!(response.contains("retry https://rpc.example/<redacted>?<redacted>, (done)"));
}

#[tokio::test]
async fn round2_m11_url_keys_are_redacted_without_map_collisions() {
    const FIRST: &str = "round2-key-one-secret-0123456789";
    const SECOND: &str = "round2-key-two-secret-0123456789";
    let keyed = |scheme: &str| {
        let mut value = serde_json::Map::new();
        value.insert(
            format!("{scheme}://user:{FIRST}@rpc.example/v2/{FIRST}?token={FIRST}"),
            json!("first-entry"),
        );
        value.insert(
            format!("{scheme}://user:{SECOND}@rpc.example/v2/{SECOND}?token={SECOND}"),
            json!("second-entry"),
        );
        value.insert(
            "zz_padding".to_string(),
            Value::String("x".repeat(MAX_HEALTH_RESPONSE_TEXT_BYTES + 1024)),
        );
        Value::Object(value)
    };
    let cases = [
        ("direct", keyed("https"), "", "https"),
        (
            "nested-marker",
            json!({"observation":"not_attempted","nested":[keyed("https")]}),
            "/nested/0",
            "https",
        ),
        ("uppercase", keyed("HTTPS"), "", "HTTPS"),
    ];
    for (label, result, pointer, scheme) in cases {
        let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":result})).unwrap();
        assert!(body.len() < 4 * 1024 * 1024);
        let (base, server) = serve_json_forever(body.clone()).await;
        let getter = StaticProviderConfig::new(
            IndexMap::from([(
                "ethereum".to_string(),
                ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(base)], 1),
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
        let report = source.get_provider_health_report().await.unwrap();
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        let entry = &report["ethereum"].providers[0];
        let selected = entry.response.pointer(pointer).unwrap();
        let serialized = serde_json::to_string(&report).unwrap();
        record(
            &format!("m11-url-key-{label}"),
            json!({
                "case":label,
                "provider_body_bytes":body.len(),
                "diagnostic":selected,
                "retained_bytes":selected.as_str().map(str::len),
                "secret_in_report":serialized.contains(FIRST) || serialized.contains(SECOND),
                "healthy":entry.healthy
            }),
        );
        assert!(!entry.healthy);
        assert!(
            !serialized.contains(FIRST) && !serialized.contains(SECOND),
            "{label}: URL-key credentials reached the report"
        );
        let diagnostic = selected
            .as_str()
            .expect("URL-keyed object must be a diagnostic string");
        assert!(diagnostic.len() <= MAX_HEALTH_RESPONSE_TEXT_BYTES + 64);
        assert!(diagnostic.contains("…[truncated "));
        assert!(diagnostic.contains("first-entry") && diagnostic.contains("second-entry"));
        let redacted_key = format!("{scheme}://<redacted>@rpc.example/<redacted>?<redacted>");
        assert_eq!(diagnostic.matches(&redacted_key).count(), 2);
        if label == "nested-marker" {
            assert_eq!(entry.response["observation"], "not_attempted");
            assert!(entry.response["nested"].is_array());
        }
    }
}
