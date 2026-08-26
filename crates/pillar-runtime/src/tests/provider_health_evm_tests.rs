use super::*;

#[test]
fn normalizes_numeric_responses_like_typescript_bigint() {
    let hex = normalize_provider_health_entry(
        "https://rpc.example".to_string(),
        Value::String("0x89".to_string()),
        Some(12),
    );
    assert!(hex.healthy);
    assert_eq!(hex.numeric_response, Some("137".to_string()));
    assert_eq!(hex.latency_ms, Some(12));

    let decimal = normalize_provider_health_entry(
        "https://rpc.example".to_string(),
        Value::String("101".to_string()),
        None,
    );
    assert!(decimal.healthy);
    assert_eq!(decimal.numeric_response, Some("101".to_string()));

    let invalid = normalize_provider_health_entry(
        "https://rpc.example".to_string(),
        json!({"error": "no numeric result"}),
        None,
    );
    assert!(!invalid.healthy);
    assert_eq!(invalid.numeric_response, None);
}

#[tokio::test]
async fn probes_eth_chain_id_and_preserves_provider_headers() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://rpc.example".to_string(),
                    headers: HashMap::from([(
                        "authorization".to_string(),
                        "Bearer token".to_string(),
                    )]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "0x1"}))])),
    };
    let source = RpcProviderHealthSource::from_getter(&getter, transport, || 1234);
    let report = source.get_provider_health_report().await;

    assert!(report["ethereum"].healthy);
    assert_eq!(report["ethereum"].checked_at_unix_ms, 1234);
    assert_eq!(
        report["ethereum"].providers[0].numeric_response,
        Some("1".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://rpc.example");
    assert_eq!(
        calls[0].1.get("authorization"),
        Some(&"Bearer token".to_string())
    );
    assert_eq!(calls[0].2["method"], "eth_chainId");
}

#[tokio::test]
async fn falls_back_to_net_version_when_chain_id_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Err("chain id unavailable".to_string()),
            Ok(json!({"result": "10"})),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter(&getter, transport, || 1);
    let snapshot = source.get_provider_health().await.unwrap();

    assert!(snapshot["ethereum"]);
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].2["method"], "eth_chainId");
    assert_eq!(calls[1].2["method"], "net_version");
}
