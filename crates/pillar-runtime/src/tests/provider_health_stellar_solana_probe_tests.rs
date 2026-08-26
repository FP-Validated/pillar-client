use super::*;

#[tokio::test]
async fn provider_health_probes_stellar_latest_ledger_like_typescript() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://stellar-rpc.example".to_string(),
                    headers: HashMap::from([(
                        "authorization".to_string(),
                        "Bearer stellar-token".to_string(),
                    )]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(
            json!({"result": {"sequence": 112233}}),
        )])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 5555,
        HashMap::from([("stellar".to_string(), "STELLAR".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["stellar"].healthy);
    assert_eq!(report["stellar"].checked_at_unix_ms, 5555);
    assert_eq!(
        report["stellar"].providers[0].url,
        "https://stellar-rpc.example"
    );
    assert_eq!(report["stellar"].providers[0].response, Value::from(112233));
    assert_eq!(
        report["stellar"].providers[0].numeric_response,
        Some("112233".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://stellar-rpc.example");
    assert_eq!(
        calls[0].1.get("authorization"),
        Some(&"Bearer stellar-token".to_string())
    );
    assert_eq!(calls[0].2["method"], "getLatestLedger");
    assert_eq!(calls[0].2["params"], json!({}));
}

#[tokio::test]
async fn provider_health_marks_stellar_unhealthy_when_latest_ledger_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://stellar-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Err(
            "latest ledger unavailable".to_string()
        )])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("stellar".to_string(), "STELLAR".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["stellar"].healthy);
    assert_eq!(
        report["stellar"].providers[0].response,
        Value::from("latest ledger unavailable")
    );
    assert_eq!(report["stellar"].providers[0].numeric_response, None);
}

#[tokio::test]
async fn provider_health_probes_solana_confirmed_slot_like_typescript() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://solana-rpc.example".to_string(),
                    headers: HashMap::from([(
                        "authorization".to_string(),
                        "Bearer token".to_string(),
                    )]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": 987654321}))])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 2222,
        HashMap::from([("solana".to_string(), "SOLANA".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["solana"].healthy);
    assert_eq!(report["solana"].checked_at_unix_ms, 2222);
    assert_eq!(
        report["solana"].providers[0].url,
        "https://solana-rpc.example"
    );
    assert_eq!(
        report["solana"].providers[0].response,
        Value::from(987654321)
    );
    assert_eq!(
        report["solana"].providers[0].numeric_response,
        Some("987654321".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://solana-rpc.example");
    assert_eq!(
        calls[0].1.get("authorization"),
        Some(&"Bearer token".to_string())
    );
    assert_eq!(calls[0].2["method"], "getSlot");
    assert_eq!(
        calls[0].2["params"][0]["commitment"],
        Value::from("confirmed")
    );
}
