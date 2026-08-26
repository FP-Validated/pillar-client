use super::*;

#[tokio::test]
async fn provider_health_marks_solana_unhealthy_when_slot_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Err("slot unavailable".to_string())])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("solana".to_string(), "SOLANA".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["solana"].healthy);
    assert_eq!(
        report["solana"].providers[0].response,
        Value::from("slot unavailable")
    );
    assert_eq!(report["solana"].providers[0].numeric_response, None);
}

#[tokio::test]
async fn provider_health_concurrency_probes_solana_fallbacks_without_serial_delay() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://solana-primary.example".to_string()),
                    ProviderUri::Uri("https://solana-fallback.example".to_string()),
                ],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = DelayedTransport {
        calls: calls.clone(),
        delay: std::time::Duration::from_millis(120),
        response: Ok(json!({"result": 987654321})),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("solana".to_string(), "SOLANA".to_string())]),
    );

    let started_at = std::time::Instant::now();
    let report = source.get_provider_health_report().await;
    let elapsed = started_at.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(220),
        "provider probes were serialized: elapsed={elapsed:?}"
    );
    assert!(report["solana"].healthy);
    assert_eq!(report["solana"].providers.len(), 2);
    assert!(report["solana"]
        .providers
        .iter()
        .all(|entry| entry.response == 987654321));
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn provider_ordering_preserves_solana_primary_then_fallback_visibility() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://solana-primary.example".to_string()),
                    ProviderUri::Uri("https://solana-fallback.example".to_string()),
                ],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Err("primary slot unavailable".to_string()),
            Ok(json!({"result": 987654321})),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("solana".to_string(), "SOLANA".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["solana"].healthy);
    let mut urls: Vec<_> = report["solana"]
        .providers
        .iter()
        .map(|entry| entry.url.as_str())
        .collect();
    urls.sort_unstable();
    assert_eq!(
        urls,
        vec![
            "https://solana-fallback.example",
            "https://solana-primary.example"
        ]
    );
    let calls = calls.lock().unwrap();
    assert!(calls
        .iter()
        .any(|(url, _, _)| url == "https://solana-primary.example"));
    assert!(calls
        .iter()
        .any(|(url, _, _)| url == "https://solana-fallback.example"));
}
