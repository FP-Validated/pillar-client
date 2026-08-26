use super::*;

#[tokio::test]
async fn provider_health_probes_sui_latest_checkpoint_like_typescript() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sui".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://sui-rpc.example".to_string(),
                    headers: HashMap::from([("x-api-key".to_string(), "token".to_string())]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["sui".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "54321"}))])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 3333,
        HashMap::from([("sui".to_string(), "SUI".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["sui"].healthy);
    assert_eq!(report["sui"].checked_at_unix_ms, 3333);
    assert_eq!(report["sui"].providers[0].url, "https://sui-rpc.example");
    assert_eq!(report["sui"].providers[0].response, Value::from("54321"));
    assert_eq!(
        report["sui"].providers[0].numeric_response,
        Some("54321".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://sui-rpc.example");
    assert_eq!(calls[0].1.get("x-api-key"), Some(&"token".to_string()));
    assert_eq!(
        calls[0].2["method"],
        "sui_getLatestCheckpointSequenceNumber"
    );
    assert_eq!(calls[0].2["params"], json!([]));
}

#[tokio::test]
async fn provider_health_marks_sui_unhealthy_when_checkpoint_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sui".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://sui-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["sui".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Err("checkpoint unavailable".to_string())])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("sui".to_string(), "SUI".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["sui"].healthy);
    assert_eq!(
        report["sui"].providers[0].response,
        Value::from("checkpoint unavailable")
    );
    assert_eq!(report["sui"].providers[0].numeric_response, None);
}

#[tokio::test]
async fn provider_health_probes_starknet_block_number_like_typescript() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://starknet-rpc.example".to_string(),
                    headers: HashMap::from([(
                        "authorization".to_string(),
                        "Bearer starknet-token".to_string(),
                    )]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": 7654321}))])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 4444,
        HashMap::from([("starknet".to_string(), "STARKNET".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["starknet"].healthy);
    assert_eq!(report["starknet"].checked_at_unix_ms, 4444);
    assert_eq!(
        report["starknet"].providers[0].url,
        "https://starknet-rpc.example"
    );
    assert_eq!(
        report["starknet"].providers[0].numeric_response,
        Some("7654321".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://starknet-rpc.example");
    assert_eq!(
        calls[0].1.get("authorization"),
        Some(&"Bearer starknet-token".to_string())
    );
    assert_eq!(calls[0].2["method"], "starknet_blockNumber");
    assert_eq!(calls[0].2["params"], json!([]));
}

#[tokio::test]
async fn provider_health_marks_starknet_unhealthy_when_block_number_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://starknet-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Err("block number unavailable".to_string()),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("starknet".to_string(), "STARKNET".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["starknet"].healthy);
    assert_eq!(
        report["starknet"].providers[0].response,
        Value::from("block number unavailable")
    );
    assert_eq!(report["starknet"].providers[0].numeric_response, None);
}

#[tokio::test]
async fn provider_health_probes_iota_latest_checkpoint() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "iotal1".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://iota-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["iotal1".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "123"}))])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 4444,
        HashMap::from([("iotal1".to_string(), "IOTAMOVE".to_string())]),
    );
    let report = source.get_provider_health_report().await;
    assert!(report["iotal1"].healthy);
    assert_eq!(
        report["iotal1"].providers[0].numeric_response,
        Some("123".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].2["method"],
        "iota_getLatestCheckpointSequenceNumber"
    );
    assert_eq!(calls[0].2["params"], json!([]));
}
