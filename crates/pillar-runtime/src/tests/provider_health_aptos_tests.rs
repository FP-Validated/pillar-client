use super::*;

#[tokio::test]
async fn provider_health_probes_aptos_with_rest_ledger_info() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri(
                    "https://aptos-rpc.example/v1?auth=secret-token".to_string(),
                )],
                quorum: Some(1),
            },
        )]),
        Some(&["aptos".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "chain_id": 1,
            "ledger_version": "123",
        }))])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1234,
        HashMap::from([("aptos".to_string(), "APTOS".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["aptos"].healthy);
    assert_eq!(report["aptos"].checked_at_unix_ms, 1234);
    assert_eq!(report["aptos"].providers.len(), 1);
    assert_eq!(
        report["aptos"].providers[0].url,
        "https://aptos-rpc.example/<redacted>"
    );
    assert_eq!(report["aptos"].providers[0].response, Value::from(1));
    assert_eq!(
        report["aptos"].providers[0].numeric_response,
        Some("1".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://aptos-rpc.example/v1");
    assert_eq!(calls[0].1["authorization"], "Bearer secret-token");
    assert_eq!(calls[0].2["method"], "GET");
}

#[tokio::test]
async fn provider_health_probes_aptos_no_code_indexer_like_typescript() {
    let getter = StaticProviderConfig::new(indexmap::IndexMap::from([(
        "aptos".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::UriWithHeaders {
                uri: "https://aptos-rpc.example/v1?auth=rpc-token&event-indexer=https%3A%2F%2Fevent-indexer.example%2Fgraphql&event-indexer-api-key=event-token&no-code-indexer=https%3A%2F%2Fno-code.example%2Fv1%2Fgraphql&no-code-indexer-api-key=no-code-token".to_string(),
                headers: HashMap::from([("x-extra".to_string(), "yes".to_string())]),
            }],
            quorum: Some(1),
        },
    )]), Some(&["aptos".to_string()]))
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "chain_id": 1,
                "ledger_version": "123",
            })),
            Ok(json!({
                "data": {
                    "processor_status": [{
                        "last_success_version": "98765"
                    }]
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1234,
        HashMap::from([("aptos".to_string(), "APTOS".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["aptos"].healthy);
    assert_eq!(report["aptos"].checked_at_unix_ms, 1234);
    assert_eq!(report["aptos"].providers.len(), 2);
    let rpc_entry = &report["aptos"].providers[0];
    assert_eq!(rpc_entry.response, Value::from(1));
    assert_eq!(rpc_entry.numeric_response, Some("1".to_string()));
    let indexer_entry = &report["aptos"].providers[1];
    assert_eq!(indexer_entry.url, "https://no-code.example/<redacted>");
    assert_eq!(indexer_entry.response, Value::from("98765"));
    assert_eq!(indexer_entry.numeric_response, Some("98765".to_string()));

    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://aptos-rpc.example/v1");
    assert_eq!(calls[0].1["authorization"], "Bearer rpc-token");
    assert_eq!(calls[0].1["x-extra"], "yes");
    assert_eq!(calls[0].2["method"], "GET");
    assert_eq!(calls[1].0, "https://no-code.example/v1/graphql/");
    assert_eq!(calls[1].1["Authorization"], "Bearer event-token");
    assert_eq!(calls[1].1["x-extra"], "yes");
    assert_eq!(calls[1].2["operationName"], "MyQuery");
    assert!(calls[1].2["query"]
        .as_str()
        .unwrap()
        .contains("processor_status"));
}

#[tokio::test]
async fn provider_health_probes_movement_event_indexer_like_typescript() {
    let getter = StaticProviderConfig::new(indexmap::IndexMap::from([(
        "movement".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::Uri(
                "https://movement-rpc.example/v1?event-indexer=https%3A%2F%2Fevent-indexer.example%2Fgraphql&event-indexer-api-key=event-token".to_string(),
            )],
            quorum: Some(1),
        },
    )]), Some(&["movement".to_string()]))
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "ledger_version": "123",
            })),
            Ok(json!({
                "data": {
                    "events": [{
                        "transaction_version": "456"
                    }]
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1234,
        HashMap::from([("movement".to_string(), "APTOS".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["movement"].healthy);
    assert_eq!(
        report["movement"].providers[0].numeric_response,
        Some("123".to_string())
    );
    assert_eq!(
        report["movement"].providers[1].numeric_response,
        Some("456".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[1].0, "https://event-indexer.example/graphql/");
    assert_eq!(calls[1].1["Authorization"], "Bearer event-token");
    assert_eq!(calls[1].2["operationName"], "MovementLatest");
    assert!(calls[1].2["query"]
        .as_str()
        .unwrap()
        .contains("transaction_version"));
}

#[tokio::test]
async fn provider_health_marks_aptos_unhealthy_when_ledger_info_is_not_numeric() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://aptos-a.example/v1".to_string()),
                    ProviderUri::Uri("https://aptos-b.example/v1".to_string()),
                ],
                quorum: Some(1),
            },
        )]),
        Some(&["aptos".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"chain_id": 1})),
            Ok(json!({"chain_id": "not-a-number"})),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("aptos".to_string(), "APTOS".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["aptos"].healthy);
    assert_eq!(report["aptos"].providers.len(), 2);
    assert!(report["aptos"]
        .providers
        .iter()
        .any(|entry| entry.healthy && entry.numeric_response == Some("1".to_string())));
    assert!(report["aptos"]
        .providers
        .iter()
        .any(|entry| !entry.healthy && entry.numeric_response.is_none()));
}
