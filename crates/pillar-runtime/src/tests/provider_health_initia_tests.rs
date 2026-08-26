use super::*;

#[tokio::test]
async fn provider_health_probes_initia_latest_block_like_typescript() {
    let getter = StaticProviderConfig::new(indexmap::IndexMap::from([(
        "initia".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::UriWithHeaders {
                uri: "https://initia-rpc.example/lcd?event-indexer=https%3A%2F%2Findexer.example%2Fgraphql&rest-api=https%3A%2F%2Frest.example".to_string(),
                headers: HashMap::from([("authorization".to_string(), "Bearer initia-token".to_string())]),
            }],
            quorum: Some(1),
        },
    )]), Some(&["initia".to_string()]))
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "block": {
                    "header": {
                        "height": "13579"
                    }
                }
            })),
            Ok(json!({
                "data": {
                    "move_events_aggregate": {
                        "aggregate": {
                            "max": {
                                "block_height": "24680"
                            }
                        }
                    }
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 7777,
        HashMap::from([("initia".to_string(), "INITIA".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["initia"].healthy);
    assert_eq!(report["initia"].checked_at_unix_ms, 7777);
    assert_eq!(report["initia"].providers.len(), 2);
    let rpc_entry = &report["initia"].providers[0];
    assert_eq!(rpc_entry.response, Value::from("13579"));
    assert_eq!(rpc_entry.numeric_response, Some("13579".to_string()));
    let indexer_entry = &report["initia"].providers[1];
    assert_eq!(indexer_entry.response, Value::from("24680"));
    assert_eq!(indexer_entry.numeric_response, Some("24680".to_string()));
    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].0,
        "https://initia-rpc.example/lcd/cosmos/base/tendermint/v1beta1/blocks/latest"
    );
    assert_eq!(
        calls[0].1.get("authorization"),
        Some(&"Bearer initia-token".to_string())
    );
    assert_eq!(calls[0].2["method"], "GET");
    assert_eq!(calls[1].0, "https://indexer.example/graphql/");
    assert_eq!(
        calls[1].1.get("authorization"),
        Some(&"Bearer initia-token".to_string())
    );
    assert_eq!(calls[1].2["operationName"], "InitiaLatest");
    assert!(calls[1].2["query"]
        .as_str()
        .unwrap()
        .contains("move_events_aggregate"));
}

#[tokio::test]
async fn provider_health_marks_initia_unhealthy_when_latest_block_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri(
                    "https://initia-rpc.example/lcd".to_string(),
                )],
                quorum: Some(1),
            },
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Err("latest block unavailable".to_string()),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("initia".to_string(), "INITIA".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["initia"].healthy);
    assert_eq!(
        report["initia"].providers[0].response,
        Value::from("latest block unavailable")
    );
    assert_eq!(report["initia"].providers[0].numeric_response, None);
}

#[tokio::test]
async fn provider_health_falls_back_when_initia_indexer_probe_fails_like_typescript() {
    let getter = StaticProviderConfig::new(indexmap::IndexMap::from([(
        "initia".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::Uri(
                "https://initia-rpc.example/lcd?event-indexer=https%3A%2F%2Findexer.example%2Fgraphql".to_string(),
            )],
            quorum: Some(1),
        },
    )]), Some(&["initia".to_string()]))
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "block": {
                    "header": {
                        "height": "111"
                    }
                }
            })),
            Err("indexer unavailable".to_string()),
            Ok(json!({
                "block": {
                    "header": {
                        "height": "222"
                    }
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("initia".to_string(), "INITIA".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["initia"].healthy);
    assert_eq!(
        report["initia"].providers[0].numeric_response,
        Some("111".to_string())
    );
    assert_eq!(
        report["initia"].providers[1].numeric_response,
        Some("222".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[1].0, "https://indexer.example/graphql/");
    assert_eq!(
        calls[2].0,
        "https://initia-rpc.example/lcd/cosmos/base/tendermint/v1beta1/blocks/latest"
    );
    assert_eq!(calls[2].2["method"], "GET");
}
