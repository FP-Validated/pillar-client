use super::*;

#[tokio::test]
async fn provider_health_probes_ton_v2_and_v3_masterchain_info_like_typescript() {
    let getter = StaticProviderConfig::new(indexmap::IndexMap::from([(
        "ton".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::UriWithHeaders {
                uri: "https://ton-rpc.example/api/v2?v3-endpoint=https%3A%2F%2Fton-rpc.example%2Fapi%2Fv3&api-key=secret-token&timeout=10".to_string(),
                headers: HashMap::from([("x-extra".to_string(), "yes".to_string())]),
            }],
            quorum: Some(1),
        },
    )]), Some(&["ton".to_string()]))
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "result": {"last": {"seqno": 24680}}
            })),
            Ok(json!({
                "last": {"seqno": 13579}
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 6666,
        HashMap::from([("ton".to_string(), "TON".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["ton"].healthy);
    assert_eq!(report["ton"].checked_at_unix_ms, 6666);
    let v2_entry = &report["ton"].providers[0];
    assert_eq!(v2_entry.response, Value::from(24680));
    assert_eq!(v2_entry.numeric_response, Some("24680".to_string()));
    let v3_entry = &report["ton"].providers[1];
    assert_eq!(v3_entry.response, Value::from(13579));
    assert_eq!(v3_entry.numeric_response, Some("13579".to_string()));
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("secret-token"));
    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].0,
        "https://ton-rpc.example/api/v2/jsonRPC?api-key=secret-token&timeout=10"
    );
    assert_eq!(
        calls[0].1.get("X-API-Key"),
        Some(&"secret-token".to_string())
    );
    assert_eq!(calls[0].1.get("x-extra"), Some(&"yes".to_string()));
    assert_eq!(calls[0].2["method"], "getMasterchainInfo");
    assert_eq!(calls[0].2["params"], json!({}));
    assert_eq!(calls[0].2["id"], Value::from("1"));
    assert_eq!(calls[1].0, "https://ton-rpc.example/api/v3/masterchainInfo");
    assert_eq!(
        calls[1].1.get("X-API-Key"),
        Some(&"secret-token".to_string())
    );
    assert_eq!(calls[1].1.get("x-extra"), Some(&"yes".to_string()));
    assert_eq!(calls[1].2["method"], "GET");
}

#[tokio::test]
async fn provider_health_marks_ton_unhealthy_when_masterchain_info_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri(
                    "https://ton-rpc.example/api/v2".to_string(),
                )],
                quorum: Some(1),
            },
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Err("masterchain unavailable".to_string())])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("ton".to_string(), "TON".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["ton"].healthy);
    assert_eq!(
        report["ton"].providers[0].response,
        Value::from("masterchain unavailable")
    );
    assert_eq!(report["ton"].providers[0].numeric_response, None);
}
