use super::*;

#[tokio::test]
async fn provider_health_probes_tron_json_rpc_block_number_like_typescript() {
    let getter = StaticProviderConfig::new(indexmap::IndexMap::from([(
        "tron".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::UriWithHeaders {
                uri: "https://tron-rpc.example/jsonrpc?tron-web-url=https%3A%2F%2Ftron-web.example&tron-api-key=secret-token&keep=true".to_string(),
                headers: HashMap::from([
                    ("x-extra".to_string(), "yes".to_string()),
                    ("Authorization".to_string(), "Basic dXNlcjpwYXNz".to_string()),
                ]),
            }],
            quorum: Some(1),
        },
    )]), Some(&["tron".to_string()]))
        .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "result": "0x2a",
                "block_header": {
                    "raw_data": {
                        "number": 84
                    }
                }
            })),
            Ok(json!({
                "result": "0x2a",
                "block_header": {
                    "raw_data": {
                        "number": 84
                    }
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 8888,
        HashMap::from([("tron".to_string(), "TRON".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["tron"].healthy);
    assert_eq!(report["tron"].checked_at_unix_ms, 8888);
    assert_eq!(report["tron"].providers.len(), 2);
    let json_rpc_entry = &report["tron"].providers[0];
    assert_eq!(json_rpc_entry.response, Value::from("0x2a"));
    assert_eq!(json_rpc_entry.numeric_response, Some("42".to_string()));
    let tron_web_entry = &report["tron"].providers[1];
    assert_eq!(tron_web_entry.response, Value::from(84));
    assert_eq!(tron_web_entry.numeric_response, Some("84".to_string()));
    let serialized_report = serde_json::to_string(&report).unwrap();
    assert!(!serialized_report.contains("secret-token"));
    assert!(!serialized_report.contains("user:pass"));
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://tron-rpc.example/jsonrpc?keep=true");
    assert_eq!(
        calls[0].1.get("TRON-PRO-API-KEY"),
        Some(&"secret-token".to_string())
    );
    assert_eq!(
        calls[0].1.get("Authorization"),
        Some(&"Basic dXNlcjpwYXNz".to_string())
    );
    assert_eq!(calls[0].1.get("x-extra"), Some(&"yes".to_string()));
    assert_eq!(calls[0].2["method"], "eth_blockNumber");
    assert_eq!(calls[0].2["params"], json!([]));
    assert_eq!(calls[1].0, "https://tron-web.example/wallet/getblock");
    assert_eq!(
        calls[1].1.get("TRON-PRO-API-KEY"),
        Some(&"secret-token".to_string())
    );
    assert_eq!(calls[1].1.get("x-extra"), Some(&"yes".to_string()));
    assert_eq!(calls[1].2["detail"], Value::from(false));
}

#[tokio::test]
async fn provider_health_matches_real_trongrid_mainnet_response_shape() {
    // Captured live from https://api.trongrid.io on 2026-07-14:
    //   POST /jsonrpc {"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}
    //     -> {"jsonrpc":"2.0","id":1,"result":"0x5086ce7"}
    //   POST /wallet/getblock {"detail":false}
    //     -> {"blockID":"...","block_header":{"raw_data":{"number":84438242,...},...}}
    // This proves the probe's field paths (`result`, `block_header.raw_data.number`)
    // are not just fixture-shaped guesses but match real TronGrid mainnet output.
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "tron".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri(
                    "https://api.trongrid.io/jsonrpc?tron-web-url=https%3A%2F%2Fapi.trongrid.io"
                        .to_string(),
                )],
                quorum: Some(1),
            },
        )]),
        Some(&["tron".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0x5086ce7"
            })),
            Ok(json!({
                "blockID": "0000000005086ce2c7d99e5d98ada9c8cf472b61a6782b2a949c15a7d15256b8",
                "block_header": {
                    "raw_data": {
                        "number": 84438242,
                        "txTrieRoot": "426903ec745bf8ccbda25e4cde0da27ceacc20af2050abb809a67e2eefcf35eb",
                        "witness_address": "41beab998551416b02f6721129bb01b51fceceba08",
                        "parentHash": "0000000005086ce10bee8c1bb03624c0c299e56acc38ff159cefd5bc0a8b0bc3",
                        "version": 35,
                        "timestamp": 1783984794000_u64
                    },
                    "witness_signature": "3fee44f8b28ab7970bb8e15d657f753e322b94f09e1d0b8b60658bd39f76f6166f1f2b7f378ea9a2d962ac47ece5b7b4045b1478882ef3333e19f511466835ec00"
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("tron".to_string(), "TRON".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["tron"].healthy);
    let json_rpc_entry = &report["tron"].providers[0];
    assert_eq!(json_rpc_entry.response, Value::from("0x5086ce7"));
    assert_eq!(
        json_rpc_entry.numeric_response,
        Some("84438247".to_string())
    );
    let tron_web_entry = &report["tron"].providers[1];
    assert_eq!(tron_web_entry.response, Value::from(84_438_242_u64));
    assert_eq!(
        tron_web_entry.numeric_response,
        Some("84438242".to_string())
    );
}

#[tokio::test]
async fn provider_health_marks_tron_unhealthy_when_block_number_probe_fails() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "tron".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri(
                    "https://tron-rpc.example/jsonrpc".to_string(),
                )],
                quorum: Some(1),
            },
        )]),
        Some(&["tron".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Err("block number unavailable".to_string()),
            Ok(json!({
                "block_header": {
                    "raw_data": {
                        "number": 84
                    }
                }
            })),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("tron".to_string(), "TRON".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(!report["tron"].healthy);
    assert!(report["tron"].providers.iter().any(|entry| {
        entry.response == "block number unavailable" && entry.numeric_response.is_none()
    }));
}
