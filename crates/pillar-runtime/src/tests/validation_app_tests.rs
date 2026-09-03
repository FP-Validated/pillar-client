use super::*;

#[test]
fn runtime_extra_context_config_builds_from_runtime_config() {
    let runtime_config = RuntimeConfig {
        server_port: 3000,
        provider_config_type: pillar_config::ProviderConfigType::LOCAL,
        environment: Some("mainnet".to_string()),
        available_chain_names: Some(vec!["ethereum".to_string()]),
        supported_uln_versions: vec!["V2".to_string(), "V301".to_string()],
        debug_mode: false,
        extra_context_request_url: Some("https://policy.example/extra".to_string()),
        extra_context_request_auth_token: Some("secret-token".to_string()),
        extra_context_aws_lambda_name: None,
        image_version: None,
        api_auth_tokens: vec!["test-token-0123456789abcdef0123456789".to_string()],
        public_sign_routes: false,
        max_connections: 1024,
        shutdown_grace_seconds: 25,
    };

    assert_eq!(
        RuntimeExtraContextConfig::from_runtime_config(&runtime_config),
        RuntimeExtraContextConfig {
            request_url: Some("https://policy.example/extra".to_string()),
            request_auth_token: Some("secret-token".to_string()),
            aws_lambda_name: None,
        }
    );
}

#[tokio::test]
async fn runtime_app_validator_matches_core_checks_and_delegates_external_checks() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let checks = Arc::new(FixedValidationChecks {
        current_timestamp: 160,
        calls: calls.clone(),
        ranges: ranges.clone(),
    });
    let validator = RuntimeAppValidator::with_expiration_bounds(checks, 604800, 30);
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0x68656c6c6f".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::new(),
    };
    let mut request = request_v2();
    request.message_hash =
        "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8".to_string();

    validator
        .validate_message_hash(&request, &sent_event)
        .await
        .unwrap();
    validator
        .validate_readiness(&sent_event, &request.signing_context)
        .await
        .unwrap();
    validator.validate_expiration("bsc", 604900).await.unwrap();
    validator
        .validate_payload_signed(&sent_event, "0xdvn", "bsc")
        .await
        .unwrap();
    validator.validate_extra_context(&sent_event).await.unwrap();

    assert_eq!(
        ranges.lock().unwrap().as_slice(),
        &[ExpirationValidRange {
            min: 100,
            max: 604930
        }]
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        &[
            "readiness:None".to_string(),
            "timestamp:bsc".to_string(),
            "payload:0xdvn:bsc".to_string(),
            "extra".to_string(),
        ]
    );
}

#[tokio::test]
async fn runtime_app_validator_preserves_ts_error_text_for_expiration_bounds() {
    let validator = RuntimeAppValidator::with_expiration_bounds(
        Arc::new(FixedValidationChecks {
            current_timestamp: 100,
            calls: Arc::new(Mutex::new(Vec::new())),
            ranges: Arc::new(Mutex::new(Vec::new())),
        }),
        604800,
        30,
    );

    let err = validator
        .validate_expiration("bsc", 605000)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "expiration is too far in the future: expiration=605000, maxAllowed=604900"
    );
}

#[tokio::test]
async fn runtime_app_validator_rejects_expiration_range_overflow_before_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let validator = RuntimeAppValidator::with_expiration_bounds(
        Arc::new(FixedValidationChecks {
            current_timestamp: 100,
            calls: calls.clone(),
            ranges: Arc::new(Mutex::new(Vec::new())),
        }),
        604800,
        30,
    );

    for expiration in [i64::MIN, i64::MAX] {
        let error = validator
            .validate_expiration("bsc", expiration)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("expiration is outside supported range: expiration={expiration}")
        );
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_latest_evm_block_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://bsc-rpc.example".to_string(),
                    headers: HashMap::from([(
                        "authorization".to_string(),
                        "Bearer token".to_string(),
                    )]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "timestamp": "0x64"
            }
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp("bsc", ExpirationValidRange { min: 90, max: 110 })
        .await
        .unwrap();

    assert_eq!(timestamp, 100);
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://bsc-rpc.example");
    assert_eq!(
        calls[0].1.get("authorization"),
        Some(&"Bearer token".to_string())
    );
    assert_eq!(
        calls[0].2,
        json!({
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_solana_block_time_via_slot() {
    // Solana has no single-call analog to eth_getBlockByNumber: getSlot then
    // getBlockTime(slot). Regression for the "No block timestamp quorum for
    // chain solana" bug, where this path unconditionally sent an EVM-only
    // eth_getBlockByNumber RPC to every destination chain, including Solana.
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
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": 350_000_000_u64 })),
            Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": 1_783_984_794_u64 })),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "solana",
            ExpirationValidRange {
                min: 1_783_984_000,
                max: 1_783_985_000,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_783_984_794);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "https://solana-rpc.example");
    assert_eq!(
        calls[0].2,
        json!({
            "method": "getSlot",
            "params": [{ "commitment": "confirmed" }],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
    assert_eq!(
        calls[1].2,
        json!({
            "method": "getBlockTime",
            "params": [350_000_000_u64],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_normalizes_millisecond_timestamps() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "seismic".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://seismic-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["seismic".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "result": {
                "timestamp": "0x38e18d128c0"
            }
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    assert_eq!(
        checks
            .current_block_timestamp(
                "seismic",
                ExpirationValidRange {
                    min: 3_908_836_500,
                    max: 3_908_836_700
                }
            )
            .await
            .unwrap(),
        3_908_836_600
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_requires_validity_quorum() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://bsc-a.example".to_string()),
                    ProviderUri::Uri("https://bsc-b.example".to_string()),
                    ProviderUri::Uri("https://bsc-c.example".to_string()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": {"timestamp": "0x64"}})),
            Ok(json!({"result": {"timestamp": "0x65"}})),
            Ok(json!({"result": {"timestamp": "0x3e8"}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    assert_eq!(
        checks
            .current_block_timestamp("bsc", ExpirationValidRange { min: 90, max: 110 })
            .await
            .unwrap(),
        100
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_missing_validity_quorum() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://bsc-a.example".to_string()),
                    ProviderUri::Uri("https://bsc-b.example".to_string()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": {"timestamp": "0x64"}})),
            Ok(json!({"result": {"timestamp": "0x3e8"}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let err = checks
        .current_block_timestamp("bsc", ExpirationValidRange { min: 90, max: 110 })
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .starts_with("No block timestamp quorum for chain bsc"));
}
