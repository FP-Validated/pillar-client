use super::*;

#[tokio::test]
async fn runtime_rpc_validation_checks_validates_read_resolved_time_markers() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                100,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                90,
            )),
            Ok(block_time(
                12,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                120,
            )),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(10, 95, 2))
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].2["method"], "eth_getBlockByNumber");
    assert_eq!(calls[0].2["params"], json!(["0xa", false]));
    assert_eq!(calls[1].2["params"], json!(["0x9", false]));
    assert_eq!(calls[2].2["params"], json!(["latest", false]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_cross_checks_read_command_timestamp_markers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(
        vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                1_700_000_000,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1_699_999_990,
            )),
            Ok(block_time(
                22,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                1_700_000_100,
            )),
        ],
        calls.clone(),
    );

    checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_timestamp_marker()),
            &read_command_signing_context(10, 1_700_000_000, 12),
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].2["params"], json!(["0xa", false]));
    assert_eq!(calls[1].2["params"], json!(["0x9", false]));
    assert_eq!(calls[2].2["params"], json!(["latest", false]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_read_command_marker_confirmation_mismatch() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(vec![], calls.clone());

    let err = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_timestamp_marker()),
            &read_command_signing_context(10, 1_700_000_000, 11),
        )
        .await
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "Resolved timestamp time marker blockConfirmation mismatch for chainName bsc timestamp 1700000000: 11 != 12"
        );
    assert!(matches!(err, AppCoreError::BadRequest(_)));
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_validates_read_command_block_number_markers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_read_command_checks(
        vec![Ok(block_time(
            75,
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            1_700_000_100,
        ))],
        calls.clone(),
    );

    let err = checks
        .validate_readiness(
            &read_command_sent_event(evm_read_command_with_block_marker()),
            &SigningContext::Read {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "Block confirmation for chainName bsc for read command block marker is greater than current block number: 76 > 75"
        );
    assert!(matches!(err, AppCoreError::BadRequest(_)));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2["params"], json!(["latest", false]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_invalid_read_resolved_time_marker() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                100,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                90,
            )),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let future_err = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(10, 101, 0))
        .await
        .unwrap_err();

    assert!(future_err
        .to_string()
        .starts_with("Invalid resolved time marker for chainName bsc"));
    assert!(matches!(future_err, AppCoreError::BadRequest(_)));

    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(block_time(
            1,
            "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            1_000,
        ))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let lower_err = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(1, 900, 0))
        .await
        .unwrap_err();

    assert_eq!(
        lower_err.to_string(),
        "Invalid resolved time marker for chainName bsc: blockNumber 1 with resolved timestamp 900 does not meet actual timestamp for blockNumber 1000 and previous blockNumber null"
    );
    assert!(matches!(lower_err, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_unconfirmed_read_time_marker() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(block_time(
                10,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                100,
            )),
            Ok(block_time(
                9,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                90,
            )),
            Ok(block_time(
                11,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                120,
            )),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let err = checks
        .validate_readiness(&readiness_sent_event(), &read_signing_context(10, 95, 2))
        .await
        .unwrap_err();

    assert_eq!(
            err.to_string(),
            "Block confirmation for chainName bsc for time marker is greater than current block number: 12 > 11"
        );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_read_marker_confirmation_overflow() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(block_time(
                    i64::MAX,
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    100,
                )),
                Ok(block_time(
                    i64::MAX - 1,
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    90,
                )),
                Ok(block_time(
                    i64::MAX,
                    "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    120,
                )),
            ])),
        },
    );

    let error = checks
        .validate_readiness(
            &readiness_sent_event(),
            &read_signing_context(i64::MAX, 95, 1),
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("confirmation range overflow"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_non_evm_read_time_marker_chain() {
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
        responses: Arc::new(Mutex::new(Vec::new())),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    // Read time-marker block resolution is EVM-only (TS
    // ChainTimeMarkerValidatorSdkFactory throws for non-EVM chain types), so a
    // solana marker must fail closed before any EVM-shaped RPC is issued.
    let err = checks
        .validate_read_time_markers(
            &payload_signed_sent_event(),
            &[pillar_core::ResolvedTimestampTimeMarker {
                block_confirmation: 1,
                is_block_number: false,
                chain_name: "solana".to_string(),
                block_number: 10,
                timestamp: 100,
            }],
        )
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains("Unsupported chain type"),
        "unexpected error: {err}"
    );
    assert!(matches!(err, AppCoreError::Internal(_)));
}
