use super::*;

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_aptos_move_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://aptos.example/".to_string())],
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
            "ledger_timestamp": "1767323045000000"
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "aptos",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://aptos.example");
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_movement_move_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://movement.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["movement".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "ledger_timestamp": "1767323045000000"
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "movement",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://movement.example");
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_initia_move_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://initia.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "block": {"header": {"time": "2026-01-02T03:04:05Z"}}
        }))])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let timestamp = checks
        .current_block_timestamp(
            "initia",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();

    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0,
        "https://initia.example/cosmos/base/tendermint/v1beta1/blocks/latest"
    );
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_starknet_latest_block_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://starknet.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": {"timestamp": 1_767_323_045}
            }))])),
        },
    );

    assert_eq!(
        checks
            .current_block_timestamp(
                "starknet",
                ExpirationValidRange {
                    min: 1_767_323_000,
                    max: 1_767_323_100,
                },
            )
            .await
            .unwrap(),
        1_767_323_045
    );
    assert_eq!(calls.lock().unwrap()[0].2["params"], json!(["latest"]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_iota_checkpoint_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "iotal1".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://iota.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["iotal1".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": "123"})),
            Ok(json!({"result": {"timestampMs": "1767323045000"}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );
    let timestamp = checks
        .current_block_timestamp(
            "iotal1",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();
    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].2["method"],
        "iota_getLatestCheckpointSequenceNumber"
    );
    assert_eq!(calls[0].2["params"], json!([]));
    assert_eq!(calls[1].2["method"], "iota_getCheckpoint");
    assert_eq!(calls[1].2["params"], json!(["123"]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reads_stellar_ledger_timestamp() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://stellar.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": {"sequence": 108}})),
            Ok(json!({"result": {"ledgers": [{
                "sequence": 108,
                "ledgerCloseTime": "1767323045"
            }]}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );
    let timestamp = checks
        .current_block_timestamp(
            "stellar",
            ExpirationValidRange {
                min: 1_767_323_000,
                max: 1_767_323_100,
            },
        )
        .await
        .unwrap();
    assert_eq!(timestamp, 1_767_323_045);
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .any(|(_, _, body)| body["method"] == "getLatestLedger"));
    assert!(calls
        .iter()
        .any(|(_, _, body)| body["method"] == "getLedgers"));
}
