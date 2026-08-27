use super::*;

pub(super) fn readiness_sent_event() -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::new(),
    }
}

pub(super) fn receipt_at(block_hash: &str, block_number: &str) -> Value {
    json!({
        "result": {
            "blockHash": block_hash,
            "blockNumber": block_number
        }
    })
}

pub(super) fn latest_block(number: &str) -> Value {
    json!({
        "result": {
            "number": number
        }
    })
}

fn solana_readiness_sent_event() -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "solana".to_string(),
                dst_chain_name: "base".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "solana-signature".to_string(),
        extra: IndexMap::new(),
    }
}

pub(super) fn block_time(number: i64, hash: &str, timestamp: i64) -> Value {
    json!({
        "result": {
            "number": format!("0x{number:x}"),
            "hash": hash,
            "timestamp": format!("0x{timestamp:x}")
        }
    })
}

fn move_readiness_sent_event(chain_name: &str, tx_hash: &str) -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: chain_name.to_string(),
                dst_chain_name: "ethereum".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: tx_hash.to_string(),
        extra: IndexMap::new(),
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_aptos_move_readiness() {
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
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"version": "7"})),
            Ok(json!({"block_height": "42"})),
            Ok(json!({"block_height": "50"})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    checks
        .validate_readiness(
            &move_readiness_sent_event("aptos", "0xtx"),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 8,
            },
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].0,
        "https://aptos.example/transactions/by_hash/0xtx"
    );
    assert_eq!(
        calls[1].0,
        "https://aptos.example/blocks/by_version/7?with_transactions=false"
    );
    assert_eq!(calls[2].0, "https://aptos.example");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_movement_move_readiness() {
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
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"version": "7"})),
            Ok(json!({"block_height": "42"})),
            Ok(json!({"block_height": "50"})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    checks
        .validate_readiness(
            &move_readiness_sent_event("movement", "0xtx"),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 8,
            },
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].0,
        "https://movement.example/transactions/by_hash/0xtx"
    );
    assert_eq!(
        calls[1].0,
        "https://movement.example/blocks/by_version/7?with_transactions=false"
    );
    assert_eq!(calls[2].0, "https://movement.example");
    assert!(calls
        .iter()
        .all(|(_, _, body)| body.get("method") == Some(&json!("GET"))));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_initia_move_readiness() {
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
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"tx_response": {"height": "42"}})),
            Ok(json!({"block": {"header": {"height": "50"}}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    checks
        .validate_readiness(
            &move_readiness_sent_event("initia", "ABC"),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 8,
            },
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[0].0,
        "https://initia.example/cosmos/tx/v1beta1/txs/ABC"
    );
    assert_eq!(
        calls[1].0,
        "https://initia.example/cosmos/base/tendermint/v1beta1/blocks/latest"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_validates_message_readiness_with_quorum() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::UriWithHeaders {
                        uri: "https://eth-a.example".to_string(),
                        headers: HashMap::from([("x-api-key".to_string(), "a".to_string())]),
                    },
                    ProviderUri::Uri("https://eth-b.example".to_string()),
                    ProviderUri::Uri("https://eth-c.example".to_string()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(receipt_at("0xaaa", "0x64")),
            Ok(latest_block("0x67")),
            Ok(receipt_at("0xaaa", "0x64")),
            Ok(latest_block("0x68")),
            Ok(receipt_at("0xbbb", "0xc8")),
            Ok(latest_block("0xc9")),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    checks
        .validate_readiness(
            &readiness_sent_event(),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 2,
            },
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].0, "https://eth-a.example");
    assert_eq!(calls[0].1["x-api-key"], "a");
    assert_eq!(calls[0].2["method"], "eth_getTransactionReceipt");
    assert_eq!(calls[0].2["params"], json!(["0xtx"]));
    assert_eq!(calls[1].2["method"], "eth_getBlockByNumber");
    assert_eq!(calls[1].2["params"], json!(["latest", false]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_validates_solana_message_readiness_with_slots() {
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
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "slot": 1_000,
                },
            })),
            Ok(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": 1_200,
            })),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    checks
        .validate_readiness(
            &solana_readiness_sent_event(),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 128,
            },
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "https://solana-rpc.example");
    assert_eq!(
        calls[0].2,
        json!({
            "method": "getTransaction",
            "params": [
                "solana-signature",
                {
                    "encoding": "json",
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
    assert_eq!(
        calls[1].2,
        json!({
            "method": "getSlot",
            "params": [{ "commitment": "finalized" }],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_insufficient_message_confirmations() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://eth.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(receipt_at("0xaaa", "0x64")),
            Ok(latest_block("0x65")),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let err = checks
        .validate_readiness(
            &readiness_sent_event(),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 2,
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "block confirmations not met, current block confirmation: 1"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_confirmation_overflow() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://eth.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(receipt_at("0xaaa", "0x1")),
                Ok(latest_block("0x1")),
            ])),
        },
    );

    let error = checks
        .validate_readiness(
            &readiness_sent_event(),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: i64::MAX,
            },
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("confirmation range overflow"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_missing_message_readiness_data() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://eth.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": null})),
            Ok(latest_block("0x65")),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let err = checks
        .validate_readiness(
            &readiness_sent_event(),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 1,
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Transaction receipt or block not found for 0xtx"
    );
}

pub(super) fn read_signing_context(
    block_number: i64,
    timestamp: i64,
    block_confirmation: i64,
) -> SigningContext {
    SigningContext::Read {
        expiration: 1,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: vec![ResolvedTimestampTimeMarker {
            block_confirmation,
            is_block_number: false,
            chain_name: "bsc".to_string(),
            block_number,
            timestamp,
        }],
    }
}

pub(super) fn read_command_signing_context(
    block_number: i64,
    timestamp: i64,
    block_confirmation: i64,
) -> SigningContext {
    SigningContext::Read {
        expiration: 1,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: vec![ResolvedTimestampTimeMarker {
            block_confirmation,
            is_block_number: false,
            chain_name: "bsc".to_string(),
            block_number,
            timestamp,
        }],
    }
}

pub(super) fn read_command_sent_event(message: String) -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("ReadV1002"),
        },
        message,
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::new(),
    }
}

pub(super) fn runtime_rpc_read_command_checks(
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
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
        calls,
        responses: Arc::new(Mutex::new(responses)),
    };
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    )
    .with_evm_chain_names(HashMap::from([(30_102, "bsc".to_string())]))
}

#[tokio::test]
async fn runtime_rpc_validation_checks_sui_checkpoint_readiness() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sui".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://sui.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["sui".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": {"checkpoint": "7"}})),
            Ok(json!({"result": "50"})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );
    checks
        .validate_readiness(
            &move_readiness_sent_event("sui", "sui-tx"),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 8,
            },
        )
        .await
        .unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].2["method"], "sui_getTransactionBlock");
    assert_eq!(calls[0].2["params"], json!(["sui-tx", null]));
    assert_eq!(
        calls[1].2["method"],
        "sui_getLatestCheckpointSequenceNumber"
    );
    assert_eq!(calls[1].2["params"], json!([]));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_stellar_ledger_readiness() {
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
            Ok(json!({"result": {"status": "SUCCESS", "ledger": 100}})),
            Ok(json!({"result": {"sequence": 108}})),
        ])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );
    let mut event = readiness_sent_event();
    event.lz_message_id.pathway_id.src_chain_name = "stellar".to_string();
    event.tx_hash = "stellar-tx".to_string();
    checks
        .validate_readiness(
            &event,
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 8,
            },
        )
        .await
        .unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls
        .iter()
        .any(|(_, _, body)| body["method"] == "getTransaction"));
    assert!(calls
        .iter()
        .any(|(_, _, body)| body["method"] == "getLatestLedger"));
}

/// Companion to the timestamp exhaustiveness test, for the generic EVM block-confirmation
/// fallback that begins at `validation_readiness.rs:338`. It calls
/// `observe_block_confirmations`, which issues `eth_getTransactionReceipt`. Readiness is
/// the check that decides whether a packet has been confirmed enough to sign, so a
/// non-EVM chain answered with Ethereum receipt semantics is the worst of the three.
#[tokio::test]
async fn no_non_evm_chain_falls_through_to_the_evm_block_confirmation_default() {
    for chain_name in &super::validation_timestamp_tests::non_evm_chain_roster() {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.clone(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    quorum: Some(1),
                },
            )]),
            Some(std::slice::from_ref(chain_name)),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({})); 32])),
        };
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            transport,
        );
        let mut sent_event = readiness_sent_event();
        sent_event.lz_message_id.pathway_id.src_chain_name = chain_name.clone();

        let _ = checks
            .validate_readiness_with_quorum(
                &sent_event,
                &SigningContext::Message {
                    expiration: 1,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 8,
                },
            )
            .await;

        for (_, _, body) in calls.lock().unwrap().iter() {
            assert_ne!(
                body["method"], "eth_getTransactionReceipt",
                "{chain_name} is a non-EVM chain but reached the EVM block-confirmation \
                 default, so its readiness would be decided with Ethereum receipt semantics"
            );
        }
    }
}
