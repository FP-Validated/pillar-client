use super::*;

fn record(name: &str, value: Value) {
    super::round1_artifact(name, value);
}

#[test]
fn round1_solana_projection_ignores_metadata_but_binds_consumed_fields() {
    let mut first = json!({
        "result": {
            "slot": 42,
            "blockTime": 123,
            "transaction": {"message": {"accountKeys": [{"pubkey": "FeePayer"}]}},
            "meta": {
                "err": null,
                "innerInstructions": [{"index": 1, "instructions": [{"programId": "Endpoint", "data": "packet-data"}]}],
                "fee": 5000,
                "logMessages": ["provider detail"]
            }
        }
    });
    let baseline =
        crate::provider_health::parse_solana_transaction_from_observation(&first).unwrap();
    record(
        "solana-metadata-projection",
        json!({"baseline_fingerprint": baseline.fingerprint}),
    );
    first["result"]["meta"]["fee"] = json!(9000);
    first["result"]["meta"]["logMessages"] = json!(["different provider detail"]);
    first["result"]["meta"]["innerInstructions"][0]["index"] = json!(8);
    let metadata_variant =
        crate::provider_health::parse_solana_transaction_from_observation(&first).unwrap();
    record(
        "solana-metadata-variant",
        json!({"variant_fingerprint": metadata_variant.fingerprint}),
    );
    assert_eq!(baseline.fingerprint, metadata_variant.fingerprint);

    for (name, pointer, value) in [
        ("slot", "/result/slot", json!(43)),
        ("blockTime", "/result/blockTime", json!(124)),
        (
            "fee payer",
            "/result/transaction/message/accountKeys/0/pubkey",
            json!("Other"),
        ),
        (
            "inner program",
            "/result/meta/innerInstructions/0/instructions/0/programId",
            json!("OtherProgram"),
        ),
        (
            "inner data",
            "/result/meta/innerInstructions/0/instructions/0/data",
            json!("other-data"),
        ),
    ] {
        let mut changed = first.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let observation =
            crate::provider_health::parse_solana_transaction_from_observation(&changed).unwrap();
        record(
            &format!("solana-consumed-field-{}", name.replace(' ', "-")),
            json!({"field": name, "baseline": baseline.fingerprint, "mutated": observation.fingerprint}),
        );
        assert_ne!(baseline.fingerprint, observation.fingerprint, "{name}");
    }
    for invalid_err in [json!(false), json!({})] {
        let artifact_name = if invalid_err.is_boolean() {
            "solana-invalid-err-boolean"
        } else {
            "solana-invalid-err-object"
        };
        let mut malformed = first.clone();
        malformed["result"]["meta"]["err"] = invalid_err;
        let observed =
            crate::provider_health::parse_solana_transaction_from_observation(&malformed);
        record(artifact_name, json!({"result": format!("{observed:?}")}));
        assert!(observed.is_err());
    }
    let mut missing_err = first.clone();
    missing_err["result"]["meta"]
        .as_object_mut()
        .unwrap()
        .remove("err");
    let observed = crate::provider_health::parse_solana_transaction_from_observation(&missing_err);
    record(
        "solana-missing-err",
        json!({"result": format!("{observed:?}")}),
    );
    assert!(observed.is_err());
    let mut invalid_slot = first.clone();
    invalid_slot["result"]["slot"] = json!("not-a-slot");
    let observed = crate::provider_health::parse_solana_transaction_from_observation(&invalid_slot);
    record(
        "solana-invalid-slot",
        json!({"result": format!("{observed:?}")}),
    );
    assert!(observed.is_err());
    let mut invalid_time = first;
    invalid_time["result"]["blockTime"] = json!("123");
    let observed = crate::provider_health::parse_solana_transaction_from_observation(&invalid_time);
    record(
        "solana-invalid-block-time",
        json!({"result": format!("{observed:?}")}),
    );
    assert!(observed.is_err());
}

fn recorded_solana_request() -> LzMessageId {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/upstream-stage3-events.json"
    ))
    .unwrap();
    let event = &fixture["events"]["solana"]["event"];
    LzMessageId {
        pathway_id: serde_json::from_value(event["pathway"].clone()).unwrap(),
        nonce: event["nonce"].as_u64().unwrap(),
        uln_send_version: event["ulnSendVersion"].clone(),
    }
}

#[tokio::test]
async fn round1_solana_source_resolver_quorums_only_consumed_projection() {
    let first: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/solana-getTransaction-jsonParsed.response.json"
    ))
    .unwrap();
    let tx_hash = first
        .pointer("/result/transaction/signatures/0")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let mut second = first.clone();
    second["result"]["meta"]["fee"] = json!(999_999);
    second["result"]["meta"]["logMessages"] = json!(["provider-specific log"]);
    second["result"]["meta"]["computeUnitsConsumed"] = json!(1);
    second["result"]["meta"]["innerInstructions"][0]["index"] = json!(99);
    record(
        "solana-source-quorum-responses",
        json!({
            "first_fee": first.pointer("/result/meta/fee"),
            "second_fee": second.pointer("/result/meta/fee"),
            "first_inner_index": first.pointer("/result/meta/innerInstructions/0/index"),
            "second_inner_index": second.pointer("/result/meta/innerInstructions/0/index"),
        }),
    );
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://solana-a.example".to_string()),
                    ProviderUri::Uri("https://solana-b.example".to_string()),
                ],
                2,
            ),
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(first), Ok(second)])),
        },
        runtime_evm_layerzero_config("mainnet", &["solana".to_string(), "bsc".to_string()])
            .unwrap()
            .packet_sent_resolver_config,
    );
    let result = resolver
        .get_lz_sent_event(&tx_hash, &recorded_solana_request())
        .await;
    record(
        "solana-source-quorum-resolution",
        json!({
            "result": format!("{result:?}"),
            "calls": calls.lock().unwrap().clone(),
        }),
    );
    assert_eq!(result.unwrap().lz_message_id.nonce, 3826);
}
async fn resolve_starknet_fixture_event(receipt: Value) -> LzSentEvent {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/starknet_source_events.json"
    ))
    .unwrap();
    let tx_hash = fixture["txHash"].as_str().unwrap();
    let request: LzMessageId =
        serde_json::from_value(fixture["scenarios"][0]["request"].clone()).unwrap();
    let config =
        runtime_evm_layerzero_config("mainnet", &["starknet".to_string(), "ethereum".to_string()])
            .unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://starknet.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({"result": receipt}))])),
        },
        config.packet_sent_resolver_config,
    )
    .get_lz_sent_event(tx_hash, &request)
    .await
    .unwrap()
}

async fn validate_starknet_readiness(
    sent_event: &LzSentEvent,
    receipt: Value,
) -> (
    Result<Vec<pillar_core::ReadBlockPin>, AppCoreError>,
    Vec<RecordedJsonCall>,
) {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://starknet.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/starknet_source_events.json"
    ))
    .unwrap();
    let canonical_receipt = &fixture["scenarios"][0]["receipt"];
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![
                Ok(json!({"result": receipt})),
                Ok(json!({"result": 800})),
                Ok(json!({"result": {
                    "block_hash": canonical_receipt["block_hash"],
                    "block_number": canonical_receipt["block_number"]
                }})),
            ])),
        },
    );
    let result = checks
        .validate_readiness(
            sent_event,
            &SigningContext::Message {
                expiration: 0,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 0,
            },
        )
        .await;
    let calls = calls.lock().unwrap().clone();
    (result, calls)
}

#[tokio::test]
async fn round1_starknet_readiness_binds_resolved_event_to_current_canonical_receipt() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/starknet_source_events.json"
    ))
    .unwrap();
    let receipt = fixture["scenarios"][0]["receipt"].clone();
    let sent_event = resolve_starknet_fixture_event(receipt.clone()).await;
    let initial_event = receipt["events"][0].clone();
    let initial_hash = receipt["block_hash"].clone();

    let mut progressed = receipt.clone();
    progressed["finality_status"] = json!("ACCEPTED_ON_L1");
    let (stable, stable_calls) = validate_starknet_readiness(&sent_event, progressed).await;
    record(
        "starknet-stable-finality-progress",
        json!({"result": format!("{stable:?}"), "calls": stable_calls}),
    );
    stable.unwrap();

    let mut reorg = receipt.clone();
    reorg["block_hash"] =
        json!("0xabababababababababababababababababababababababababababababababab");
    let (reorg_result, reorg_calls) = validate_starknet_readiness(&sent_event, reorg.clone()).await;
    record(
        "starknet-reorg",
        json!({"resolved_hash": initial_hash, "current_hash": reorg["block_hash"], "result": format!("{reorg_result:?}"), "calls": reorg_calls}),
    );
    assert!(reorg_result.is_err());

    let mut changed_event = receipt.clone();
    changed_event["events"][0]["data"][0] = json!("0x4");
    let (event_result, event_calls) =
        validate_starknet_readiness(&sent_event, changed_event.clone()).await;
    record(
        "starknet-selected-event-mutation",
        json!({"resolved_event": initial_event, "current_event": changed_event["events"][0], "result": format!("{event_result:?}"), "calls": event_calls}),
    );
    assert!(event_result.is_err());

    let mut shifted_event = receipt.clone();
    shifted_event["events"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"from_address": "0x1", "keys": [], "data": []}));
    let (placement_result, placement_calls) =
        validate_starknet_readiness(&sent_event, shifted_event.clone()).await;
    record(
        "starknet-selected-event-placement",
        json!({"selected_event": initial_event, "current_events": shifted_event["events"], "result": format!("{placement_result:?}"), "calls": placement_calls}),
    );
    assert!(placement_result.is_err());
    let mut reverted = receipt;
    reverted["execution_status"] = json!("REVERTED");
    let (revert_result, revert_calls) =
        validate_starknet_readiness(&sent_event, reverted.clone()).await;
    record(
        "starknet-execution-revert",
        json!({"execution_status": reverted["execution_status"], "result": format!("{revert_result:?}"), "calls": revert_calls}),
    );
    assert!(revert_result.is_err());
}

async fn resolve_solana_with_untrusted_large_instruction() -> Result<LzSentEvent, AppCoreError> {
    let mut response: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/solana-getTransaction-jsonParsed.response.json"
    ))
    .unwrap();
    let tx_hash = response
        .pointer("/result/transaction/signatures/0")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let instructions = response["result"]["meta"]["innerInstructions"][0]["instructions"]
        .as_array_mut()
        .unwrap();
    instructions.insert(
        0,
        json!({
            "programId": "untrusted-program",
            "data": "z".repeat(1_000_000)
        }),
    );
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana.example".to_string())],
                1,
            ),
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(response)])),
        },
        runtime_evm_layerzero_config("mainnet", &["solana".to_string(), "bsc".to_string()])
            .unwrap()
            .packet_sent_resolver_config,
    )
    .get_lz_sent_event(&tx_hash, &recorded_solana_request())
    .await
}

#[tokio::test]
async fn round1_solana_untrusted_large_instruction_does_not_mask_trusted_packet() {
    if std::env::var_os("PILLAR_ROUND1_M04_CHILD").is_some() {
        let result = resolve_solana_with_untrusted_large_instruction().await;
        record(
            "solana-untrusted-large-instruction-child",
            json!({"result": format!("{result:?}")}),
        );
        assert_eq!(result.unwrap().lz_message_id.nonce, 3826);
        return;
    }
    let started = std::time::Instant::now();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "round1_solana_untrusted_large_instruction_does_not_mask_trusted_packet",
            "--nocapture",
        ])
        .env("PILLAR_ROUND1_M04_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = started + std::time::Duration::from_secs(8);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    record(
        "solana-untrusted-large-instruction-cost-bound",
        json!({
            "completed": status.is_some(),
            "success": status.as_ref().is_some_and(std::process::ExitStatus::success),
            "elapsed_ms": started.elapsed().as_millis()
        }),
    );
    assert!(
        status.is_some_and(|status| status.success()),
        "untrusted 1 MB base58 payload must be skipped before decode"
    );
}

#[tokio::test]
async fn round1_ton_confirmation_arithmetic_rejects_negative_head_and_clamps_behind_head() {
    async fn check(current: i64) -> Result<Vec<pillar_core::ReadBlockPin>, AppCoreError> {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                "ton".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(
                        "https://ton.example/v2?v3-endpoint=https://ton.example/v3".to_string(),
                    )],
                    1,
                ),
            )]),
            Some(&["ton".to_string()]),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls,
                responses: Arc::new(Mutex::new(vec![Ok(json!({"last": {"seqno": current}}))])),
            },
        );
        let mut sent_event = readiness_sent_event();
        sent_event.lz_message_id.pathway_id.src_chain_name = "ton".to_string();
        sent_event
            .extra
            .insert("blockNumber".to_string(), json!(20));
        checks
            .validate_readiness(
                &sent_event,
                &SigningContext::Message {
                    expiration: 0,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 0,
                },
            )
            .await
    }

    let negative = check(-1).await;
    let behind = check(10).await;
    record(
        "ton-confirmation-arithmetic",
        json!({"negative_head": format!("{negative:?}"), "head_behind": format!("{behind:?}")}),
    );
    assert!(negative.is_err());
    behind.unwrap();
}
