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

#[tokio::test]
async fn solana_sibling_options_do_not_poison_the_selected_packet() {
    let original: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/solana-getTransaction-jsonParsed.response.json"
    ))
    .unwrap();
    for unrelated in [true, false] {
        let mut response = original.clone();
        let groups = response
            .pointer_mut("/result/meta/innerInstructions")
            .unwrap()
            .as_array_mut()
            .unwrap();
        let (instructions, index, mut bytes) = groups
            .iter_mut()
            .find_map(|group| {
                let instructions = group["instructions"].as_array_mut()?;
                let found = instructions
                    .iter()
                    .enumerate()
                    .find_map(|(index, instruction)| {
                        let bytes = bs58::decode(instruction["data"].as_str()?)
                            .into_vec()
                            .ok()?;
                        (bytes.get(8..16)
                            == Some(&[0, 0x5c, 0xa7, 0xc9, 0x8b, 0x2e, 0xab, 0x52][..]))
                        .then_some((index, bytes))
                    })?;
                Some((instructions, found.0, found.1))
            })
            .unwrap();
        let packet_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let options_at = 20 + packet_len;
        let options_len =
            u32::from_le_bytes(bytes[options_at..options_at + 4].try_into().unwrap()) as usize;
        if unrelated {
            let nonce = u64::from_be_bytes(bytes[21..29].try_into().unwrap());
            bytes[21..29].copy_from_slice(&(nonce + 1).to_be_bytes());
        }
        // Type-3 options whose lzReceive option has no gas bytes: upstream's decoder throws.
        bytes.splice(
            options_at..options_at + 4 + options_len,
            [6, 0, 0, 0, 0, 3, 1, 0, 1, 1],
        );
        let mut malformed = instructions[index].clone();
        malformed["data"] = Value::from(bs58::encode(bytes).into_string());
        if unrelated {
            instructions.insert(index, malformed);
        } else {
            instructions[index] = malformed;
        }
        let getter = StaticProviderConfig::new(
            IndexMap::from([(
                "solana".into(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://solana.example".into())],
                    1,
                ),
            )]),
            None,
        )
        .unwrap();
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(vec![Ok(response)])),
            },
            runtime_evm_layerzero_config("mainnet", &["solana".into(), "bsc".into()])
                .unwrap()
                .packet_sent_resolver_config,
        );
        let tx_hash = original
            .pointer("/result/transaction/signatures/0")
            .unwrap()
            .as_str()
            .unwrap();
        let result = resolver
            .get_lz_sent_event(tx_hash, &recorded_solana_request())
            .await;
        if unrelated {
            assert_eq!(result.unwrap().lz_message_id.nonce, 3826);
        } else {
            assert!(result.unwrap_err().to_string().contains("options decode"));
        }
    }
}
fn recorded_ton_events() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/ton-v3-events.response.json"
    ))
    .unwrap()
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

async fn resolve_recorded_ton(tx_hash: &str, trace: Value) -> Result<LzSentEvent, AppCoreError> {
    let upstream: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/upstream-stage3-events.json"
    ))
    .unwrap();
    let event = &upstream["events"]["ton"]["event"];
    let pathway = &event["pathway"];
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "arbitrum".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: event["nonce"].as_u64().unwrap(),
        uln_send_version: event["ulnSendVersion"].clone(),
    };
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
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
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(trace.clone()),
                Ok(trace.clone()),
                Ok(trace),
            ])),
        },
        config.packet_sent_resolver_config,
    )
    .get_lz_sent_event(tx_hash, &request)
    .await
}

#[test]
fn round1_ton_recorded_trace_preserves_wallet_root_and_binds_nested_event() {
    let response = recorded_ton_events();
    let tree = crate::layerzero_runtime::ton_transaction_trace_tree(&response).unwrap();
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let resolver = config.packet_sent_resolver_config;
    let events = crate::layerzero_runtime::decode_ton_packet_sent_events(
        &tree,
        &resolver.trusted_ton_packet_emitters_by_chain_name["ton"],
        &resolver.chain_name_by_eid,
    );
    let root = tree.pointer("/transaction/in_msg").unwrap();
    let event_count = events.len();
    let event_tx_hash = events
        .first()
        .map(|event| event.tx_hash.as_str())
        .unwrap_or_default();
    let event_destination = events
        .first()
        .map(|event| event.endpoint_address.as_str())
        .unwrap_or_default();
    record(
        "ton-recorded-wallet-root",
        json!({"events": event_count, "root": root, "event_destination": event_destination, "event_tx_hash": event_tx_hash}),
    );
    assert_eq!(event_count, 1);
    // The recorded root is an external-in to the wallet; the PacketSent is the nested
    // controller-bound message, so wallet and event destination are distinct identities.
    assert_eq!(root["source"], Value::Null);
    assert_ne!(root["destination"], event_destination);
    assert!(!event_tx_hash.is_empty());
}

#[tokio::test]
async fn round1_ton_hex_and_base64url_request_hashes_resolve_same_recorded_trace() {
    let tree =
        crate::layerzero_runtime::ton_transaction_trace_tree(&recorded_ton_events()).unwrap();
    let provider_hash = tree
        .pointer("/transaction/hash")
        .and_then(Value::as_str)
        .unwrap();
    let hash_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, provider_hash).unwrap();
    let hex_hash = format!("0x{}", hex::encode(&hash_bytes));
    let base64url_hash = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &hash_bytes,
    );
    let hex_event = resolve_recorded_ton(&hex_hash, recorded_ton_events())
        .await
        .unwrap();
    let base64url_event = resolve_recorded_ton(&base64url_hash, recorded_ton_events())
        .await
        .unwrap();
    let raw_hex_event =
        resolve_recorded_ton(hex_hash.strip_prefix("0x").unwrap(), recorded_ton_events()).await;
    record(
        "ton-request-hash-encodings",
        json!({
            "provider_standard_base64": provider_hash,
            "hex_request": hex_hash,
            "base64url_request": base64url_hash,
            "hex_event_tx_hash": hex_event.tx_hash,
            "base64url_event_tx_hash": base64url_event.tx_hash,
            "hex_message": hex_event.message,
            "base64url_message": base64url_event.message,
            "raw_hex_resolution": format!("{raw_hex_event:?}")
        }),
    );
    assert_eq!(hex_event.message, base64url_event.message);
    assert_eq!(hex_event.lz_message_id, base64url_event.lz_message_id);
    assert_eq!(
        hex_event.lz_message_id,
        raw_hex_event.unwrap().lz_message_id
    );
}

#[tokio::test]
async fn round1_ton_request_hash_may_identify_a_nested_trace_transaction_only() {
    let trace =
        crate::layerzero_runtime::ton_transaction_trace_tree(&recorded_ton_events()).unwrap();
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let event = crate::layerzero_runtime::decode_ton_packet_sent_events(
        &trace,
        &config
            .packet_sent_resolver_config
            .trusted_ton_packet_emitters_by_chain_name["ton"],
        &config.packet_sent_resolver_config.chain_name_by_eid,
    )
    .into_iter()
    .next()
    .unwrap();
    let hash_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.tx_hash).unwrap();
    let request_hash = format!("0x{}", hex::encode(hash_bytes));
    let root_hash = trace
        .pointer("/transaction/hash")
        .and_then(Value::as_str)
        .unwrap();
    record(
        "ton-nested-request-hash",
        json!({"request_hash": request_hash, "root_hash": root_hash}),
    );
    assert_ne!(request_hash, root_hash);
    let resolved = resolve_recorded_ton(&request_hash, recorded_ton_events())
        .await
        .unwrap();
    assert_eq!(resolved.tx_hash, event.tx_hash);

    let missing_hash = format!("0x{}", "ff".repeat(32));
    let result = resolve_recorded_ton(&missing_hash, recorded_ton_events()).await;
    record(
        "ton-unseen-request-hash",
        json!({"request_hash": missing_hash, "result": format!("{result:?}")}),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn round1_ton_base64_hashes_with_hex_like_prefixes_resolve() {
    use base64::Engine;
    // Standard base64 of a 32-byte hash starts with "0x" for 0xd3 0x1_ and "0X" for 0xd1 0x7_.
    let root_bytes = [[0xd3, 0x10].as_slice(), &[0x5a; 30]].concat();
    let child_bytes = [[0xd1, 0x70].as_slice(), &[0xa5; 30]].concat();
    let root_hash = base64::engine::general_purpose::STANDARD.encode(&root_bytes);
    let child_hash = base64::engine::general_purpose::STANDARD.encode(&child_bytes);
    assert!(root_hash.starts_with("0x") && child_hash.starts_with("0X"));

    let mut response = recorded_ton_events();
    let event = &mut response["events"][0];
    let old_root = event["trace"]["tx_hash"].as_str().unwrap().to_string();
    let old_child = event["trace"]["children"][0]["tx_hash"]
        .as_str()
        .unwrap()
        .to_string();
    for (old, new) in [(&old_root, &root_hash), (&old_child, &child_hash)] {
        let transactions = event["transactions"].as_object_mut().unwrap();
        let mut transaction = transactions.remove(old.as_str()).unwrap();
        transaction["hash"] = json!(new);
        transactions.insert(new.clone(), transaction);
    }
    event["trace"]["tx_hash"] = json!(root_hash);
    event["trace"]["children"][0]["tx_hash"] = json!(child_hash);

    let hex_request = format!("0x{}", hex::encode(&root_bytes));
    let base64url_request = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&root_bytes);
    assert!(base64url_request.starts_with("0x"));
    let hex_result = resolve_recorded_ton(&hex_request, response.clone()).await;
    let base64url_result = resolve_recorded_ton(&base64url_request, response).await;
    record(
        "ton-hex-like-base64-hashes",
        json!({
            "root_hash": root_hash,
            "child_hash": child_hash,
            "hex_request": hex_request,
            "base64url_request": base64url_request,
            "hex_result": format!("{:?}", hex_result.as_ref().map(|event| &event.lz_message_id)),
            "base64url_result": format!("{:?}", base64url_result.as_ref().map(|event| &event.lz_message_id)),
        }),
    );
    let hex_event =
        hex_result.expect("a trace with hex-like base64 hashes resolves by hex request");
    let base64url_event =
        base64url_result.expect("a base64url request that starts with 0x is a hash, not hex");
    assert_eq!(hex_event.lz_message_id, base64url_event.lz_message_id);
    assert_eq!(hex_event.message, base64url_event.message);
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

#[tokio::test]
async fn round1_ton_malformed_root_wallet_fails_before_policy_request() {
    let mut trace = recorded_ton_events();
    let root_hash = trace
        .pointer("/events/0/trace/tx_hash")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let transaction_hash = trace["events"][0]["transactions"][&root_hash]["hash"]
        .as_str()
        .unwrap();
    let hash_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, transaction_hash)
            .unwrap();
    let requested_tx_hash = format!("0x{}", hex::encode(hash_bytes));
    trace["events"][0]["transactions"]
        .as_object_mut()
        .unwrap()
        .get_mut(&root_hash)
        .unwrap()["in_msg"]["destination"] = json!("0x1234");
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
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(trace), Ok(Value::Bool(true))])),
        },
    )
    .with_extra_context(RuntimeExtraContextConfig {
        request_url: Some("https://policy.example/extra".to_string()),
        request_auth_token: None,
        aws_lambda_name: None,
    });
    let mut sent_event = readiness_sent_event();
    sent_event.lz_message_id.pathway_id.src_chain_name = "ton".to_string();
    sent_event.tx_hash = requested_tx_hash;
    with_policy_block_identity(&mut sent_event);
    let result = checks
        .validate_extra_context_request(
            &sent_event,
            &SigningContext::Message {
                expiration: 0,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 0,
            },
        )
        .await;
    let recorded = calls.lock().unwrap().clone();
    record(
        "ton-invalid-wallet-policy-order",
        json!({"result": format!("{result:?}"), "calls": recorded}),
    );
    assert!(result.is_err());
    assert_eq!(calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn round1_ton_policy_cannot_switch_to_a_trace_for_another_transaction() {
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
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![
                Ok(recorded_ton_events()),
                Ok(Value::Bool(true)),
            ])),
        },
    )
    .with_extra_context(RuntimeExtraContextConfig {
        request_url: Some("https://policy.example/extra".to_string()),
        request_auth_token: None,
        aws_lambda_name: None,
    });
    let mut sent_event = readiness_sent_event();
    sent_event.lz_message_id.pathway_id.src_chain_name = "ton".to_string();
    sent_event.tx_hash = format!("0x{}", "11".repeat(32));
    with_policy_block_identity(&mut sent_event);
    let result = checks
        .validate_extra_context_request(
            &sent_event,
            &SigningContext::Message {
                expiration: 0,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 0,
            },
        )
        .await;
    let recorded = calls.lock().unwrap().clone();
    record(
        "ton-policy-transaction-binding",
        json!({"result": format!("{result:?}"), "calls": recorded}),
    );
    assert!(result.is_err());
    assert_eq!(calls.lock().unwrap().len(), 1);
}

/// Passes the M-38 identity gate so the TON principal checks behind it are what refuse.
fn with_policy_block_identity(sent_event: &mut LzSentEvent) {
    let pathway = &mut sent_event.lz_message_id.pathway_id.extra;
    pathway.insert(
        "sender".to_string(),
        json!(format!("0x{}", "22".repeat(32))),
    );
    pathway.insert(
        "receiver".to_string(),
        json!(format!("0x{}", "33".repeat(20))),
    );
    sent_event.extra.insert(
        "onChainTxHash".to_string(),
        json!(sent_event.tx_hash.clone()),
    );
    sent_event.extra.insert(
        "blockHash".to_string(),
        json!(format!("0x{}", "ab".repeat(32))),
    );
    sent_event
        .extra
        .insert("blockNumber".to_string(), json!(96_828_301));
}

#[test]
fn round1_ton_trace_quorum_binds_every_message_node_hash() {
    let response = recorded_ton_events();
    let tree = crate::layerzero_runtime::ton_transaction_trace_tree(&response).unwrap();
    let before = crate::layerzero_runtime::ton_trace_quorum_fingerprint(&tree).unwrap();
    let mut changed = tree.clone();
    // A non-root node hash is part of the trace's identity and must not be hidden by a
    // quorum projection that only sees PacketSent candidates.
    let root_child = changed.pointer_mut("/children/0/transaction");
    if let Some(transaction) = root_child {
        transaction["hash"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    }
    let after = crate::layerzero_runtime::ton_trace_quorum_fingerprint(&changed).unwrap();
    record(
        "ton-nested-node-hash-quorum",
        json!({"before": before, "after": after}),
    );
    assert_ne!(before, after);
}

#[test]
fn round1_ton_trace_rejects_map_key_hash_disagreement() {
    let mut response = recorded_ton_events();
    let root_hash = response
        .pointer("/events/0/trace/tx_hash")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let transactions = response["events"][0]["transactions"]
        .as_object_mut()
        .unwrap();
    transactions.get_mut(&root_hash).unwrap()["hash"] =
        json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    let observed = crate::layerzero_runtime::ton_transaction_trace_tree(&response);
    record(
        "ton-mapkey-hash-binding",
        json!({"root_trace_hash": root_hash, "tree": format!("{observed:?}")}),
    );
    assert!(observed.is_none());
}

#[test]
fn round1_ton_null_message_node_hash_is_in_quorum_projection() {
    let mut tree = json!({
        "transaction": {"hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "in_msg": null},
        "children": []
    });
    let before = crate::layerzero_runtime::ton_trace_quorum_fingerprint(&tree).unwrap();
    tree["transaction"]["hash"] = json!("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=");
    let after = crate::layerzero_runtime::ton_trace_quorum_fingerprint(&tree).unwrap();
    record(
        "ton-null-message-node-hash",
        json!({"before": before, "after": after}),
    );
    assert_ne!(before, after);
}

#[test]
fn round1_ton_trace_rejects_malformed_provider_hashes() {
    for malformed in [
        "tx0",
        "0x1234",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\u{001b}",
    ] {
        let mut response = recorded_ton_events();
        let root_hash = response
            .pointer("/events/0/trace/tx_hash")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        response["events"][0]["transactions"]
            .as_object_mut()
            .unwrap()
            .get_mut(&root_hash)
            .unwrap()["hash"] = json!(malformed);
        let accepted = crate::layerzero_runtime::ton_transaction_trace_tree(&response).is_some();
        record(
            "ton-malformed-provider-hash",
            json!({"malformed": malformed, "accepted": accepted}),
        );
        assert!(!accepted);
    }
}
