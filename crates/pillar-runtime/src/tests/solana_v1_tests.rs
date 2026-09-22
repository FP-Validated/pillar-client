use super::*;

const SIGNATURE: &str = "solana-signature";
const FEE_PAYER: &str = "6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA";
const TX_SLOT: i64 = 431_734_504;

fn solana_providers() -> ProviderSnapshotHandle {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    ProviderSnapshotHandle::from_getter(&getter)
}

/// A v1 `getTransaction` projection: `version: 1` plus the message-level
/// `transactionConfig` that replaces the ComputeBudget instructions in v1
/// (SIMD-0385). Account keys are parsed objects under `jsonParsed` and bare
/// base58 strings under `json`, exactly as in v0.
///
/// Synthesized from the recorded v0 PacketSent fixture and the documented v1
/// projection: v1 is opt-in for senders, so devnet carried no v1 transaction to
/// record when this was written, and mainnet had not activated the feature gate.
fn solana_v1_transaction(account_keys: Value) -> Value {
    let mut transaction = solana_packet_sent_transaction_data();
    transaction["version"] = json!(1);
    transaction["transaction"] = json!({
        "signatures": [SIGNATURE],
        "message": {
            "accountKeys": account_keys,
            "recentBlockhash": "GsdgFbNBoZmAB5uPHfk2xUFYyM4Wg2hYZBfBrxrqjxfF",
            "transactionConfig": {
                "computeUnitLimit": 30_000,
                "heapSize": null,
                "loadedAccountsDataSizeLimit": 200_000,
                "priorityFee": null,
            },
        },
    });
    transaction
}

fn solana_v1_response(account_keys: Value) -> Result<Value, String> {
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": solana_v1_transaction(account_keys),
    }))
}

fn parsed_account_keys() -> Value {
    json!([
        { "pubkey": FEE_PAYER, "signer": true, "writable": true, "source": "transaction" },
        {
            "pubkey": "11111111111111111111111111111111",
            "signer": false,
            "writable": false,
            "source": "transaction",
        },
    ])
}

fn solana_sent_event() -> LzSentEvent {
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
        tx_hash: SIGNATURE.to_string(),
        source_evidence: None,
        extra: IndexMap::new(),
    }
}

/// Every Solana read path asks for `maxSupportedTransactionVersion: 1`, so each
/// one now receives v1 bodies: a `version` of `1` and a `transactionConfig`
/// object the v0 projection never carried. None of the three consumers may
/// reject or misread a source transaction because of those fields.
#[tokio::test]
async fn solana_v1_transaction_bodies_read_like_v0_on_every_solana_read_path() {
    let resolver = EvmPacketSentResolver::new(
        &solana_providers(),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![solana_v1_response(parsed_account_keys())])),
        },
        evm_packet_sent_resolver_config("V302"),
    );
    let sent_event = resolver
        .get_lz_sent_event(SIGNATURE, &solana_packet_sent_request())
        .await
        .unwrap();
    assert_eq!(
        sent_event.message,
        "0x0000000000000000000000004208f85180b9556ff439bc73bc1c43131fde0409000000000007a120"
    );
    assert_eq!(sent_event.lz_message_id.nonce, 286);
    assert_eq!(sent_event.extra["slot"], TX_SLOT);

    // Fee-payer observation reads the message body itself: v1 drops address
    // lookup tables, so `accountKeys[0]` is the fee payer with no loaded
    // addresses appended.
    let from = RuntimeRpcValidationChecks::from_getter(
        &solana_providers(),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![solana_v1_response(parsed_account_keys())])),
        },
    )
    .source_transaction_from_address("solana", SIGNATURE)
    .await
    .unwrap();
    assert_eq!(from, FEE_PAYER);

    // Readiness asks for `json`, where account keys are bare base58 strings.
    RuntimeRpcValidationChecks::from_getter(
        &solana_providers(),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                solana_v1_response(json!([FEE_PAYER, "11111111111111111111111111111111"])),
                Ok(json!({ "jsonrpc": "2.0", "id": 1, "result": TX_SLOT + 128 })),
            ])),
        },
    )
    .validate_readiness(
        &solana_sent_event(),
        &SigningContext::Message {
            expiration: 1,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: 128,
        },
    )
    .await
    .unwrap();
}

/// Fee-payer observations reach provider quorum through a fingerprint of the
/// five fields TS `solanaParsedTransactionQuorumFn` compares, not the whole RPC
/// body. v1 adds `transactionConfig` and a `version` of `1` to that body, so
/// widening the fingerprint to the raw response would let two honest providers
/// disagree over fields nobody validates; narrowing it would let a provider
/// swap the fee payer or the event data unnoticed.
#[test]
fn solana_quorum_fingerprint_ignores_v1_fields_and_still_binds_the_compared_ones() {
    let v1 = json!({ "result": solana_v1_transaction(parsed_account_keys()) });
    let fingerprint = parse_solana_transaction_from_observation(&v1)
        .unwrap()
        .fingerprint;

    let mut v0 = v1.clone();
    v0["result"]["version"] = json!(0);
    v0["result"]["transaction"]["message"]
        .as_object_mut()
        .unwrap()
        .remove("transactionConfig");
    assert_eq!(
        fingerprint,
        parse_solana_transaction_from_observation(&v0)
            .unwrap()
            .fingerprint
    );

    let mut repriced = v1.clone();
    repriced["result"]["transaction"]["message"]["transactionConfig"]["priorityFee"] =
        json!(10_000);
    assert_eq!(
        fingerprint,
        parse_solana_transaction_from_observation(&repriced)
            .unwrap()
            .fingerprint
    );

    for pointer in [
        "/result/slot",
        "/result/meta/err",
        "/result/transaction/message/accountKeys/0/pubkey",
        "/result/meta/innerInstructions/0/instructions/0/programId",
        "/result/meta/innerInstructions/0/instructions/0/data",
    ] {
        let mut tampered = v1.clone();
        *tampered.pointer_mut(pointer).unwrap() = match pointer {
            "/result/slot" => json!(TX_SLOT + 1),
            "/result/meta/err" => json!({ "InstructionError": [0, "InvalidArgument"] }),
            _ => json!("11111111111111111111111111111111"),
        };
        assert_ne!(
            fingerprint,
            parse_solana_transaction_from_observation(&tampered)
                .unwrap()
                .fingerprint,
            "{pointer}"
        );
    }
}
