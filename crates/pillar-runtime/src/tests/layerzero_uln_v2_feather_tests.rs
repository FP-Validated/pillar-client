use super::*;

const PROOF_LIBRARY: &str = "0x5555555555555555555555555555555555555555";
/// `inboundBlockConfirmations` the destination's `getAppConfig` reports for the receiver.
const INBOUND_FLOOR: u64 = 64;

fn feather_builder(calls: RecordedJsonCalls) -> RuntimeEvmUlnV2PayloadBuilder<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    RuntimeEvmUlnV2PayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls,
            responses: Arc::new(Mutex::new(vec![
                eth_call_result(&abi_uln_v2_app_config_result(
                    2,
                    INBOUND_FLOOR,
                    "0x1111111111111111111111111111111111111111",
                    1,
                    12,
                    "0x2222222222222222222222222222222222222222",
                )),
                eth_call_result(&abi_address_word(PROOF_LIBRARY)),
                eth_call_result(&abi_word(1)),
                eth_call_result(&abi_word(2)),
            ])),
        },
        EvmUlnPayloadBuilder::new(HashMap::from([(
            "bsc".to_string(),
            test_receive_contracts(),
        )])),
    )
    .with_message_policy(true)
}

fn feather_sent_event() -> LzSentEvent {
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(101_u64));
    pathway_extra.insert("dstEid".to_string(), Value::from(102_u64));
    pathway_extra.insert(
        "sender".to_string(),
        Value::from("0x1111111111111111111111111111111111111111"),
    );
    pathway_extra.insert(
        "receiver".to_string(),
        Value::from("0x2222222222222222222222222222222222222222"),
    );
    let mut extra = IndexMap::new();
    extra.insert(
        "packetEmitAddress".to_string(),
        Value::from("0x3333333333333333333333333333333333333333"),
    );
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: pathway_extra,
            },
            nonce: 7,
            uln_send_version: Value::from(pillar_layerzero::ULN_VERSION_V2),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        source_evidence: None,
        read_block_pins: Vec::new(),
        extra,
    }
}

#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_discovers_feather_proof_type_from_destination_config() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let builder = feather_builder(calls.clone());
    let sent_event = feather_sent_event();

    let result = builder
        .build_uln_v2_verify_payload(&sent_event, 64, 1, "102".to_string())
        .await
        .unwrap();

    assert_eq!(result.details["ulnCallData"]["methodName"], "updateHash");
    assert_eq!(
        result.details["ulnCallData"]["proof"]["lookupHash"],
        result.details["ulnCallData"]["proof"]["blockData"]
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].0, "https://bsc-rpc.example");
    assert_eq!(
        calls[0].2["params"][0]["to"],
        "0x4444444444444444444444444444444444444444"
    );
    assert_eq!(
        calls[0].2["params"][0]["data"],
        build_evm_uln_v2_get_app_config_call_data(
            101,
            "0x2222222222222222222222222222222222222222"
        )
        .unwrap()
    );
    assert_eq!(
        calls[1].2["params"][0]["data"],
        build_evm_uln_v2_inbound_proof_library_call_data(101, 2).unwrap()
    );
    assert_eq!(calls[2].2["params"][0]["to"], PROOF_LIBRARY);
    assert_eq!(
        calls[2].2["params"][0]["data"],
        build_evm_validation_library_get_utils_version_call_data()
    );
    assert_eq!(calls[3].2["params"][0]["to"], PROOF_LIBRARY);
    assert_eq!(
        calls[3].2["params"][0]["data"],
        build_evm_validation_library_get_proof_type_call_data()
    );
}

/// GA-364: a V2 send has no guid, so the receive-config floor the guid path applies never ran.
/// The destination ULN accepts an oracle's `updateHash` only at or above the receiver's
/// `inboundBlockConfirmations`, which the builder already reads while it discovers the proof
/// library; signing below it wastes a signature the destination rejects.
#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_refuses_confirmations_below_the_inbound_floor() {
    for requested in [0, INBOUND_FLOOR as i64 - 1] {
        let builder = feather_builder(Arc::new(Mutex::new(Vec::new())));

        let error = builder
            .build_uln_v2_verify_payload(&feather_sent_event(), requested, 1, "102".to_string())
            .await
            .unwrap_err();

        assert_eq!(
            error,
            AppCoreError::BadRequest(format!(
                "blockConfirmation {requested} is below the {INBOUND_FLOOR} confirmations the destination receive config requires"
            )),
            "requested {requested}"
        );
    }
}

#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_accepts_confirmations_at_or_above_the_inbound_floor() {
    for requested in [INBOUND_FLOOR as i64, INBOUND_FLOOR as i64 + 1, 1_000] {
        let builder = feather_builder(Arc::new(Mutex::new(Vec::new())));

        let result = builder
            .build_uln_v2_verify_payload(&feather_sent_event(), requested, 1, "102".to_string())
            .await
            .unwrap();

        assert_eq!(result.details["ulnCallData"]["methodName"], "updateHash");
    }
}
