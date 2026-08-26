use super::*;

#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_discovers_feather_proof_type_from_destination_config() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let proof_library = "0x5555555555555555555555555555555555555555";
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let builder = RuntimeEvmUlnV2PayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![
                eth_call_result(&abi_uln_v2_app_config_result(
                    2,
                    64,
                    "0x1111111111111111111111111111111111111111",
                    1,
                    12,
                    "0x2222222222222222222222222222222222222222",
                )),
                eth_call_result(&abi_address_word(proof_library)),
                eth_call_result(&abi_word(3)),
                eth_call_result(&abi_word(2)),
            ])),
        },
        EvmUlnPayloadBuilder::new(HashMap::from([(
            "bsc".to_string(),
            test_receive_contracts(),
        )])),
    );
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
    let sent_event = LzSentEvent {
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
        extra,
    };

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
    assert_eq!(calls[2].2["params"][0]["to"], proof_library);
    assert_eq!(
        calls[2].2["params"][0]["data"],
        build_evm_validation_library_get_utils_version_call_data()
    );
    assert_eq!(calls[3].2["params"][0]["to"], proof_library);
    assert_eq!(
        calls[3].2["params"][0]["data"],
        build_evm_validation_library_get_proof_type_call_data()
    );
}
