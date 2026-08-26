use super::*;

#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_derives_mpt_hash_info_with_quorum() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::UriWithHeaders {
                    uri: "https://eth-rpc.example".to_string(),
                    headers: HashMap::from([("x-api-key".to_string(), "secret".to_string())]),
                }],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let builder = RuntimeEvmUlnV2PayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "blockHash": "0x0202020202020202020202020202020202020202020202020202020202020202"
                    }
                })),
                Ok(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "hash": "0x0202020202020202020202020202020202020202020202020202020202020202",
                        "receiptsRoot": "0x0303030303030303030303030303030303030303030303030303030303030303"
                    }
                })),
            ])),
        },
        EvmUlnPayloadBuilder::new(HashMap::from([(
            "bsc".to_string(),
            test_receive_contracts(),
        )])),
    );
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(30_101_u64));
    pathway_extra.insert("dstEid".to_string(), Value::from(30_102_u64));
    let mut extra = IndexMap::new();
    extra.insert("inboundProofType".to_string(), Value::from("1"));
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

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x4444444444444444444444444444444444444444"
    );
    assert_eq!(
        result.details["ulnCallData"]["proof"]["blockData"],
        "0x0303030303030303030303030303030303030303030303030303030303030303"
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "https://eth-rpc.example");
    assert_eq!(calls[0].1["x-api-key"], "secret");
    assert_eq!(calls[0].2["method"], "eth_getTransactionReceipt");
    assert_eq!(calls[1].2["method"], "eth_getBlockByHash");
    assert_eq!(
        calls[1].2["params"][0],
        "0x0202020202020202020202020202020202020202020202020202020202020202"
    );
}

#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_derives_feather_hash_info_without_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let builder = RuntimeEvmUlnV2PayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(Vec::new())),
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
    extra.insert("inboundProofType".to_string(), Value::from("2"));
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
    assert!(result.details["ulnCallData"]["proof"]["lookupHash"]
        .as_str()
        .unwrap()
        .starts_with("0x"));
    assert!(calls.lock().unwrap().is_empty());
}
