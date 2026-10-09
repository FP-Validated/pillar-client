use super::*;

const MPT_BLOCK_HASH: &str = "0x0202020202020202020202020202020202020202020202020202020202020202";

fn mpt_evidence(block_hash: &str) -> pillar_core::EvmSourceEvidence {
    pillar_core::EvmSourceEvidence {
        block_hash: block_hash.to_string(),
        block_number: 100,
        status: "1".to_string(),
        packet_log_index: 0,
        transaction_hash: "0xtx".to_string(),
        packet_log_address: "0x1a44076050125825900e736c501f859c50fe728c".to_string(),
        packet_log_topics: vec![
            "0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f".to_string(),
        ],
        packet_log_data: "0x00".to_string(),
    }
}

fn mpt_receipt(block_hash: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "transactionHash": "0xtx",
            "status": "0x1",
            "blockHash": block_hash,
            "blockNumber": "0x64",
            "logs": [{
                "address": "0x1a44076050125825900e736c501f859c50fe728c",
                "topics": ["0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f"],
                "data": "0x00",
                "transactionHash": "0xtx",
                "blockHash": block_hash,
                "blockNumber": "0x64",
                "logIndex": "0x0",
                "removed": false
            }]
        }
    })
}

#[tokio::test]
async fn runtime_evm_uln_v2_payload_builder_derives_mpt_hash_info_with_quorum() {
    run_mpt_payload(
        Some(mpt_evidence(MPT_BLOCK_HASH)),
        mpt_receipt(MPT_BLOCK_HASH),
    )
    .await
    .0
    .unwrap();
}
#[tokio::test]
async fn runtime_evm_uln_v2_mpt_refuses_missing_source_evidence() {
    let (result, calls) = run_mpt_payload(None, mpt_receipt(MPT_BLOCK_HASH)).await;
    result.expect_err("missing source evidence must fail before reading the block");
    assert_eq!(calls, 5, "no block read when source binding is absent");
}

/// The MPT proof is built from the block the *second* receipt read names, so a receipt
/// that no longer matches what resolution captured must refuse before any block is used.
#[tokio::test]
async fn runtime_evm_uln_v2_mpt_refuses_a_receipt_that_changed_after_resolution() {
    let evidence = mpt_evidence(MPT_BLOCK_HASH);
    let (result, calls) =
        run_mpt_payload(Some(evidence.clone()), mpt_receipt(MPT_BLOCK_HASH)).await;
    result.expect("an unchanged receipt still builds");
    assert_eq!(calls, 6);

    let other = "0x0909090909090909090909090909090909090909090909090909090909090909";
    let (result, calls) = run_mpt_payload(Some(evidence), mpt_receipt(other)).await;
    // A provider whose receipt contradicts the captured evidence is a failed provider
    // response, so with quorum 1 the request fails before any block is read.
    result.expect_err("a re-included receipt must not build a proof");
    assert_eq!(calls, 5, "no eth_getBlockByHash after a changed receipt");
}

async fn run_mpt_payload(
    source_evidence: Option<pillar_core::EvmSourceEvidence>,
    receipt: Value,
) -> (Result<pillar_core::HashCallDataResult, AppCoreError>, usize) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([
            (
                "ethereum".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::UriWithHeaders {
                        uri: "https://eth-rpc.example".to_string(),
                        headers: HashMap::from([("x-api-key".to_string(), "secret".to_string())]),
                    }],
                    1,
                ),
            ),
            (
                "bsc".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                    1,
                ),
            ),
        ]),
        Some(&["ethereum".to_string(), "bsc".to_string()]),
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
                eth_call_result(&abi_address_word(
                    "0x5555555555555555555555555555555555555555",
                )),
                eth_call_result(&abi_word(1)),
                eth_call_result(&abi_word(1)),
                Ok(receipt),
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
    pathway_extra.insert(
        "receiver".to_string(),
        Value::from("0x2222222222222222222222222222222222222222"),
    );
    let extra = IndexMap::new();
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
        source_evidence,
        read_block_pins: Vec::new(),
        extra,
    };

    let result = builder
        .build_uln_v2_verify_payload(&sent_event, 64, 1, "102".to_string())
        .await;
    let count = calls.lock().unwrap().len();
    if let Ok(result) = &result {
        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            "0x4444444444444444444444444444444444444444"
        );
        assert_eq!(
            result.details["ulnCallData"]["proof"]["blockData"],
            "0x0303030303030303030303030303030303030303030303030303030303030303"
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 6);
        assert!(calls[..4]
            .iter()
            .all(|call| call.0 == "https://bsc-rpc.example"));
        assert_eq!(calls[4].0, "https://eth-rpc.example");
        assert_eq!(calls[4].1["x-api-key"], "secret");
        assert_eq!(calls[4].2["method"], "eth_getTransactionReceipt");
        assert_eq!(calls[5].2["method"], "eth_getBlockByHash");
        assert_eq!(calls[5].2["params"][0], MPT_BLOCK_HASH);
        assert_eq!(calls[5].2["params"][1], false);
    }
    (result, count)
}
