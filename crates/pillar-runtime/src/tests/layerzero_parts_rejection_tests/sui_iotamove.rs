use super::*;

#[tokio::test]
async fn runtime_layerzero_parts_routes_sui_iotamove_v302_like_upstream() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
    };
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
    let recorder = Arc::new(RuntimeLayerZeroRecorder::default());
    let checks = Arc::new(FixedValidationChecks {
        current_timestamp: 777,
        calls: Arc::new(Mutex::new(Vec::new())),
        ranges: Arc::new(Mutex::new(Vec::new())),
    });
    let recorder_for_uln_v2 = recorder.clone();
    let recorder_for_read = recorder.clone();
    let uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder> = recorder_for_uln_v2;
    let read_payload_resolver: Arc<dyn ReadPayloadResolver> = recorder_for_read;
    let parts = runtime_layerzero_parts_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "mainnet",
        &[
            "ethereum".to_string(),
            "sui".to_string(),
            "iotal1".to_string(),
        ],
        RuntimeLayerZeroDependencyInputs {
            uln_v2_payload_builder,
            read_payload_resolver,
            validation_checks: checks,
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
            metrics: Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new())),
        },
    )
    .unwrap();
    let hash_builders = build_hash_call_data_builders(
        parts.uln_v2_payload_builder,
        parts.uln_v3_payload_builder,
        parts.uln_read_v1_payload_builder,
        parts.read_payload_resolver,
        "mainnet",
    );
    let cases = [
        (
            "sui",
            39_000_u64,
            "a3a435b92460100101237390814fd76b78120635c4cc0f3e2836ed5bfb4d0d54",
        ),
        (
            "iotal1",
            39_200_u64,
            "62c93905a668edcc42c971b69ff87e1bd4af96f1c5fdad3f0d2c68e4db0b0211",
        ),
    ];

    for (chain_name, dst_eid, expected_hash) in cases {
        let sent_event = LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name: "ethereum".to_string(),
                    dst_chain_name: chain_name.to_string(),
                    extra: IndexMap::from([
                        ("srcEid".to_string(), Value::from(30_101_u64)),
                        ("dstEid".to_string(), Value::from(dst_eid)),
                        (
                            "sender".to_string(),
                            Value::from("0x1111111111111111111111111111111111111111"),
                        ),
                        (
                            "receiver".to_string(),
                            Value::from("0x2222222222222222222222222222222222222222"),
                        ),
                    ]),
                },
                nonce: 7,
                uln_send_version: Value::from(ULN_VERSION_V302),
            },
            message: "0xdeadbeef".to_string(),
            tx_hash: "0xtx".to_string(),
            extra: IndexMap::from([(
                "guid".to_string(),
                Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            )]),
        };

        let result = hash_builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &sent_event,
                &SigningContext::Message {
                    expiration: 1_900_000_000,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 64,
                },
            )
            .await
            .unwrap();

        assert_eq!(result.hash_call_data, expected_hash);
    }
    assert!(recorder.calls.lock().await.is_empty());
}
