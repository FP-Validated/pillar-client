use super::*;

#[tokio::test]
async fn runtime_layerzero_parts_from_evm_config_wires_evm_resolver_and_builders() {
    let mut receipt = packet_sent_endpoint_v2_data();
    let receipt_data = receipt["logs"][0]["data"].as_str().unwrap().replace(
        "3333333333333333333333333333333333333333",
        "bB2Ea70C9E858123480642Cf96acbcCE1372dCe1",
    );
    receipt["logs"][0]["data"] = Value::from(receipt_data);
    receipt["logs"][0]["address"] = Value::from("0x1a44076050125825900e736c501f859c50fE728c");
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": receipt,
        }))])),
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
    let recorder_for_uln_v2 = recorder.clone();
    let recorder_for_read = recorder.clone();
    let uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder> = recorder_for_uln_v2;
    let read_payload_resolver: Arc<dyn ReadPayloadResolver> = recorder_for_read;
    let checks = Arc::new(FixedValidationChecks {
        current_timestamp: 777,
        calls: Arc::new(Mutex::new(Vec::new())),
        ranges: Arc::new(Mutex::new(Vec::new())),
    });
    let parts = runtime_layerzero_parts_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "mainnet",
        &["ethereum".to_string(), "bsc".to_string()],
        RuntimeLayerZeroDependencyInputs {
            uln_v2_payload_builder,
            read_payload_resolver,
            validation_checks: checks,
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
            metrics: Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new())),
        },
    )
    .unwrap();

    let sent_event = parts
        .sent_event_resolver
        .get_lz_sent_event("0xtx", &evm_packet_sent_request("V302"))
        .await
        .unwrap();
    assert_eq!(sent_event.message, "0xdeadbeef");

    let hash_builders = build_hash_call_data_builders(
        parts.uln_v2_payload_builder,
        parts.uln_v3_payload_builder,
        parts.uln_read_v1_payload_builder,
        parts.read_payload_resolver,
        test_v_ids("mainnet"),
    );
    let result = hash_builders["V302"]
        .build_dvn_hash_call_data(
            &sent_event,
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: Some(true),
                dvn_address: None,
                block_confirmation: 64,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0xB217266c3A98C8B2709Ee26836C98cf12f6cCEC1"
    );
}

#[tokio::test]
async fn runtime_layerzero_parts_match_upstream_base_route_hashes() {
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
    let parts = runtime_layerzero_parts_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "mainnet",
        &["ethereum".to_string(), "base".to_string()],
        RuntimeLayerZeroDependencyInputs {
            uln_v2_payload_builder: recorder.clone(),
            read_payload_resolver: recorder,
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
        test_v_ids("mainnet"),
    );
    let fixtures = [
        (
            "ethereum",
            "base",
            30_101_u64,
            30_184_u64,
            "0x5555555555555555555555555555555555555555",
            "0x6666666666666666666666666666666666666666",
            1_u64,
            "0x",
            10_i64,
            "0x564d6f7b7af13684c0a0e5c6be90f27d92fea817f9469ca742e5e69e55c73b3c",
            "0x754e00c4e8c2e841de9599a14a18554ef748169aab9f64241f36319afa99948f",
            "0xc70ab6f32772f59fbfc23889caf4ba3376c84baf",
        ),
        (
            "base",
            "ethereum",
            30_184_u64,
            30_101_u64,
            "0x7777777777777777777777777777777777777777",
            "0x8888888888888888888888888888888888888888",
            101_u64,
            "0xa1b2c3d4",
            32_i64,
            "0xfd9ab947aa82cf0c219437babf411223296316cbb130f835d839bde8b0218bc9",
            "0xbed70a115f8d9237e15329532b634d9fc8f0edee2ccbd0214b47364106f3a504",
            "0xc02ab410f0734efa3f14628780e6e695156024c2",
        ),
    ];

    for (
        src_chain_name,
        dst_chain_name,
        src_eid,
        dst_eid,
        sender,
        receiver,
        nonce,
        message,
        block_confirmation,
        guid,
        expected_hash,
        expected_target,
    ) in fixtures
    {
        let sent_event = LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name: src_chain_name.to_string(),
                    dst_chain_name: dst_chain_name.to_string(),
                    extra: IndexMap::from([
                        ("srcEid".to_string(), Value::from(src_eid)),
                        ("dstEid".to_string(), Value::from(dst_eid)),
                        ("sender".to_string(), Value::from(sender)),
                        ("receiver".to_string(), Value::from(receiver)),
                    ]),
                },
                nonce,
                uln_send_version: Value::from(ULN_VERSION_V302),
            },
            message: message.to_string(),
            tx_hash: "0xtx".to_string(),
            extra: IndexMap::from([("guid".to_string(), Value::from(guid))]),
        };

        let result = hash_builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &sent_event,
                &SigningContext::Message {
                    expiration: 1_781_082_000,
                    skip_v_id: Some(false),
                    dvn_address: None,
                    block_confirmation,
                },
            )
            .await
            .unwrap();

        assert_eq!(result.hash_call_data, expected_hash);
        assert!(result.details["dvnCallData"]["targetContract"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case(expected_target));
    }
}

#[tokio::test]
async fn runtime_layerzero_parts_routes_aptos_destination_to_aptos_builder() {
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
        &["ethereum".to_string(), "aptos".to_string()],
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
        test_v_ids("mainnet"),
    );
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "aptos".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(30_101_u64)),
                    ("dstEid".to_string(), Value::from(30_108_u64)),
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
                expiration: 1_712_345_678,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 20,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "c33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9"
    );
    assert!(recorder.calls.lock().await.is_empty());
}
