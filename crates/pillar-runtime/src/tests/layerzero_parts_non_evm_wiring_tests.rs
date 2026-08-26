use super::*;

#[tokio::test]
async fn runtime_layerzero_parts_routes_non_evm_destinations_to_registered_builders() {
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
            "starknet".to_string(),
            "stellar".to_string(),
            "ton".to_string(),
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

    let starknet = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &non_evm_sent_event("starknet", 30_500),
            &SigningContext::Message {
                expiration: 1_900_000_000,
                skip_v_id: None,
                dvn_address: Some("0x3333333333333333333333333333333333333333".to_string()),
                block_confirmation: 64,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        starknet.hash_call_data,
        "0xcbdab5c30da0f9a063c70b87823f1448e7d62b90c4219a4d7b702b374def9290"
    );
    assert_eq!(
        starknet.details["dvnCallData"]["targetContract"],
        "0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38"
    );

    let stellar = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &non_evm_sent_event("stellar", 30_500),
            &SigningContext::Message {
                expiration: 1_900_000_000,
                skip_v_id: None,
                dvn_address: Some("0x3333333333333333333333333333333333333333".to_string()),
                block_confirmation: 64,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        stellar.hash_call_data,
        "0xaf085cf8915739d0bf1c1a7c99ed88b4d194431087472ddc62acd89fc730d437"
    );
    assert_eq!(
        stellar.details["dvnCallData"]["targetContract"],
        "CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI"
    );

    let ton_error = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &non_evm_sent_event("ton", 30_300),
            &SigningContext::Message {
                expiration: 1_900_000_000,
                skip_v_id: None,
                dvn_address: Some(
                    "0:3333333333333333333333333333333333333333333333333333333333333333"
                        .to_string(),
                ),
                block_confirmation: 64,
            },
        )
        .await
        .unwrap_err();
    // TON is now a registered destination: it routes to the runtime on-chain
    // quorum builder (which here fails only because no `ton` provider is
    // configured), rather than being rejected as an unsupported chain. The full
    // byte-exact success path is covered in `ton_v3_builder` tests.
    assert!(
        ton_error
            .to_string()
            .contains("No provider config for chain ton"),
        "{ton_error}"
    );
    assert!(recorder.calls.lock().await.is_empty());
}

#[tokio::test]
async fn runtime_layerzero_parts_wires_starknet_and_stellar_on_testnet() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(Vec::new())),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sepolia".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["sepolia".to_string()]),
    )
    .unwrap();
    let recorder = Arc::new(RuntimeLayerZeroRecorder::default());
    let parts = runtime_layerzero_parts_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "testnet",
        &[
            "sepolia".to_string(),
            "starknet".to_string(),
            "stellar".to_string(),
        ],
        RuntimeLayerZeroDependencyInputs {
            uln_v2_payload_builder: recorder.clone(),
            read_payload_resolver: recorder.clone(),
            validation_checks: Arc::new(FixedValidationChecks {
                current_timestamp: 777,
                calls: Arc::new(Mutex::new(Vec::new())),
                ranges: Arc::new(Mutex::new(Vec::new())),
            }),
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
        "testnet",
    );
    for (chain_name, dst_eid, expected_target) in [
        (
            "starknet",
            40_500,
            "0x0706572d6f7b938c813a20dc1b0328b83de939066e25bd0fbe14c270077f769d",
        ),
        (
            "stellar",
            40_600,
            "CAWCTJDDZZEWYARYCY6IP7LJ5WAR5XHNDBNDNRFYNS5ZX22MH3RPSJSH",
        ),
    ] {
        let result = hash_builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &non_evm_sent_event(chain_name, dst_eid),
                &SigningContext::Message {
                    expiration: 1_900_000_000,
                    skip_v_id: None,
                    dvn_address: Some("0x3333333333333333333333333333333333333333".to_string()),
                    block_confirmation: 64,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            expected_target
        );
    }
}

fn non_evm_sent_event(dst_chain_name: &str, dst_eid: u64) -> LzSentEvent {
    let mut event_extra = IndexMap::new();
    let guid = match dst_eid {
        30_300 => "0x559a5d9fef2142274e3bcb7db1047d80d607a60233dd4eaef69a04f6685abb78",
        30_500 => "0xa6bdeeafd6cfa10490474502c323d26d0145f1db96a133623f469c840f45a6af",
        _ => "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    };
    event_extra.insert("guid".to_string(), Value::from(guid));
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: dst_chain_name.to_string(),
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
        extra: event_extra,
    }
}
