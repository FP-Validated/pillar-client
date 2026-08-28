use super::*;

#[tokio::test]
async fn runtime_layerzero_matrix_routes_completed_non_evm_builders() {
    let (hash_builders, recorder) = runtime_matrix_hash_builders(&[
        "ethereum", "aptos", "initia", "solana", "sui", "iotal1", "starknet", "stellar",
    ]);

    for case in MOVE_MATRIX_CASES {
        let result = hash_builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &matrix_sent_event(case.chain_name, case.dst_eid),
                &message_context(1_712_345_678, None),
            )
            .await
            .unwrap();

        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            case.expected_target
        );
        assert_eq!(result.details["ulnCallData"]["methodName"], "hashPropose");
        assert_ne!(result.hash_call_data, "0xv3");
    }

    for case in HASH_MATRIX_CASES {
        let result = hash_builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &matrix_sent_event(case.chain_name, case.dst_eid),
                &message_context(1_900_000_000, case.dvn_address),
            )
            .await
            .unwrap();

        assert_eq!(result.hash_call_data, case.expected_hash);
        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            case.expected_target
        );
    }

    assert!(recorder.calls.lock().await.is_empty());
}

/// A registered destination that refuses is not the same as an unregistered
/// one. If Stellar were simply left out, the router would fall through to the
/// default EVM builder and hand back an EVM-shaped attestation for a Stellar
/// packet - a wrong answer instead of no answer. It must be present and refuse.
#[tokio::test]
async fn runtime_layerzero_matrix_refuses_stellar_for_unconfirmed_deployment() {
    let (hash_builders, recorder) = runtime_matrix_hash_builders(&["ethereum", "stellar"]);

    let error = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &matrix_sent_event("stellar", 30_600),
            &message_context(
                1_900_000_000,
                Some("0x3333333333333333333333333333333333333333"),
            ),
        )
        .await
        .expect_err("the pinned Stellar deployment is unconfirmed, so it must not build");

    let rendered = format!("{error:?}");
    // The pinned generation, the published one, and the consequence: an
    // operator reading this line should not have to find the commit.
    for needle in [
        "CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI",
        "CCV4HEII3UC65THWGSRM2DVIJLB6HS6YMUHDTTHUECX2RHTP5FA2GOBA",
        "signed over",
    ] {
        assert!(
            rendered.contains(needle),
            "the refusal must name {needle}, got {rendered}"
        );
    }
    assert!(recorder.calls.lock().await.is_empty());
}

/// The reachable case, and the reason the gate lives in the builder rather than
/// in the already-signed validator.
///
/// `PillarApp::sign_request_v2` only runs the payload-signed check when the
/// request carries a `dvnAddress` (`pillar-core/src/lib.rs:602-609`), and the
/// validator's own Stellar arm refuses only there. A request without one skips
/// that arm entirely, so before this gate existed it went all the way to a
/// signature over the superseded ULN302 id. The refusal must therefore not
/// depend on `dvnAddress`, and it must be the provenance refusal rather than a
/// complaint about the missing address.
#[tokio::test]
async fn runtime_layerzero_matrix_refuses_stellar_even_without_a_dvn_address() {
    let (hash_builders, recorder) = runtime_matrix_hash_builders(&["ethereum", "stellar"]);

    let error = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &matrix_sent_event("stellar", 30_600),
            &message_context(1_900_000_000, None),
        )
        .await
        .expect_err("a request without a dvnAddress must not slip past the gate");

    let rendered = format!("{error:?}");
    assert!(
        rendered.contains("stellar deployment for mainnet is unconfirmed"),
        "the refusal must be about provenance, not about the absent dvnAddress: {rendered}"
    );
    assert!(recorder.calls.lock().await.is_empty());
}

#[tokio::test]
async fn source_chain_parity_routes_movement_destination() {
    let (hash_builders, recorder) = runtime_matrix_hash_builders(&["ethereum", "movement"]);

    let result = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &matrix_sent_event("movement", 30_325),
            &message_context(1_900_000_000, None),
        )
        .await
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "c33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9"
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "hashPropose");
    assert!(recorder.calls.lock().await.is_empty());
}

#[tokio::test]
async fn runtime_layerzero_matrix_routes_tron_via_default_evm_builder() {
    let (hash_builders, recorder) = runtime_matrix_hash_builders(&["ethereum", "tron"]);

    let result = hash_builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &matrix_sent_event("tron", 30_420),
            &message_context(1_900_000_000, None),
        )
        .await
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x612215D4dB0475a76dCAa36C7f9afD748c42ed2D"
    );
    assert!(recorder.calls.lock().await.is_empty());
}

struct MoveMatrixCase {
    chain_name: &'static str,
    dst_eid: u64,
    expected_target: &'static str,
}

const MOVE_MATRIX_CASES: &[MoveMatrixCase] = &[
    MoveMatrixCase {
        chain_name: "aptos",
        dst_eid: 30_108,
        expected_target: "c33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9",
    },
    MoveMatrixCase {
        chain_name: "initia",
        dst_eid: 30_326,
        expected_target: "5aab6aa28749dd073c26c4703e14eb7e89dd6a25abc2e1f0e98de59f8203a012",
    },
];

struct HashMatrixCase {
    chain_name: &'static str,
    dst_eid: u64,
    dvn_address: Option<&'static str>,
    expected_hash: &'static str,
    expected_target: &'static str,
}

const HASH_MATRIX_CASES: &[HashMatrixCase] = &[
    HashMatrixCase {
        chain_name: "solana",
        dst_eid: 30_168,
        dvn_address: Some("HtEYV4xB4wvsj5fgTkcfuChYpvGYzgzwvNhgDZQNh7wW"),
        expected_hash: "07ebd4396fa094b6edf6b2e2036e584515b30525ebfd991e6b00711482cd05b2",
        expected_target: "7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH",
    },
    HashMatrixCase {
        chain_name: "sui",
        dst_eid: 30_378,
        dvn_address: None,
        expected_hash: "b15ba9d11b5958dcaae668461f92994edfdc59afce3ca6ccf8d8367040616054",
        expected_target: "3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0",
    },
    HashMatrixCase {
        chain_name: "iotal1",
        dst_eid: 30_423,
        dvn_address: None,
        expected_hash: "916f7c3c1530260b01fdd6475fd0c7fc253ccc959dce2dcbfe8bf6ac8ab6784c",
        expected_target: "042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e",
    },
    HashMatrixCase {
        chain_name: "starknet",
        dst_eid: 30_500,
        dvn_address: Some("0x3333333333333333333333333333333333333333"),
        expected_hash: "0xcbdab5c30da0f9a063c70b87823f1448e7d62b90c4219a4d7b702b374def9290",
        expected_target: "0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38",
    },
    // Stellar is deliberately absent: it is registered but refuses. See
    // `runtime_layerzero_matrix_refuses_stellar_for_unconfirmed_deployment`.
];

fn runtime_matrix_hash_builders(
    chain_names: &[&str],
) -> (
    HashMap<String, Arc<dyn HashCallDataBuilder>>,
    Arc<RuntimeLayerZeroRecorder>,
) {
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
        &chain_names
            .iter()
            .copied()
            .map(str::to_string)
            .collect::<Vec<_>>(),
        RuntimeLayerZeroDependencyInputs {
            uln_v2_payload_builder: recorder.clone(),
            read_payload_resolver: recorder.clone(),
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
    (hash_builders, recorder)
}

fn message_context(expiration: i64, dvn_address: Option<&str>) -> SigningContext {
    SigningContext::Message {
        expiration,
        skip_v_id: None,
        dvn_address: dvn_address.map(str::to_string),
        block_confirmation: 64,
    }
}

fn matrix_sent_event(dst_chain_name: &str, dst_eid: u64) -> LzSentEvent {
    let guid = match dst_eid {
        30_300 => "0x559a5d9fef2142274e3bcb7db1047d80d607a60233dd4eaef69a04f6685abb78",
        30_500 => "0xa6bdeeafd6cfa10490474502c323d26d0145f1db96a133623f469c840f45a6af",
        _ => "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    };
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
        extra: IndexMap::from([("guid".to_string(), Value::from(guid))]),
    }
}
