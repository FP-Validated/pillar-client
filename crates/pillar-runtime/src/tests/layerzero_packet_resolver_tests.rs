use super::*;
use pillar_layerzero::{encode_lz_packet_v1, LzPacketV1};
use pillar_metrics::PillarMetrics;

#[derive(Clone)]
struct QuorumDelayTransport {
    responses: Arc<HashMap<String, (std::time::Duration, Value)>>,
}

#[async_trait]
impl JsonRpcTransport for QuorumDelayTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        let (delay, response) = self.responses.get(&url).unwrap();
        tokio::time::sleep(*delay).await;
        Ok(response.clone())
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

#[tokio::test]
async fn move_packet_sent_resolver_decodes_trusted_aptos_event() {
    let endpoint = "0xabc";
    let packet = encode_lz_packet_v1(&LzPacketV1 {
        nonce: 7,
        src_eid: 30_500,
        sender: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        dst_eid: 30_101,
        receiver: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        guid: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        message: "0xdeadbeef".to_string(),
    })
    .unwrap();
    let transaction = json!({
        "version": "7",
        "success": true,
        "events": [{
            "type": format!("{endpoint}::endpoint_v2::channels::PacketSent"),
            "data": {
                "encoded_packet": format!("0x{}", hex::encode(packet)),
                "options": "0x0102",
                "send_library": "0x4444"
            }
        }]
    });
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://aptos.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(transaction)])),
        },
        EvmPacketSentResolverConfig {
            chain_name_by_eid: HashMap::from([
                (30_101, "ethereum".to_string()),
                (30_500, "aptos".to_string()),
            ]),
            uln_version_by_send_library_address_by_chain_name: HashMap::new(),
            trusted_packet_emitters_by_chain_name: HashMap::new(),
            trusted_solana_endpoint_program_ids: HashSet::new(),
            trusted_solana_send_library_addresses: HashSet::new(),
            trusted_starknet_endpoint_addresses: HashSet::new(),
            trusted_stellar_endpoint_addresses: HashSet::new(),
            trusted_ton_packet_emitters_by_chain_name: HashMap::new(),
            trusted_move_packet_emitters_by_chain_name: HashMap::from([(
                "aptos".to_string(),
                HashSet::from([endpoint.to_string()]),
            )]),
        },
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "aptos".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), Value::from(30_500)),
                ("dstEid".to_string(), Value::from(30_101)),
                (
                    "sender".to_string(),
                    Value::from(
                        "0x1111111111111111111111111111111111111111111111111111111111111111",
                    ),
                ),
                (
                    "receiver".to_string(),
                    Value::from(
                        "0x2222222222222222222222222222222222222222222222222222222222222222",
                    ),
                ),
            ]),
        },
        nonce: 7,
        uln_send_version: Value::from("V302"),
    };

    let event = resolver.get_lz_sent_event("0xtx", &request).await.unwrap();
    assert_eq!(event.tx_hash, "0xtx");
    assert_eq!(event.message, "0xdeadbeef");
    assert_eq!(event.lz_message_id.pathway_id.src_chain_name, "aptos");
    assert_eq!(event.lz_message_id.pathway_id.dst_chain_name, "ethereum");
    assert_eq!(event.lz_message_id.nonce, 7);
    assert_eq!(event.extra["options"], "0x0102");
    assert_eq!(event.extra["sendLibrary"], "0x4444");
}

#[tokio::test]
async fn source_chain_parity_decodes_trusted_movement_event() {
    let endpoint = "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c";
    let packet = encode_lz_packet_v1(&LzPacketV1 {
        nonce: 7,
        src_eid: 30_325,
        sender: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        dst_eid: 30_101,
        receiver: "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        guid: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        message: "0xdeadbeef".to_string(),
    })
    .unwrap();
    let transaction = json!({
        "version": "7",
        "success": true,
        "events": [{
            "type": format!("{endpoint}::endpoint_v2::channels::PacketSent"),
            "data": {
                "encoded_packet": format!("0x{}", hex::encode(packet)),
                "options": "0x0102",
                "send_library": "0x4444"
            }
        }]
    });
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://movement.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(transaction)])),
        },
        EvmPacketSentResolverConfig {
            chain_name_by_eid: HashMap::from([
                (30_101, "ethereum".to_string()),
                (30_325, "movement".to_string()),
            ]),
            uln_version_by_send_library_address_by_chain_name: HashMap::new(),
            trusted_packet_emitters_by_chain_name: HashMap::new(),
            trusted_solana_endpoint_program_ids: HashSet::new(),
            trusted_solana_send_library_addresses: HashSet::new(),
            trusted_starknet_endpoint_addresses: HashSet::new(),
            trusted_stellar_endpoint_addresses: HashSet::new(),
            trusted_ton_packet_emitters_by_chain_name: HashMap::new(),
            trusted_move_packet_emitters_by_chain_name: HashMap::from([(
                "movement".to_string(),
                HashSet::from([endpoint.to_string()]),
            )]),
        },
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "movement".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), Value::from(30_325)),
                ("dstEid".to_string(), Value::from(30_101)),
                (
                    "sender".to_string(),
                    Value::from(
                        "0x1111111111111111111111111111111111111111111111111111111111111111",
                    ),
                ),
                (
                    "receiver".to_string(),
                    Value::from(
                        "0x2222222222222222222222222222222222222222222222222222222222222222",
                    ),
                ),
            ]),
        },
        nonce: 7,
        uln_send_version: Value::from("V302"),
    };

    let event = resolver.get_lz_sent_event("0xtx", &request).await.unwrap();
    assert_eq!(event.lz_message_id.pathway_id.src_chain_name, "movement");
    assert_eq!(event.lz_message_id.pathway_id.dst_chain_name, "ethereum");
    assert_eq!(event.extra["options"], "0x0102");
    assert_eq!(event.extra["sendLibrary"], "0x4444");
}

#[tokio::test]
async fn evm_packet_sent_resolver_returns_after_unambiguous_quorum() {
    let fast_receipt = json!({ "result": packet_sent_endpoint_v2_data() });
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://rpc-a.example".to_string()),
                    ProviderUri::Uri("https://rpc-b.example".to_string()),
                    ProviderUri::Uri("https://rpc-slow.example".to_string()),
                ],
                quorum: Some(2),
            },
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        QuorumDelayTransport {
            responses: Arc::new(HashMap::from([
                (
                    "https://rpc-a.example".to_string(),
                    (std::time::Duration::from_millis(10), fast_receipt.clone()),
                ),
                (
                    "https://rpc-b.example".to_string(),
                    (std::time::Duration::from_millis(10), fast_receipt.clone()),
                ),
                (
                    "https://rpc-slow.example".to_string(),
                    (std::time::Duration::from_secs(2), fast_receipt),
                ),
            ])),
        },
        evm_packet_sent_resolver_config("V302"),
    );

    let event = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        resolver.get_lz_sent_event("0xtx", &evm_packet_sent_request("V302")),
    )
    .await
    .expect("unambiguous quorum must cancel the slow provider")
    .unwrap();

    assert_eq!(event.lz_message_id.nonce, 7);
}

#[tokio::test]
async fn evm_packet_sent_resolver_decodes_endpoint_v2_receipt_log() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": packet_sent_endpoint_v2_data(),
        }))])),
    };
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
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let sent_event = resolver
        .get_lz_sent_event("0xtx", &evm_packet_sent_request("V302"))
        .await
        .unwrap();

    assert_eq!(sent_event.message, "0xdeadbeef");
    assert_eq!(
        sent_event.lz_message_id.pathway_id.src_chain_name,
        "ethereum"
    );
    assert_eq!(sent_event.lz_message_id.pathway_id.dst_chain_name, "bsc");
    assert_eq!(
        sent_event.lz_message_id.uln_send_version,
        Value::from("V302")
    );
    assert_eq!(
        sent_event.extra["guid"],
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(sent_event.extra["options"], "0x1234");
    assert_eq!(
        sent_event.extra["sendLibrary"],
        "0x3333333333333333333333333333333333333333"
    );
    assert_eq!(
        sent_event.extra["packetEmitAddress"],
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    );
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["srcEid"], 30_101);
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["dstEid"], 30_102);
    assert_eq!(calls.lock().unwrap()[0].0, "https://eth-rpc.example");
    assert_eq!(
        calls.lock().unwrap()[0].1["x-api-key"],
        "secret".to_string()
    );
    assert_eq!(
        calls.lock().unwrap()[0].2,
        json!({
            "method": "eth_getTransactionReceipt",
            "params": ["0xtx"],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
}

#[tokio::test]
async fn evm_packet_sent_resolver_requires_receipt_quorum() {
    let agreed = packet_sent_endpoint_v2_data();
    let mut forged = agreed.clone();
    forged["logs"][0]["address"] = Value::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({ "result": forged })),
            Ok(json!({ "result": agreed.clone() })),
            Ok(json!({ "result": agreed })),
        ])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://forged.example".to_string()),
                    ProviderUri::Uri("https://honest-a.example".to_string()),
                    ProviderUri::Uri("https://honest-b.example".to_string()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let sent_event = resolver
        .get_lz_sent_event("0xtx", &evm_packet_sent_request("V302"))
        .await
        .unwrap();

    assert_eq!(sent_event.message, "0xdeadbeef");
    assert_eq!(
        sent_event.extra["packetEmitAddress"],
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    );
}

#[tokio::test]
async fn evm_packet_sent_resolver_fails_closed_without_receipt_quorum() {
    let first = packet_sent_endpoint_v2_data();
    let mut second = first.clone();
    second["logs"][0]["address"] = Value::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({ "result": first })),
            Ok(json!({ "result": second })),
            Ok(json!({ "result": null })),
        ])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://rpc-a.example".to_string()),
                    ProviderUri::Uri("https://rpc-b.example".to_string()),
                    ProviderUri::Uri("https://rpc-c.example".to_string()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("0xtx", &evm_packet_sent_request("V302"))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("No receipt quorum"));
}

#[tokio::test]
async fn evm_packet_sent_resolver_rejects_untrusted_event_emitter() {
    let mut forged = packet_sent_endpoint_v2_data();
    forged["logs"][0]["address"] = Value::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": forged }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("0xtx", &evm_packet_sent_request("V302"))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("trusted PacketSent emitter"));
}

#[tokio::test]
async fn evm_packet_sent_resolver_distinguishes_identity_mismatch_from_untrusted_emitter() {
    // Trusted emitter, valid PacketSent event — but a pathway identity
    // (nonce) that doesn't match what was requested. This must not be
    // reported as an "untrusted emitter" failure; the two causes need
    // distinct diagnostics.
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "result": packet_sent_endpoint_v2_data(),
        }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let mut request = evm_packet_sent_request("V302");
    request.nonce += 1;
    let error = resolver
        .get_lz_sent_event("0xtx", &request)
        .await
        .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("trusted PacketSent emitter"), "{message}");
    assert!(
        message.contains("does not match the requested pathway identity"),
        "{message}"
    );
}

#[test]
fn lz_message_id_match_binds_full_pathway_identity() {
    let expected = evm_packet_sent_request("V302");
    assert!(lz_message_id_matches(&expected, &expected));

    for field in ["srcEid", "dstEid", "sender", "receiver"] {
        let mut actual = expected.clone();
        actual.pathway_id.extra.insert(
            field.to_string(),
            if field.ends_with("Eid") {
                Value::from(1)
            } else {
                Value::from("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            },
        );
        assert!(!lz_message_id_matches(&expected, &actual), "{field}");
    }
}

#[test]
fn lz_message_id_matches_stellar_strkey_contract_receiver_like_layerzero_scan() {
    // Real production constant: this StrKey is the Stellar mainnet ULN302
    // contract address (`STELLAR_ULN_302_MAINNET` in pillar-layerzero), and
    // its 32-byte payload is `STELLAR_ULN_302_MAINNET_BYTES`. LayerZero Scan
    // (and any Stellar-aware caller) reports Stellar addresses as StrKey,
    // never as the raw hex the packet decodes to.
    let mut expected = evm_packet_sent_request("V302");
    expected.pathway_id.extra["receiver"] =
        Value::from("CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI");
    let mut actual = expected.clone();
    actual.pathway_id.extra["receiver"] =
        Value::from("0x3b1d26188a6e55d8e4ddd6b43b7a3b0bc62078c69abb30d8c4076553c19dd7fa");
    assert!(lz_message_id_matches(&expected, &actual));
}

#[test]
fn lz_message_id_matches_stellar_strkey_account_sender_like_layerzero_scan() {
    let mut expected = evm_packet_sent_request("V302");
    expected.pathway_id.extra["sender"] =
        Value::from("GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M");
    let mut actual = expected.clone();
    // The G-account StrKey above encodes 32 bytes of 0x11.
    actual.pathway_id.extra["sender"] = Value::from(format!("0x{}", "11".repeat(32)).as_str());
    assert!(lz_message_id_matches(&expected, &actual));
}

#[test]
fn lz_message_id_rejects_invalid_stellar_strkey_checksum() {
    let mut expected = evm_packet_sent_request("V302");
    // Last character flipped, breaking the CRC16 checksum.
    expected.pathway_id.extra["receiver"] =
        Value::from("CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJJ");
    let mut actual = expected.clone();
    actual.pathway_id.extra["receiver"] =
        Value::from("0x3b1d26188a6e55d8e4ddd6b43b7a3b0bc62078c69abb30d8c4076553c19dd7fa");
    assert!(!lz_message_id_matches(&expected, &actual));
}

#[test]
fn lz_message_id_matches_ton_raw_address_receiver_like_upstream_fixtures() {
    // This codebase's own TON payload-builder fixture
    // (`pillar-layerzero::other_non_evm::ton::SOURCE_VECTOR_DVN`) uses this
    // exact "raw" `workchain:hex` address form for TON.
    let mut expected = evm_packet_sent_request("V302");
    expected.pathway_id.extra["receiver"] =
        Value::from("0:3333333333333333333333333333333333333333333333333333333333333333");
    let mut actual = expected.clone();
    actual.pathway_id.extra["receiver"] = Value::from(format!("0x{}", "33".repeat(32)).as_str());
    assert!(lz_message_id_matches(&expected, &actual));
}

#[test]
fn lz_message_id_matches_ton_friendly_address_sender_like_layerzero_scan() {
    let mut expected = evm_packet_sent_request("V302");
    expected.pathway_id.extra["sender"] =
        Value::from("EQAiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIp3C");
    let mut actual = expected.clone();
    actual.pathway_id.extra["sender"] = Value::from(format!("0x{}", "22".repeat(32)).as_str());
    assert!(lz_message_id_matches(&expected, &actual));
}

#[test]
fn lz_message_id_matches_initia_bech32_receiver_like_layerzero_scan() {
    // Initia is a Cosmos SDK chain: 20-byte account addresses, embedded in
    // the 32-byte packet field the same way EVM's 20-byte addresses are
    // (zero-padded), so the existing leading-zero-strip identity compare
    // handles the width difference.
    let mut expected = evm_packet_sent_request("V302");
    expected.pathway_id.extra["receiver"] =
        Value::from("init1xvenxvenxvenxvenxvenxvenxvenxvenjg92yg");
    let mut actual = expected.clone();
    actual.pathway_id.extra["receiver"] = Value::from(format!("0x{}", "33".repeat(20)).as_str());
    assert!(lz_message_id_matches(&expected, &actual));
}

#[test]
fn lz_message_id_matches_move_style_hex_address_across_padding_like_layerzero_scan() {
    // Aptos, Sui, and Starknet accounts are natively 0x-hex, but real
    // clients (LayerZero Scan included) often report them without the
    // packet's full 32-byte zero-padding. No new decode branch is needed
    // here — the existing leading-zero-strip hex compare already covers it,
    // the same way it already does for 20-byte EVM addresses.
    let mut expected = evm_packet_sent_request("V302");
    expected.pathway_id.extra["receiver"] =
        Value::from("0x4e65a6e5a409c9fc43ef184a642ceb490fd29b238f99c93e69e5cf11879fdf");
    let mut actual = expected.clone();
    actual.pathway_id.extra["receiver"] =
        Value::from("0x004e65a6e5a409c9fc43ef184a642ceb490fd29b238f99c93e69e5cf11879fdf");
    assert!(lz_message_id_matches(&expected, &actual));
}

#[tokio::test]
async fn evm_packet_sent_resolver_decodes_legacy_uln_v2_packet_log() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": legacy_uln_v2_packet_data(),
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
    let mut config = evm_packet_sent_resolver_config("V302");
    config.chain_name_by_eid.insert(101, "ethereum".to_string());
    config.chain_name_by_eid.insert(102, "bsc".to_string());
    config
        .uln_version_by_send_library_address_by_chain_name
        .get_mut("ethereum")
        .unwrap()
        .insert(
            "0x4444444444444444444444444444444444444444".to_string(),
            "V2".to_string(),
        );
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        config,
    );

    let mut request = evm_packet_sent_request("V2");
    request.pathway_id.extra["srcEid"] = Value::from(101);
    request.pathway_id.extra["dstEid"] = Value::from(102);
    let sent_event = resolver.get_lz_sent_event("0xtx", &request).await.unwrap();

    assert_eq!(sent_event.message, "0xdeadbeef");
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["srcEid"], 101);
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["dstEid"], 102);
    assert_eq!(
        sent_event.extra["packetEmitAddress"],
        "0x4444444444444444444444444444444444444444"
    );
    assert_eq!(sent_event.extra["options"], "0x");
}

#[tokio::test]
async fn evm_packet_sent_resolver_uses_uln301_log_address_as_send_library() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": packet_sent_uln301_data(),
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
    let mut config = evm_packet_sent_resolver_config("V302");
    config
        .uln_version_by_send_library_address_by_chain_name
        .get_mut("ethereum")
        .unwrap()
        .insert(
            "0x4444444444444444444444444444444444444444".to_string(),
            "V301".to_string(),
        );
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        config,
    );

    let sent_event = resolver
        .get_lz_sent_event("0xtx", &evm_packet_sent_request("V301"))
        .await
        .unwrap();

    assert_eq!(
        sent_event.lz_message_id.uln_send_version,
        Value::from("V301")
    );
    assert_eq!(
        sent_event.extra["sendLibrary"],
        "0x4444444444444444444444444444444444444444"
    );
}

#[tokio::test]
async fn packet_sent_resolver_decodes_solana_program_return_packet() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": solana_packet_sent_transaction_data(),
        }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let sent_event = resolver
        .get_lz_sent_event("solana-signature", &solana_packet_sent_request())
        .await
        .unwrap();

    assert_eq!(
        sent_event.message,
        "0x0000000000000000000000004208f85180b9556ff439bc73bc1c43131fde0409000000000007a120"
    );
    assert_eq!(sent_event.lz_message_id.pathway_id.src_chain_name, "solana");
    assert_eq!(
        sent_event.lz_message_id.pathway_id.dst_chain_name,
        "hyperliquid"
    );
    assert_eq!(sent_event.lz_message_id.nonce, 286);
    assert_eq!(
        sent_event.extra["guid"],
        "0xef08c522ae69e298671d4cb1f58084a21e5be098ed9a5170afa468e26a53a9fc"
    );
    assert_eq!(sent_event.extra["slot"], 431_734_504);
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["srcEid"], 30_168);
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["dstEid"], 30_367);
    assert_eq!(
        calls.lock().unwrap()[0].2,
        json!({
            "method": "getTransaction",
            "params": [
                "solana-signature",
                {
                    "encoding": "jsonParsed",
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
}

#[tokio::test]
async fn packet_sent_resolver_matches_base58_solana_sender_like_layerzero_scan() {
    // LayerZero Scan (and real API clients) report Solana pathway addresses as
    // base58 public keys, not the raw 32-byte hex the packet decodes to.
    let mut request = solana_packet_sent_request();
    request.pathway_id.extra["sender"] = Value::from("XWxJJE6Dq8EgdnhMWYU587f7St4HJuWbBHPstV2GtKR");
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": solana_packet_sent_transaction_data(),
        }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let sent_event = resolver
        .get_lz_sent_event("solana-signature", &request)
        .await
        .unwrap();

    assert_eq!(sent_event.lz_message_id.nonce, 286);
}

#[tokio::test]
async fn packet_sent_resolver_rejects_failed_solana_transaction() {
    let mut transaction = solana_packet_sent_transaction_data();
    transaction["meta"]["err"] = json!({ "InstructionError": [1, "Custom"] });
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": transaction }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("solana-signature", &solana_packet_sent_request())
        .await
        .unwrap_err();

    assert!(matches!(error, AppCoreError::BadRequest(_)));
    assert!(error.to_string().starts_with("Solana transaction failed"));
}

#[tokio::test]
async fn packet_sent_resolver_rejects_untrusted_solana_program_return() {
    let mut transaction = solana_packet_sent_transaction_data();
    transaction["meta"]["innerInstructions"][0]["instructions"][0]["programId"] =
        Value::from("Attacker1111111111111111111111111111111111111");
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": transaction }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("solana-signature", &solana_packet_sent_request())
        .await
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("trusted Solana PacketSent event"));
}

#[tokio::test]
async fn packet_sent_resolver_rejects_untrusted_solana_send_library() {
    let mut transaction = solana_packet_sent_transaction_data();
    let encoded = transaction["meta"]["innerInstructions"][0]["instructions"][0]["data"]
        .as_str()
        .unwrap();
    let mut instruction = bs58::decode(encoded).into_vec().unwrap();
    let send_library_start = instruction.len() - 32;
    instruction[send_library_start..].fill(9);
    transaction["meta"]["innerInstructions"][0]["instructions"][0]["data"] =
        Value::from(bs58::encode(instruction).into_string());
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": transaction }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("solana-signature", &solana_packet_sent_request())
        .await
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("trusted Solana PacketSent event"));
}

#[tokio::test]
async fn packet_sent_resolver_rejects_trusted_return_without_packet_sent_event() {
    let mut transaction = solana_packet_sent_transaction_data();
    transaction["meta"]["innerInstructions"] = json!([]);
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": transaction }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("solana-signature", &solana_packet_sent_request())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("PacketSent event"));
}

#[tokio::test]
async fn packet_sent_resolver_derives_solana_chain_and_version_from_packet() {
    let transaction = solana_packet_sent_transaction_data();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();

    for request in [
        {
            let mut request = solana_packet_sent_request();
            request.pathway_id.dst_chain_name = "base".to_string();
            request
        },
        {
            let mut request = solana_packet_sent_request();
            request.uln_send_version = Value::from("V301");
            request
        },
    ] {
        let transport = RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": transaction.clone()
            }))])),
        };
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&getter),
            transport,
            evm_packet_sent_resolver_config("V302"),
        );

        resolver
            .get_lz_sent_event("solana-signature", &request)
            .await
            .unwrap_err();
    }
}

#[tokio::test]
async fn packet_sent_resolver_skips_solana_program_return_false_positive_packet() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": solana_packet_sent_transaction_with_false_positive_packet_data(),
        }))])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let sent_event = resolver
        .get_lz_sent_event(
            "2C7dLfgX339zg7g5rSrvifYsmLtDVh6UrR5pmZCjEhKy4tGwtLmkLNd5rk51aBNZBuJ7ZJ87zLzfD74A8MFWWnAH",
            &solana_false_positive_packet_request(),
        )
        .await
        .unwrap();

    assert_eq!(sent_event.lz_message_id.nonce, 1918);
    assert_eq!(sent_event.lz_message_id.pathway_id.src_chain_name, "solana");
    assert_eq!(sent_event.lz_message_id.pathway_id.dst_chain_name, "base");
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["srcEid"], 30_168);
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["dstEid"], 30_184);
    assert_eq!(
        sent_event.message,
        "0x000000000000000000000000d7ca08ec1aee9cce8a8eda9365343ef197674e1a0000000184fb6d08"
    );
}

/// A refresh has to reach the signing path, not just `/provider-health`.
///
/// Every component here used to hold a `ProviderConfigs` cloned at startup, so
/// an accepted refresh moved the health report and left signing dispatching to
/// the endpoints the process booted with - indefinitely, and with no signal
/// that the two disagreed.
#[tokio::test]
async fn an_accepted_refresh_moves_where_the_signing_path_dispatches() {
    let serving = StaticProviderConfig::new(
        pillar_config::ProviderConfigs::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://booted.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        None,
    )
    .unwrap();
    let providers = ProviderSnapshotHandle::from_getter(&serving);
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let resolver = EvmPacketSentResolver::new(
        &providers,
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![
                Err("boot".to_string()),
                Err("refreshed".to_string()),
            ])),
        },
        evm_packet_sent_resolver_config("V302"),
    );

    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ethereum".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::new(),
        },
        nonce: 1,
        uln_send_version: Value::from("V302"),
    };
    let _ = resolver.get_lz_sent_event("0xtx", &request).await;

    let candidate = providers.candidate(pillar_config::ProviderConfigs::from([(
        "ethereum".to_string(),
        ProviderConfig {
            uris: vec![ProviderUri::Uri("https://refreshed.example/".to_string())],
            quorum: Some(1),
        },
    )]));
    providers.publish(candidate);

    let _ = resolver.get_lz_sent_event("0xtx", &request).await;

    let urls = calls
        .lock()
        .unwrap()
        .iter()
        .map(|(url, _, _)| url.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        urls,
        vec![
            "https://booted.example/".to_string(),
            "https://refreshed.example/".to_string()
        ],
        "the resolver must dispatch to the generation now serving"
    );
}

/// `README.md` documents `pillar_provider_request_errors_total{kind="quorum"}`
/// as "provider quorum was not reached for that chain, and every quorum path
/// reports it, EVM and non-EVM alike". That second clause is only true if every
/// quorum path records it. The Move and TON resolvers each build their
/// own `ExactQuorumAccumulator` and used to call `finish` directly, so a chain
/// family could fail quorum on every provider and the counter stayed at zero -
/// an operator alerting on this metric would see nothing at all.
#[tokio::test]
async fn move_quorum_failure_records_a_provider_request_error() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://aptos.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        None,
    )
    .unwrap();
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let mut config = evm_packet_sent_resolver_config("V302");
    config.chain_name_by_eid.insert(30_500, "aptos".to_string());
    // The trusted-emitter lookup runs before any provider is dialled, so
    // without this the request is rejected before quorum is even attempted.
    config
        .trusted_move_packet_emitters_by_chain_name
        .insert("aptos".to_string(), HashSet::from(["0xabc".to_string()]));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Err("provider unreachable".to_string())])),
        },
        config,
    )
    .with_metrics(metrics.clone());

    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "aptos".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::new(),
        },
        nonce: 7,
        uln_send_version: Value::from("V302"),
    };
    resolver
        .get_lz_sent_event("0xtx", &request)
        .await
        .expect_err("every provider failed, so quorum cannot be met");

    let rendered = metrics
        .lock()
        .await
        .render_prometheus("mainnet", "test-version");
    assert!(
        rendered
            .contains("pillar_provider_request_errors_total{chain=\"aptos\",kind=\"quorum\"} 1"),
        "the Move quorum failure went uncounted: {rendered}"
    );
}

#[tokio::test]
async fn ton_quorum_failure_records_a_provider_request_error() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri(
                    "https://ton.example/?v3-endpoint=https://ton.example/v3".to_string(),
                )],
                quorum: Some(1),
            },
        )]),
        None,
    )
    .unwrap();
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let mut config = evm_packet_sent_resolver_config("V302");
    config.chain_name_by_eid.insert(30_300, "ton".to_string());
    config
        .trusted_ton_packet_emitters_by_chain_name
        .insert("ton".to_string(), HashSet::from(["0xabc".to_string()]));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Err("provider unreachable".to_string())])),
        },
        config,
    )
    .with_metrics(metrics.clone());

    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::new(),
        },
        nonce: 7,
        uln_send_version: Value::from("V302"),
    };
    resolver
        .get_lz_sent_event("0xtx", &request)
        .await
        .expect_err("every provider failed, so quorum cannot be met");

    let rendered = metrics
        .lock()
        .await
        .render_prometheus("mainnet", "test-version");
    assert!(
        rendered.contains("pillar_provider_request_errors_total{chain=\"ton\",kind=\"quorum\"} 1"),
        "the TON quorum failure went uncounted: {rendered}"
    );
}

/// The TON resolver skips URIs it cannot parse a `v3-endpoint` out of, so it
/// pushes fewer futures than the accumulator's declared total. `remaining` then
/// never reaches zero, `unambiguous_result` keeps returning `None`, the loop
/// drains and `finish` still succeeds on the responses it did get. Recording
/// before consulting that result therefore counts a *successful* resolution as a
/// quorum failure - the counter must follow the verdict, not the fact that the
/// loop ended.
#[tokio::test]
async fn a_skipped_ton_uri_does_not_count_as_a_quorum_failure() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri(
                        "https://ton.example/?v3-endpoint=https://ton.example/v3".to_string(),
                    ),
                    // No v3-endpoint: skipped before a future is pushed.
                    ProviderUri::Uri("https://ton-broken.example/".to_string()),
                ],
                quorum: Some(1),
            },
        )]),
        None,
    )
    .unwrap();
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let mut config = evm_packet_sent_resolver_config("V302");
    config.chain_name_by_eid.insert(30_300, "ton".to_string());
    config
        .trusted_ton_packet_emitters_by_chain_name
        .insert("ton".to_string(), HashSet::from(["0xabc".to_string()]));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({"trace": []}))])),
        },
        config,
    )
    .with_metrics(metrics.clone());

    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::new(),
        },
        nonce: 7,
        uln_send_version: Value::from("V302"),
    };
    // The trace decodes to no matching packet, so resolution still fails - but
    // it fails *after* quorum was reached, which is not a provider failure.
    let _ = resolver.get_lz_sent_event("0xtx", &request).await;

    let rendered = metrics
        .lock()
        .await
        .render_prometheus("mainnet", "test-version");
    let counted = rendered.contains("pillar_provider_request_errors_total{chain=\"ton\"");
    assert!(
        !counted,
        "quorum was reached from the one usable URI, so nothing may be counted: {rendered}"
    );
}

/// A `ReadV1002` packet must survive the resolver and land on the read arms of the
/// pathway mapping and the payload hash.
///
/// Before the fix this failed with `No chain name for endpoint id 4294967295`: the two
/// endpoint ids are flipped for a read packet, so the post-flip `src_eid` is a channel,
/// and both ids were then looked up in `chain_name_by_eid` - a map built from chain names
/// that never holds a channel id. Every read packet died here, before any payload builder
/// ran.
///
/// Upstream references: the flip is
/// `packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:292-295`, and both chain
/// names coming from `dstEid` is `formatPathwayId`,
/// `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:24-26`.
#[tokio::test]
async fn runtime_evm_resolver_maps_a_read_channel_pathway_like_typescript() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": packet_sent_read_v1002_data(),
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
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("ReadV1002"),
    );

    let sent_event = resolver
        .get_lz_sent_event("0xtx", &evm_read_packet_sent_request())
        .await
        .expect("a read packet must resolve");

    // The flipped ids are kept verbatim - both are signed inside the packet header.
    assert_eq!(
        sent_event.lz_message_id.pathway_id.extra["srcEid"],
        4_294_967_295_u64
    );
    assert_eq!(sent_event.lz_message_id.pathway_id.extra["dstEid"], 30_101);
    // Both names resolve to the chain, never to the channel.
    assert_eq!(
        sent_event.lz_message_id.pathway_id.src_chain_name,
        "ethereum"
    );
    assert_eq!(
        sent_event.lz_message_id.pathway_id.dst_chain_name,
        "ethereum"
    );
    assert_eq!(
        sent_event.lz_message_id.uln_send_version,
        Value::from("ReadV1002")
    );

    // And the read arm of the payload hash is now reachable: a read source hashes the
    // message alone, so the guid is excluded.
    let proof = pillar_layerzero::compute_lz_packet_v1_proof_from_event(&sent_event)
        .expect("proof from the resolved read event");
    let expected = format!(
        "0x{}",
        hex::encode(<sha3::Keccak256 as sha3::Digest>::digest(
            hex::decode("deadbeef").expect("message bytes")
        ))
    );
    assert_eq!(proof.payload_hash, expected);
}

/// The fifth and last dispatch site: `EvmPacketSentResolver::get_lz_sent_event`. Its
/// terminal guard (`packet_resolver.rs:795-803`) rejects a chain that is not a trusted
/// EVM packet emitter, which is why a missing arm normally fails closed rather than
/// computing the wrong answer. That guard is exactly what makes the failure invisible
/// in the one configuration where it matters: a chain that IS configured as a trusted
/// EVM emitter passes the guard and gets decoded from Ethereum receipt logs.
///
/// So each chain is deliberately configured as a trusted EVM emitter here - the worst
/// case, not the convenient one - and the observable is the EVM receipt call the
/// fallback issues.
#[tokio::test]
async fn no_non_evm_chain_falls_through_to_the_evm_receipt_decode() {
    for chain_name in &super::validation_timestamp_tests::non_evm_chain_roster() {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.clone(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    quorum: Some(1),
                },
            )]),
            Some(std::slice::from_ref(chain_name)),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut config = evm_packet_sent_resolver_config("V302");
        config.trusted_packet_emitters_by_chain_name.insert(
            chain_name.clone(),
            HashSet::from(["0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string()]),
        );
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(vec![Ok(json!({})); 32])),
            },
            config,
        );
        let lz_message_id = LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: chain_name.clone(),
                dst_chain_name: "ethereum".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        };

        let _ = resolver.get_lz_sent_event("0xtx", &lz_message_id).await;

        for (_, _, body) in calls.lock().unwrap().iter() {
            assert_ne!(
                body["method"], "eth_getTransactionReceipt",
                "{chain_name} is a non-EVM chain but reached the EVM receipt decode, so \
                 its PacketSent event would be read from Ethereum receipt logs"
            );
        }
    }
}

/// The property that matters is the path a URL parser produces, not the string
/// the encoder returns. The first version of this test asserted
/// `encode_path_segment("..") == "%2E%2E"` and passed while the fix was useless:
/// WHATWG defines a double-dot segment to include its percent-encoded spellings,
/// and `url` implements that, so `%2E%2E` still popped the preceding segment.
/// Measured against url 2.5.8 - `https://rpc.example/a/b/%2E%2E` parses to path
/// `/a/`. So the encoder refuses a dot instead, and this test checks the parsed
/// path of the URL that would actually be requested.
#[test]
fn path_segment_encoding_cannot_shorten_the_request_path() {
    use crate::layerzero_runtime::encode_path_segment;

    const BASE: &str = "https://rpc.example/transactions/by_hash/";

    // A literal dot in the input is what cannot be made safe, so it is refused
    // outright and no URL is built at all.
    for refused in [
        "..",
        ".",
        "..%2F..",
        "../../admin",
        "a.b",
        "0xdead.beef",
        "",
    ] {
        assert!(
            encode_path_segment(refused).is_none(),
            "{refused:?} must be refused, got {:?}",
            encode_path_segment(refused)
        );
    }

    // An input that merely SPELLS a percent escape is not a dot: the `%` is
    // itself encoded, so `%2E` becomes `%252E`, which a parser keeps as a
    // literal segment rather than treating as `.`. Accepting these is correct,
    // and asserting the parsed path is what proves it.
    for spelled in ["%2E", "%2e", "%2E%2E", "%2e%2e"] {
        let encoded = encode_path_segment(spelled).expect("a percent escape is not a dot");
        let parsed = url::Url::parse(&format!("{BASE}{encoded}")).expect("parses");
        assert_eq!(
            parsed.path(),
            format!("/transactions/by_hash/{encoded}"),
            "{spelled:?} must survive as a literal segment"
        );
        assert_eq!(
            parsed.path_segments().unwrap().count(),
            3,
            "{spelled:?} must stay one segment: path {}",
            parsed.path()
        );
    }

    // Path metacharacters that are not dots are encoded, and the parsed path
    // keeps them inside the final segment.
    for metacharacter in ["/", "?", "#", "%", ":", "@", " ", "\\", "..%00"] {
        let Some(encoded) = encode_path_segment(metacharacter) else {
            continue;
        };
        let parsed = url::Url::parse(&format!("{BASE}{encoded}")).expect("parses");
        assert!(
            parsed.path().starts_with("/transactions/by_hash/"),
            "{metacharacter:?} escaped its segment: encoded {encoded}, path {}",
            parsed.path()
        );
        assert_eq!(
            parsed.path_segments().unwrap().count(),
            3,
            "{metacharacter:?} must stay one segment: path {}",
            parsed.path()
        );
    }

    // Real transaction ids round-trip byte-identically and stay one segment.
    for id in [
        "0xdeadbeef",
        "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe",
        "abc-DEF_123~",
    ] {
        let encoded = encode_path_segment(id).expect("a legitimate id is accepted");
        assert_eq!(encoded, id, "a legitimate id must not be rewritten: {id}");
        let parsed = url::Url::parse(&format!("{BASE}{encoded}")).expect("parses");
        assert_eq!(
            parsed.path(),
            format!("/transactions/by_hash/{id}"),
            "{id} must survive parsing unchanged"
        );
    }
}
