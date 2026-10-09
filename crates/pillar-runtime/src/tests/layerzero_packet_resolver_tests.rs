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
        receiver: "0x0000000000000000000000002222222222222222222222222222222222222222".to_string(),
        guid: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        message: "0xdeadbeef".to_string(),
    })
    .unwrap();
    let transaction = json!({
        "version": "7",
        "success": true,
        "events": [{
            "type": format!("{endpoint}::channels::PacketSent"),
            "data": {
                "encoded_packet": format!("0x{}", hex::encode(packet)),
                "options": "0x00030100110100000000000000000000000000030d40",
                "send_library": "0x4444"
            }
        }]
    });
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://aptos.example/".to_string())],
                1,
            ),
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
            packet_sent_bindings_by_chain_name: HashMap::new(),
            trusted_solana_endpoint_program_ids: HashSet::new(),
            trusted_solana_send_library_addresses: HashSet::new(),
            trusted_starknet_endpoint_addresses: HashSet::new(),
            trusted_stellar_endpoint_addresses: HashSet::new(),
            trusted_ton_packet_emitters_by_chain_name: HashMap::new(),
            trusted_move_packet_emitters_by_chain_name: HashMap::from([(
                "aptos".to_string(),
                HashSet::from([endpoint.to_string()]),
            )]),
            aptos_v1_source: None,
            max_eth_get_logs_block_range_by_chain_name: HashMap::new(),
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
                    Value::from("0x2222222222222222222222222222222222222222"),
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
    assert_eq!(
        event.extra["options"],
        json!({"lzReceive": {"gas": "200000", "value": "0"}, "ordered": false})
    );
    assert_eq!(
        event.extra["sendLibrary"],
        "0x0000000000000000000000000000000000000000000000000000000000004444"
    );
}

#[tokio::test]
async fn source_chain_parity_decodes_trusted_movement_event() {
    let endpoint = "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c";
    let packet = encode_lz_packet_v1(&LzPacketV1 {
        nonce: 7,
        src_eid: 30_325,
        sender: "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        dst_eid: 30_101,
        receiver: "0x0000000000000000000000002222222222222222222222222222222222222222".to_string(),
        guid: "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        message: "0xdeadbeef".to_string(),
    })
    .unwrap();
    let transaction = json!({
        "version": "7",
        "success": true,
        "events": [{
            "type": format!("{endpoint}::channels::PacketSent"),
            "data": {
                "encoded_packet": format!("0x{}", hex::encode(packet)),
                "options": "0x00030100110100000000000000000000000000030d40",
                "send_library": "0x4444"
            }
        }]
    });
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://movement.example/".to_string())],
                1,
            ),
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
            packet_sent_bindings_by_chain_name: HashMap::new(),
            trusted_solana_endpoint_program_ids: HashSet::new(),
            trusted_solana_send_library_addresses: HashSet::new(),
            trusted_starknet_endpoint_addresses: HashSet::new(),
            trusted_stellar_endpoint_addresses: HashSet::new(),
            trusted_ton_packet_emitters_by_chain_name: HashMap::new(),
            trusted_move_packet_emitters_by_chain_name: HashMap::from([(
                "movement".to_string(),
                HashSet::from([endpoint.to_string()]),
            )]),
            aptos_v1_source: None,
            max_eth_get_logs_block_range_by_chain_name: HashMap::new(),
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
                    Value::from("0x2222222222222222222222222222222222222222"),
                ),
            ]),
        },
        nonce: 7,
        uln_send_version: Value::from("V302"),
    };

    let event = resolver.get_lz_sent_event("0xtx", &request).await.unwrap();
    assert_eq!(event.lz_message_id.pathway_id.src_chain_name, "movement");
    assert_eq!(event.lz_message_id.pathway_id.dst_chain_name, "ethereum");
    assert_eq!(
        event.extra["options"],
        json!({"lzReceive": {"gas": "200000", "value": "0"}, "ordered": false})
    );
    assert_eq!(
        event.extra["sendLibrary"],
        "0x0000000000000000000000000000000000000000000000000000000000004444"
    );
}

#[tokio::test]
async fn evm_packet_sent_resolver_returns_after_unambiguous_quorum() {
    let fast_receipt = json!({ "result": packet_sent_endpoint_v2_data() });
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://rpc-a.example".to_string()),
                    ProviderUri::Uri("https://rpc-b.example".to_string()),
                    ProviderUri::Uri("https://rpc-slow.example".to_string()),
                ],
                2,
            ),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::UriWithHeaders {
                    uri: "https://eth-rpc.example".to_string(),
                    headers: HashMap::from([("x-api-key".to_string(), "secret".to_string())]),
                }],
                1,
            ),
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
    // `0x1234` is options type 0x1234, which upstream's `Options.fromOptions` decodes to nothing.
    assert_eq!(sent_event.extra["options"], json!({"ordered": false}));
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
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://forged.example".to_string()),
                    ProviderUri::Uri("https://honest-a.example".to_string()),
                    ProviderUri::Uri("https://honest-b.example".to_string()),
                ],
                2,
            ),
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
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://rpc-a.example".to_string()),
                    ProviderUri::Uri("https://rpc-b.example".to_string()),
                    ProviderUri::Uri("https://rpc-c.example".to_string()),
                ],
                2,
            ),
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

/// Upstream filters receipt logs by the trusted endpoint and throws one error -
/// `Packet does not match lzMessageId` - whether nothing trusted was emitted or
/// the trusted event belongs to another message (`endpoint/evm/index.ts:205-231`).
/// Neither case may resolve, and both carry the identity-mismatch class.
#[tokio::test]
async fn evm_resolver_treats_untrusted_emitters_and_other_messages_as_upstreams_mismatch() {
    let mut forged = packet_sent_endpoint_v2_data();
    forged["logs"][0]["address"] = Value::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mut other_nonce = evm_packet_sent_request("V302");
    other_nonce.nonce += 1;
    for (receipt, request) in [
        (forged, evm_packet_sent_request("V302")),
        (packet_sent_endpoint_v2_data(), other_nonce),
    ] {
        let transport = RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": receipt }))])),
        };
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                "ethereum".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://rpc.example".to_string())],
                    1,
                ),
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
            .get_lz_sent_event("0xtx", &request)
            .await
            .unwrap_err();

        assert!(
            matches!(&error, AppCoreError::BadRequest(message)
                if message.ends_with(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX)),
            "{error:?}"
        );
    }
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

/// Upstream compares sender and receiver with `===` against `formatPathwayId`'s
/// rendering, so only that exact string matches: the chain-native and padded
/// spellings LayerZero Scan shows are an upstream 400 and must not match here.
#[test]
fn lz_message_id_matches_only_upstreams_rendering_of_each_address() {
    let evm = format!("0x{}{}", "00".repeat(12), "1a".repeat(20));
    let evm_rendered = format!("0x{}", "1a".repeat(20));
    let wide = format!("0x{}", "3b".repeat(32));
    let solana = format!("0x{}", "07".repeat(32));
    let solana_rendered = bs58::encode(vec![7u8; 32]).into_string();
    let zero = format!("0x{}", "00".repeat(32));
    let id = |src: &str, sender: &str, dst: &str, receiver: &str| {
        let mut id = evm_packet_sent_request("V302");
        id.pathway_id.src_chain_name = src.to_string();
        id.pathway_id.dst_chain_name = dst.to_string();
        id.pathway_id.extra["sender"] = Value::from(sender);
        id.pathway_id.extra["receiver"] = Value::from(receiver);
        id
    };
    // (event as resolved, request upstream accepts, key, spellings upstream refuses)
    for (event, accepted, key, refused) in [
        (
            id("ethereum", &evm, "aptos", &wide),
            id("ethereum", &evm_rendered, "aptos", &wide),
            "sender",
            vec![
                evm.clone(),
                format!("0x{}", "1A".repeat(20)),
                "1a".repeat(20),
            ],
        ),
        (
            id("ethereum", &evm, "stellar", &wide),
            id("ethereum", &evm_rendered, "stellar", &wide),
            "receiver",
            vec![
                "CA5R2JQYRJXFLWHE3XLLIO32HMF4MIDYY2NLWMGYYQDWKU6BTXL7URJI".to_string(),
                format!("0x{}", "3B".repeat(32)),
            ],
        ),
        (
            id("ethereum", &evm, "ton", &wide),
            id("ethereum", &evm_rendered, "ton", &wide),
            "receiver",
            vec![format!("0:{}", "3b".repeat(32))],
        ),
        (
            id("ethereum", &evm, "canton", &wide),
            id("ethereum", &evm_rendered, "canton", &wide),
            "receiver",
            vec![
                format!("0x{}", "3b".repeat(20)),
                format!("0x{}", "3B".repeat(32)),
            ],
        ),
        (
            id("solana", &solana, "ethereum", &evm),
            id("solana", &solana_rendered, "ethereum", &evm_rendered),
            "sender",
            vec![solana.clone()],
        ),
        (
            id("aptos", &zero, "ethereum", &evm),
            id("aptos", &zero, "ethereum", &evm_rendered),
            "sender",
            vec!["0x0".to_string(), "0x00".to_string()],
        ),
    ] {
        assert!(
            lz_message_id_matches(&accepted, &event),
            "{key}: {accepted:?}"
        );
        for alias in refused {
            let mut request = accepted.clone();
            request.pathway_id.extra[key] = Value::from(alias.as_str());
            assert!(!lz_message_id_matches(&request, &event), "{alias}");
        }
    }
}

/// Upstream keeps only the last 20 bytes of an EVM-chain address; two different
/// 32-byte senders sharing them stay two senders here.
#[test]
fn evm_rendering_refuses_a_non_zero_upper_twelve_bytes() {
    let mut actual = evm_packet_sent_request("V302");
    actual.pathway_id.extra["sender"] =
        Value::from(format!("0x{}{}", "ff".repeat(12), "11".repeat(20)));
    assert!(!lz_message_id_matches(
        &evm_packet_sent_request("V302"),
        &actual
    ));
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let mut config = evm_packet_sent_resolver_config("V302");
    config.chain_name_by_eid.insert(101, "ethereum".to_string());
    config.chain_name_by_eid.insert(102, "bsc".to_string());
    config
        .packet_sent_bindings_by_chain_name
        .get_mut("ethereum")
        .unwrap()
        .uln_v2 = Some("0x4444444444444444444444444444444444444444".to_string());
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
    assert!(
        !sent_event.extra.contains_key("options"),
        "a ULNv2 Packet carries no options: {:?}",
        sent_event.extra
    );
    assert!(
        !sent_event.extra.contains_key("guid"),
        "a ULNv2 Packet has no guid to report: {:?}",
        sent_event.extra
    );
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let mut config = evm_packet_sent_resolver_config("V302");
    config
        .packet_sent_bindings_by_chain_name
        .get_mut("ethereum")
        .unwrap()
        .send_uln_301 = Some("0x4444444444444444444444444444444444444444".to_string());
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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
    assert!(sent_event.extra["options"].is_object());
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
                    "maxSupportedTransactionVersion": 1,
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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

    // Upstream's extractor drops a failed transaction and its sdk throws a plain
    // `Transaction not found` (`common-solana/src/events.ts:55`).
    assert_eq!(
        error,
        AppCoreError::Internal("Transaction not found".to_string())
    );
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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

    assert_eq!(
        error,
        AppCoreError::Internal("Transaction not found".to_string())
    );
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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

    assert_eq!(
        error,
        AppCoreError::Internal("Could not find sentEvent that matches lzMessageId".to_string())
    );
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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

    assert_eq!(
        error,
        AppCoreError::Internal("Transaction not found".to_string())
    );
}

#[tokio::test]
async fn packet_sent_resolver_derives_solana_chain_and_version_from_packet() {
    let transaction = solana_packet_sent_transaction_data();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://booted.example/".to_string())],
                1,
            ),
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
        ProviderConfig::with_distinct_entities(
            vec![ProviderUri::Uri("https://refreshed.example/".to_string())],
            1,
        ),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://aptos.example/".to_string())],
                1,
            ),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(
                    "https://ton.example/?v3-endpoint=https://ton.example/v3".to_string(),
                )],
                1,
            ),
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
            // One refusal for each of upstream's three trace endpoints.
            responses: Arc::new(Mutex::new(vec![Err("provider unreachable".to_string()); 3])),
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
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri(
                        "https://ton.example/?v3-endpoint=https://ton.example/v3".to_string(),
                    ),
                    // No v3-endpoint: skipped before a future is pushed.
                    ProviderUri::Uri("https://ton-broken.example/".to_string()),
                ],
                1,
            ),
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
            responses: Arc::new(Mutex::new(vec![Ok(
                json!({"transaction": {"in_msg": null}, "children": []}),
            )])),
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
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                1,
            ),
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
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    1,
                ),
            )]),
            Some(std::slice::from_ref(chain_name)),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut config = evm_packet_sent_resolver_config("V302");
        config.packet_sent_bindings_by_chain_name.insert(
            chain_name.clone(),
            EvmPacketSentBindings {
                endpoint_v2: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                ..EvmPacketSentBindings::default()
            },
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

/// Upstream's Starknet and Stellar endpoint sdks throw `NonRetryableError('Transaction
/// failed for tx ...')` (a 500) for a failed transaction and `Packet does not match
/// lzMessageId` (remapped to the 400 `cannot find packet event`) when no trusted
/// PacketSent matches (`endpoint/starknet/index.ts:210-242`,
/// `endpoint/stellar/index.ts:263-289`).
#[tokio::test]
async fn starknet_and_stellar_resolution_failures_match_upstream() {
    for (chain, failed, succeeded) in [
        (
            "starknet",
            json!({ "execution_status": "REVERTED", "events": [] }),
            json!({ "execution_status": "SUCCEEDED", "block_hash": "0x1", "events": [] }),
        ),
        (
            "stellar",
            json!({ "status": "FAILED" }),
            json!({ "status": "SUCCESS" }),
        ),
    ] {
        let mut request = evm_packet_sent_request("V302");
        request.pathway_id.src_chain_name = chain.to_string();
        for (transaction, expected_mismatch) in [(failed, false), (succeeded, true)] {
            let transport = RecordingTransport {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(vec![Ok(json!({ "result": transaction }))])),
            };
            let getter = StaticProviderConfig::new(
                indexmap::IndexMap::from([(
                    chain.to_string(),
                    ProviderConfig::with_distinct_entities(
                        vec![ProviderUri::Uri("https://rpc.example".to_string())],
                        1,
                    ),
                )]),
                Some(&[chain.to_string()]),
            )
            .unwrap();
            let resolver = EvmPacketSentResolver::new(
                &ProviderSnapshotHandle::from_getter(&getter),
                transport,
                evm_packet_sent_resolver_config("V302"),
            );

            let error = resolver
                .get_lz_sent_event("0xtx", &request)
                .await
                .unwrap_err();

            if expected_mismatch {
                assert!(
                    matches!(&error, AppCoreError::BadRequest(message)
                        if message.ends_with(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX)),
                    "{chain}: {error:?}"
                );
            } else {
                assert_eq!(
                    error,
                    AppCoreError::Internal("Transaction failed for tx 0xtx".to_string()),
                    "{chain}"
                );
            }
        }
    }
}

/// A successful Starknet receipt without a block hash is upstream's plain `Error`
/// (a 500), checked before any event is read (`endpoint/starknet/index.ts:214-216`).
#[tokio::test]
async fn starknet_receipt_without_block_hash_fails_like_upstream() {
    let mut request = evm_packet_sent_request("V302");
    request.pathway_id.src_chain_name = "starknet".to_string();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(
            json!({ "result": { "execution_status": "SUCCEEDED", "events": [] } }),
        )])),
    };
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        evm_packet_sent_resolver_config("V302"),
    );

    let error = resolver
        .get_lz_sent_event("0xtx", &request)
        .await
        .unwrap_err();

    assert_eq!(
        error,
        AppCoreError::Internal("Block hash not yet populated for tx 0xtx".to_string())
    );
}
