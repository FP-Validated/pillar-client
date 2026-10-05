use super::*;

const APTOS_V301_TX: &str = include_str!("../../tests/gasolina_parity/aptos_v301_source_tx.json");
const APTOS_V301_EMITTER: &str =
    "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812";

#[test]
fn archived_aptos_v301_event_decodes_with_v301_binding() {
    let transaction: Value = serde_json::from_str(APTOS_V301_TX).unwrap();
    let events = decode_move_packet_sent_events(
        "aptos",
        &transaction,
        &HashSet::from([APTOS_V301_EMITTER.to_string()]),
        "V301",
    )
    .unwrap();

    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.endpoint_address, APTOS_V301_EMITTER);
    assert_eq!(event.uln_send_version, "V301");
    assert_eq!(event.packet.src_eid, 108);
    assert_eq!(event.packet.dst_eid, 102);
    assert_eq!(event.options.as_deref(), Ok("0x"));
    assert_eq!(event.send_library, None);
}

fn move_request(chain: &str, version: &str) -> LzMessageId {
    LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: chain.to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::new(),
        },
        nonce: 0,
        uln_send_version: Value::from(version),
    }
}

fn resolver_and_calls() -> (EvmPacketSentResolver<RecordingTransport>, RecordedJsonCalls) {
    let providers = StaticProviderConfig::new(indexmap::IndexMap::new(), None).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(Vec::new())),
        },
        evm_packet_sent_resolver_config(ULN_VERSION_V302),
    );
    (resolver, calls)
}

const APTOS_V1_SOURCE: &str = include_str!("../../tests/gasolina_parity/aptos_v1_source.json");

/// Serves the recorded Aptos transaction and block by route, and records every URL.
#[derive(Clone)]
struct AptosV1Replay {
    transaction: Value,
    block: Value,
    urls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for AptosV1Replay {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        self.urls.lock().unwrap().push(url.clone());
        if url.contains("/transactions/by_version/") {
            Ok(self.transaction.clone())
        } else if url.contains("/blocks/by_version/") {
            Ok(self.block.clone())
        } else {
            Err(format!("unexpected GET {url}"))
        }
    }
}

/// Upstream's own `LZAptosSdk.getLZSentEventFromSrcTxHash`, `getDerivedHash` and
/// `GasolinaEvmSdk.buildULNV2VerifyPayload` over upstream's test packet
/// (`scripts/gasolina-parity/emit-aptos-v1-source.ts`): the resolved event, the reads made,
/// the feather hash and the signed hash call data, or the same refusal.
#[tokio::test]
async fn aptos_v1_source_matches_gasolina() {
    let fixture: Value = serde_json::from_str(APTOS_V1_SOURCE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let config =
        runtime_evm_layerzero_config(environment, &["aptos".to_string(), "arbitrum".to_string()])
            .unwrap();
    let builder = EvmUlnPayloadBuilder::new(config.receive_contracts_by_chain_name.clone());
    let mut compared = 0;
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let urls = Arc::new(Mutex::new(Vec::new()));
        let transport = AptosV1Replay {
            transaction: json!({
                "type": "user_transaction",
                "version": "26629",
                "hash": format!("0x{}", "aa".repeat(32)),
                "success": true,
                "events": scenario["events"],
            }),
            block: fixture["block"].clone(),
            urls: urls.clone(),
        };
        let providers = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                "aptos".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://aptos.example".to_string())],
                    1,
                ),
            )]),
            Some(&["aptos".to_string()]),
        )
        .unwrap();
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&providers),
            transport,
            config.packet_sent_resolver_config.clone(),
        );
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let result = resolver
            .get_lz_sent_event(scenario["srcTxHash"].as_str().unwrap(), &request)
            .await;

        let upstream_paths: HashSet<String> = scenario["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|path| path.as_str().unwrap().to_string())
            .collect();
        for url in urls.lock().unwrap().iter() {
            let path = url
                .trim_start_matches("https://aptos.example/")
                .split('?')
                .next()
                .unwrap();
            assert!(
                upstream_paths.contains(path),
                "{name}: upstream never read {url}"
            );
        }
        assert_eq!(
            urls.lock().unwrap().is_empty(),
            upstream_paths.is_empty(),
            "{name}: reads"
        );

        match (&scenario["outcome"]["ok"], result) {
            (Value::Null, Err(error)) => {
                let theirs = scenario["outcome"]["error"].as_str().unwrap();
                if theirs == "Packet does not match lzMessageId" {
                    assert!(
                        matches!(&error, AppCoreError::BadRequest(message)
                            if message.ends_with(pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX)),
                        "{name}: {error:?}"
                    );
                } else {
                    assert_eq!(error, AppCoreError::Internal(theirs.to_string()), "{name}");
                }
            }
            (Value::Null, Ok(event)) => panic!("{name}: upstream refused, resolved {event:?}"),
            (_, Err(error)) => panic!("{name}: upstream resolved, refused {error:?}"),
            (ok, Ok(event)) => {
                let theirs = &ok["event"];
                assert_eq!(
                    crate::provider_health::resolved_message_id_json(&event.lz_message_id),
                    format!(
                        r#"{{"pathwayId":{{"srcEid":{},"srcChainName":"aptos","dstEid":{},"dstChainName":"arbitrum","sender":"{}","receiver":"{}"}},"nonce":{},"ulnSendVersion":"V2"}}"#,
                        theirs["lzMessageId"]["pathwayId"]["srcEid"],
                        theirs["lzMessageId"]["pathwayId"]["dstEid"],
                        theirs["lzMessageId"]["pathwayId"]["sender"]
                            .as_str()
                            .unwrap(),
                        theirs["lzMessageId"]["pathwayId"]["receiver"]
                            .as_str()
                            .unwrap(),
                        theirs["lzMessageId"]["nonce"],
                    ),
                    "{name}: lzMessageId"
                );
                assert_eq!(event.message, theirs["message"].as_str().unwrap(), "{name}");
                assert_eq!(
                    event.tx_hash,
                    theirs["onChainEvent"]["txHash"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    event.extra["blockHash"], theirs["onChainEvent"]["blockHash"],
                    "{name}"
                );
                assert_eq!(
                    event.extra["blockNumber"], theirs["onChainEvent"]["blockNumber"],
                    "{name}"
                );
                assert_eq!(
                    event.extra["packetEmitAddress"], theirs["packetEmitAddress"],
                    "{name}"
                );
                assert!(
                    !event.extra.contains_key("guid"),
                    "{name}: a V1 send carries no guid"
                );

                let hash_info = pillar_layerzero::derive_aptos_feather_hash_info(
                    &event,
                    event.extra["packetEmitAddress"].as_str().unwrap(),
                )
                .unwrap();
                let hex = |value: &str| value.trim_start_matches("0x").to_ascii_lowercase();
                assert_eq!(
                    hex(&hash_info.lookup_hash),
                    hex(ok["derived"]["lookupHash"].as_str().unwrap()),
                    "{name}: feather hash"
                );
                let built = builder
                    .build_uln_v2_verify_payload_from_hash_info(
                        &event,
                        hash_info,
                        15,
                        1_900_000_000,
                        ok["vId"].as_str().unwrap(),
                    )
                    .unwrap();
                assert_eq!(
                    hex(&built.hash_call_data),
                    hex(ok["hashCallData"].as_str().unwrap()),
                    "{name}: hash call data"
                );
                assert_eq!(ok["mptProofType"]["error"], "Unknown proof type 1");
            }
        }
        compared += 1;
    }
    assert_eq!(compared, 8, "every upstream scenario is replayed");
}

#[tokio::test]
async fn initia_and_movement_v301_source_refusals_happen_before_provider_call() {
    for chain in ["initia", "movement"] {
        let (resolver, calls) = resolver_and_calls();
        let error = resolver
            .get_lz_sent_event(
                "0xdead",
                &move_request(chain, pillar_layerzero::ULN_VERSION_V301),
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, AppCoreError::BadRequest(message) if message.contains("V301 source event resolution is unavailable") && message.contains("EndpointV1 eid mapping"))
        );
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[test]
fn aptos_v301_rejects_wrong_emitter_module_pairings() {
    let endpoint = "0xe60045e20fc2c99e869c1c34a65b9291c020cd12a0d37a00a53ac1348af4f43c";
    let mut transaction: Value = serde_json::from_str(APTOS_V301_TX).unwrap();
    let packet_event_index = transaction["events"]
        .as_array()
        .unwrap()
        .iter()
        .position(|event| event["type"].as_str() == Some("0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812::sending::PacketSent"))
        .unwrap();
    for (emitter, module) in [
        (endpoint, "sending::PacketSent"),
        (APTOS_V301_EMITTER, "channels::PacketSent"),
        (APTOS_V301_EMITTER, "wrong_module::PacketSent"),
        ("0x1", "sending::PacketSent"),
    ] {
        transaction["events"][packet_event_index]["type"] =
            Value::String(format!("{emitter}::{module}"));
        for token_version in ["V301", "V302"] {
            assert!(decode_move_packet_sent_events(
                "aptos",
                &transaction,
                &HashSet::from([endpoint.to_string(), APTOS_V301_EMITTER.to_string()]),
                token_version,
            )
            .unwrap()
            .is_empty());
        }
    }
}

fn archived_v301_upstream() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/aptos_v301_source_upstream.json"
    ))
    .unwrap()
}

/// The recorded mainnet V301 send through the production resolver and runtime config,
/// requested with every upstream pathway field and the given ULN version.
async fn resolve_archived_v301_send(
    uln_send_version: &str,
) -> (Result<LzSentEvent, AppCoreError>, Vec<String>) {
    let upstream = archived_v301_upstream();
    let names = vec!["aptos".to_string(), "bsc".to_string()];
    let config = runtime_evm_layerzero_config("mainnet", &names).unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://aptos.example/v1".to_string())],
                1,
            ),
        )]),
        None,
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transaction: Value = serde_json::from_str(APTOS_V301_TX).unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(transaction.clone()), Ok(transaction)])),
        },
        config.packet_sent_resolver_config,
    );
    let pathway = &upstream["event"]["lzMessageId"]["pathwayId"];
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "aptos".to_string(),
            dst_chain_name: "bsc".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: 314_702,
        uln_send_version: Value::from(uln_send_version),
    };
    let result = resolver
        .get_lz_sent_event(
            "0x038ab162500d08cfba80b42cfa26cf0a42f20a5d2d53af76bd16451f439481bf",
            &request,
        )
        .await;
    let urls = calls
        .lock()
        .unwrap()
        .iter()
        .map(|(url, _, _)| url.clone())
        .collect();
    (result, urls)
}

/// A ULN301 event is a V301 send whatever the request claims; resolving it as V302
/// would sign it for the wrong receive library.
#[tokio::test]
async fn archived_aptos_v301_send_is_not_resolved_as_v302() {
    let (result, urls) = resolve_archived_v301_send("V302").await;

    assert_eq!(
        result.unwrap_err(),
        AppCoreError::Internal(
            "Did not find correct PacketSent() event in tx 0x038ab162500d08cfba80b42cfa26cf0a42f20a5d2d53af76bd16451f439481bf".to_string()
        )
    );
    assert_eq!(urls.len(), 1);
}

/// The archived upstream event is its extractor's output; `getLZSentEvent` then adds the
/// send's `executor_v1::RequestEvent` adapter params (`0x000100000000000249f0`, gas 150000)
/// to the V301 options (`endpoint/aptos/index.ts:182-232`), read by the tx's ledger version.
#[tokio::test]
async fn archived_aptos_v301_send_resolves_to_upstreams_event() {
    let upstream = archived_v301_upstream();
    let expected = &upstream["event"];
    let pathway = &expected["lzMessageId"]["pathwayId"];
    let (result, urls) = resolve_archived_v301_send("V301").await;
    let event = result.unwrap();

    let ours = &event.lz_message_id;
    assert_eq!(ours.pathway_id.src_chain_name, pathway["srcChainName"]);
    assert_eq!(ours.pathway_id.dst_chain_name, pathway["dstChainName"]);
    for key in ["srcEid", "dstEid"] {
        assert_eq!(ours.pathway_id.extra[key], pathway[key], "{key}");
    }
    assert_eq!(
        ours.pathway_id.extra["sender"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        pathway["sender"].as_str().unwrap()
    );
    assert!(ours.pathway_id.extra["receiver"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .ends_with(&pathway["receiver"].as_str().unwrap()[2..]));
    assert_eq!(Value::from(ours.nonce), expected["lzMessageId"]["nonce"]);
    assert_eq!(
        ours.uln_send_version,
        expected["lzMessageId"]["ulnSendVersion"]
    );
    assert_eq!(event.message, expected["message"]);
    assert_eq!(event.extra["guid"], expected["guid"]);
    assert_eq!(event.extra["packetEmitAddress"], expected["sendLibrary"]);
    assert_eq!(event.extra["sendLibrary"], expected["sendLibrary"]);
    assert_eq!(expected["options"], json!({}));
    assert_eq!(
        event.extra["options"],
        json!({"lzReceive": {"gas": "150000", "value": "0"}})
    );
    assert_eq!(urls.len(), 2, "the transaction, then its executor events");
    assert!(
        urls[1].ends_with("/transactions/by_version/7469155248"),
        "{}",
        urls[1]
    );
}
