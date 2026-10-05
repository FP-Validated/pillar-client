use super::*;

/// Recorded public mainnet responses and upstream's own normalized events for them
/// (`scripts/gasolina-parity/emit-source-replay-sol-tron-ton.ts`).
fn replay_file(name: &str) -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/source_replay");
    path.push(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture present"))
        .expect("fixture parses")
}

/// Serves only recorded exchanges, keyed by JSON-RPC method or GET path, and fails
/// closed on anything else, so an extra or differently shaped read is a test failure.
#[derive(Clone)]
struct ReplayTransport {
    recorded: Arc<HashMap<String, Value>>,
    requests: RecordedJsonCalls,
}

impl ReplayTransport {
    fn serve(&self, key: String, url: String, body: Value) -> Result<Value, String> {
        self.requests
            .lock()
            .unwrap()
            .push((url, HashMap::new(), body));
        self.recorded
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("unrecorded request {key}"))
    }
}

#[async_trait]
impl JsonRpcTransport for ReplayTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let key = format!("POST {}", body["method"].as_str().unwrap_or_default());
        self.serve(key, url, body)
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        let path = url.split('?').next().unwrap_or_default().to_string();
        let key = format!("GET {}", path.rsplit('/').next().unwrap_or_default());
        self.serve(key, url, json!({ "method": "GET" }))
    }
}

async fn replay(
    family: &str,
    uri: &str,
    recorded: &[(&str, &str)],
    src_tx_hash: &str,
) -> (
    Result<LzSentEvent, AppCoreError>,
    Vec<RecordedJsonCall>,
    Value,
) {
    let upstream = replay_file("upstream-stage3-events.json")["events"][family]["event"].clone();
    let pathway = &upstream["pathway"];
    let src = pathway["srcChainName"].as_str().unwrap().to_string();
    let dst = pathway["dstChainName"].as_str().unwrap().to_string();
    let config = runtime_evm_layerzero_config("mainnet", &[src.clone(), dst.clone()]).unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            src.clone(),
            ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(uri.to_string())], 1),
        )]),
        None,
    )
    .unwrap();
    let requests: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReplayTransport {
            recorded: Arc::new(
                recorded
                    .iter()
                    .map(|(key, file)| (key.to_string(), replay_file(file)))
                    .collect(),
            ),
            requests: requests.clone(),
        },
        config.packet_sent_resolver_config,
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: src,
            dst_chain_name: dst,
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: upstream["nonce"].as_u64().unwrap(),
        uln_send_version: upstream["ulnSendVersion"].clone(),
    };
    let result = resolver.get_lz_sent_event(src_tx_hash, &request).await;
    let requests = requests.lock().unwrap().clone();
    (result, requests, upstream)
}

fn assert_same_event(family: &str, ours: &LzSentEvent, upstream: &Value) {
    let pathway = &upstream["pathway"];
    let id = &ours.lz_message_id;
    assert_eq!(
        id.pathway_id.src_chain_name, pathway["srcChainName"],
        "{family}"
    );
    assert_eq!(
        id.pathway_id.dst_chain_name, pathway["dstChainName"],
        "{family}"
    );
    for key in ["srcEid", "dstEid"] {
        assert_eq!(id.pathway_id.extra[key], pathway[key], "{family} {key}");
    }
    assert_eq!(Value::from(id.nonce), upstream["nonce"], "{family}");
    assert_eq!(id.uln_send_version, upstream["ulnSendVersion"], "{family}");
    assert_eq!(ours.extra["guid"], upstream["guid"], "{family}");
    assert_eq!(ours.message, upstream["message"], "{family}");
    // Sender/receiver renderings differ per family (base58, bytes32, 20-byte hex);
    // the matcher that gates resolution is what decides equivalence.
    let mut expected = id.clone();
    for key in ["sender", "receiver"] {
        expected.pathway_id.extra[key] = pathway[key].clone();
    }
    assert!(
        lz_message_id_matches(&expected, id),
        "{family} pathway identity"
    );
}

#[tokio::test]
async fn tron_recorded_send_resolves_to_upstreams_event() {
    let (result, requests, upstream) = replay(
        "tron",
        "https://api.trongrid.io/jsonrpc",
        &[(
            "POST eth_getTransactionReceipt",
            "tron-eth_getTransactionReceipt.response.json",
        )],
        "0x5d3ab0f3d02c1337a00efd75e2cab69783d3c2850a1af27e069cdbc5697b671b",
    )
    .await;

    assert_same_event("tron", &result.unwrap(), &upstream);
    // Upstream issues the same receipt read (its TRON path is the EVM JSON-RPC SDK).
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].2["method"], "eth_getTransactionReceipt");
}

#[tokio::test]
async fn solana_recorded_send_resolves_to_upstreams_event() {
    let (result, requests, upstream) = replay(
        "solana",
        "https://api.mainnet-beta.solana.com",
        &[(
            "POST getTransaction",
            "solana-getTransaction-jsonParsed.response.json",
        )],
        "4ZqmmZjUknnLey1DwN12KGa58cnqDroVeZP6zU6hA3wXwgk9sVsvpodHmTwWjBZUAKGCfrc6st5UVmcw3JWMgHEd",
    )
    .await;

    assert_same_event("solana", &result.unwrap(), &upstream);
    // Upstream additionally reads getBlock(slot); this service resolves from the
    // transaction alone, so that read is a transport difference, not replayed here.
    let methods: Vec<&str> = requests
        .iter()
        .map(|(_, _, body)| body["method"].as_str().unwrap())
        .collect();
    assert_eq!(methods, ["getTransaction"]);
}

const TON_TX: &str = "0xec1bd8457acc170bb32848246d0a203e42d2bd525dbc5593eec73fcff58c7ad8";
const TON_URI: &str = "https://toncenter.com/api/v2?v3-endpoint=https://toncenter.com/api/v3";

/// Upstream's own read: toncenter `/api/v3/events?tx_hash=` (`upstream-stage3-events.json`
/// requestList), with the same recorded response upstream consumed.
#[tokio::test]
async fn ton_recorded_send_resolves_to_upstreams_event() {
    let (result, requests, upstream) = replay(
        "ton",
        TON_URI,
        &[("GET events", "ton-v3-events.response.json")],
        TON_TX,
    )
    .await;

    assert_same_event("ton", &result.unwrap(), &upstream);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].0,
        format!("https://toncenter.com/api/v3/events?tx_hash={TON_TX}")
    );
}

/// A provider without `/events` falls back to `/traces?tx_hash=`, as upstream's client
/// does; the path form `/traces/{hash}` this service used before is answered by public
/// toncenter with HTTP 500 (`stage0b-recordings/ton/pillar-shape-traces-path`).
#[tokio::test]
async fn ton_recorded_send_resolves_through_the_traces_fallback() {
    let (result, requests, upstream) = replay(
        "ton",
        TON_URI,
        &[("GET traces", "ton-v3-traces.response.json")],
        TON_TX,
    )
    .await;

    assert_same_event("ton", &result.unwrap(), &upstream);
    let urls: Vec<&str> = requests.iter().map(|(url, _, _)| url.as_str()).collect();
    assert_eq!(
        urls,
        [
            format!("https://toncenter.com/api/v3/events?tx_hash={TON_TX}"),
            format!("https://toncenter.com/api/v3/traces?tx_hash={TON_TX}"),
        ]
    );
}

/// The recorded PacketSent with one field of its controller-bound message changed;
/// each change must leave no event, as upstream's `getLzSentEventFilter` and
/// `isEventValid` would (`lz-ton-contracts/src/channel.ts:20-65`).
fn decoded_ton_events_with(change: impl Fn(&mut Value)) -> usize {
    let mut response = replay_file("ton-v3-events.response.json");
    let transactions = response["events"][0]["transactions"]
        .as_object_mut()
        .unwrap();
    for transaction in transactions.values_mut() {
        if transaction["in_msg"]["opcode"] == "0xe33b9873" {
            change(&mut transaction["in_msg"]);
        }
    }
    let tree = crate::layerzero_runtime::ton_transaction_trace_tree(&response).unwrap();
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let resolver = config.packet_sent_resolver_config;
    crate::layerzero_runtime::decode_ton_packet_sent_events(
        &tree,
        &resolver.trusted_ton_packet_emitters_by_chain_name["ton"],
        &resolver.chain_name_by_eid,
    )
    .len()
}

#[test]
fn ton_packet_sent_requires_the_controller_owned_channel_as_sender() {
    assert_eq!(decoded_ton_events_with(|_| {}), 1);
    // A message to the controller from any other account carries no event.
    assert_eq!(
        decoded_ton_events_with(|message| message["source"] =
            Value::from("0:316456309B2987B7EB03E4CC6BB227126890DF18F744058FFFEAA34DDAF39CCE")),
        0
    );
    // Only the event opcode marks an action event.
    assert_eq!(
        decoded_ton_events_with(|message| message["opcode"] = Value::from("0xe33b9874")),
        0
    );
}

/// Two independent providers answering `/events` for the recorded send, the second
/// with `change` applied to its copy; both must agree for the event to resolve.
async fn ton_two_provider_resolution(
    change: impl Fn(&mut serde_json::Map<String, Value>),
) -> Result<LzSentEvent, AppCoreError> {
    #[derive(Clone)]
    struct PerHost(Arc<HashMap<&'static str, Value>>);
    #[async_trait]
    impl JsonRpcTransport for PerHost {
        async fn post_json(
            &self,
            url: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            Err(format!("unrecorded POST {url}"))
        }
        async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
            self.0
                .iter()
                .find(|(prefix, _)| url.starts_with(&format!("{prefix}/events?tx_hash=")))
                .map(|(_, response)| response.clone())
                .ok_or_else(|| format!("unrecorded GET {url}"))
        }
    }
    let honest = replay_file("ton-v3-events.response.json");
    let mut other = honest.clone();
    change(other["events"][0]["transactions"].as_object_mut().unwrap());
    let upstream = replay_file("upstream-stage3-events.json")["events"]["ton"]["event"].clone();
    let pathway = &upstream["pathway"];
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri(
                        "https://a.example/v2?v3-endpoint=https://a.example/v3".into(),
                    ),
                    ProviderUri::Uri(
                        "https://b.example/v2?v3-endpoint=https://b.example/v3".into(),
                    ),
                ],
                2,
            ),
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        PerHost(Arc::new(HashMap::from([
            ("https://a.example/v3", honest),
            ("https://b.example/v3", other),
        ]))),
        config.packet_sent_resolver_config,
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "arbitrum".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: upstream["nonce"].as_u64().unwrap(),
        uln_send_version: upstream["ulnSendVersion"].clone(),
    };
    resolver.get_lz_sent_event(TON_TX, &request).await
}

/// Upstream quorums TON traces on a message projection
/// (`multiprovider/src/ton.ts:40-54`), so state hashes, fees, finality labels and the
/// numeric-vs-string rendering of a seqno do not split honest providers.
#[tokio::test]
async fn ton_providers_differing_only_in_trace_metadata_reach_quorum() {
    let upstream = replay_file("upstream-stage3-events.json")["events"]["ton"]["event"].clone();
    let event = ton_two_provider_resolution(|transactions| {
        for transaction in transactions.values_mut() {
            transaction["finality"] = json!("pending");
            transaction["total_fees"] = json!("1");
            transaction["account_state_after"] = json!({ "hash": "other" });
            transaction["mc_block_seqno"] = json!(transaction["mc_block_seqno"].to_string());
        }
    })
    .await
    .expect("metadata-only differences agree");
    assert_same_event("ton", &event, &upstream);
}

/// Every projected field is security-relevant: a provider placing any message in
/// another block, or reporting another message hash, sender, recipient or body,
/// leaves no quorum and nothing is signed.
#[tokio::test]
async fn ton_providers_differing_in_a_projected_message_field_fail_closed() {
    type Change = fn(&mut Value);
    let changes: [(&str, Change); 4] = [
        ("seqno", |t| {
            t["mc_block_seqno"] = json!(t["mc_block_seqno"].as_u64().unwrap() + 1)
        }),
        ("hash", |t| {
            t["in_msg"]["hash"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        }),
        ("destination", |t| {
            t["in_msg"]["destination"] = json!(format!("0:{}", "22".repeat(32)))
        }),
        ("bounced", |t| t["in_msg"]["bounced"] = json!(true)),
    ];
    for (field, change) in changes {
        let error = ton_two_provider_resolution(|transactions| {
            for transaction in transactions.values_mut() {
                if transaction["in_msg"]["opcode"] == "0xe33b9873" {
                    change(transaction);
                }
            }
        })
        .await
        .expect_err(field);
        assert!(
            matches!(&error, AppCoreError::Internal(message) if message.contains("quorum")),
            "{field}: {error:?}"
        );
    }
}
#[tokio::test]
async fn ton_three_providers_resolve_on_two_matching_projection_fingerprints() {
    #[derive(Clone)]
    struct PerHost(Arc<HashMap<&'static str, Value>>);
    #[async_trait]
    impl JsonRpcTransport for PerHost {
        async fn post_json(
            &self,
            url: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            Err(format!("unrecorded POST {url}"))
        }
        async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
            self.0
                .iter()
                .find(|(prefix, _)| url.starts_with(&format!("{prefix}/events?tx_hash=")))
                .map(|(_, response)| response.clone())
                .ok_or_else(|| format!("unrecorded GET {url}"))
        }
    }
    let matching = replay_file("ton-v3-events.response.json");
    let mut disagreement = matching.clone();
    for transaction in disagreement["events"][0]["transactions"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        if transaction["in_msg"]["opcode"] == "0xe33b9873" {
            transaction["mc_block_seqno"] = json!("96828302");
        }
    }
    let upstream = replay_file("upstream-stage3-events.json")["events"]["ton"]["event"].clone();
    let pathway = &upstream["pathway"];
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri(
                        "https://a.example/v2?v3-endpoint=https://a.example/v3".into(),
                    ),
                    ProviderUri::Uri(
                        "https://b.example/v2?v3-endpoint=https://b.example/v3".into(),
                    ),
                    ProviderUri::Uri(
                        "https://c.example/v2?v3-endpoint=https://c.example/v3".into(),
                    ),
                ],
                2,
            ),
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        PerHost(Arc::new(HashMap::from([
            ("https://a.example/v3", matching.clone()),
            ("https://b.example/v3", matching),
            ("https://c.example/v3", disagreement),
        ]))),
        config.packet_sent_resolver_config,
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "arbitrum".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: upstream["nonce"].as_u64().unwrap(),
        uln_send_version: upstream["ulnSendVersion"].clone(),
    };
    let event = resolver
        .get_lz_sent_event(TON_TX, &request)
        .await
        .expect("two matching providers");
    assert_same_event("ton", &event, &upstream);
}
#[tokio::test]
async fn ton_three_provider_missing_in_msg_loses_vote_before_resolver_quorum() {
    #[derive(Clone)]
    struct PerHost(Arc<HashMap<&'static str, Value>>);
    #[async_trait]
    impl JsonRpcTransport for PerHost {
        async fn post_json(
            &self,
            url: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            Err(format!("unrecorded POST {url}"))
        }
        async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
            self.0
                .iter()
                .find(|(prefix, _)| url.starts_with(&format!("{prefix}/events?tx_hash=")))
                .map(|(_, response)| response.clone())
                .ok_or_else(|| format!("unrecorded GET {url}"))
        }
    }
    let first = replay_file("ton-v3-events.response.json");
    let mut second = first.clone();
    let mut malformed = first.clone();
    for transaction in second["events"][0]["transactions"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        if transaction["in_msg"]["opcode"] == "0xe33b9873" {
            transaction["mc_block_seqno"] = json!("96828302");
        }
    }
    for transaction in malformed["events"][0]["transactions"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        if transaction["in_msg"]["opcode"] == "0xe33b9873" {
            transaction.as_object_mut().unwrap().remove("in_msg");
        }
    }
    let upstream = replay_file("upstream-stage3-events.json")["events"]["ton"]["event"].clone();
    let pathway = &upstream["pathway"];
    let config =
        runtime_evm_layerzero_config("mainnet", &["ton".to_string(), "arbitrum".to_string()])
            .unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri(
                        "https://a.example/v2?v3-endpoint=https://a.example/v3".into(),
                    ),
                    ProviderUri::Uri(
                        "https://b.example/v2?v3-endpoint=https://b.example/v3".into(),
                    ),
                    ProviderUri::Uri(
                        "https://c.example/v2?v3-endpoint=https://c.example/v3".into(),
                    ),
                ],
                2,
            ),
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        PerHost(Arc::new(HashMap::from([
            ("https://a.example/v3", first),
            ("https://b.example/v3", second),
            ("https://c.example/v3", malformed),
        ]))),
        config.packet_sent_resolver_config,
    );
    let request = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "ton".to_string(),
            dst_chain_name: "arbitrum".to_string(),
            extra: ["srcEid", "dstEid", "sender", "receiver"]
                .into_iter()
                .map(|key| (key.to_string(), pathway[key].clone()))
                .collect(),
        },
        nonce: upstream["nonce"].as_u64().unwrap(),
        uln_send_version: upstream["ulnSendVersion"].clone(),
    };
    let error = resolver
        .get_lz_sent_event(TON_TX, &request)
        .await
        .expect_err("only one provider voted for each projection");
    assert!(
        matches!(&error, AppCoreError::Internal(message) if message.contains("quorum")),
        "missing in_msg must lose its vote: {error:?}"
    );
}
