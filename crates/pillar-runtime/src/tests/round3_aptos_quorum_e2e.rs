use super::*;

const ARCHIVED_V301_TX: &str =
    include_str!("../../tests/gasolina_parity/aptos_v301_source_tx.json");
const ARCHIVED_V301_HASH: &str =
    "0x038ab162500d08cfba80b42cfa26cf0a42f20a5d2d53af76bd16451f439481bf";

/// Serves each provider host its own copy of the archived transaction, for both the
/// `by_hash` source read and the `by_version` executor read.
#[derive(Clone)]
struct PerHostAptos {
    by_host: Arc<HashMap<&'static str, Value>>,
    calls: RecordedJsonCalls,
}

#[async_trait]
impl JsonRpcTransport for PerHostAptos {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers, json!({"method": "GET"})));
        self.by_host
            .iter()
            .find(|(host, _)| url.starts_with(&format!("https://{host}/")))
            .map(|(_, transaction)| transaction.clone())
            .ok_or_else(|| format!("unexpected GET {url}"))
    }
}

fn archived_transaction() -> Value {
    serde_json::from_str(ARCHIVED_V301_TX).unwrap()
}

/// What a v1.47 node answers: the field Aptos Core added in 1.48 is absent.
fn without_txn_limits_request(mut transaction: Value) -> Value {
    assert!(transaction
        .as_object_mut()
        .unwrap()
        .remove("txn_limits_request")
        .is_some());
    transaction
}

/// What a node with the table-info indexer answers: decoded table writes.
fn with_table_indexer(mut transaction: Value) -> Value {
    let mut decoded = 0;
    for change in transaction["changes"].as_array_mut().unwrap() {
        if change["type"] == "write_table_item" {
            change["data"] = json!({
                "key": "1",
                "key_type": "u64",
                "value": "0x00",
                "value_type": "vector<u8>",
            });
            decoded += 1;
        }
    }
    assert_eq!(decoded, 3);
    transaction
}

async fn resolve_with_two_providers(
    provider_a: Value,
    provider_b: Value,
) -> (Result<LzSentEvent, AppCoreError>, Vec<String>) {
    let upstream: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/aptos_v301_source_upstream.json"
    ))
    .unwrap();
    let names = vec!["aptos".to_string(), "bsc".to_string()];
    let config = runtime_evm_layerzero_config("mainnet", &names).unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://aptos-a.example/v1".to_string()),
                    ProviderUri::Uri("https://aptos-b.example/v1".to_string()),
                ],
                2,
            ),
        )]),
        None,
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        PerHostAptos {
            by_host: Arc::new(HashMap::from([
                ("aptos-a.example", provider_a),
                ("aptos-b.example", provider_b),
            ])),
            calls: calls.clone(),
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
        uln_send_version: Value::from("V301"),
    };
    let result = resolver
        .get_lz_sent_event(ARCHIVED_V301_HASH, &request)
        .await;
    let urls = calls
        .lock()
        .unwrap()
        .iter()
        .map(|(url, _, _)| url.clone())
        .collect();
    (result, urls)
}

fn assert_archived_send(event: &LzSentEvent) {
    assert_eq!(event.lz_message_id.nonce, 314_702);
    assert_eq!(
        event.extra["options"],
        json!({"lzReceive": {"gas": "150000", "value": "0"}})
    );
}

/// Round 3 M-12: two honest providers on different node releases, or with and without
/// the table-info indexer, answer the same transaction with different JSON. Both the
/// `by_hash` source read and the `by_version` executor read must still agree.
#[tokio::test]
async fn round3_m12_aptos_node_release_and_indexer_differences_still_reach_quorum() {
    let (baseline, _) =
        resolve_with_two_providers(archived_transaction(), archived_transaction()).await;
    assert_archived_send(&baseline.unwrap());

    for (case, provider_a) in [
        (
            "node release without txn_limits_request",
            without_txn_limits_request(archived_transaction()),
        ),
        (
            "table-info indexer enabled",
            with_table_indexer(archived_transaction()),
        ),
    ] {
        let (result, urls) = resolve_with_two_providers(provider_a, archived_transaction()).await;
        let event = result.unwrap_or_else(|error| panic!("{case}: {error}"));
        assert_archived_send(&event);
        assert_eq!(
            urls.len(),
            4,
            "{case}: two by_hash and two by_version reads"
        );
        assert_eq!(
            urls.iter()
                .filter(|url| url.ends_with("/transactions/by_version/7469155248"))
                .count(),
            2,
            "{case}"
        );
    }
}

/// The projection must still bind everything the resolver consumes: a provider that
/// disagrees on events, success, the ledger version or the hash cannot be outvoted into
/// agreement by dropping that field.
#[tokio::test]
async fn round3_m12_aptos_consumed_fields_still_split_the_quorum() {
    let mut changed_event = archived_transaction();
    let events = changed_event["events"].as_array_mut().unwrap();
    let last = events.len() - 1;
    events[last]["sequence_number"] = Value::from("999999");
    let mut failed = archived_transaction();
    failed["success"] = Value::Bool(false);
    let mut other_version = archived_transaction();
    other_version["version"] = Value::from("7469155249");
    let mut other_hash = archived_transaction();
    other_hash["hash"] =
        Value::from("0x1111111111111111111111111111111111111111111111111111111111111111");

    for (case, provider_a) in [
        ("events", changed_event),
        ("success", failed),
        ("version", other_version),
        ("hash", other_hash),
    ] {
        let (result, _) = resolve_with_two_providers(provider_a, archived_transaction()).await;
        let error = result.expect_err(case).to_string();
        assert!(
            error.contains("quorum: response set is ambiguous or incomplete"),
            "{case}: {error}"
        );
    }
}

#[derive(Clone)]
struct AptosV1PerHost {
    by_host: Arc<HashMap<&'static str, (Value, Value)>>,
}

#[async_trait]
impl JsonRpcTransport for AptosV1PerHost {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        let (transaction, block) = self
            .by_host
            .iter()
            .find(|(host, _)| url.starts_with(&format!("https://{host}/")))
            .map(|(_, responses)| responses)
            .ok_or_else(|| format!("unexpected GET {url}"))?;
        if url.contains("/transactions/by_version/") {
            Ok(transaction.clone())
        } else if url.contains("/blocks/by_version/") {
            Ok(block.clone())
        } else {
            Err(format!("unexpected GET {url}"))
        }
    }
}

async fn resolve_aptos_v1_with_providers(
    providers: Vec<ProviderUri>,
    quorum: u64,
    by_host: HashMap<&'static str, (Value, Value)>,
    src_tx_hash: &str,
    request: &LzMessageId,
) -> Result<LzSentEvent, AppCoreError> {
    let config =
        runtime_evm_layerzero_config("mainnet", &["aptos".to_string(), "arbitrum".to_string()])
            .unwrap();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(providers, quorum),
        )]),
        None,
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        AptosV1PerHost {
            by_host: Arc::new(by_host),
        },
        config.packet_sent_resolver_config,
    );
    resolver.get_lz_sent_event(src_tx_hash, request).await
}

#[tokio::test]
async fn round3_m12_aptos_v1_transaction_and_block_extras_still_reach_quorum() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/aptos_v1_source.json"
    ))
    .unwrap();
    let scenario = &fixture["scenarios"][0];
    let src_tx_hash = scenario["srcTxHash"].as_str().unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();

    let mut transaction = json!({
        "type": "user_transaction",
        "version": src_tx_hash,
        "hash": format!("0x{}", "aa".repeat(32)),
        "success": true,
        "events": scenario["events"],
    });
    transaction["txn_limits_request"] = json!({"max_gas_amount": "10000"});
    let mut transaction_without_extra = transaction.clone();
    transaction_without_extra
        .as_object_mut()
        .unwrap()
        .remove("txn_limits_request");
    let mut block = fixture["block"].clone();
    block["block_timestamp"] = Value::from("1700000000000000");
    let mut block_without_extra = block.clone();
    block_without_extra
        .as_object_mut()
        .unwrap()
        .remove("block_timestamp");

    let one_provider = resolve_aptos_v1_with_providers(
        vec![ProviderUri::Uri("https://aptos-a.example/v1".to_string())],
        1,
        HashMap::from([("aptos-a.example", (transaction.clone(), block.clone()))]),
        src_tx_hash,
        &request,
    )
    .await
    .unwrap();
    let two_providers = resolve_aptos_v1_with_providers(
        vec![
            ProviderUri::Uri("https://aptos-a.example/v1".to_string()),
            ProviderUri::Uri("https://aptos-b.example/v1".to_string()),
        ],
        2,
        HashMap::from([
            ("aptos-a.example", (transaction, block)),
            (
                "aptos-b.example",
                (transaction_without_extra, block_without_extra),
            ),
        ]),
        src_tx_hash,
        &request,
    )
    .await
    .unwrap();
    assert_eq!(two_providers.lz_message_id, one_provider.lz_message_id);
    assert_eq!(two_providers.message, one_provider.message);
    assert_eq!(two_providers.tx_hash, one_provider.tx_hash);
    assert_eq!(two_providers.extra, one_provider.extra);
}

const INITIA_SOURCE_EVENTS: &str =
    include_str!("../../tests/gasolina_parity/initia_source_events.json");

/// Serves each Initia provider host its own copy of a transaction as `tx_response`.
#[derive(Clone)]
struct InitiaPerHost {
    by_host: Arc<HashMap<&'static str, Value>>,
}

#[async_trait]
impl JsonRpcTransport for InitiaPerHost {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.by_host
            .iter()
            .find(|(host, _)| url.starts_with(&format!("https://{host}/cosmos/tx/v1beta1/txs/")))
            .map(|(_, transaction)| json!({ "tx_response": transaction }))
            .ok_or_else(|| format!("unexpected GET {url}"))
    }
}

fn initia_pool() -> StaticProviderConfig {
    StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://initia-a.example/".to_string()),
                    ProviderUri::Uri("https://initia-b.example/".to_string()),
                ],
                2,
            ),
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap()
}

fn initia_per_host(provider_a: Value, provider_b: Value) -> InitiaPerHost {
    InitiaPerHost {
        by_host: Arc::new(HashMap::from([
            ("initia-a.example", provider_a),
            ("initia-b.example", provider_b),
        ])),
    }
}

/// What an Initia LCD answers: each event attribute carries the node's own `index` flag,
/// set from its `app.toml` `index-events`, which is not consensus data.
fn with_index_events(mut transaction: Value, indexed: fn(&str) -> bool) -> Value {
    for event in transaction["events"].as_array_mut().unwrap() {
        for attribute in event["attributes"].as_array_mut().unwrap() {
            let flag = indexed(attribute["key"].as_str().unwrap());
            attribute["index"] = Value::Bool(flag);
        }
    }
    transaction
}

fn index_all(_: &str) -> bool {
    true
}

fn index_type_tag_only(key: &str) -> bool {
    key == "type_tag"
}

async fn resolve_initia_with_two_providers(
    provider_a: Value,
    provider_b: Value,
) -> Result<LzSentEvent, AppCoreError> {
    let fixture: Value = serde_json::from_str(INITIA_SOURCE_EVENTS).unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["initia".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&initia_pool()),
        initia_per_host(provider_a, provider_b),
        config.packet_sent_resolver_config,
    )
    .get_lz_sent_event(fixture["txHash"].as_str().unwrap(), &request)
    .await
}

fn initia_match_transaction() -> Value {
    let fixture: Value = serde_json::from_str(INITIA_SOURCE_EVENTS).unwrap();
    fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "match")
        .unwrap()["transaction"]
        .clone()
}

/// Two honest Initia nodes with different `index-events` settings answer the same
/// transaction with different attribute `index` flags. The source read must still agree,
/// and a provider that disagrees on an attribute's key or value must still split it.
#[tokio::test]
async fn round3_m12_initia_node_index_events_still_reach_quorum() {
    let indexed = with_index_events(initia_match_transaction(), index_all);
    let baseline = resolve_initia_with_two_providers(indexed.clone(), indexed.clone())
        .await
        .unwrap();
    let mixed = resolve_initia_with_two_providers(
        indexed.clone(),
        with_index_events(initia_match_transaction(), index_type_tag_only),
    )
    .await
    .unwrap_or_else(|error| panic!("index-events difference: {error}"));
    assert_eq!(mixed, baseline);

    let mut changed_value = indexed.clone();
    let attribute = &mut changed_value["events"][0]["attributes"][0];
    attribute["value"] = Value::from(format!("{}X", attribute["value"].as_str().unwrap()));
    let error = resolve_initia_with_two_providers(changed_value, indexed)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("quorum: response set is ambiguous or incomplete"),
        "{error}"
    );
}

/// The Initia sender read consumes only the transaction hash and the signer key (M-61), so
/// event attributes, indexed or changed, never split it, and a different hash still does.
#[tokio::test]
async fn round3_m12_initia_sender_read_ignores_node_index_events() {
    let transaction = |indexed: fn(&str) -> bool, value: &str| {
        json!({
            "txhash": "ABC",
            "tx": {"auth_info": {"signer_infos": [{"public_key": {
                "@type": "/cosmos.crypto.secp256k1.PubKey",
                "key": "Anm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeY"
            }}]}},
            "events": [{
                "type": "move",
                "attributes": [
                    {"key": "type_tag", "value": "0x1::fungible_asset::WithdrawEvent", "index": true},
                    {"key": "amount", "value": value, "index": indexed("amount")},
                ],
            }],
        })
    };
    let sender = |provider_a: Value, provider_b: Value| async move {
        RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&initia_pool()),
            initia_per_host(provider_a, provider_b),
        )
        .source_transaction_from_address("initia", "ABC")
        .await
    };

    assert_eq!(
        sender(
            transaction(index_all, "2294"),
            transaction(index_type_tag_only, "2294"),
        )
        .await
        .unwrap(),
        "init1w508d6qejxtdg4y5r3zarvary0c5xw7k5thfy6"
    );
    let mut other_hash = transaction(index_all, "2294");
    other_hash["txhash"] = json!("ABD");
    assert_eq!(
        sender(
            transaction(index_all, "2294"),
            transaction(index_all, "2295"),
        )
        .await
        .unwrap(),
        "init1w508d6qejxtdg4y5r3zarvary0c5xw7k5thfy6"
    );
    let error = sender(transaction(index_all, "2294"), other_hash)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("quorum: response set is ambiguous or incomplete"),
        "{error}"
    );
}
