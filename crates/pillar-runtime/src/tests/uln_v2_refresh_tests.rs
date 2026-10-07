//! Upstream's own refresh of a ULNv2 send before it is rebuilt for a migrated receive
//! library, replayed through this resolver: `LZEvmSdk.getLZSentEvent` and
//! `LZAptosSdk.getLZSentEvent` over scripted providers
//! (`scripts/gasolina-parity/emit-v1-refresh.ts`, `tests/gasolina_parity/v1_refresh.json`).
//! Each scenario must make the same reads in the same order, end in the same outcome
//! (re-read event, upstream's `null`, or a throw) and carry the same `dstGasLimit`.

use super::*;
use pillar_core::EvmSourceEvidence;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/v1_refresh.json");

type Calls = Arc<Mutex<Vec<Value>>>;

#[derive(Clone)]
struct ScriptedEvm {
    script: Value,
    calls: Calls,
}

fn abi_bytes(hex_value: &str) -> String {
    let bytes = hex::decode(hex_value.trim_start_matches("0x")).unwrap();
    let padded = bytes.len().div_ceil(32) * 32;
    let mut out = format!("0x{:064x}{:064x}{}", 32, bytes.len(), hex::encode(&bytes));
    out.push_str(&"00".repeat(padded - bytes.len()));
    out
}

#[async_trait]
impl JsonRpcTransport for ScriptedEvm {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let method = body["method"].as_str().unwrap().to_string();
        self.calls
            .lock()
            .unwrap()
            .push(json!({"method": method, "params": body["params"]}));
        let error = |key: &str| self.script[key].as_str().map(str::to_string);
        let result = match method.as_str() {
            "eth_getTransactionReceipt" => {
                if let Some(error) = error("receiptError") {
                    return Err(error);
                }
                let tx = body["params"][0].as_str().unwrap();
                self.script["receipts"]
                    .get(tx)
                    .cloned()
                    .unwrap_or(Value::Null)
            }
            "eth_getLogs" => {
                if let Some(error) = error("logsError") {
                    return Err(error);
                }
                self.script.get("logs").cloned().unwrap_or(json!([]))
            }
            "eth_call" => {
                if let Some(error) = error("callError") {
                    return Err(error);
                }
                let returned = self.script["defaultAdapterParams"].as_str().unwrap_or(
                    "0x00010000000000000000000000000000000000000000000000000000000000030d40",
                );
                Value::from(abi_bytes(returned))
            }
            other => return Err(format!("unscripted {other}")),
        };
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

#[derive(Clone)]
struct ScriptedAptos {
    script: Value,
    calls: Calls,
}

#[async_trait]
impl JsonRpcTransport for ScriptedAptos {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let handle = url
            .split("/tables/")
            .nth(1)
            .unwrap()
            .trim_end_matches("/item");
        assert!(url.ends_with("/item"), "unexpected POST {url}");
        self.calls
            .lock()
            .unwrap()
            .push(json!({"getTableItem": {"handle": handle, "data": body}}));
        match self.script["tableError"].as_str() {
            Some(error) => Err(error.to_string()),
            None => Ok(self.script["tableItem"].clone()),
        }
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        if let Some(version) = url.split("/transactions/by_version/").nth(1) {
            self.calls
                .lock()
                .unwrap()
                .push(json!({"getTransactionByVersion": version}));
            return Ok(
                json!({"type": "user_transaction", "version": "26629", "events": self.script["events"]}),
            );
        }
        if let Some(path) = url.split("/accounts/").nth(1) {
            let (account, resource_type) = path.split_once("/resource/").unwrap();
            let resource_type = resource_type.replace("%3A", ":");
            self.calls.lock().unwrap().push(json!({
                "getAccountResource": {"accountAddress": account, "resourceType": resource_type}
            }));
            return match self.script["resourceError"].as_str() {
                Some(error) => Err(error.to_string()),
                None => Ok(json!({
                    "type": resource_type,
                    "data": {"params": {"handle": format!("0x{}", "ee".repeat(32))}}
                })),
            };
        }
        Err(format!("unexpected GET {url}"))
    }
}

fn providers(chain: &str) -> StaticProviderConfig {
    StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!("https://{chain}.example"))],
                1,
            ),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap()
}

fn sent_event_from(upstream: &Value, source_evidence: Option<EvmSourceEvidence>) -> LzSentEvent {
    let pathway = &upstream["lzMessageId"]["pathwayId"];
    let mut extra = IndexMap::new();
    for key in ["srcEid", "dstEid", "sender", "receiver"] {
        extra.insert(key.to_string(), pathway[key].clone());
    }
    let emitter = upstream["packetEmitAddress"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase();
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: pathway["srcChainName"].as_str().unwrap().to_string(),
                dst_chain_name: pathway["dstChainName"].as_str().unwrap().to_string(),
                extra,
            },
            nonce: upstream["lzMessageId"]["nonce"].as_u64().unwrap(),
            uln_send_version: Value::from("V2"),
        },
        message: upstream["message"].as_str().unwrap().to_string(),
        tx_hash: upstream["onChainEvent"]["txHash"]
            .as_str()
            .unwrap()
            .to_string(),
        source_evidence,
        read_block_pins: Vec::new(),
        extra: IndexMap::from([
            ("options".to_string(), Value::from("0x")),
            ("sendLibrary".to_string(), Value::from(emitter.clone())),
            ("packetEmitAddress".to_string(), Value::from(emitter)),
        ]),
    }
}

/// `hydrateV1SentEventToV2` over the re-read send, field by field; `sendLibrary` is the
/// emitter, which upstream renders checksummed from the ethers log.
fn assert_hydrated_like_upstream(
    name: &str,
    refreshed: &pillar_core::UlnV2RefreshedEvent,
    upstream: &Value,
) {
    let hydrated = pillar_core::hydrate_uln_v2_sent_event(
        &refreshed.sent_event,
        refreshed.lz_receive_gas.as_deref(),
    )
    .unwrap();
    for key in ["guid", "options", "payload"] {
        assert_eq!(hydrated.extra[key], upstream[key], "{name}: hydrated {key}");
    }
    assert_eq!(
        hydrated.message,
        upstream["message"].as_str().unwrap(),
        "{name}: hydrated message"
    );
    assert!(
        hydrated.extra["sendLibrary"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case(upstream["sendLibrary"].as_str().unwrap()),
        "{name}: hydrated sendLibrary"
    );
}

fn upstream_gas(refreshed: &Value) -> Option<String> {
    refreshed["adapterParams"]["decodedAdapterParams"]["dstGasLimit"]
        .as_str()
        .map(str::to_string)
}

#[tokio::test]
async fn evm_uln_v2_refresh_matches_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let evm = &fixture["evm"];
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["bsc".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    assert_eq!(
        config
            .packet_sent_resolver_config
            .max_eth_get_logs_block_range_by_chain_name["bsc"],
        evm["maxEthGetLogsBlockRange"].as_u64().unwrap() as u32
    );
    let upstream_event = &evm["sentEvent"];
    let event = sent_event_from(
        upstream_event,
        Some(EvmSourceEvidence {
            block_hash: upstream_event["onChainEvent"]["blockHash"]
                .as_str()
                .unwrap()
                .to_string(),
            block_number: upstream_event["onChainEvent"]["blockNumber"]
                .as_i64()
                .unwrap(),
            status: "1".to_string(),
            packet_log_index: 1,
            transaction_hash: upstream_event["onChainEvent"]["txHash"]
                .as_str()
                .unwrap()
                .to_string(),
            packet_log_address: String::new(),
            packet_log_topics: Vec::new(),
            packet_log_data: String::new(),
        }),
    );
    let mut compared = 0;
    for scenario in evm["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&providers("bsc")),
            ScriptedEvm {
                script: scenario["script"].clone(),
                calls: calls.clone(),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let result = resolver.refresh_uln_v2_sent_event(&event).await;

        let ours = calls.lock().unwrap().clone();
        let theirs = scenario["calls"].as_array().unwrap();
        let methods = |calls: &[Value]| -> Vec<String> {
            calls
                .iter()
                .map(|call| call["method"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(methods(&ours), methods(theirs), "{name}: reads");
        for (mine, upstream) in ours.iter().zip(theirs) {
            let lower = |value: &Value| value.to_string().to_ascii_lowercase();
            assert_eq!(
                lower(&mine["params"]),
                lower(&upstream["params"]),
                "{name}: params"
            );
        }

        match (&scenario["outcome"], result) {
            (outcome, Err(error)) if outcome.get("error").is_some() => {
                assert!(
                    matches!(error, AppCoreError::Internal(_)),
                    "{name}: {error:?}"
                );
            }
            (outcome, Ok(None))
                if outcome["refreshed"].is_null() && outcome.get("error").is_none() => {}
            (outcome, Ok(Some(refreshed))) if outcome["refreshed"].is_object() => {
                let theirs = &outcome["refreshed"];
                let evidence = refreshed.sent_event.source_evidence.as_ref().unwrap();
                assert_eq!(
                    refreshed.sent_event.tx_hash,
                    theirs["onChainEvent"]["txHash"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    evidence.block_hash,
                    theirs["onChainEvent"]["blockHash"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    evidence.block_number,
                    theirs["onChainEvent"]["blockNumber"].as_i64().unwrap(),
                    "{name}"
                );
                assert!(
                    lz_message_id_matches(
                        &event.lz_message_id,
                        &refreshed.sent_event.lz_message_id
                    ),
                    "{name}: lzMessageId"
                );
                assert_eq!(
                    refreshed.sent_event.message,
                    theirs["message"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    refreshed.lz_receive_gas,
                    upstream_gas(theirs),
                    "{name}: gas"
                );
                assert_hydrated_like_upstream(name, &refreshed, &outcome["hydrated"]);
            }
            (outcome, result) => panic!("{name}: upstream {outcome}, ours {result:?}"),
        }
        compared += 1;
    }
    assert_eq!(compared, 14, "every upstream EVM scenario is replayed");
}

#[tokio::test]
async fn aptos_uln_v2_refresh_matches_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let config =
        runtime_evm_layerzero_config(environment, &["aptos".to_string(), "arbitrum".to_string()])
            .unwrap();
    let source = config
        .packet_sent_resolver_config
        .aptos_v1_source
        .clone()
        .unwrap();
    let addresses = &fixture["aptosAddresses"][environment];
    assert_eq!(
        source.layerzero_account,
        addresses["layerzero"].as_str().unwrap()
    );
    assert_eq!(
        source.layerzero_account,
        addresses["executorV2"].as_str().unwrap()
    );

    let aptos = &fixture["aptos"];
    let event = sent_event_from(&aptos["sentEvent"], None);
    assert_eq!(
        crate::layerzero_runtime::aptos_v1_guid(&event.lz_message_id).unwrap(),
        aptos["guid"].as_str().unwrap()
    );
    let mut compared = 0;
    for scenario in aptos["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&providers("aptos")),
            ScriptedAptos {
                script: scenario["script"].clone(),
                calls: calls.clone(),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let result = resolver.refresh_uln_v2_sent_event(&event).await;
        assert_eq!(
            &Value::from(calls.lock().unwrap().clone()),
            &scenario["calls"],
            "{name}: reads"
        );

        let outcome = &scenario["outcome"];
        match (outcome.get("error").and_then(Value::as_str), result) {
            (Some(theirs), Err(error)) => {
                let javascript = theirs.starts_with("Cannot read properties")
                    || theirs == "invalid adapter params";
                if javascript {
                    assert_eq!(error, AppCoreError::Internal(theirs.to_string()), "{name}");
                } else {
                    assert!(
                        matches!(error, AppCoreError::Internal(_)),
                        "{name}: {error:?}"
                    );
                }
            }
            (None, Ok(Some(refreshed))) => {
                assert_eq!(
                    refreshed.sent_event, event,
                    "{name}: the send itself is kept"
                );
                assert_eq!(
                    refreshed.lz_receive_gas,
                    upstream_gas(&outcome["refreshed"]),
                    "{name}: gas"
                );
                assert_hydrated_like_upstream(name, &refreshed, &outcome["hydrated"]);
            }
            (theirs, ours) => panic!("{name}: upstream {theirs:?}, ours {ours:?}"),
        }
        compared += 1;
    }
    assert_eq!(compared, 10, "every upstream Aptos scenario is replayed");
}
