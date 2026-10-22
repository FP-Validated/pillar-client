//! Quorum reads outside the Aptos family that fingerprinted the provider's whole answer:
//! honest providers that differ only in fields this resolver never reads must agree, and a
//! provider that differs in a field it does read must still split the quorum.

use super::*;
use pillar_core::EvmSourceEvidence;

const V1_REFRESH: &str = include_str!("../../tests/gasolina_parity/v1_refresh.json");
const STARKNET: &str = include_str!("../../tests/gasolina_parity/starknet_source_events.json");
const SUI_FAMILY: &str = include_str!("../../tests/gasolina_parity/sui_source_events.json");

fn two_provider_pool(chain: &str) -> StaticProviderConfig {
    StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri(format!("https://{chain}-a.example/")),
                    ProviderUri::Uri(format!("https://{chain}-b.example/")),
                ],
                2,
            ),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap()
}

fn host_of(url: &str) -> String {
    url.split('/').nth(2).unwrap().to_string()
}

fn assert_split(error: AppCoreError, case: &str) {
    let error = error.to_string();
    assert!(
        error.contains("quorum: response set is ambiguous or incomplete"),
        "{case}: {error}"
    );
}

type LogEdit = fn(&mut Value);

/// Each host's `eth_getLogs` answer, edited from the scripted one.
#[derive(Clone)]
struct LogsPerHost {
    script: Value,
    edit_by_host: Arc<HashMap<String, LogEdit>>,
}

#[async_trait]
impl JsonRpcTransport for LogsPerHost {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let result = match body["method"].as_str().unwrap() {
            "eth_getTransactionReceipt" => self.script["receipts"]
                .get(body["params"][0].as_str().unwrap())
                .cloned()
                .unwrap_or(Value::Null),
            "eth_getLogs" => {
                let mut logs = self.script["logs"].clone();
                if let Some(edit) = self.edit_by_host.get(&host_of(&url)) {
                    for log in logs.as_array_mut().unwrap() {
                        edit(log);
                    }
                }
                logs
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

fn uln_v2_sent_event(upstream: &Value) -> LzSentEvent {
    let pathway = &upstream["lzMessageId"]["pathwayId"];
    let emitter = upstream["packetEmitAddress"]
        .as_str()
        .unwrap()
        .to_ascii_lowercase();
    let tx_hash = upstream["onChainEvent"]["txHash"].as_str().unwrap();
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: pathway["srcChainName"].as_str().unwrap().to_string(),
                dst_chain_name: pathway["dstChainName"].as_str().unwrap().to_string(),
                extra: ["srcEid", "dstEid", "sender", "receiver"]
                    .into_iter()
                    .map(|key| (key.to_string(), pathway[key].clone()))
                    .collect(),
            },
            nonce: upstream["lzMessageId"]["nonce"].as_u64().unwrap(),
            uln_send_version: Value::from("V2"),
        },
        message: upstream["message"].as_str().unwrap().to_string(),
        tx_hash: tx_hash.to_string(),
        source_evidence: Some(pillar_core::SourceEvidence::Evm(EvmSourceEvidence {
            block_hash: upstream["onChainEvent"]["blockHash"]
                .as_str()
                .unwrap()
                .to_string(),
            block_number: upstream["onChainEvent"]["blockNumber"].as_i64().unwrap(),
            status: "1".to_string(),
            packet_log_index: 1,
            transaction_hash: tx_hash.to_string(),
            packet_log_address: String::new(),
            packet_log_topics: Vec::new(),
            packet_log_data: String::new(),
        })),
        read_block_pins: Vec::new(),
        extra: IndexMap::from([
            ("options".to_string(), Value::from("0x")),
            ("sendLibrary".to_string(), Value::from(emitter.clone())),
            ("packetEmitAddress".to_string(), Value::from(emitter)),
        ]),
    }
}

/// `arb1.arbitrum.io` answers `eth_getLogs` with `"blockTimestamp": "0x0"` where other
/// Arbitrum providers give the block's time, and older clients omit the field. The ULNv2
/// refresh that searches logs after a reorg must agree across them, and still split on a
/// log field it reads.
#[tokio::test]
async fn uln_v2_refresh_logs_agree_on_the_fields_the_refresh_reads() {
    let fixture: Value = serde_json::from_str(V1_REFRESH).unwrap();
    let evm = &fixture["evm"];
    let scenario = evm["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "receipt gone, moved by reorg")
        .unwrap();
    let moved_to = scenario["outcome"]["refreshed"]["onChainEvent"]["txHash"]
        .as_str()
        .unwrap();
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["bsc".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    let event = uln_v2_sent_event(&evm["sentEvent"]);
    let refresh = |edit_a: fn(&mut Value), edit_b: fn(&mut Value)| {
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&two_provider_pool("bsc")),
            LogsPerHost {
                script: scenario["script"].clone(),
                edit_by_host: Arc::new(HashMap::from([
                    ("bsc-a.example".to_string(), edit_a),
                    ("bsc-b.example".to_string(), edit_b),
                ])),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let event = event.clone();
        async move { resolver.refresh_uln_v2_sent_event(&event).await }
    };
    let block_time: fn(&mut Value) = |log| log["blockTimestamp"] = json!("0x6ad9657b");

    for (case, edit_a) in [
        (
            "blockTimestamp 0x0",
            (|log: &mut Value| log["blockTimestamp"] = json!("0x0")) as fn(&mut Value),
        ),
        ("blockTimestamp absent", |_: &mut Value| {}),
        ("transactionIndex and removed differ", |log: &mut Value| {
            log["blockTimestamp"] = json!("0x6ad9657b");
            log["transactionIndex"] = json!("0x63");
            log["removed"] = json!(null);
        }),
    ] {
        let refreshed = refresh(edit_a, block_time)
            .await
            .unwrap_or_else(|error| panic!("{case}: {error}"))
            .unwrap_or_else(|| panic!("{case}: found by logs"));
        assert_eq!(refreshed.sent_event.tx_hash, moved_to, "{case}");
    }

    for (case, edit_a) in [
        (
            "data",
            (|log: &mut Value| {
                let data = log["data"].as_str().unwrap().to_string();
                log["data"] = Value::from(format!("{}ff", &data[..data.len() - 2]));
            }) as fn(&mut Value),
        ),
        ("logIndex", |log: &mut Value| {
            log["logIndex"] = json!("0x7f")
        }),
        ("blockHash", |log: &mut Value| {
            log["blockHash"] = json!(format!("0x{}", "ee".repeat(32)))
        }),
    ] {
        let error = refresh(edit_a, |_| {}).await.expect_err(case);
        assert_split(error, case);
    }
}

#[derive(Clone)]
struct StarknetPerHost {
    receipt_by_host: Arc<HashMap<String, Value>>,
}

#[async_trait]
impl JsonRpcTransport for StarknetPerHost {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        assert_eq!(body["method"], "starknet_getTransactionReceipt");
        let receipt = self.receipt_by_host[&host_of(&url)].clone();
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": receipt}))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

/// Starknet providers mark a block `ACCEPTED_ON_L1` when each sees the L1 state update, so
/// for a while one answers L1 and another L2, and providers on different RPC spec versions
/// shape `execution_resources` and `actual_fee` differently. Both are acceptance; neither
/// is read. A different event, execution status or a non-accepted finality still splits.
#[tokio::test]
async fn starknet_receipts_agree_on_acceptance_and_the_fields_the_resolver_reads() {
    let fixture: Value = serde_json::from_str(STARKNET).unwrap();
    let tx_hash = fixture["txHash"].as_str().unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == "match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let mut receipt = scenario["receipt"].clone();
    receipt["transaction_hash"] = Value::from(format!("0x00{}", &tx_hash[2..]));
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["starknet".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    let resolve = |provider_a: Value, provider_b: Value| {
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&two_provider_pool("starknet")),
            StarknetPerHost {
                receipt_by_host: Arc::new(HashMap::from([
                    ("starknet-a.example".to_string(), provider_a),
                    ("starknet-b.example".to_string(), provider_b),
                ])),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let request = request.clone();
        async move { resolver.get_lz_sent_event(tx_hash, &request).await }
    };
    let baseline = resolve(receipt.clone(), receipt.clone()).await.unwrap();

    let mut on_l1 = receipt.clone();
    on_l1["finality_status"] = json!("ACCEPTED_ON_L1");
    on_l1["execution_resources"] =
        json!({"steps": 4, "data_availability": {"l1_gas": 0, "l1_data_gas": 0}});
    on_l1["actual_fee"] = json!({"amount": "0x01", "unit": "FRI"});
    let agreed = resolve(on_l1, receipt.clone())
        .await
        .unwrap_or_else(|error| panic!("L1/L2 and spec-shape differences: {error}"));
    assert_eq!(agreed, baseline);

    let mut received = receipt.clone();
    received["finality_status"] = json!("RECEIVED");
    let mut reverted = receipt.clone();
    reverted["execution_status"] = json!("REVERTED");
    let mut other_event = receipt.clone();
    let data = other_event["events"][0]["data"].as_array_mut().unwrap();
    data[0] = json!("0x1234");
    for (case, provider_a) in [
        ("finality RECEIVED", received),
        ("execution_status", reverted),
        ("event data", other_event),
    ] {
        let error = resolve(provider_a, receipt.clone()).await.expect_err(case);
        assert_split(error, case);
    }
}

#[derive(Clone)]
struct IotaPerHost {
    events_by_host: Arc<HashMap<String, Value>>,
}

#[async_trait]
impl JsonRpcTransport for IotaPerHost {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        assert_eq!(body["method"], "iotax_queryEvents");
        let host = host_of(&url);
        let digest = body["params"][0]["Transaction"].clone();
        let mut page = self.events_by_host[&host].clone();
        for event in page["data"].as_array_mut().unwrap() {
            event["id"]["txDigest"] = digest.clone();
        }
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": page}))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

/// IOTA events carry `bcs`, `bcsEncoding`, `timestampMs` and a cursor alongside the
/// `type` and `parsedJson` the resolver reads; Sui nodes changed `bcs` from Base58 to
/// Base64 in one release, which is how IOTA nodes can differ. Those must not split the
/// quorum; a different `type` or `parsedJson` must.
#[tokio::test]
async fn iota_events_agree_on_type_and_parsed_json() {
    let fixture: Value = serde_json::from_str(SUI_FAMILY).unwrap();
    let digest = fixture["digest"].as_str().unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["chain"] == "iotal1" && scenario["name"] == "V302 match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let config = runtime_evm_layerzero_config(
        fixture["environment"].as_str().unwrap(),
        &["iotal1".to_string(), "ethereum".to_string()],
    )
    .unwrap();
    let page = |encoding: &str, bcs: &str, cursor_seq: &str| {
        let mut events = scenario["response"]["data"].clone();
        for event in events.as_array_mut().unwrap() {
            event["bcs"] = Value::from(bcs);
            event["bcsEncoding"] = Value::from(encoding);
            event["timestampMs"] = Value::from("1767323050000");
        }
        json!({
            "data": events,
            "hasNextPage": false,
            "nextCursor": {"txDigest": digest, "eventSeq": cursor_seq},
        })
    };
    let resolve = |provider_a: Value, provider_b: Value| {
        let resolver = EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&two_provider_pool("iotal1")),
            IotaPerHost {
                events_by_host: Arc::new(HashMap::from([
                    ("iotal1-a.example".to_string(), provider_a),
                    ("iotal1-b.example".to_string(), provider_b),
                ])),
            },
            config.packet_sent_resolver_config.clone(),
        );
        let request = request.clone();
        async move { resolver.get_lz_sent_event(digest, &request).await }
    };
    let base64 = page("base64", "AQID", "0");
    let baseline = resolve(base64.clone(), base64.clone()).await.unwrap();
    let agreed = resolve(page("base58", "Ldp", "1"), base64.clone())
        .await
        .unwrap_or_else(|error| panic!("bcs encoding and cursor differences: {error}"));
    assert_eq!(agreed, baseline);

    let mut other_json = base64.clone();
    other_json["data"][0]["parsedJson"]["nonce"] = json!("999");
    let mut other_type = base64.clone();
    other_type["data"][0]["type"] = json!("0x2::other::Event");
    for (case, provider_a) in [("parsedJson", other_json), ("type", other_type)] {
        let error = resolve(provider_a, base64.clone()).await.expect_err(case);
        assert_split(error, case);
    }
}
