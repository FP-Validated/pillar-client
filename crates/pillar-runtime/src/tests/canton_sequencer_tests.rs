//! Canton's sequencer path against upstream 1.2.66's own run of it
//! (`tests/gasolina_parity/canton_sequencer.json`, from
//! `scripts/gasolina-parity/emit-ve3-sequencer.ts`): provider construction, source
//! resolution, source readiness and the already-signed check. Each scenario's HTTP
//! exchanges are served back byte for byte, every request this service makes must be one
//! upstream made, and the outcome — value or error text — must be upstream's.
use super::*;
use crate::layerzero_runtime::{
    canton_block_confirmations, canton_payload_signed, canton_sequencer, resolve_canton_packet_sent,
};
use crate::provider_health::address_encoded_by_chain;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/canton_sequencer.json");
const LEDGER_URI: &str =
    "https://ledger.example/?admin-api=admin.example:5002&wallet-url=https://wallet.example";

#[derive(Clone)]
struct Replay {
    exchanges: Arc<Mutex<Vec<(Value, bool)>>>,
}

impl Replay {
    fn new(exchanges: &[Value]) -> Self {
        Self {
            exchanges: Arc::new(Mutex::new(
                exchanges
                    .iter()
                    .cloned()
                    .map(|exchange| (exchange, false))
                    .collect(),
            )),
        }
    }

    fn serve(
        &self,
        method: &str,
        url: &str,
        headers: &HashMap<String, String>,
        body: Option<&Value>,
    ) -> Result<(u16, String), String> {
        let mut exchanges = self.exchanges.lock().unwrap();
        let found = exchanges.iter_mut().find(|(exchange, used)| {
            !used
                && exchange["method"] == method
                && exchange["url"] == url
                && exchange["body"] == body.cloned().unwrap_or(Value::Null)
        });
        let Some((exchange, used)) = found else {
            return Err(format!(
                "upstream made no such request: {method} {url} {body:?}"
            ));
        };
        let expected: HashMap<String, String> =
            serde_json::from_value(exchange["headers"].clone()).unwrap();
        let lowered = |map: &HashMap<String, String>| {
            map.iter()
                .map(|(key, value)| (key.to_lowercase(), value.clone()))
                .collect::<HashMap<_, _>>()
        };
        assert_eq!(lowered(headers), lowered(&expected), "{method} {url}");
        *used = true;
        Ok((
            exchange["status"].as_u64().unwrap() as u16,
            exchange["text"].as_str().unwrap().to_string(),
        ))
    }
}

#[async_trait]
impl JsonRpcTransport for Replay {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected JSON POST {url}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected JSON GET {url}"))
    }

    async fn post_text(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<(u16, String), String> {
        self.serve("POST", &url, &headers, Some(&body))
    }

    async fn get_text(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<(u16, String), String> {
        self.serve("GET", &url, &headers, None)
    }
}

fn provider_config(provider: &Value) -> ProviderConfig {
    let headers: HashMap<String, String> =
        serde_json::from_value(provider["headers"].clone()).unwrap();
    let uri = provider["uri"].as_str().unwrap().to_string();
    let sequencer = if headers.is_empty() {
        ProviderUri::Uri(uri)
    } else {
        ProviderUri::UriWithHeaders { uri, headers }
    };
    ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(LEDGER_URI.to_string())], 1)
        .with_sequencer(vec![sequencer])
}

fn sent_event(upstream: &Value) -> LzSentEvent {
    let pathway = &upstream["lzMessageId"]["pathwayId"];
    let mut extra = IndexMap::new();
    for key in ["srcEid", "dstEid", "sender", "receiver"] {
        extra.insert(key.to_string(), pathway[key].clone());
    }
    let mut event_extra = IndexMap::new();
    event_extra.insert("guid".to_string(), upstream["guid"].clone());
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: pathway["srcChainName"].as_str().unwrap().to_string(),
                dst_chain_name: pathway["dstChainName"].as_str().unwrap().to_string(),
                extra,
            },
            nonce: upstream["lzMessageId"]["nonce"].as_u64().unwrap(),
            uln_send_version: upstream["lzMessageId"]["ulnSendVersion"].clone(),
        },
        message: upstream["message"].as_str().unwrap().to_string(),
        tx_hash: upstream["onChainEvent"]["txHash"]
            .as_str()
            .unwrap()
            .to_string(),
        extra: event_extra,
        source_evidence: None,
        read_block_pins: Vec::new(),
    }
}

/// The fields of upstream's `LZSentEventV2` this service carries, in upstream's rendering.
fn resolved_view(event: &LzSentEvent) -> Value {
    let pathway = &event.lz_message_id.pathway_id;
    let render = |key: &str, chain: &str| {
        address_encoded_by_chain(chain, pathway.extra[key].as_str().unwrap()).unwrap()
    };
    json!({
        "txHash": event.tx_hash,
        "blockNumber": event.extra["blockNumber"],
        "pathwayId": {
            "srcEid": pathway.extra["srcEid"],
            "srcChainName": pathway.src_chain_name,
            "dstEid": pathway.extra["dstEid"],
            "dstChainName": pathway.dst_chain_name,
            "sender": render("sender", &pathway.src_chain_name),
            "receiver": render("receiver", &pathway.dst_chain_name),
        },
        "nonce": event.lz_message_id.nonce,
        "ulnSendVersion": event.lz_message_id.uln_send_version,
        "guid": event.extra["guid"],
        "message": event.message,
        "sendLibrary": event.extra["sendLibrary"],
    })
}

fn upstream_view(event: &Value) -> Value {
    json!({
        "txHash": event["onChainEvent"]["txHash"],
        "blockNumber": event["onChainEvent"]["blockNumber"],
        "pathwayId": event["lzMessageId"]["pathwayId"],
        "nonce": event["lzMessageId"]["nonce"],
        "ulnSendVersion": event["lzMessageId"]["ulnSendVersion"],
        "guid": event["guid"],
        "message": event["message"],
        "sendLibrary": event["sendLibrary"],
    })
}

fn outcome<T>(result: Result<T, AppCoreError>, view: impl FnOnce(T) -> Value) -> Value {
    match result {
        Ok(value) => json!({ "ok": view(value) }),
        Err(AppCoreError::Internal(message) | AppCoreError::BadRequest(message)) => {
            json!({ "error": message })
        }
        Err(other) => json!({ "error": format!("{other:?}") }),
    }
}

#[tokio::test]
async fn canton_sequencer_path_matches_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(
        fixture["staticVe3ContractAddresses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| pair[1].as_str().unwrap())
            .collect::<Vec<_>>(),
        crate::layerzero_runtime::CANTON_STATIC_VE3_CONTRACTS,
    );
    let scenarios = fixture["scenarios"].as_array().unwrap();
    let mut kinds = HashMap::<&str, usize>::new();
    for scenario in scenarios {
        let kind = scenario["kind"].as_str().unwrap();
        *kinds.entry(kind).or_default() += 1;
        let name = scenario["name"].as_str().unwrap();
        let config = provider_config(&scenario["provider"]);
        let transport = Replay::new(scenario["exchanges"].as_array().unwrap_or(&Vec::new()));
        let sequencer = canton_sequencer("canton", &config);
        let (actual, expected) = match kind {
            "uri" => (
                outcome(sequencer, |sequencer| sequencer.describe()),
                scenario["outcome"].clone(),
            ),
            "resolve" => {
                let lz_message_id: LzMessageId =
                    serde_json::from_value(scenario["lzMessageId"].clone()).unwrap();
                let result = match sequencer {
                    Ok(sequencer) => {
                        resolve_canton_packet_sent(
                            &transport,
                            &sequencer,
                            scenario["srcTxHash"].as_str().unwrap(),
                            &lz_message_id,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                let expected = match scenario["outcome"].get("ok") {
                    Some(event) => json!({ "ok": upstream_view(event) }),
                    None => scenario["outcome"].clone(),
                };
                (outcome(result, |event| resolved_view(&event)), expected)
            }
            "confirmations" => {
                let now = (scenario["nowMs"].as_f64().unwrap() / 1000.0).floor();
                let result = match sequencer {
                    Ok(sequencer) => {
                        canton_block_confirmations(
                            &transport,
                            &sequencer,
                            scenario["nonce"].as_f64().unwrap(),
                            now,
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                (
                    outcome(result, |seconds| json!(seconds as u64)),
                    scenario["outcome"].clone(),
                )
            }
            "payloadSigned" => {
                let event = sent_event(&scenario["sentEvent"]);
                let result = match sequencer {
                    Ok(sequencer) => {
                        canton_payload_signed(
                            &transport,
                            &sequencer,
                            &event,
                            scenario["dvnAddress"].as_str().unwrap(),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                };
                (outcome(result, Value::Bool), scenario["outcome"].clone())
            }
            other => panic!("unknown scenario kind {other}"),
        };
        assert_eq!(actual, expected, "{kind} / {name}");
    }
    assert_eq!(
        kinds,
        HashMap::from([
            ("uri", 25),
            ("resolve", 15),
            ("confirmations", 5),
            ("payloadSigned", 10)
        ]),
        "every upstream scenario is replayed"
    );
}
