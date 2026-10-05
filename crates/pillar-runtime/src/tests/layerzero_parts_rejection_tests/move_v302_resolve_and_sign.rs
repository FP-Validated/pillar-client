use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const SOURCE: &str = "ethereum";
const SOURCE_EID: u32 = 30_101;
const NONCE: u64 = 117;
const APTOS_RECEIVER: &str = "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa";
const MOVEMENT_RECEIVER: &str =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
const DVN: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const SEND_ULN_302: &str = "0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1";
const EXPIRATION: i64 = 1_760_000_000;

struct CountingSigner(Arc<AtomicUsize>);

#[async_trait]
impl SignerGetter for CountingSigner {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<Signature, AppCoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        FixedSigner
            .pillar_sign(dst_chain_name, wallet_name, data_hex)
            .await
    }
}

fn word(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn abi_bytes(value: &[u8]) -> Vec<u8> {
    let mut encoded = word(value.len() as u64).to_vec();
    encoded.extend_from_slice(value);
    encoded.resize(32 + value.len().div_ceil(32) * 32, 0);
    encoded
}

fn packet_sent_receipt(packet: &[u8]) -> Value {
    let packet = abi_bytes(packet);
    // Type-3 options with one 200000-gas lzReceive; upstream skips a packet whose options
    // it cannot decode, and empty options are one.
    let options = abi_bytes(&hex::decode("00030100110100000000000000000000000000030d40").unwrap());
    let mut data = Vec::with_capacity(128 + packet.len() + options.len());
    data.extend_from_slice(&word(0x80));
    data.extend_from_slice(&word(0x80 + packet.len() as u64));
    let mut library = [0; 32];
    library[12..].copy_from_slice(&hex::decode(&SEND_ULN_302[2..]).unwrap());
    data.extend_from_slice(&library);
    data.extend_from_slice(&word(NONCE));
    data.extend_from_slice(&packet);
    data.extend_from_slice(&options);
    let mut receipt = packet_sent_endpoint_v2_data();
    receipt["logs"][0]["data"] = Value::from(format!("0x{}", hex::encode(data)));
    receipt["logs"][0]["address"] = Value::from(
        pillar_config::layerzero_contract_address(SOURCE, "mainnet", "EndpointV2").unwrap(),
    );
    receipt
}

#[derive(Clone)]
struct E2eTransport {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    source_url: String,
    destination_urls: Vec<String>,
    receipt: Value,
    verifiable: Value,
    confirmations: Value,
    config: Value,
    receive_libraries: HashMap<String, Result<Value, String>>,
}

impl E2eTransport {
    fn answer(&self, url: &str, body: &Value) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.to_string(), body.clone()));
        if url == self.source_url {
            return match body["method"].as_str().unwrap_or_default() {
                "eth_getTransactionReceipt" => Ok(json!({ "result": self.receipt })),
                "eth_getBlockByNumber" => Ok(json!({ "result": { "number": "0x100" } })),
                method => Err(format!("unexpected source RPC method: {method}")),
            };
        }
        if url.ends_with("/view") {
            let function = body["function"].as_str().unwrap_or_default();
            if function.ends_with("::endpoint::get_effective_receive_library") {
                let provider_url = url.strip_suffix("/view").unwrap_or(url);
                return self
                    .receive_libraries
                    .get(provider_url)
                    .cloned()
                    .unwrap_or_else(|| Err("missing provider answer".to_string()));
            }
            if function.ends_with("::endpoint::get_config") {
                // Public fullnodes answer string u32 arguments with HTTP 400 (Aptos
                // exchange 009, Movement 005) and numbers with the recorded body (010, 006).
                if body["arguments"][2].is_string() || body["arguments"][3].is_string() {
                    return Err("Provider returned HTTP 400 Bad Request".to_string());
                }
                return Ok(self.config.clone());
            }
            if function.ends_with("::uln_302::verifiable") {
                return Ok(self.verifiable.clone());
            }
            if function.ends_with("::msglib::get_verification_confirmations") {
                return Ok(self.confirmations.clone());
            }
            return Err(format!("unexpected Move view {function}: {body}"));
        }
        Err(format!("unexpected POST {url}: {body}"))
    }
}

#[async_trait]
impl JsonRpcTransport for E2eTransport {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.answer(&url, &body)
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        self.calls.lock().unwrap().push((url.clone(), Value::Null));
        if self.destination_urls.contains(&url) {
            Ok(
                json!({ "ledger_timestamp": (EXPIRATION - 600).to_string().parse::<i64>().unwrap() * 1_000_000 }),
            )
        } else {
            Err(format!("unexpected GET {url}"))
        }
    }
}

fn recorded_move_config(chain: &str) -> Value {
    let name = if chain == "aptos" {
        "010-mainnet-v302-get_config-u32-numbers.response.body"
    } else {
        "006-movement-mainnet-v302-get_config-u32-numbers.response.body"
    };
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/gasolina_parity/aptos_public_node")
            .join(name),
    )
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

async fn run_resolve_and_sign(
    chain: &str,
    state: u8,
    receive_libraries: Vec<Result<Value, String>>,
) -> (StatusCode, Value, usize, Vec<Value>) {
    let (destination_eid, receiver) = if chain == "aptos" {
        (30_108, APTOS_RECEIVER)
    } else {
        (30_325, MOVEMENT_RECEIVER)
    };
    let message = "0xdeadbeef";
    let packet = pillar_layerzero::encode_lz_packet_v1(&pillar_layerzero::LzPacketV1 {
        nonce: NONCE,
        src_eid: SOURCE_EID,
        sender: format!("0x{}{}", "00".repeat(12), "11".repeat(20)),
        dst_eid: destination_eid,
        receiver: receiver.to_string(),
        guid: format!("0x{}", "5a".repeat(32)),
        message: message.to_string(),
    })
    .unwrap();
    let receipt = packet_sent_receipt(&packet);
    let names = vec![SOURCE.to_string(), chain.to_string()];
    let source_url = "https://ethereum-rpc.example".to_string();
    let destination_urls: Vec<String> = (0..receive_libraries.len())
        .map(|index| format!("https://{chain}-rpc-{index}.example/v1"))
        .collect();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([
            (
                SOURCE.to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(source_url.clone())],
                    1,
                ),
            ),
            (
                chain.to_string(),
                ProviderConfig::with_distinct_entities(
                    destination_urls
                        .iter()
                        .cloned()
                        .map(ProviderUri::Uri)
                        .collect(),
                    destination_urls.len() as u64,
                ),
            ),
        ]),
        Some(&names),
    )
    .unwrap();
    let library_by_url = destination_urls
        .iter()
        .cloned()
        .zip(receive_libraries)
        .collect();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = E2eTransport {
        calls: calls.clone(),
        source_url,
        destination_urls,
        receipt,
        receive_libraries: library_by_url,
        verifiable: json!([state]),
        confirmations: json!(["0"]),
        config: recorded_move_config(chain),
    };
    let snapshot = ProviderSnapshotHandle::from_getter(&getter);
    let evm = runtime_evm_layerzero_config("mainnet", &names).unwrap();
    let resolver = EvmPacketSentResolver::new(
        &snapshot,
        transport.clone(),
        evm.packet_sent_resolver_config,
    );
    let checks =
        runtime_rpc_validation_checks_from_evm_config(&snapshot, transport, "mainnet", &names)
            .unwrap();
    let (builders, _) = super::matrix::runtime_hash_builders_for("mainnet", &[SOURCE, chain]);
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let mut app = core_api_app();
    app.core.available_chain_names = Arc::new(names.clone());
    app.core.wallets_by_chain_name = HashMap::from([(
        chain.to_string(),
        vec![WalletRef {
            wallet_name: "wallet-1".to_string(),
        }],
    )]);
    app.core.hash_call_data_builders = builders;
    app.core.sent_event_resolver = Arc::new(resolver);
    app.core.validator = Arc::new(RuntimeAppValidator::new(Arc::new(checks)));
    app.core.signer_getter = Arc::new(CountingSigner(signer_calls.clone()));
    let router = pillar_api::router(app.with_public_sign_routes(true), "move-v302-e2e");
    use sha3::{Digest, Keccak256};
    let message_hash = format!(
        "0x{}",
        hex::encode(Keccak256::digest(hex::decode(&message[2..]).unwrap()))
    );
    let request = PillarApiRequestV2 {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: SOURCE.to_string(),
                dst_chain_name: chain.to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(SOURCE_EID)),
                    ("dstEid".to_string(), Value::from(destination_eid)),
                    (
                        "sender".to_string(),
                        Value::from(format!("0x{}", "11".repeat(20))),
                    ),
                    ("receiver".to_string(), Value::from(receiver)),
                ]),
            },
            nonce: NONCE,
            uln_send_version: Value::from("V302"),
        },
        signing_context: SigningContext::Message {
            expiration: EXPIRATION,
            skip_v_id: None,
            dvn_address: Some(DVN.to_string()),
            block_confirmation: 1,
        },
        message_hash,
        ..request_v2()
    };
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/resolve-and-sign")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    let requests = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(url, _)| url.ends_with("/view"))
        .map(|(_, body)| body.clone())
        .collect();
    (status, body, signer_calls.load(Ordering::SeqCst), requests)
}

#[tokio::test]
async fn evm_v302_to_aptos_and_movement_runs_resolver_validator_builder_and_signer() {
    for chain in ["aptos", "movement"] {
        let (status, body, signatures, requests) = run_resolve_and_sign(
            chain,
            0,
            vec![Ok(json!([format!("0x{}", "44".repeat(32))]))],
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{chain}: {body}");
        assert_eq!(signatures, 1, "{chain}");
        assert!(requests[0]["function"].as_str().is_some_and(
            |function| function.ends_with("::endpoint::get_effective_receive_library")
        ));
        assert_eq!(requests[0]["arguments"][1], json!(SOURCE_EID));
        let get_config = requests
            .iter()
            .find(|body| {
                body["function"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("::endpoint::get_config"))
            })
            .unwrap();
        assert_eq!(get_config["arguments"][2], json!(SOURCE_EID));
        assert_eq!(get_config["arguments"][3], json!(3));

        let (status, body, signatures, _) = run_resolve_and_sign(
            chain,
            2,
            vec![Ok(json!([format!("0x{}", "44".repeat(32))]))],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{chain}: {body}");
        assert_eq!(signatures, 0, "{chain}: signed an already-verified payload");
    }
}

#[tokio::test]
async fn move_v302_receive_library_error_and_malformed_value_refuse_without_signing() {
    let cases = [
        (
            vec![Err("Provider returned HTTP 400 Bad Request".to_string())],
            "provider error",
        ),
        (vec![Ok(json!([42]))], "malformed address"),
    ];
    for (responses, label) in cases {
        let (status, body, signatures, requests) =
            run_resolve_and_sign("aptos", 0, responses).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{label}: {body}");
        assert_eq!(
            body["body"],
            "No payload-signed validation for chain aptos quorum: response set is ambiguous or incomplete; 0 distinct successful responses, 1 errors"
        );
        assert_eq!(signatures, 0, "{label}: signer was called");
        assert_eq!(
            requests.len(),
            1,
            "{label}: processing continued past receive-library failure"
        );
    }
}

#[tokio::test]
async fn move_v302_receive_library_quorum_failure_and_disagreement_refuse_without_signing() {
    let library = |digit: char| Ok(json!([format!("0x{}", digit.to_string().repeat(64))]));
    let cases = [
        (
            vec![library('4'), Err("Provider returned HTTP 400 Bad Request".to_string())],
            "one provider failed",
            "No payload-signed validation for chain aptos quorum: response set is ambiguous or incomplete; 1 distinct successful responses, 1 errors",
        ),
        (
            vec![library('4'), library('5')],
            "providers disagree on library address",
            "No payload-signed validation for chain aptos quorum: response set is ambiguous or incomplete; 2 distinct successful responses, 0 errors",
        ),
    ];
    for (responses, label, reason) in cases {
        let (status, body, signatures, _) = run_resolve_and_sign("aptos", 0, responses).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{label}: {body}");
        assert_eq!(body["body"], reason, "{label}");
        assert_eq!(signatures, 0, "{label}: signer was called");
    }
}
