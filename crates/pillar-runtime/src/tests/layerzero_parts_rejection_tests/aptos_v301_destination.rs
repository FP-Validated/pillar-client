use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use pillar_core::PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX;
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

const UPSTREAM: &str = include_str!("../../../tests/gasolina_parity/non_evm_destination.json");

fn upstream_aptos_v301(environment: &str) -> (Value, Value) {
    let fixture: Value = serde_json::from_str(UPSTREAM).unwrap();
    let row = fixture["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["environment"] == environment && row["chainName"] == "aptos")
        .unwrap()
        .clone();
    (fixture["input"].clone(), row)
}

/// The Aptos EndpointV1 ids (108/10108) that name V301 packets also make an EVM V301
/// send to Aptos reachable, so its arm must equal upstream's: hashCallData, target
/// (Aptos V1 ULN301 module) and vId, through the production builders and vIds.
#[tokio::test]
async fn evm_v301_to_aptos_matches_upstream_for_mainnet_and_testnet() {
    for environment in ["mainnet", "testnet"] {
        let (input, row) = upstream_aptos_v301(environment);
        let expected = &row["arms"]["V301"];
        assert_eq!(expected["outcome"], "built", "{environment}");
        let pathway = &expected["details"]["proof"]["lzMessageId"]["pathwayId"];
        let src = pathway["srcChainName"].as_str().unwrap();
        let (builders, recorder) =
            super::matrix::runtime_hash_builders_for(environment, &[src, "aptos"]);
        assert_eq!(
            test_v_ids(environment).get("aptos").map(String::as_str),
            row["vId"].as_str(),
            "{environment} production vId"
        );
        let mut event =
            super::matrix::matrix_sent_event("aptos", pathway["dstEid"].as_u64().unwrap());
        event.lz_message_id.pathway_id.src_chain_name = src.to_string();
        event.lz_message_id.uln_send_version = Value::from("V301");
        event.lz_message_id.nonce = 4242;
        for key in ["srcEid", "sender", "receiver"] {
            event
                .lz_message_id
                .pathway_id
                .extra
                .insert(key.to_string(), pathway[key].clone());
        }
        event.message = input["message"].as_str().unwrap().to_string();
        event
            .extra
            .insert("guid".to_string(), input["guid"].clone());

        let actual = builders["V301"]
            .build_dvn_hash_call_data(
                &event,
                &SigningContext::Message {
                    expiration: 1_760_000_000,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 15,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            actual.hash_call_data, expected["hashCallData"],
            "{environment} hashCallData"
        );
        assert_eq!(
            format!(
                "0x{}",
                actual.details["dvnCallData"]["targetContract"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x")
            ),
            expected["target"],
            "{environment} target"
        );
        assert_eq!(
            actual.details["dvnCallData"]["vid"], row["vId"],
            "{environment} vId"
        );
        assert!(recorder.calls.lock().await.is_empty());
    }
}

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

fn abi_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = solidity_word(bytes.len() as u64).to_vec();
    out.extend_from_slice(bytes);
    out.resize(32 + bytes.len().div_ceil(32) * 32, 0);
    out
}

fn solidity_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

/// A SendUln301 `PacketSent(bytes,bytes,uint256,uint256)` receipt for an EVM V301
/// send to Aptos, emitted by the source chain's own SendUln301.
fn uln301_send_to_aptos_receipt(
    src: &str,
    environment: &str,
    packet: &[u8],
    transaction_hash: &str,
) -> Value {
    let payload = abi_bytes(packet);
    // Type-3 options with one 200000-gas lzReceive; upstream skips a packet whose options
    // it cannot decode, and empty options are one.
    let options = abi_bytes(&hex::decode("00030100110100000000000000000000000000030d40").unwrap());
    let mut data = Vec::new();
    data.extend_from_slice(&solidity_word(0x80));
    data.extend_from_slice(&solidity_word(0x80 + payload.len() as u64));
    data.extend_from_slice(&solidity_word(5));
    data.extend_from_slice(&solidity_word(0));
    data.extend_from_slice(&payload);
    data.extend_from_slice(&options);
    json!({
        "transactionHash": transaction_hash,
        "blockHash": SOURCE_BLOCK_HASH,
        "blockNumber": SOURCE_BLOCK_NUMBER,
        "status": "0x1",
        "logs": [{
            "address": pillar_config::layerzero_contract_address(src, environment, "SendUln301").unwrap(),
            "transactionHash": transaction_hash,
            "blockHash": SOURCE_BLOCK_HASH,
            "blockNumber": SOURCE_BLOCK_NUMBER,
            "removed": false,
            "logIndex": "0x0",
            "topics": [pillar_layerzero::ULN_301_PACKET_SENT_TOPIC],
            "data": format!("0x{}", hex::encode(data)),
        }]
    })
}

type Answer = dyn Fn(&str, &Value) -> Option<Result<Value, String>> + Send + Sync;

/// Answers each request from `answer` by its content and refuses anything it does not
/// recognise, so an unexpected read fails the scenario instead of passing it.
#[derive(Clone)]
struct ScriptedTransport {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    answer: Arc<Answer>,
}

impl ScriptedTransport {
    fn serve(&self, url: String, body: Value) -> Result<Value, String> {
        let answer = (self.answer)(&url, &body);
        self.calls.lock().unwrap().push((url.clone(), body.clone()));
        answer.unwrap_or_else(|| Err(format!("unrecorded request {url} {body}")))
    }
}

#[async_trait]
impl JsonRpcTransport for ScriptedTransport {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.serve(url, body)
    }
    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        self.serve(url, Value::Null)
    }
}

const APTOS_RPC: &str = "https://aptos-rpc-0.example/v1";
const NOT_FOUND: &str = "Provider returned HTTP 404 Not Found";
const EXPIRATION: i64 = 1_760_000_000;
const NONCE: u64 = 74_756;
const DVN: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const SOURCE_TX_HASH: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const SOURCE_BLOCK_HASH: &str =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE_BLOCK_NUMBER: &str = "0x64";

/// What the destination reports for one scenario; each field drives one upstream read.
#[derive(Clone, Copy)]
struct AptosState {
    receive_msglib: (&'static str, &'static str),
    required_confirmations: u64,
    dvn_confirmations: u64,
    verifiable: u8,
    verifiable_response: Option<&'static str>,
    inbound_nonce: u64,
    /// `None` answers the V1 `Channels` resource read with HTTP 404.
    stored_payload_hash: Option<&'static str>,
    ledger_seconds: i64,
    expiration: i64,
    source_head: u64,
    source_heads: [u64; 3],
    source_provider_count: usize,
    source_quorum: u64,
    aptos_provider_count: usize,
    aptos_quorum: u64,
    request_receiver_override: Option<&'static str>,
    verifiable_votes: [u8; 3],
    live_recorded: bool,
    empty_confirmations: bool,
    missing_channels: bool,
    missing_channel_remote: bool,
}

const UNSIGNED: AptosState = AptosState {
    receive_msglib: ("2", "0"),
    required_confirmations: 2,
    dvn_confirmations: 1,
    verifiable: 0,
    verifiable_response: None,
    inbound_nonce: NONCE - 1,
    stored_payload_hash: None,
    ledger_seconds: EXPIRATION - 600,
    expiration: EXPIRATION,
    source_head: 0x64 + 20,
    source_heads: [0x64 + 20, 0x64 + 20, 0x64 + 20],
    source_provider_count: 1,
    source_quorum: 1,
    aptos_provider_count: 1,
    aptos_quorum: 1,
    request_receiver_override: None,
    verifiable_votes: [0, 0, 0],
    live_recorded: false,
    empty_confirmations: false,
    missing_channels: false,
    missing_channel_remote: false,
};

struct Outcome {
    status: StatusCode,
    body: Value,
    signatures: usize,
    aptos_reads: Vec<(String, Value)>,
}

fn recorded_aptos_json(exchange: &str, extension: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gasolina_parity/aptos_public_node")
        .join(format!("{exchange}.{extension}"));
    let bytes = std::fs::read(path).expect("committed public Aptos exchange fixture");
    serde_json::from_slice(&bytes).expect("recorded public Aptos JSON")
}

fn recorded_aptos_response(exchange: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gasolina_parity/aptos_public_node")
        .join(format!("{exchange}.response.body"));
    let bytes = std::fs::read(path).expect("committed public Aptos response body");
    serde_json::from_slice(&bytes).expect("recorded public Aptos response JSON")
}

fn recorded_aptos_answer(
    environment: &str,
    _url: &str,
    path: &str,
    request: &Value,
    state: AptosState,
) -> Option<Result<Value, String>> {
    if path.is_empty() {
        return Some(Ok(
            json!({ "ledger_timestamp": (state.ledger_seconds * 1_000_000).to_string() }),
        ));
    }
    let exchange = if path.starts_with("/accounts/") {
        if state.missing_channels {
            "037-mainnet-uaaccount-no-channels-404"
        } else if environment == "mainnet" {
            "003-mainnet-bridge-channels"
        } else {
            "023-testnet-bridge-channels"
        }
    } else if path.starts_with("/tables/") {
        if request["key_type"].as_str()?.contains("::channel::Remote") {
            if state.missing_channel_remote || environment == "testnet" {
                "035-testnet-bridge-channel-remote-10161-absent"
            } else {
                "012-mainnet-bridge-channel-remote-101"
            }
        } else {
            "013-mainnet-bridge-payload_hashs-74756-absent"
        }
    } else if path == "/view" {
        match request["function"].as_str()?.rsplit("::").next()? {
            "get_receive_msglib" if environment == "mainnet" => {
                "004-mainnet-bridge-get_receive_msglib-101"
            }
            "get_receive_msglib" if environment == "mainnet" => {
                "004-mainnet-bridge-get_receive_msglib-101"
            }
            "get_receive_msglib" => "024-testnet-bridge-get_receive_msglib-10161",
            "endpoint_view::get_config" | "get_config" if environment == "mainnet" => {
                "008-mainnet-bridge-get_config-u64-string-u8-number"
            }
            "endpoint_view::get_config" | "get_config" => {
                "032-testnet-bridge-get_config-10161-typed"
            }
            "get_verification_confirmations" if state.empty_confirmations => {
                return Some(Ok(json!([])));
            }
            "get_verification_confirmations" => {
                "016-mainnet-uln301-get_verification_confirmations-synthetic"
            }
            "verifiable" => "015-mainnet-uln301-verifiable-synthetic",
            "inbound_nonce" if environment == "mainnet" => "011-mainnet-bridge-inbound_nonce-101",
            "inbound_nonce" => "034-testnet-bridge-inbound_nonce-10161-unconfigured",
            _ => return None,
        }
    } else {
        return None;
    };
    let body = recorded_aptos_response(exchange);
    if matches!(
        exchange,
        "013-mainnet-bridge-payload_hashs-74756-absent"
            | "035-testnet-bridge-channel-remote-10161-absent"
    ) {
        assert_eq!(body["error_code"], "table_item_not_found");
        Some(Err(NOT_FOUND.to_string()))
    } else if exchange == "037-mainnet-uaaccount-no-channels-404" {
        assert_eq!(body["error_code"], "resource_not_found");
        Some(Err(NOT_FOUND.to_string()))
    } else {
        Some(Ok(body))
    }
}

/// End to end through `/v2/resolve-and-sign` with the production validator
/// (`runtime_rpc_validation_checks_from_evm_config` + `RuntimeAppValidator`), the real
/// EVM resolver and the production builders, for an EVM `V301` send to Aptos.
async fn sign_v301_to_aptos(environment: &str, dvn: Option<&str>, state: AptosState) -> Outcome {
    let (src, src_eid, dst_eid, receiver, sender) = match environment {
        "mainnet" => (
            "ethereum",
            101,
            108,
            "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa",
            "0x50002cdfe7ccb0c41f519c6eb0653158d11cd907",
        ),
        _ => (
            "sepolia",
            10161,
            10_108,
            "0xec84c05cc40950c86d8a8bed19552f1e8ebb783196bb021c916161d22dc179f7",
            "0x2afd0d8a477ad393d2234253407fb1cec92749d1",
        ),
    };
    let request_receiver = state.request_receiver_override.unwrap_or(receiver);
    let message = format!("0x{}", "c0ffee".repeat(11));
    let sender_bytes32 = format!("0x{}{}", "00".repeat(12), &sender[2..]);
    let packet = pillar_layerzero::encode_lz_packet_v1(&pillar_layerzero::LzPacketV1 {
        nonce: NONCE,
        src_eid,
        sender: sender_bytes32,
        dst_eid,
        receiver: receiver.to_string(),
        guid: format!("0x{}", "5a".repeat(32)),
        message: message.clone(),
    })
    .unwrap();
    let message_hash = {
        use sha3::{Digest, Keccak256};
        format!(
            "0x{}",
            hex::encode(Keccak256::digest(hex::decode(&message[2..]).unwrap()))
        )
    };
    let receipt = uln301_send_to_aptos_receipt(src, environment, &packet, SOURCE_TX_HASH);
    let names = vec![src.to_string(), "aptos".to_string()];
    let src_rpc = format!("https://{src}-rpc.example");
    let src_rpcs = (0..state.source_provider_count)
        .map(|index| format!("{src_rpc}/{index}"))
        .collect::<Vec<_>>();
    let aptos_rpcs = (0..state.aptos_provider_count)
        .map(|index| {
            if index == 0 {
                APTOS_RPC.to_string()
            } else {
                format!("https://aptos-rpc-{index}.example/v1")
            }
        })
        .collect::<Vec<_>>();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([
            (
                src.to_string(),
                ProviderConfig::with_distinct_entities(
                    src_rpcs.iter().cloned().map(ProviderUri::Uri).collect(),
                    state.source_quorum,
                ),
            ),
            (
                "aptos".to_string(),
                ProviderConfig::with_distinct_entities(
                    aptos_rpcs.iter().cloned().map(ProviderUri::Uri).collect(),
                    state.aptos_quorum,
                ),
            ),
        ]),
        Some(&names),
    )
    .unwrap();
    let live_environment = environment.to_string();
    let answer = move |url: &str, body: &Value| -> Option<Result<Value, String>> {
        if url.starts_with(&src_rpc) {
            return match body["method"].as_str()? {
                "eth_getTransactionReceipt" => Some(Ok(json!({ "result": receipt }))),
                "eth_getBlockByNumber" => {
                    let provider_index = url
                        .rsplit('/')
                        .next()
                        .and_then(|index| index.parse::<usize>().ok())
                        .unwrap_or(0);
                    let head = if state.source_provider_count == 1 {
                        state.source_head
                    } else {
                        state
                            .source_heads
                            .get(provider_index)
                            .copied()
                            .unwrap_or(state.source_head)
                    };
                    Some(Ok(json!({ "result": { "number": format!("0x{head:x}") } })))
                }
                _ => None,
            };
        }
        let path = url.split_once("/v1")?.1;
        let aptos_provider_index = url
            .split_once("aptos-rpc-")?
            .1
            .split_once(".")?
            .0
            .parse::<usize>()
            .ok()?;
        if state.live_recorded {
            return recorded_aptos_answer(&live_environment, url, path, body, state);
        }
        if path.is_empty() {
            return Some(Ok(json!({
                "ledger_timestamp": (state.ledger_seconds * 1_000_000).to_string()
            })));
        }
        if path.starts_with("/accounts/") {
            return Some(match state.stored_payload_hash {
                None => Err(NOT_FOUND.to_string()),
                Some(_) => Ok(json!({ "data": { "states": { "handle": "0xstates" } } })),
            });
        }
        if path == "/tables/0xstates/item" {
            return Some(Ok(json!({ "payload_hashs": { "handle": "0xhashes" } })));
        }
        if path == "/tables/0xhashes/item" {
            return Some(Ok(json!(state.stored_payload_hash?)));
        }
        if path != "/view" {
            return None;
        }
        let function = body["function"].as_str()?;
        let value = match function.rsplit("::").next()? {
            "get_receive_msglib" => json!([state.receive_msglib.0, state.receive_msglib.1]),
            // `serializeUlnConfig` layout, as upstream's own decoder requires in the oracle.
            "get_config" => json!([format!(
                "0x{:016x}0001{}00000000",
                state.required_confirmations,
                &DVN[2..]
            )]),
            "get_verification_confirmations" => {
                if state.empty_confirmations {
                    json!([])
                } else {
                    json!([state.dvn_confirmations.to_string()])
                }
            }
            "verifiable" if state.verifiable_response.is_some() => state
                .verifiable_response
                .and_then(|response| serde_json::from_str(response).ok())
                .unwrap_or_else(|| json!([state.verifiable])),
            "verifiable" if state.aptos_provider_count > 1 => {
                json!([state.verifiable_votes[aptos_provider_index]])
            }
            "verifiable" => json!([state.verifiable]),
            "inbound_nonce" => json!([state.inbound_nonce.to_string()]),
            _ => return None,
        };
        Some(Ok(value))
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = ScriptedTransport {
        calls: calls.clone(),
        answer: Arc::new(answer),
    };
    let snapshot = ProviderSnapshotHandle::from_getter(&getter);
    let config = runtime_evm_layerzero_config(environment, &names).unwrap();
    let resolver = EvmPacketSentResolver::new(
        &snapshot,
        transport.clone(),
        config.packet_sent_resolver_config,
    );
    let checks =
        runtime_rpc_validation_checks_from_evm_config(&snapshot, transport, environment, &names)
            .unwrap();
    let (builders, _) = super::matrix::runtime_hash_builders_for(environment, &[src, "aptos"]);
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let mut app = core_api_app();
    app.core.available_chain_names = Arc::new(names.clone());
    app.core.wallets_by_chain_name = HashMap::from([(
        "aptos".to_string(),
        vec![WalletRef {
            wallet_name: "wallet-1".to_string(),
        }],
    )]);
    app.core.hash_call_data_builders = builders;
    app.core.sent_event_resolver = Arc::new(resolver);
    app.core.validator = Arc::new(RuntimeAppValidator::new(Arc::new(checks)));
    app.core.signer_getter = Arc::new(CountingSigner(signer_calls.clone()));
    let router = pillar_api::router(app.with_public_sign_routes(true), "aptos-v301");
    let request = PillarApiRequestV2 {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: src.to_string(),
                dst_chain_name: "aptos".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(src_eid)),
                    ("dstEid".to_string(), Value::from(dst_eid)),
                    ("sender".to_string(), Value::from(sender)),
                    ("receiver".to_string(), Value::from(request_receiver)),
                ]),
            },
            nonce: NONCE,
            uln_send_version: Value::from("V301"),
        },
        signing_context: SigningContext::Message {
            expiration: state.expiration,
            skip_v_id: None,
            dvn_address: dvn.map(str::to_string),
            block_confirmation: 15,
        },
        src_tx_hash: SOURCE_TX_HASH.to_string(),
        message_hash,
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
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    let aptos_reads = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(url, _)| url.contains("aptos-rpc-"))
        .map(|(url, body)| {
            let label = body["function"].as_str().map_or_else(
                || {
                    url.split_once("/v1")
                        .map_or_else(|| url.to_string(), |(_, path)| path.to_string())
                },
                str::to_string,
            );
            (label, body.clone())
        })
        .collect();
    Outcome {
        status,
        body,
        signatures: signer_calls.load(Ordering::SeqCst),
        aptos_reads,
    }
}

fn read_labels(outcome: &Outcome) -> Vec<&str> {
    outcome
        .aptos_reads
        .iter()
        .map(|(label, _)| label.as_str())
        .collect()
}

/// The Aptos reads in upstream's request shape, without the ledger-time read the
/// oracle does not make and without argument types, which the JSON view API omits.
fn upstream_shaped_reads(outcome: &Outcome) -> Vec<Value> {
    outcome
        .aptos_reads
        .iter()
        .filter(|(label, _)| !label.is_empty())
        .map(|(label, body)| {
            if let Some(rest) = label.strip_prefix("/accounts/") {
                let (account, resource) = rest.split_once("/resource/").unwrap();
                json!({ "kind": "getAccountResource", "accountAddress": account, "resourceType": resource })
            } else if let Some(rest) = label.strip_prefix("/tables/") {
                let handle = rest.strip_suffix("/item").unwrap();
                json!({ "kind": "getTableItem", "handle": handle, "data": body })
            } else {
                json!({ "kind": "view", "function": label, "arguments": body["arguments"] })
            }
        })
        .collect()
}

/// Every scenario upstream's own `getUlnReceiveDetails` → `getDstUlnConfig` →
/// `hasPayloadSigned` chain was run over (`tests/gasolina_parity/aptos_v301_payload_signed.json`,
/// `scripts/gasolina-parity/emit-aptos-v301-payload-signed.ts`), replayed through
/// `/v2/resolve-and-sign` with the production validator: the same destination reads in
/// the same order with the same arguments, and the same verdict.
#[tokio::test]
async fn v301_to_aptos_matches_upstreams_already_signed_chain_read_for_read() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/gasolina_parity/aptos_v301_payload_signed.json"
    ))
    .unwrap();
    assert_eq!(fixture["dvn"], DVN);
    assert_eq!(fixture["nonce"], NONCE);
    let scenarios: [(&str, AptosState); 11] = [
        ("unsigned", UNSIGNED),
        (
            "confirmationsAtThreshold",
            AptosState {
                dvn_confirmations: 2,
                ..UNSIGNED
            },
        ),
        (
            "nonceAlreadyReceived",
            AptosState {
                inbound_nonce: NONCE,
                ..UNSIGNED
            },
        ),
        (
            "payloadHashStored",
            AptosState {
                stored_payload_hash: Some("0xfeed"),
                ..UNSIGNED
            },
        ),
        ("verifyingWithoutStoredHash", UNSIGNED),
        (
            "verified",
            AptosState {
                verifiable: 2,
                ..UNSIGNED
            },
        ),
        (
            "verifiable",
            AptosState {
                verifiable: 1,
                ..UNSIGNED
            },
        ),
        (
            "notInitializable",
            AptosState {
                verifiable: 3,
                ..UNSIGNED
            },
        ),
        (
            "capExceeded",
            AptosState {
                verifiable: 4,
                ..UNSIGNED
            },
        ),
        (
            "unknownState",
            AptosState {
                verifiable: 5,
                ..UNSIGNED
            },
        ),
        (
            "ulnV2ReceiveLibrary",
            AptosState {
                receive_msglib: ("1", "0"),
                ..UNSIGNED
            },
        ),
    ];
    for environment in ["mainnet", "testnet"] {
        let cases = fixture["environments"][environment].as_object().unwrap();
        assert_eq!(cases.len(), scenarios.len(), "{environment}");
        for (name, state) in scenarios {
            let upstream = &cases[name];
            let given = &upstream["state"];
            assert_eq!(
                (
                    json!([
                        state.receive_msglib.0,
                        state.receive_msglib.1.parse::<u8>().unwrap()
                    ]),
                    state.required_confirmations,
                    state.dvn_confirmations,
                    u64::from(state.verifiable),
                    state.inbound_nonce,
                    state.stored_payload_hash.map_or(Value::Null, Value::from),
                ),
                (
                    given["receiveMsglib"].clone(),
                    given["requiredConfirmations"].as_u64().unwrap(),
                    given["dvnConfirmations"].as_u64().unwrap(),
                    given["verificationState"].as_u64().unwrap(),
                    given["inboundNonce"].as_u64().unwrap(),
                    given["storedPayloadHash"].clone(),
                ),
                "{environment} {name}: scenario drifted from the oracle's"
            );
            let outcome = sign_v301_to_aptos(environment, Some(DVN), state).await;
            let expected_reads: Vec<Value> = upstream["requests"]
                .as_array()
                .unwrap()
                .iter()
                .map(|request| {
                    let mut request = request.clone();
                    let object = request.as_object_mut().unwrap();
                    if object.get("kind").and_then(Value::as_str) == Some("view") {
                        let args = object["functionArguments"].as_array().unwrap();
                        let types = object["functionArgumentTypes"].as_array().unwrap();
                        let typed = args
                            .iter()
                            .zip(types)
                            .map(|(value, ty)| {
                                let value = value.as_str().unwrap();
                                match ty.as_str().unwrap() {
                                    "u8" | "u16" | "u32" => {
                                        Value::from(value.parse::<u64>().unwrap())
                                    }
                                    "u64" | "u128" | "u256" => Value::String(value.to_string()),
                                    "bool" => Value::Bool(value.parse().unwrap()),
                                    _ => Value::String(value.to_string()),
                                }
                            })
                            .collect::<Vec<_>>();
                        object.insert("arguments".to_string(), Value::Array(typed));
                        object.remove("functionArguments");
                        object.remove("functionArgumentTypes");
                        object.remove("argumentTypes");
                    }
                    request
                })
                .collect();
            assert_eq!(
                upstream_shaped_reads(&outcome),
                expected_reads,
                "{environment} {name}"
            );
            let verdict = &upstream["verdict"];
            match verdict["signed"].as_bool() {
                Some(false) => {
                    assert_eq!(
                        outcome.status,
                        StatusCode::OK,
                        "{environment} {name}: {}",
                        outcome.body
                    );
                    assert_eq!(outcome.signatures, 1, "{environment} {name}");
                }
                Some(true) => {
                    assert_eq!(
                        outcome.status,
                        StatusCode::BAD_REQUEST,
                        "{environment} {name}"
                    );
                    assert!(outcome
                        .body
                        .to_string()
                        .contains(PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX));
                    assert_eq!(outcome.signatures, 0, "{environment} {name}");
                }
                // Upstream throws `Unsupported ULN version`; this service refuses with 400.
                None => {
                    assert_eq!(
                        verdict["error"],
                        if name == "unknownState" {
                            "Unknown delivery state: 5"
                        } else {
                            "Unsupported ULN version"
                        },
                        "{environment} {name}"
                    );
                    assert_eq!(
                        outcome.status,
                        if name == "unknownState" {
                            StatusCode::INTERNAL_SERVER_ERROR
                        } else {
                            StatusCode::BAD_REQUEST
                        },
                        "{environment} {name}"
                    );
                    assert_eq!(outcome.signatures, 0, "{environment} {name}");
                }
            }
        }
    }
}

/// Pinned `@layerzerolabs/lz-aptos-sdk-v1@3.0.168` accounts: (LayerZero, LayerZeroView,
/// LayerZeroView ULN301, ULN301).
fn v1_accounts(environment: &str) -> [&'static str; 4] {
    match environment {
        "mainnet" => [
            "0x54ad3d30af77b60d939ae356e6606de9a4da67583f02b962d2d3f2e481484e90",
            "0xe6f6eb32853cb7a43f6ead4bea489b5bb0705b40c41dc13fffd9147c91adfbbf",
            "0x49bbf8d8214fb2b158f50ecf3d75a73da133440776bff0db6005c1175138e7c0",
            "0x844bec096472b9ca651bfce5e639f8ef92dafb7b4e5a54461dd8c8f5c5231812",
        ],
        _ => [
            "0x1759cc0d3161f1eb79f65847d4feb9d1f74fb79014698a23b16b28b9cd4c37e3",
            "0x2eed41cf51a714f968d2ee4a3fa1483bc7e2ce7fb22192fd55c0df96a2aad45f",
            "0xa37316bc18fa9b5b5e976b9bc9b103565443cc72b85981d61c72324bf50ede1f",
            "0x9b4f328857baf5471ffe873471459a75da3aa3db0629f4c1b0ede4d48cf9fac1",
        ],
    }
}

/// With a `dvnAddress`, upstream's `validatePayloadSigned` asks the receiver's EndpointV1
/// receive library, its ULN301 config, this DVN's confirmations and the ULN301 view's
/// `verifiable`, each on the pinned account for the environment, then signs once.
#[tokio::test]
async fn v301_to_aptos_with_a_dvn_reads_upstreams_views_and_signs_once() {
    for environment in ["mainnet", "testnet"] {
        let [layerzero, view, view_uln301, uln_301] = v1_accounts(environment);
        let outcome = sign_v301_to_aptos(environment, Some(DVN), UNSIGNED).await;

        assert_eq!(
            outcome.status,
            StatusCode::OK,
            "{environment}: {}",
            outcome.body
        );
        assert_eq!(outcome.signatures, 1, "{environment}");
        let get_receive_msglib = format!("{view}::endpoint_view::get_receive_msglib");
        let get_config = format!("{view}::endpoint_view::get_config");
        let confirmations = format!("{uln_301}::msglib::get_verification_confirmations");
        let verifiable = format!("{view_uln301}::uln_301::verifiable");
        let inbound_nonce = format!("{view}::endpoint_view::inbound_nonce");
        let receiver = if environment == "mainnet" {
            "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa"
        } else {
            "0xec84c05cc40950c86d8a8bed19552f1e8ebb783196bb021c916161d22dc179f7"
        };
        let resource = format!("/accounts/{receiver}/resource/{layerzero}::channel::Channels");
        let mut reads = read_labels(&outcome);
        reads.sort_unstable();
        let mut expected = vec![
            "",
            get_receive_msglib.as_str(),
            get_config.as_str(),
            confirmations.as_str(),
            verifiable.as_str(),
            inbound_nonce.as_str(),
            resource.as_str(),
        ];
        expected.sort_unstable();
        assert_eq!(reads, expected, "{environment}");
        let arguments = |function: &str| {
            outcome
                .aptos_reads
                .iter()
                .find(|(label, _)| label == function)
                .unwrap()
                .1["arguments"]
                .clone()
        };
        let receiver = if environment == "mainnet" {
            "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa"
        } else {
            "0xec84c05cc40950c86d8a8bed19552f1e8ebb783196bb021c916161d22dc179f7"
        };
        let src_eid = if environment == "mainnet" {
            "101"
        } else {
            "10161"
        };
        assert_eq!(arguments(&get_receive_msglib), json!([receiver, src_eid]));
        assert_eq!(
            arguments(&get_config),
            json!([receiver, "2", 0, src_eid, 3])
        );
        assert_eq!(arguments(&confirmations)[2], DVN);
        let details = &outcome.body["body"]["debugInfo"]["details"];
        assert_eq!(
            details["dvnCallData"]["targetContract"],
            uln_301.trim_start_matches("0x"),
            "{environment}"
        );
        assert_eq!(
            details["dvnCallData"]["vid"],
            if environment == "mainnet" {
                "108"
            } else {
                "10108"
            }
        );
    }
}

/// Without a `dvnAddress` upstream skips `validatePayloadSigned` (`app.ts:308-309`): the
/// only destination read is the ledger timestamp for expiration.
#[tokio::test]
async fn v301_to_aptos_without_a_dvn_skips_the_payload_signed_reads() {
    for environment in ["mainnet", "testnet"] {
        let outcome = sign_v301_to_aptos(environment, None, UNSIGNED).await;
        assert_eq!(
            outcome.status,
            StatusCode::OK,
            "{environment}: {}",
            outcome.body
        );
        assert_eq!(outcome.signatures, 1, "{environment}");
        assert_eq!(read_labels(&outcome), [""], "{environment}");
    }
}

/// Each way upstream's `hasPayloadSigned` reports an existing signature refuses with
/// 400 and signs nothing: this DVN's confirmations at the threshold, a nonce the
/// receiver already took, or a payload hash stored for the nonce.
#[tokio::test]
async fn v301_to_aptos_already_signed_is_refused_without_signing() {
    let cases = [
        (
            "confirmations at threshold",
            AptosState {
                dvn_confirmations: 2,
                ..UNSIGNED
            },
            true,
            false,
        ),
        (
            "nonce already received",
            AptosState {
                inbound_nonce: NONCE,
                ..UNSIGNED
            },
            false,
            false,
        ),
        (
            "payload hash stored",
            AptosState {
                stored_payload_hash: Some("0xfeed"),
                ..UNSIGNED
            },
            true,
            true,
        ),
    ];
    for environment in ["mainnet", "testnet"] {
        let [layerzero, view, ..] = v1_accounts(environment);
        for (name, state, reads_resource, reads_tables) in cases {
            let outcome = sign_v301_to_aptos(environment, Some(DVN), state).await;
            assert_eq!(
                outcome.status,
                StatusCode::BAD_REQUEST,
                "{environment} {name}"
            );
            assert!(
                outcome
                    .body
                    .to_string()
                    .contains(PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX),
                "{environment} {name}: {}",
                outcome.body
            );
            assert_eq!(outcome.signatures, 0, "{environment} {name}");
            let reads = read_labels(&outcome);
            let inbound_nonce = format!("{view}::endpoint_view::inbound_nonce");
            assert_eq!(
                reads.contains(&inbound_nonce.as_str()),
                state.verifiable == 0,
                "{environment} {name}: {reads:?}"
            );
            let resource = format!(
                "/accounts/{}/resource/{layerzero}::channel::Channels",
                match environment {
                    "mainnet" =>
                        "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa",
                    _ => "0xec84c05cc40950c86d8a8bed19552f1e8ebb783196bb021c916161d22dc179f7",
                }
            );
            assert_eq!(
                reads.contains(&resource.as_str()),
                reads_resource,
                "{environment} {name}: {reads:?}"
            );
            if reads_tables {
                let (_, remote) = outcome
                    .aptos_reads
                    .iter()
                    .find(|(label, _)| label == "/tables/0xstates/item")
                    .unwrap();
                assert_eq!(
                    remote["key"],
                    json!({ "chain_id": if environment == "mainnet" { "101" } else { "10161" }, "addr": if environment == "mainnet" { "0x50002cdfe7ccb0c41f519c6eb0653158d11cd907" } else { "0x2afd0d8a477ad393d2234253407fb1cec92749d1" } })
                );
                assert_eq!(remote["key_type"], format!("{layerzero}::channel::Remote"));
                let (_, hash) = outcome
                    .aptos_reads
                    .iter()
                    .find(|(label, _)| label == "/tables/0xhashes/item")
                    .unwrap();
                assert_eq!(hash["key"], NONCE.to_string());
            }
        }
    }
}

/// VERIFYING with neither a received nonce nor a stored payload hash (the V1 channel
/// resource answering 404) is not signed, so the request is signed once.
/// Raw values emitted by the Move REST API stay compatible for numeric strings; malformed
/// Move u8 values lose the provider vote before any signature or subsequent reads.
/// Replays public node response bytes in the production validator path for the captured
/// mainnet 101->108 and testnet 10161->10108 V301 bridge reads.
#[tokio::test]
async fn v301_to_aptos_reaches_upstream_verdict_from_recorded_public_node_bytes() {
    for (environment, receive_id, config_id, nonce_id) in [
        (
            "mainnet",
            "004-mainnet-bridge-get_receive_msglib-101",
            "008-mainnet-bridge-get_config-u64-string-u8-number",
            "011-mainnet-bridge-inbound_nonce-101",
        ),
        (
            "testnet",
            "024-testnet-bridge-get_receive_msglib-10161",
            "032-testnet-bridge-get_config-10161-typed",
            "034-testnet-bridge-inbound_nonce-10161-unconfigured",
        ),
    ] {
        let outcome = sign_v301_to_aptos(
            environment,
            Some(DVN),
            AptosState {
                live_recorded: true,
                ..UNSIGNED
            },
        )
        .await;
        assert_eq!(
            outcome.status,
            StatusCode::OK,
            "{environment}: {}",
            outcome.body
        );
        assert_eq!(outcome.signatures, 1, "{environment}");
        let recorded_body = |exchange: &str| {
            let request = recorded_aptos_json(exchange, "request.json");
            serde_json::from_str::<Value>(request["body"].as_str().unwrap()).unwrap()
        };
        for (suffix, exchange) in [
            ("::endpoint_view::get_receive_msglib", receive_id),
            ("::endpoint_view::get_config", config_id),
            ("::endpoint_view::inbound_nonce", nonce_id),
        ] {
            let actual = outcome
                .aptos_reads
                .iter()
                .find(|(label, _)| label.ends_with(suffix))
                .unwrap_or_else(|| {
                    panic!(
                        "{environment} missing {suffix}: {:?}",
                        read_labels(&outcome)
                    )
                })
                .1
                .clone();
            let mut expected = recorded_body(exchange);
            assert_eq!(
                actual["function"], expected["function"],
                "{environment} {exchange}"
            );
            if let (Some(expected_args), Some(actual_args)) = (
                expected["arguments"].as_array_mut(),
                actual["arguments"].as_array(),
            ) {
                for (expected, actual) in expected_args.iter_mut().zip(actual_args) {
                    if expected
                        .as_str()
                        .is_some_and(|value| value.starts_with("0x") && value.len() >= 40)
                        && actual
                            .as_str()
                            .is_some_and(|value| value.starts_with("0x") && value.len() >= 40)
                    {
                        *expected = actual.clone();
                    }
                }
            }
            assert_eq!(
                actual["arguments"], expected["arguments"],
                "{environment} {exchange}"
            );
        }
        assert!(
            read_labels(&outcome)
                .iter()
                .any(|label| label.contains("/accounts/")),
            "{environment}: {:?}",
            read_labels(&outcome)
        );
        assert!(
            read_labels(&outcome)
                .iter()
                .any(|label| label.contains("/tables/")),
            "{environment}: {:?}",
            read_labels(&outcome)
        );
    }
}

#[tokio::test]
async fn v301_to_aptos_verifiable_state_decodes_exactly_and_fails_closed() {
    for environment in ["mainnet", "testnet"] {
        for (raw, status, signatures) in [
            ("[\"0\"]", StatusCode::OK, 1),
            ("[\"2\"]", StatusCode::BAD_REQUEST, 0),
        ] {
            let outcome = sign_v301_to_aptos(
                environment,
                Some(DVN),
                AptosState {
                    verifiable_response: Some(raw),
                    ..UNSIGNED
                },
            )
            .await;
            assert_eq!(
                outcome.status, status,
                "{environment} {raw}: {}",
                outcome.body
            );
            assert_eq!(outcome.signatures, signatures, "{environment} {raw}");
            assert!(read_labels(&outcome)
                .iter()
                .any(|label| label.ends_with("::verifiable")));
            assert_eq!(
                read_labels(&outcome)
                    .iter()
                    .any(|label| label.ends_with("::inbound_nonce")),
                raw == "[\"0\"]",
                "{environment} {raw}: {:?}",
                read_labels(&outcome)
            );
        }
        for raw in [
            "[-1]",
            "[true]",
            "[null]",
            "[\"not-a-number\"]",
            "[]",
            "[256]",
        ] {
            let outcome = sign_v301_to_aptos(
                environment,
                Some(DVN),
                AptosState {
                    verifiable_response: Some(raw),
                    ..UNSIGNED
                },
            )
            .await;
            assert_eq!(
                outcome.status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{environment} {raw}: {}",
                outcome.body
            );
            assert_eq!(outcome.signatures, 0, "{environment} {raw}");
            assert!(
                !read_labels(&outcome)
                    .iter()
                    .any(|label| label.ends_with("::inbound_nonce")),
                "malformed state must stop after verifiable: {environment} {raw}"
            );
        }
    }
}

/// A receiver whose EndpointV1 receive library is not ULN301 (2, 0) is refused before
/// anything is signed, as is a source that is not yet confirmed or an expiration
/// outside the window around the destination's ledger time.
#[tokio::test]
async fn v301_to_aptos_refuses_before_signing_when_a_gate_fails() {
    let cases = [
        (
            "ULN V2 receive library",
            AptosState {
                receive_msglib: ("1", "0"),
                ..UNSIGNED
            },
            "cannot validate",
        ),
        (
            "source not confirmed",
            AptosState {
                source_head: 0x64 + 3,
                ..UNSIGNED
            },
            "",
        ),
        (
            "expired",
            AptosState {
                ledger_seconds: EXPIRATION + 3_600,
                ..UNSIGNED
            },
            "",
        ),
    ];
    for environment in ["mainnet", "testnet"] {
        for (name, state, message) in cases {
            let outcome = sign_v301_to_aptos(environment, Some(DVN), state).await;
            if name == "source not confirmed" {
                assert_eq!(
                    outcome.status,
                    StatusCode::BAD_REQUEST,
                    "{environment} {name}: {}",
                    outcome.body
                );
                assert_eq!(
                    outcome.body["body"],
                    "block confirmations not met, current block confirmation: 3"
                );
            } else if name == "expired" {
                assert_eq!(
                    outcome.status,
                    StatusCode::BAD_REQUEST,
                    "{environment} {name}: {}",
                    outcome.body
                );
                assert_eq!(outcome.body["body"], format!("Expiration has already passed: expiration={EXPIRATION}, currentTimestamp={}", EXPIRATION + 3_600));
            } else {
                assert_ne!(outcome.status, StatusCode::OK, "{environment} {name}");
                assert!(
                    outcome.body.to_string().contains(message),
                    "{environment} {name}: {}",
                    outcome.body
                );
            }
            assert_eq!(outcome.signatures, 0, "{environment} {name}");
        }
    }
}

#[tokio::test]
async fn v301_to_aptos_replays_missing_channels_and_empty_confirmations() {
    let outcome = sign_v301_to_aptos(
        "mainnet",
        Some(DVN),
        AptosState {
            live_recorded: true,
            missing_channels: true,
            ..UNSIGNED
        },
    )
    .await;
    assert_eq!(outcome.status, StatusCode::OK, "{}", outcome.body);
    assert_eq!(outcome.signatures, 1);
    assert!(read_labels(&outcome)
        .iter()
        .any(|label| label.contains("/accounts/")));
    assert!(!read_labels(&outcome)
        .iter()
        .any(|label| label.contains("/tables/")));

    let outcome = sign_v301_to_aptos(
        "mainnet",
        Some(DVN),
        AptosState {
            live_recorded: true,
            empty_confirmations: true,
            ..UNSIGNED
        },
    )
    .await;
    assert_eq!(outcome.status, StatusCode::OK, "{}", outcome.body);
    assert_eq!(outcome.signatures, 1);
    assert!(read_labels(&outcome)
        .iter()
        .any(|label| label.contains("get_verification_confirmations")));
}

#[tokio::test]
async fn v301_aptos_expiration_comparisons_match_inclusive_boundary_semantics() {
    const MAX_AHEAD: i64 = 60 * 60 * 24 * 7;
    const GRACE: i64 = 30;
    let expiration = EXPIRATION;
    let cases = [
        (
            "max-ahead minus one",
            expiration - MAX_AHEAD - 1,
            StatusCode::BAD_REQUEST,
            format!(
                "expiration is too far in the future: expiration={expiration}, maxAllowed={}",
                expiration - 1
            ),
            0,
        ),
        (
            "max-ahead boundary",
            expiration - MAX_AHEAD,
            StatusCode::OK,
            String::new(),
            1,
        ),
        (
            "max-ahead plus one",
            expiration - MAX_AHEAD + 1,
            StatusCode::OK,
            String::new(),
            1,
        ),
        (
            "expiry grace minus one",
            expiration + GRACE - 1,
            StatusCode::OK,
            String::new(),
            1,
        ),
        (
            "expiry grace boundary",
            expiration + GRACE,
            StatusCode::OK,
            String::new(),
            1,
        ),
        (
            "expiry grace plus one",
            expiration + GRACE + 1,
            StatusCode::BAD_REQUEST,
            format!(
                "Expiration has already passed: expiration={expiration}, currentTimestamp={}",
                expiration + GRACE + 1
            ),
            0,
        ),
    ];
    for (label, ledger_seconds, expected_status, reason, signatures) in cases {
        let outcome = sign_v301_to_aptos(
            "mainnet",
            Some(DVN),
            AptosState {
                ledger_seconds,
                ..UNSIGNED
            },
        )
        .await;
        assert_eq!(outcome.status, expected_status, "{label}: {}", outcome.body);
        assert_eq!(outcome.signatures, signatures, "{label}");
        if signatures == 0 {
            assert_eq!(outcome.body["body"], reason, "{label}");
        }
    }
}

#[tokio::test]
async fn v301_aptos_verifiable_values_and_destination_provider_votes_fail_closed() {
    for value in [0, 1, 3, 4] {
        let outcome = sign_v301_to_aptos(
            "mainnet",
            Some(DVN),
            AptosState {
                verifiable: value,
                ..UNSIGNED
            },
        )
        .await;
        assert_eq!(
            outcome.status,
            StatusCode::OK,
            "verifiable={value}: {}",
            outcome.body
        );
        assert_eq!(outcome.signatures, 1, "verifiable={value}");
        assert!(
            outcome
                .aptos_reads
                .iter()
                .any(|(label, _)| label.ends_with("::uln_301::verifiable")),
            "verifiable={value}"
        );
    }
    let already = sign_v301_to_aptos(
        "mainnet",
        Some(DVN),
        AptosState {
            verifiable: 2,
            ..UNSIGNED
        },
    )
    .await;
    assert_eq!(already.status, StatusCode::BAD_REQUEST, "{}", already.body);
    assert_eq!(already.signatures, 0);

    for raw in ["[5]", "[-1]", "[true]", "[null]", "[\"x\"]", "[]"] {
        let state = AptosState {
            aptos_provider_count: 2,
            aptos_quorum: 2,
            verifiable_response: Some(raw),
            ..UNSIGNED
        };
        let outcome = sign_v301_to_aptos("mainnet", Some(DVN), state).await;
        assert_eq!(
            outcome.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "raw={raw}: {}",
            outcome.body
        );
        assert_eq!(outcome.signatures, 0, "raw={raw}");
    }

    let cases = [
        ("2-of-2 agree", 2, 2, [0, 0, 0], StatusCode::OK, 1),
        (
            "2-of-2 disagree",
            2,
            2,
            [0, 2, 0],
            StatusCode::INTERNAL_SERVER_ERROR,
            0,
        ),
        ("3-of-2 majority", 3, 2, [0, 0, 2], StatusCode::OK, 1),
        (
            "3 distinct votes",
            3,
            2,
            [0, 1, 2],
            StatusCode::INTERNAL_SERVER_ERROR,
            0,
        ),
    ];
    for (name, count, quorum, votes, expected_status, signatures) in cases {
        let outcome = sign_v301_to_aptos(
            "mainnet",
            Some(DVN),
            AptosState {
                aptos_provider_count: count,
                aptos_quorum: quorum,
                verifiable_votes: votes,
                ..UNSIGNED
            },
        )
        .await;
        assert_eq!(outcome.status, expected_status, "{name}: {}", outcome.body);
        assert_eq!(outcome.signatures, signatures, "{name}");
        if signatures == 0 {
            assert_eq!(
                outcome.body["body"],
                format!("No payload-signed validation for chain aptos quorum: response set is ambiguous or incomplete; {count} distinct successful responses, 0 errors"),
                "{name}"
            );
        }
    }
}
#[tokio::test]
async fn aptos_validator_normalizes_short_receiver_at_move_adapter_boundary() {
    let names = vec!["aptos".to_string()];
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(APTOS_RPC.to_string())],
                1,
            ),
        )]),
        Some(&names),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let answer = move |url: &str, request: &Value| {
        let path = url.split_once("/v1")?.1;
        recorded_aptos_answer("mainnet", url, path, request, UNSIGNED)
    };
    let transport = ScriptedTransport {
        calls: calls.clone(),
        answer: Arc::new(answer),
    };
    let snapshot = ProviderSnapshotHandle::from_getter(&getter);
    let checks =
        runtime_rpc_validation_checks_from_evm_config(&snapshot, transport, "mainnet", &names)
            .unwrap();
    for receiver in ["0xabc", "abc"] {
        calls.lock().unwrap().clear();
        let mut event = super::matrix::matrix_sent_event("aptos", 108);
        event.lz_message_id.pathway_id.src_chain_name = "ethereum".to_string();
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("srcEid".to_string(), Value::from(101));
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("dstEid".to_string(), Value::from(108));
        event.lz_message_id.pathway_id.extra.insert(
            "sender".to_string(),
            Value::from("0x50002cdfe7ccb0c41f519c6eb0653158d11cd907"),
        );
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("receiver".to_string(), Value::from(receiver));
        event.lz_message_id.nonce = NONCE;
        event.lz_message_id.uln_send_version = Value::from("V301");
        event.message = format!("0x{}", "c0ffee".repeat(11));
        checks
            .validate_payload_not_signed(&event, Some(DVN), "aptos")
            .await
            .unwrap();

        let captured = calls.lock().unwrap();
        let normalized = format!("0x{}0abc", "0".repeat(60));
        let view_arguments = |suffix: &str| {
            captured
                .iter()
                .find(|(url, body)| {
                    url.ends_with("/view") && body["function"].as_str().unwrap().ends_with(suffix)
                })
                .unwrap_or_else(|| panic!("missing {suffix} for {receiver}"))
                .1["arguments"]
                .clone()
        };
        assert_eq!(
            view_arguments("::endpoint_view::get_receive_msglib"),
            json!([normalized, "101"])
        );
        assert_eq!(
            view_arguments("::endpoint_view::get_config"),
            json!([receiver, "2", 0, "101", 3])
        );
        assert_eq!(
            view_arguments("::endpoint_view::inbound_nonce"),
            json!([
                receiver,
                "101",
                "0x50002cdfe7ccb0c41f519c6eb0653158d11cd907"
            ])
        );
        let channels = captured
            .iter()
            .find(|(url, _)| url.contains("/accounts/") && url.contains("/resource/"))
            .unwrap();
        let expected_channels = format!(
            "/accounts/{receiver}/resource/{}::channel::Channels",
            v1_accounts("mainnet")[0]
        );
        assert!(channels.0.ends_with(&expected_channels), "{}", channels.0);
    }
}
#[tokio::test]
async fn http_resolver_rejects_short_receiver_identity_before_aptos_reads() {
    let outcome = sign_v301_to_aptos(
        "mainnet",
        Some(DVN),
        AptosState {
            request_receiver_override: Some("0xabc"),
            ..UNSIGNED
        },
    )
    .await;
    assert_eq!(outcome.status, StatusCode::BAD_REQUEST, "{}", outcome.body);
    assert_eq!(outcome.signatures, 0);
    assert!(outcome.aptos_reads.is_empty(), "{:?}", outcome.aptos_reads);
}

#[tokio::test]
async fn v301_aptos_source_readiness_accepts_exact_confirmation_threshold() {
    let below = sign_v301_to_aptos(
        "mainnet",
        Some(DVN),
        AptosState {
            source_head: 0x64 + 14,
            ..UNSIGNED
        },
    )
    .await;
    assert_eq!(below.status, StatusCode::BAD_REQUEST, "{}", below.body);
    assert_eq!(
        below.body["body"],
        "block confirmations not met, current block confirmation: 14"
    );
    assert_eq!(below.signatures, 0);
    let outcome = sign_v301_to_aptos(
        "mainnet",
        Some(DVN),
        AptosState {
            source_head: 0x64 + 15,
            ..UNSIGNED
        },
    )
    .await;
    assert_eq!(outcome.status, StatusCode::OK, "{}", outcome.body);
    assert_eq!(outcome.signatures, 1);
}
