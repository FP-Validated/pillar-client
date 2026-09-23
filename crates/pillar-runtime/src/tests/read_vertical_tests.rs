//! The READ counterpart of the source-receipt binding verticals in
//! `core_app_tests.rs`: the production composition from the env map, a real
//! `ReadV1002` PacketSent resolved from a receipt, the real validator, the real
//! read payload resolver inside the real `ReadV1002` builder, and a real
//! local-mnemonic signer.
//!
//! What is under test is the seam between two stages. Readiness agrees on the
//! identity of the block a read command addresses; the builder then reads state
//! from it. A reorg between the two used to leave the read answered by whatever
//! block sat at that height afterwards, with every honest provider agreeing on
//! the new answer. The transport below models a chain whose canonical block at
//! the command's height can change between those stages.

use super::*;

/// Both read command fixtures address block 0x40 on endpoint 30102 (bsc) with
/// 12 confirmations: `evm_read_command_with_block_marker` names the block,
/// `evm_read_command_with_timestamp_marker` names timestamp 1_700_000_000,
/// which the caller resolves to 0x40.
const READ_BLOCK_TAG: &str = "0x40";
const READ_PREVIOUS_BLOCK_TAG: &str = "0x3f";
/// 0x40 is the first block at or after the marker's timestamp: 0x3f is before
/// it and 0x40 is not (`block_matches_resolved_timestamp`).
const READ_TIMESTAMP: i64 = 1_700_000_000;
const READ_BLOCK_TIMESTAMP: &str = "0x6553f105";
const READ_PREVIOUS_BLOCK_TIMESTAMP: &str = "0x6553f0fb";
const READ_TARGET: &str = "0x1111111111111111111111111111111111111111";
const READ_RESPONSE: &str = "0x1234";
const BLOCK_A: &str = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const BLOCK_B: &str = "0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
/// The expiration window is the destination's (`ethereum` here: a read packet's
/// pathway names the chain on both ends), and this timestamp opens it.
const DESTINATION_BLOCK_TIMESTAMP: &str = "0x6862d3a5";
const READ_EXPIRATION: i64 = 1_751_500_000;

/// Which kind of time marker the read command carries. The two take different
/// routes through readiness - a block-number marker is looked up directly, a
/// timestamp marker through the caller's resolution - and both must end in the
/// same pin.
#[derive(Clone, Copy, Debug)]
enum ReadMarker {
    BlockNumber,
    Timestamp,
}

impl ReadMarker {
    const ALL: [Self; 2] = [Self::BlockNumber, Self::Timestamp];

    fn command(self) -> String {
        match self {
            Self::BlockNumber => evm_read_command_with_block_marker(),
            Self::Timestamp => evm_read_command_with_timestamp_marker(),
        }
    }

    fn resolved_markers(self) -> Vec<ResolvedTimestampTimeMarker> {
        match self {
            Self::BlockNumber => Vec::new(),
            Self::Timestamp => vec![ResolvedTimestampTimeMarker {
                block_confirmation: 12,
                is_block_number: false,
                chain_name: "bsc".to_string(),
                block_number: 0x40,
                timestamp: READ_TIMESTAMP,
            }],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadChain {
    /// Canonical block 0x40 is `BLOCK_A` for the whole request.
    Stable,
    /// Canonical block 0x40 is `BLOCK_A` while readiness looks at it and has
    /// become `BLOCK_B` by the time the builder reads state.
    ReorgedBeforeRead,
}

/// Answers by JSON-RPC method and host. An unstubbed call is an error naming
/// itself, so a new RPC on this path shows up instead of being answered by a
/// catch-all.
#[derive(Clone)]
struct ReadVerticalTransport {
    calls: RecordedJsonCalls,
    receipt: Value,
    chain: ReadChain,
}

impl ReadVerticalTransport {
    /// The builder's `eth_call`s are the first to the read target, so they are
    /// what marks the boundary between the two stages.
    fn canonical_hash(&self, reading_state: bool) -> &'static str {
        match (self.chain, reading_state) {
            (ReadChain::ReorgedBeforeRead, true) => BLOCK_B,
            _ => BLOCK_A,
        }
    }

    /// The destination (`ethereum`) calls payload-signed validation makes.
    /// Each selector is pinned to the one contract that answers it, so a call
    /// sent to the wrong library fails instead of being answered.
    fn destination_call(&self, body: &Value) -> Result<Value, String> {
        let data = body["params"][0]["data"].as_str().unwrap_or_default();
        let to = body["params"][0]["to"].as_str().unwrap_or_default();
        let selector = &data[..data.len().min(10)];
        let (expected, result) = match selector {
            // EndpointV2.getReceiveLibrary(address,uint32) -> (address, bool):
            // the READ channel's receive library is ReadLib1002.
            "0x402f8468" => (
                ethereum_contract("EndpointV2"),
                format!(
                    "0x{:0>64}{:0>64}",
                    ethereum_contract("ReadLib1002")[2..].to_lowercase(),
                    "1"
                ),
            ),
            // getUlnConfig(address,uint32) on the READ library, read as one
            // word of required confirmations (`abi.rs:344-350`).
            "0x43ea4fa9" => (ethereum_contract("ReadLib1002"), format!("0x{:0>64}", "1")),
            // verifiable(bytes,bytes32) on the READ library's view: 0 is
            // `Verifying`, so the packet is still collecting verifications.
            "0x27d12cd9" => (
                ethereum_contract("ReadLib1002View"),
                format!("0x{:0>64}", "0"),
            ),
            other => return Err(format!("unstubbed destination selector {other}: {body}")),
        };
        if !to.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "eth_call {selector} went to {to}, expected {expected}"
            ));
        }
        Ok(json!({ "result": result }))
    }
}

fn ethereum_contract(name: &str) -> &'static str {
    pillar_config::layerzero_contract_address("ethereum", "mainnet", name)
        .unwrap_or_else(|error| panic!("ethereum mainnet {name}: {error}"))
}

#[async_trait]
impl JsonRpcTransport for ReadVerticalTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers, body.clone()));
        let target_chain = url.contains("bsc-rpc");
        match (body["method"].as_str().unwrap_or_default(), target_chain) {
            ("eth_getTransactionReceipt", false) => Ok(self.receipt.clone()),
            // Startup provider health: each host must report its own chain.
            ("eth_chainId", false) => Ok(json!({"result": "0x1"})),
            ("net_version", false) => Ok(json!({"result": "1"})),
            ("eth_chainId", true) => Ok(json!({"result": "0x38"})),
            ("net_version", true) => Ok(json!({"result": "56"})),
            ("eth_getBlockByNumber", true) => match body["params"][0].as_str() {
                Some("latest") => Ok(json!({"result": {
                    "number": "0x80",
                    "hash": format!("0x{}", "80".repeat(32)),
                    "timestamp": "0x6862d3a5",
                }})),
                Some(READ_BLOCK_TAG) => Ok(json!({"result": {
                    "number": READ_BLOCK_TAG,
                    "hash": self.canonical_hash(false),
                    "timestamp": READ_BLOCK_TIMESTAMP,
                }})),
                Some(READ_PREVIOUS_BLOCK_TAG) => Ok(json!({"result": {
                    "number": READ_PREVIOUS_BLOCK_TAG,
                    "hash": format!("0x{}", "3f".repeat(32)),
                    "timestamp": READ_PREVIOUS_BLOCK_TIMESTAMP,
                }})),
                other => Err(format!("unstubbed target block {other:?}: {body}")),
            },
            ("eth_getBlockByNumber", false) => Ok(json!({"result": {
                "number": "0x64",
                "hash": format!("0x{}", "64".repeat(32)),
                "timestamp": DESTINATION_BLOCK_TIMESTAMP,
            }})),
            ("eth_call", true) => {
                let to = body["params"][0]["to"].as_str().unwrap_or_default();
                if !to.eq_ignore_ascii_case(READ_TARGET) {
                    return Err(format!("unstubbed target eth_call to {to}: {body}"));
                }
                let canonical = self.canonical_hash(true);
                let block = &body["params"][1];
                match (
                    block["blockHash"].as_str(),
                    block["requireCanonical"].as_bool(),
                ) {
                    // What geth answers for an EIP-1898 call whose block has
                    // been reorganised out.
                    (Some(hash), Some(true)) if hash != canonical => Ok(json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {
                            "code": -32000,
                            "message": format!("hash {hash} is not currently canonical"),
                        },
                    })),
                    (Some(_), Some(true)) => Ok(json!({"result": READ_RESPONSE})),
                    // Without `requireCanonical` a node still serves a block it
                    // holds by hash, reorganised out or not, so the pin alone
                    // would read a sibling the chain has abandoned.
                    (Some(_), None | Some(false)) => Ok(json!({"result": READ_RESPONSE})),
                    // A number tag is served from whatever is canonical now,
                    // which is exactly the read the pin exists to prevent.
                    (None, _) if block.as_str() == Some(READ_BLOCK_TAG) => {
                        Ok(json!({"result": READ_RESPONSE}))
                    }
                    _ => Err(format!("unexpected block parameter {block}: {body}")),
                }
            }
            ("eth_call", false) => self.destination_call(&body),
            (method, _) => Err(format!("unstubbed {method} on {url}: {body}")),
        }
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url, headers, json!({"method": "GET"})));
        Err("unexpected GET on the READ vertical".to_string())
    }
}

/// An ethereum mainnet PacketSent from the trusted EndpointV2, sent through the
/// deployed ReadLib1002 on the READ channel, whose message is the read command.
fn read_vertical_receipt(marker: ReadMarker) -> Value {
    let command = marker.command();
    let encoded_payload = format!(
        "01{nonce:016x}{src_eid:08x}{sender:0>64}{dst_eid:08x}{receiver:0>64}{guid}{message}",
        nonce = 7,
        src_eid = 30_101,
        sender = "1111111111111111111111111111111111111111",
        dst_eid = u32::MAX,
        receiver = "2222222222222222222222222222222222222222",
        guid = "bb".repeat(32),
        message = command.strip_prefix("0x").unwrap(),
    );
    let data = format!(
        "0x{}",
        abi_encode_packet_sent(
            &encoded_payload,
            "1234",
            &ethereum_contract("ReadLib1002")[2..].to_lowercase()
        )
    );
    json!({"result": {
        "blockHash": format!("0x{}", "ab".repeat(32)),
        "blockNumber": "0x60",
        "status": "0x1",
        "logs": [{
            "address": ethereum_contract("EndpointV2").to_lowercase(),
            "logIndex": "0x0",
            "topics": [pillar_layerzero::ENDPOINT_V2_PACKET_SENT_TOPIC],
            "data": data,
        }]
    }})
}

/// `PacketSent(bytes encodedPayload, bytes options, address sendLibrary)`.
fn abi_encode_packet_sent(payload_hex: &str, options_hex: &str, send_library: &str) -> String {
    fn padded(hex: &str) -> String {
        let words = hex.len().div_ceil(64).max(1);
        format!("{hex:0<width$}", width = words * 64)
    }
    let payload_words = padded(payload_hex);
    let options_offset = 0x60 + 32 + payload_words.len() / 2;
    format!(
        "{:064x}{options_offset:064x}{send_library:0>64}{:064x}{payload_words}{:064x}{}",
        0x60,
        payload_hex.len() / 2,
        options_hex.len() / 2,
        padded(options_hex),
    )
}

fn read_vertical_request(marker: ReadMarker) -> PillarApiRequestV2 {
    let command = marker.command();
    let message_hash = format!(
        "0x{}",
        hex::encode(<sha3::Keccak256 as sha3::Digest>::digest(
            hex::decode(command.strip_prefix("0x").unwrap()).unwrap()
        ))
    );
    PillarApiRequestV2 {
        src_tx_hash: "0xtx".to_string(),
        lz_message_id: evm_read_packet_sent_request(),
        signing_context: SigningContext::Read {
            expiration: READ_EXPIRATION,
            skip_v_id: None,
            dvn_address: None,
            resolved_timestamp_time_markers: marker.resolved_markers(),
        },
        message_hash,
    }
}

fn read_vertical_env_map() -> HashMap<String, String> {
    HashMap::from([
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
            "test-token-0123456789abcdef0123456789".to_string(),
        ),
        (SERVER_PORT.to_string(), "3000".to_string()),
        // Deliberately silent about READ: `ReadV1002` is always built, so this
        // setting cannot switch the path under test off.
        (
            pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
            r#"["V2"]"#.to_string(),
        ),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (pillar_config::LZ_DEBUG_MODE.to_string(), "true".to_string()),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            "ethereum,bsc".to_string(),
        ),
        // Two agreeing providers on the read target, so a refusal is the pin
        // doing its job rather than the providers disagreeing.
        (
            LZ_PROVIDER_CONFIG.to_string(),
            r#"{"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1},"bsc":{"uris":["https://bsc-rpc-a.example","https://bsc-rpc-b.example"],"quorum":2}}"#
                .to_string(),
        ),
        (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
        (
            pillar_config::LZ_WALLETS.to_string(),
            config_wallet_json("wallet-a", "EVM", "secret-a"),
        ),
        (
            pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            r#"{"wallet-a-EVM":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/60'/0'/0/0"}}"#.to_string(),
        ),
    ])
}

async fn read_vertical_app(
    chain: ReadChain,
    marker: ReadMarker,
) -> (RuntimeServerApp<ReadVerticalTransport>, RecordedJsonCalls) {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let transport = ReadVerticalTransport {
        calls: calls.clone(),
        receipt: read_vertical_receipt(marker),
        chain,
    };
    let app = RuntimeServerApp::from_env_map_with_runtime_core(
        read_vertical_env_map(),
        transport,
        || 1_767_323_045_000,
    )
    .await
    .unwrap_or_else(|error| panic!("the production wiring did not assemble: {error}"));
    (app, calls)
}

/// The block parameter of every builder `eth_call` against the read target.
fn read_call_blocks(calls: &RecordedJsonCalls) -> Vec<Value> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(url, _, body)| url.contains("bsc-rpc") && body["method"] == "eth_call")
        .map(|(_, _, body)| body["params"][1].clone())
        .collect()
}

/// `host method params` per call, for failure messages that name the RPC trail.
fn describe_calls(calls: &RecordedJsonCalls) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .map(|(url, _, body)| format!("{url} {} {}", body["method"], body["params"]))
        .collect()
}

/// The positive control, which is what makes the refusal below mean
/// something: on a stable chain the READ request signs, and the state read
/// carries the exact hash readiness agreed on.
#[tokio::test]
async fn production_read_vertical_signs_state_from_the_validated_block() {
    for marker in ReadMarker::ALL {
        let (app, calls) = read_vertical_app(ReadChain::Stable, marker).await;

        let outcome = app.sign_request_v2(read_vertical_request(marker)).await;

        let stages = stages_of(&app).await;
        let response = outcome.unwrap_or_else(|error| {
            panic!(
                "the READ vertical ({marker:?}) did not complete: {error}\nstages={stages:?}\ncalls={:#?}",
                describe_calls(&calls)
            )
        });
        assert!(
            !response.signatures.is_empty(),
            "{marker:?}: no signature was produced"
        );
        assert!(
            stages.iter().any(|stage| stage == "sign"),
            "{marker:?}: the signer stage never ran; stages={stages:?}"
        );
        assert_eq!(
            read_call_blocks(&calls),
            vec![json!({"blockHash": BLOCK_A, "requireCanonical": true}); 2],
            "{marker:?}: each provider must read the validated block by hash"
        );
    }
}

/// Readiness agrees on block 0x40 = A; before the builder reads, the chain
/// reorganises so that 0x40 = B. Both providers still agree with each other,
/// so the refusal comes from the pin, and the key is never reached.
#[tokio::test]
async fn production_read_vertical_never_signs_when_the_read_block_moved_after_validation() {
    for marker in ReadMarker::ALL {
        let (app, calls) = read_vertical_app(ReadChain::ReorgedBeforeRead, marker).await;

        let error = app
            .sign_request_v2(read_vertical_request(marker))
            .await
            .expect_err("a read block reorganised after validation must not be signed");

        assert!(
            error.to_string().contains("No ReadV1002 eth_call quorum"),
            "{marker:?}: the request failed for a reason other than the pinned read: {error}"
        );
        let stages = stages_of(&app).await;
        assert!(
            stages.iter().any(|stage| stage == "build_hash_call_data"),
            "{marker:?}: the refusal must come from the read, after validation passed; \
             stages={stages:?}"
        );
        assert!(
            stages.iter().all(|stage| stage != "sign"),
            "{marker:?}: the signer stage was entered for a read from a reorganised block; \
             stages={stages:?}"
        );
        assert_eq!(
            read_call_blocks(&calls),
            vec![json!({"blockHash": BLOCK_A, "requireCanonical": true}); 2],
            "{marker:?}: both providers must have been asked for the validated block"
        );
    }
}
