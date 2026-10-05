//! A message sent on ULNv2 (`ulnSendVersion: V2`) is verified wherever its
//! destination receiver currently receives. Upstream reads that receive library
//! for every V2 send and, when it is a V3-family library, signs with the V3
//! builder over the V1 event rebuilt as V2 worker input
//! (gasolina-audit `213cd500`: `apps/gasolina/src/app/app.ts:254-273`,
//! `hashCallDataBuilder/ulnV3.ts:36-63`,
//! `packages/sdks/lz-v2-sdk/src/utils/common/hydrateV1SentEvent.ts:36-88`,
//! `packages/sdks/lz-v2-sdk/src/endpoint/evm/endpointV1.ts:78-111`).
//!
//! These verticals run the production composition from the env map: a real
//! legacy `Packet` log resolved from a bsc receipt, the real validator, the real
//! builders and a real local-mnemonic signer. The transport answers each
//! contract by address and fails anything unstubbed, so a call to the wrong
//! library is an error rather than an answer.

use super::*;
use pillar_layerzero::{
    build_evm_get_uln_config_call_data, build_evm_v1_get_receive_library_address_call_data,
};
use sha3::{Digest, Keccak256};

const NONCE: u64 = 7;
const SRC_EID_V1: u32 = 102;
const DST_EID_V1: u32 = 101;
const SENDER: &str = "0x1111111111111111111111111111111111111111";
const RECEIVER: &str = "0x2222222222222222222222222222222222222222";
const MESSAGE: &str = "0xdeadbeefcafe";
const BLOCK_CONFIRMATION: i64 = 12;
const SOURCE_BLOCK: &str = "0xabababababababababababababababababababababababababababababababab";
const REORGED_SOURCE_BLOCK: &str =
    "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const DESTINATION_BLOCK_TIMESTAMP: &str = "0x6862d3a5";
const EXPIRATION: i64 = 1_751_500_000;
const PROOF_LIBRARY: &str = "0x5555555555555555555555555555555555555555";
const UNKNOWN_LIBRARY: &str = "0x9999999999999999999999999999999999999999";

/// Which library the destination's V1 endpoint reports for the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiveLibrary {
    /// Not migrated: the legacy UltraLightNodeV2.
    UltraLightNodeV2,
    /// Migrated off ULNv2: ReceiveUln301 on the same V1 endpoint.
    ReceiveUln301,
    /// Migrated, and this payload is already Verified on ReceiveUln301.
    ReceiveUln301AlreadyVerified,
    /// A library no deployment table names.
    Unknown,
    /// Two destination providers disagree: one says ReceiveUln301, one ULNv2.
    Split,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceChain {
    Stable,
    /// The source receipt has moved to another block between the refresh that
    /// rebuilds the V2 send and readiness.
    ReorgedAfterResolution,
    /// The receipt carries no `RelayerParams`, and no log search finds the send again.
    NoAdapterParams,
}

fn contract(chain_name: &str, name: &str) -> &'static str {
    pillar_config::layerzero_contract_address(chain_name, "mainnet", name)
        .unwrap_or_else(|error| panic!("{chain_name} mainnet {name}: {error}"))
}

#[derive(Clone)]
struct RouteTransport {
    calls: RecordedJsonCalls,
    receive_library: ReceiveLibrary,
    source: SourceChain,
    source_receipt_reads: Arc<Mutex<usize>>,
    feather_utils_version: u64,
    /// What `eth-rpc-b` reports instead, when the destination has two providers.
    feather_utils_version_at_b: Option<u64>,
}

impl RouteTransport {
    fn receipt(&self) -> Value {
        let mut reads = self.source_receipt_reads.lock().unwrap();
        *reads += 1;
        let block_hash = match (self.source, *reads) {
            // Read 1 resolves the send and read 2 is upstream's refresh; the move lands after.
            (SourceChain::ReorgedAfterResolution, reads) if reads > 2 => REORGED_SOURCE_BLOCK,
            _ => SOURCE_BLOCK,
        };
        let mut receipt = legacy_packet_receipt(block_hash);
        if self.source == SourceChain::NoAdapterParams {
            receipt["result"]["logs"].as_array_mut().unwrap().remove(0);
        }
        receipt
    }

    fn library_for(&self, url: &str) -> &'static str {
        match self.receive_library {
            ReceiveLibrary::UltraLightNodeV2 => contract("ethereum", "UltraLightNodeV2"),
            ReceiveLibrary::ReceiveUln301 | ReceiveLibrary::ReceiveUln301AlreadyVerified => {
                contract("ethereum", "ReceiveUln301")
            }
            ReceiveLibrary::Unknown => UNKNOWN_LIBRARY,
            ReceiveLibrary::Split if url.contains("eth-rpc-a") => {
                contract("ethereum", "ReceiveUln301")
            }
            ReceiveLibrary::Split => contract("ethereum", "UltraLightNodeV2"),
        }
    }

    fn destination_call(&self, url: &str, body: &Value) -> Result<Value, String> {
        let to = body["params"][0]["to"].as_str().unwrap_or_default();
        let data = body["params"][0]["data"].as_str().unwrap_or_default();
        let is = |chain: &str, name: &str| to.eq_ignore_ascii_case(contract(chain, name));
        let result = if is("ethereum", "Endpoint")
            && data == build_evm_v1_get_receive_library_address_call_data(RECEIVER).unwrap()
        {
            abi_word_address(self.library_for(url))
        } else if is("ethereum", "ReceiveUln301")
            && data == build_evm_get_uln_config_call_data(RECEIVER, SRC_EID_V1).unwrap()
        {
            abi_word(1)
        } else if is("ethereum", "ReceiveUln301View") {
            // `verifiable`: 0 is Verifying (not yet signed), 2 is Verified.
            abi_word(
                if self.receive_library == ReceiveLibrary::ReceiveUln301AlreadyVerified {
                    2
                } else {
                    0
                },
            )
        } else if is("ethereum", "UltraLightNodeV2")
            && data
                == build_evm_uln_v2_get_app_config_call_data(u64::from(SRC_EID_V1), RECEIVER)
                    .unwrap()
        {
            abi_uln_v2_app_config_result(
                2,
                64,
                "0x1111111111111111111111111111111111111111",
                1,
                12,
                "0x2222222222222222222222222222222222222222",
            )
        } else if is("ethereum", "UltraLightNodeV2")
            && data
                == build_evm_uln_v2_inbound_proof_library_call_data(u64::from(SRC_EID_V1), 2)
                    .unwrap()
        {
            abi_address_word(PROOF_LIBRARY)
        } else if to.eq_ignore_ascii_case(PROOF_LIBRARY)
            && data == build_evm_validation_library_get_utils_version_call_data()
        {
            // Every FPValidator deployment that ships source sets `utilsVersion = 1`.
            abi_word(
                self.feather_utils_version_at_b
                    .filter(|_| url.contains("eth-rpc-b"))
                    .unwrap_or(self.feather_utils_version),
            )
        } else if to.eq_ignore_ascii_case(PROOF_LIBRARY)
            && data == build_evm_validation_library_get_proof_type_call_data()
        {
            // Feather: the hash is derived from the packet, no block read.
            abi_word(2)
        } else {
            return Err(format!("unstubbed destination eth_call to {to}: {body}"));
        };
        Ok(json!({ "result": result }))
    }
}

#[async_trait]
impl JsonRpcTransport for RouteTransport {
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
        let source = url.contains("bsc-rpc");
        match (body["method"].as_str().unwrap_or_default(), source) {
            ("eth_chainId", true) => Ok(json!({"result": "0x38"})),
            ("net_version", true) => Ok(json!({"result": "56"})),
            ("eth_chainId", false) => Ok(json!({"result": "0x1"})),
            ("net_version", false) => Ok(json!({"result": "1"})),
            ("eth_getTransactionReceipt", true) => Ok(self.receipt()),
            ("eth_blockNumber", true) => Ok(json!({"result": "0x100"})),
            ("eth_getLogs", true) => Ok(json!({"result": []})),
            ("eth_getBlockByNumber", true) => Ok(json!({"result": {
                "number": "0x80",
                "hash": format!("0x{}", "80".repeat(32)),
                "timestamp": DESTINATION_BLOCK_TIMESTAMP,
            }})),
            ("eth_getBlockByNumber", false) => Ok(json!({"result": {
                "number": "0x64",
                "hash": format!("0x{}", "64".repeat(32)),
                "timestamp": DESTINATION_BLOCK_TIMESTAMP,
            }})),
            ("eth_call", false) => self.destination_call(&url, &body),
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
        Err("unexpected GET on the ULNv2 receive-route vertical".to_string())
    }
}

/// A bsc receipt carrying a `RelayerParams(bytes,uint16)` and then one legacy
/// `Packet(bytes)` from bsc's UltraLightNodeV2, as `UltraLightNodeV2.send` emits them:
/// nonce | srcChainId u16 | srcAddress | dstChainId u16 | dstAddress | message.
fn legacy_packet_receipt(block_hash: &str) -> Value {
    let payload = format!(
        "{NONCE:016x}{SRC_EID_V1:04x}{}{DST_EID_V1:04x}{}{}",
        &SENDER[2..],
        &RECEIVER[2..],
        &MESSAGE[2..],
    );
    let words = (payload.len() / 2).div_ceil(32);
    let data = format!(
        "0x{:064x}{:064x}{payload:0<width$}",
        0x20,
        payload.len() / 2,
        width = words * 64,
    );
    // adapterParams v1 with 200000 gas, outboundProofType 2.
    let relayer_params = format!(
        "0x{:064x}{:064x}{:064x}0001{:064x}{}",
        0x40,
        2,
        34,
        200_000,
        "0".repeat(60)
    );
    let uln = contract("bsc", "UltraLightNodeV2").to_lowercase();
    json!({"result": {
        "blockHash": block_hash,
        "blockNumber": "0x60",
        "status": "0x1",
        "logs": [{
            "address": uln,
            "logIndex": "0x0",
            "topics": [pillar_layerzero::ULN_V2_RELAYER_PARAMS_TOPIC],
            "data": relayer_params,
        }, {
            "address": uln,
            "logIndex": "0x1",
            "topics": [pillar_layerzero::LEGACY_ULN_V2_PACKET_TOPIC],
            "data": data,
        }]
    }})
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn bytes32(address: &str) -> [u8; 32] {
    let raw = hex::decode(address.trim_start_matches("0x")).unwrap();
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    out
}

/// The V3 verification of this packet on ReceiveUln301, derived from the
/// protocol rather than from Pillar's encoders: guid as `GUID.generate`
/// (lz-v2-utilities 3.0.168 `calculateGuid`), `verify(bytes,bytes32,uint64)`
/// over PacketV1 header and `keccak(guid || message)`, then
/// `solidityPack(uint32 vId, address target, uint256 expiration, bytes)`
/// (`apps/gasolina/src/app/sdks/gasolinaSdk/evm/utils.ts:3-15`).
struct ExpectedV3 {
    guid: String,
    payload_hash: String,
    hash_call_data: String,
}

fn expected_v3_on_receive_uln_301() -> ExpectedV3 {
    let mut guid_preimage = Vec::new();
    guid_preimage.extend_from_slice(&NONCE.to_be_bytes());
    guid_preimage.extend_from_slice(&SRC_EID_V1.to_be_bytes());
    guid_preimage.extend_from_slice(&bytes32(SENDER));
    guid_preimage.extend_from_slice(&DST_EID_V1.to_be_bytes());
    guid_preimage.extend_from_slice(&bytes32(RECEIVER));
    let guid = keccak(&guid_preimage);

    let mut header = vec![1u8];
    header.extend_from_slice(&guid_preimage);
    assert_eq!(header.len(), 81);

    let mut payload = guid.to_vec();
    payload.extend_from_slice(&hex::decode(&MESSAGE[2..]).unwrap());
    let payload_hash = keccak(&payload);

    let word = |value: u64| {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        out
    };
    let mut uln_call_data = hex::decode("0223536e").unwrap();
    uln_call_data.extend_from_slice(&word(0x60));
    uln_call_data.extend_from_slice(&payload_hash);
    uln_call_data.extend_from_slice(&word(BLOCK_CONFIRMATION as u64));
    uln_call_data.extend_from_slice(&word(81));
    let mut padded_header = header.clone();
    padded_header.resize(96, 0);
    uln_call_data.extend_from_slice(&padded_header);

    let mut dvn_call_data = DST_EID_V1.to_be_bytes().to_vec();
    dvn_call_data
        .extend_from_slice(&hex::decode(&contract("ethereum", "ReceiveUln301")[2..]).unwrap());
    dvn_call_data.extend_from_slice(&word(EXPIRATION as u64));
    dvn_call_data.extend_from_slice(&uln_call_data);

    ExpectedV3 {
        guid: format!("0x{}", hex::encode(guid)),
        payload_hash: format!("0x{}", hex::encode(payload_hash)),
        hash_call_data: format!("0x{}", hex::encode(keccak(&dvn_call_data))),
    }
}

fn v2_request() -> PillarApiRequestV2 {
    PillarApiRequestV2 {
        src_tx_hash: "0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
            .to_string(),
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "bsc".to_string(),
                dst_chain_name: "ethereum".to_string(),
                extra: IndexMap::from([
                    ("srcEid".to_string(), Value::from(SRC_EID_V1)),
                    ("dstEid".to_string(), Value::from(DST_EID_V1)),
                    ("sender".to_string(), Value::from(SENDER)),
                    ("receiver".to_string(), Value::from(RECEIVER)),
                ]),
            },
            nonce: NONCE,
            uln_send_version: Value::from("V2"),
        },
        signing_context: SigningContext::Message {
            expiration: EXPIRATION,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: BLOCK_CONFIRMATION,
        },
        message_hash: format!(
            "0x{}",
            hex::encode(keccak(&hex::decode(&MESSAGE[2..]).unwrap()))
        ),
    }
}

fn env_map(destination_uris: &[&str]) -> HashMap<String, String> {
    let destination_uris = destination_uris
        .iter()
        .map(|uri| format!("\"{uri}\""))
        .collect::<Vec<_>>()
        .join(",");
    HashMap::from([
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
            "test-token-0123456789abcdef0123456789".to_string(),
        ),
        (SERVER_PORT.to_string(), "3000".to_string()),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (pillar_config::LZ_DEBUG_MODE.to_string(), "true".to_string()),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            "bsc,ethereum".to_string(),
        ),
        (LZ_PROVIDER_CONFIG.to_string(), providers_json(format!(r#"{{"bsc":{{"uris":["https://bsc-rpc.example"],"quorum":1}},"ethereum":{{"uris":[{destination_uris}],"quorum":{}}}}}"#,
        destination_uris.matches(',').count() + 1))), (LZ_QUORUM_STRATEGY_CONFIG.to_string(), strategy_json(format!(r#"{{"bsc":{{"uris":["https://bsc-rpc.example"],"quorum":1}},"ethereum":{{"uris":[{destination_uris}],"quorum":{}}}}}"#,
        destination_uris.matches(',').count() + 1))),
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

async fn route_app(
    receive_library: ReceiveLibrary,
    source: SourceChain,
) -> (RuntimeServerApp<RouteTransport>, RecordedJsonCalls) {
    route_app_with_feather_utils_version(receive_library, source, 1, None).await
}

async fn route_app_with_feather_utils_version(
    receive_library: ReceiveLibrary,
    source: SourceChain,
    feather_utils_version: u64,
    feather_utils_version_at_b: Option<u64>,
) -> (RuntimeServerApp<RouteTransport>, RecordedJsonCalls) {
    let destination_uris: &[&str] =
        if receive_library == ReceiveLibrary::Split || feather_utils_version_at_b.is_some() {
            &["https://eth-rpc-a.example", "https://eth-rpc-b.example"]
        } else {
            &["https://eth-rpc-a.example"]
        };
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let transport = RouteTransport {
        calls: calls.clone(),
        receive_library,
        source,
        source_receipt_reads: Arc::new(Mutex::new(0)),
        feather_utils_version,
        feather_utils_version_at_b,
    };
    let app = RuntimeServerApp::from_env_map_with_runtime_core(
        env_map(destination_uris),
        transport,
        || 1_767_323_045_000,
    )
    .await
    .unwrap_or_else(|error| panic!("the production wiring did not assemble: {error}"));
    (app, calls)
}

fn describe_calls(calls: &RecordedJsonCalls) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .map(|(url, _, body)| format!("{url} {} {}", body["method"], body["params"]))
        .collect()
}

/// Destination `eth_call` targets after startup, in order.
fn destination_targets(calls: &RecordedJsonCalls) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(url, _, body)| url.contains("eth-rpc") && body["method"] == "eth_call")
        .map(|(_, _, body)| {
            body["params"][0]["to"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
        })
        .collect()
}

/// `tests/gasolina_parity/v2_v3_route.json` is upstream's own output for these
/// inputs (gasolina-audit `213cd500`, `GasolinaEvmSdk.buildULNV3VerifyPayload`
/// over `hydrateV1SentEventToV2`, and `FeatherProofBuilder.deriveHash` +
/// `buildULNV2VerifyPayload`), emitted by
/// `scripts/gasolina-parity/emit-v2-v3-route.ts`. Every leaf of the
/// signed hash and the debug details must match; hex compares case-insensitively
/// because upstream lowercases `targetContract` and Pillar checksums it.
fn assert_matches_upstream(arm: &str, hash_call_data: &str, details: &Value) {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/gasolina_parity/v2_v3_route.json"),
        )
        .expect("v2_v3_route.json is committed"),
    )
    .expect("v2_v3_route.json parses");
    fn leaves(prefix: String, value: &Value, out: &mut Vec<(String, String)>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    leaves(format!("{prefix}.{key}"), value, out);
                }
            }
            Value::String(text) => out.push((prefix, text.to_ascii_lowercase())),
            other => out.push((prefix, other.to_string())),
        }
    }
    let mut upstream = Vec::new();
    leaves(
        "hashCallData".to_string(),
        &fixture[arm]["hashCallData"],
        &mut upstream,
    );
    leaves(
        "details".to_string(),
        &fixture[arm]["details"],
        &mut upstream,
    );
    let mut pillar = Vec::new();
    leaves(
        "hashCallData".to_string(),
        &Value::from(hash_call_data),
        &mut pillar,
    );
    leaves("details".to_string(), details, &mut pillar);
    upstream.sort();
    pillar.sort();
    assert!(upstream.len() > 10, "{arm} fixture is empty");
    assert_eq!(pillar, upstream, "{arm} differs from upstream's output");
}

/// Migrated destination: the request signs, and what is signed is the V3
/// verification on ReceiveUln301 over the rebuilt packet, byte for byte.
#[tokio::test]
async fn v2_send_to_a_receive_uln_301_destination_signs_the_v3_verification() {
    let (app, calls) = route_app(ReceiveLibrary::ReceiveUln301, SourceChain::Stable).await;
    let expected = expected_v3_on_receive_uln_301();

    let outcome = app.sign_request_v2(v2_request()).await;

    let stages = stages_of(&app).await;
    let response = outcome.unwrap_or_else(|error| {
        panic!(
            "the migrated V2 send did not sign: {error}\nstages={stages:?}\ncalls={:#?}",
            describe_calls(&calls)
        )
    });
    assert!(!response.signatures.is_empty());
    let debug = response.debug_info.expect("debug mode is on");
    assert_matches_upstream("migratedV3", &debug.dvn_hash_call_data, &debug.details);
    assert_eq!(
        debug.details["dvnCallData"]["targetContract"]
            .as_str()
            .map(str::to_lowercase),
        Some(contract("ethereum", "ReceiveUln301").to_lowercase()),
        "a migrated receiver is verified on ReceiveUln301: {}",
        debug.details
    );
    assert_eq!(debug.details["ulnCallData"]["methodName"], "verify");
    assert_eq!(debug.dvn_hash_call_data, expected.hash_call_data);

    let targets = destination_targets(&calls);
    let uln_v2 = contract("ethereum", "UltraLightNodeV2").to_lowercase();
    assert!(
        !targets.contains(&uln_v2),
        "nothing about a migrated receiver is read from ULNv2: {targets:?}"
    );
    // The already-signed check reads ReceiveUln301 with the rebuilt payload
    // hash, not the guid-less V1 event.
    let verifiable = calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(url, _, body)| url.contains("eth-rpc") && body["method"] == "eth_call")
        .map(|(_, _, body)| body["params"][0].clone())
        .find(|params| {
            params["to"].as_str().is_some_and(|to| {
                to.eq_ignore_ascii_case(contract("ethereum", "ReceiveUln301View"))
            })
        })
        .expect("payload-signed validation read ReceiveUln301View");
    assert!(
        verifiable["data"]
            .as_str()
            .unwrap()
            .contains(&expected.payload_hash[2..]),
        "verifiable() must be asked about keccak({} || message): {verifiable}",
        expected.guid
    );
}

/// Unmigrated destination: the request still goes to the V2 builder, which
/// signs `updateHash` for the destination's UltraLightNodeV2.
#[tokio::test]
async fn v2_send_to_an_ultra_light_node_v2_destination_signs_the_v2_update_hash() {
    let (app, calls) = route_app(ReceiveLibrary::UltraLightNodeV2, SourceChain::Stable).await;

    let outcome = app.sign_request_v2(v2_request()).await;

    let stages = stages_of(&app).await;
    let response = outcome.unwrap_or_else(|error| {
        panic!(
            "the unmigrated V2 send did not sign: {error}\nstages={stages:?}\ncalls={:#?}",
            describe_calls(&calls)
        )
    });
    assert!(!response.signatures.is_empty());
    let debug = response.debug_info.expect("debug mode is on");
    assert_matches_upstream("ulnV2", &debug.dvn_hash_call_data, &debug.details);
    assert_eq!(debug.details["ulnCallData"]["methodName"], "updateHash");
    assert_eq!(
        debug.details["dvnCallData"]["targetContract"]
            .as_str()
            .map(str::to_lowercase),
        Some(contract("ethereum", "UltraLightNodeV2").to_lowercase()),
        "{}",
        debug.details
    );
    let targets = destination_targets(&calls);
    for v3_library in ["ReceiveUln301", "ReceiveUln301View"] {
        assert!(
            !targets.contains(&contract("ethereum", v3_library).to_lowercase()),
            "an unmigrated receiver is never checked on {v3_library}: {targets:?}"
        );
    }
}

/// Only `utilsVersion = 1` has a deployed FPValidator whose source fixes the proof
/// layout (`bytes32(srcUln) || packet`); upstream's packet-only meaning for 2 has no
/// on-chain counterpart, so 2 and every other value are refused before signing.
#[tokio::test]
async fn v2_send_is_refused_when_the_feather_library_reports_an_unsupported_utils_version() {
    for utils_version in [0, 2, 3, u64::from(u8::MAX)] {
        let (app, calls) = route_app_with_feather_utils_version(
            ReceiveLibrary::UltraLightNodeV2,
            SourceChain::Stable,
            utils_version,
            None,
        )
        .await;

        let error = app
            .sign_request_v2(v2_request())
            .await
            .expect_err("an unverifiable feather layout must not be signed for");

        let stages = stages_of(&app).await;
        assert!(
            matches!(&error, pillar_api::AppError::BadRequest(message)
                if message.contains(&format!("utilsVersion {utils_version};"))),
            "utilsVersion {utils_version} is the receiver's configuration: {error}; calls={:#?}",
            describe_calls(&calls)
        );
        assert!(
            stages.iter().any(|stage| stage == "build_hash_call_data")
                && stages.iter().all(|stage| stage != "sign"),
            "utilsVersion {utils_version}: refused while building, before the signer; \
             stages={stages:?}"
        );
    }
}

/// Providers that disagree on `utilsVersion` are a provider fault, not the caller's
/// configuration: the quorum fails as a 500 and nothing is built or signed.
#[tokio::test]
async fn v2_send_is_refused_as_a_server_fault_when_providers_disagree_on_utils_version() {
    let (app, calls) = route_app_with_feather_utils_version(
        ReceiveLibrary::UltraLightNodeV2,
        SourceChain::Stable,
        1,
        Some(2),
    )
    .await;

    let error = app
        .sign_request_v2(v2_request())
        .await
        .expect_err("an ambiguous proof library must not be signed for");

    let stages = stages_of(&app).await;
    assert!(
        matches!(&error, pillar_api::AppError::Internal(message)
            if message.contains("ULN V2 inbound proofType")),
        "a provider split is a server-side 500: {error}; calls={:#?}",
        describe_calls(&calls)
    );
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "stages={stages:?}"
    );
}

/// The receive library is the routing decision itself, so providers that
/// disagree about it must stop the request before anything is built.
#[tokio::test]
async fn v2_send_is_refused_when_providers_disagree_on_the_receive_library() {
    let (app, calls) = route_app(ReceiveLibrary::Split, SourceChain::Stable).await;

    let error = app
        .sign_request_v2(v2_request())
        .await
        .expect_err("an ambiguous receive library must not be signed for");

    let stages = stages_of(&app).await;
    assert!(
        stages.iter().all(|stage| stage == "get_sent_event"),
        "the receive library is decided before validation, building or signing: \
         {error}; stages={stages:?}; calls={:#?}",
        describe_calls(&calls)
    );
    assert!(
        matches!(&error, pillar_api::AppError::Internal(message)
            if message.contains("No receive library lookup for chain ethereum quorum")),
        "a provider split is a server-side 500 naming the receive-library quorum: {error}"
    );
}

/// A library outside upstream's table is its `NonRetryableError`, a 500, and
/// it is raised before the source transaction is read (TS 1.2.66:
/// `app.ts:263-271`, `endpoint/evm/endpointV1.ts:99-110`).
#[tokio::test]
async fn v2_send_is_refused_when_the_receive_library_is_unknown() {
    let (app, calls) = route_app(ReceiveLibrary::Unknown, SourceChain::Stable).await;

    let error = app
        .sign_request_v2(v2_request())
        .await
        .expect_err("an unknown receive library must not be signed for");

    let stages = stages_of(&app).await;
    assert!(
        matches!(&error, pillar_api::AppError::Internal(message)
            if message == "Unsupported ULN version: undefined"),
        "{error}"
    );
    let described = format!("{:?}", describe_calls(&calls));
    assert!(
        !described.contains("eth_getTransactionReceipt"),
        "the source must not be read before routing: {described}"
    );
    assert!(
        stages.iter().all(|stage| stage == "get_sent_event"),
        "{error}; stages={stages:?}"
    );
}

/// The rebuilt event keeps the source receipt it was resolved from, so a
/// receipt that has moved by readiness refuses the migrated request too.
#[tokio::test]
async fn v2_send_to_a_migrated_destination_is_refused_when_the_source_reorganised() {
    let (app, calls) = route_app(
        ReceiveLibrary::ReceiveUln301,
        SourceChain::ReorgedAfterResolution,
    )
    .await;

    let error = app
        .sign_request_v2(v2_request())
        .await
        .expect_err("a reorganised source must not be signed for");

    let stages = stages_of(&app).await;
    assert!(
        error.to_string().contains("source receipt binding changed"),
        "the refusal must come from the source binding: {error}; calls={:#?}",
        describe_calls(&calls)
    );
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "stages={stages:?}"
    );
}

/// The already-signed check of a migrated send runs on ReceiveUln301 over the
/// rebuilt packet, so a payload already Verified there is refused before signing.
#[tokio::test]
async fn v2_send_to_a_migrated_destination_is_refused_when_already_verified() {
    let (app, calls) = route_app(
        ReceiveLibrary::ReceiveUln301AlreadyVerified,
        SourceChain::Stable,
    )
    .await;

    let error = app
        .sign_request_v2(v2_request())
        .await
        .expect_err("a payload already Verified on ReceiveUln301 must not be signed again");

    let stages = stages_of(&app).await;
    assert!(
        matches!(&error, pillar_api::AppError::BadRequest(message)
            if message.contains("Payload already signed")),
        "{error}; calls={:#?}",
        describe_calls(&calls)
    );
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "stages={stages:?}"
    );
}

/// Upstream re-reads a V2 send before rebuilding it (`ulnV3.ts:54-61`); a receipt whose
/// adapter params cannot be found, with no log search finding the send elsewhere, is its
/// 400 "possible reorg". The window is the source's `maxEthGetLogsBlockRange` (500 on bsc)
/// around the receipt's block, a negative start resolved against the latest block as ethers does.
#[tokio::test]
async fn v2_send_to_a_migrated_destination_is_refused_when_it_cannot_be_refreshed() {
    let (app, calls) = route_app(ReceiveLibrary::ReceiveUln301, SourceChain::NoAdapterParams).await;

    let error = app
        .sign_request_v2(v2_request())
        .await
        .expect_err("an unrefreshable V2 send must not be signed for");

    let expected = format!(
        "Could not refresh V1 sent event for srcTxHash {} on pathway {{\"srcEid\":{SRC_EID_V1},\"dstEid\":{DST_EID_V1},\"sender\":\"{SENDER}\",\"receiver\":\"{RECEIVER}\",\"srcChainName\":\"bsc\",\"dstChainName\":\"ethereum\"}} (possible reorg)",
        v2_request().src_tx_hash
    );
    assert!(
        matches!(&error, pillar_api::AppError::BadRequest(message) if *message == expected),
        "{error}; calls={:#?}",
        describe_calls(&calls)
    );
    let logs_request = calls
        .lock()
        .unwrap()
        .iter()
        .find(|(_, _, body)| body["method"] == "eth_getLogs")
        .map(|(_, _, body)| body["params"][0].clone())
        .expect("the send is searched for by its logs");
    assert_eq!(
        logs_request,
        json!({
            "fromBlock": "0x66",
            "toBlock": "0x15a",
            "address": contract("bsc", "UltraLightNodeV2").to_lowercase(),
            "topics": [pillar_layerzero::ULN_V2_PACKET_TOPIC],
        })
    );
    let stages = stages_of(&app).await;
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "stages={stages:?}"
    );
}
