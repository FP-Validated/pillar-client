//! Stellar `hasPayloadSigned`, as upstream 1.2.66 asks it: the receiver's receive
//! library from EndpointV2, the effective receive ULN config and the DVN's
//! confirmations from ULN302, and `uln_verifiable` from LayerZeroViews, each a
//! Soroban `simulateTransaction` (TS: `app.ts:399-431`,
//! `endpoint/stellar/index.ts:545-571`, `uln/stellar/index.ts:110-206,494-501`).
use super::source_events_stellar::{stellar_account_address, stellar_contract_address};
use super::validation_payload::payload_signed_validation_result;
use super::*;
use base64::Engine;

const SCV_BOOL: i32 = 0;
const SCV_VOID: i32 = 1;
const SCV_U32: i32 = 3;
const SCV_U64: i32 = 5;
const SCV_BYTES: i32 = 13;
const SCV_STRING: i32 = 14;
const SCV_SYMBOL: i32 = 15;
const SCV_VEC: i32 = 16;
const SCV_MAP: i32 = 17;
const SCV_ADDRESS: i32 = 18;

/// `OAPP_CONFIG_ERROR_PATTERNS`: a views simulation failing this way means the
/// pathway is not initializable (`uln/stellar/index.ts:58,135-141,200-203`).
const OAPP_CONFIG_ERROR_PATTERNS: [&str; 3] =
    ["contract not found", "entry not found", "not deployed"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StellarAddress {
    Account([u8; 32]),
    Contract([u8; 32]),
}

impl StellarAddress {
    fn strkey(&self) -> String {
        match self {
            StellarAddress::Account(bytes) => stellar_account_address(bytes),
            StellarAddress::Contract(bytes) => stellar_contract_address(bytes),
        }
    }
}

enum ScArg<'a> {
    Address(StellarAddress),
    U32(u32),
    Bytes(&'a [u8]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScValue {
    Bool(bool),
    Void,
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
    Text(String),
    Vec(Vec<ScValue>),
    Map(Vec<(ScValue, ScValue)>),
    Address(StellarAddress),
}

impl ScValue {
    fn field(&self, name: &str) -> Option<&ScValue> {
        let ScValue::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find(|(key, _)| matches!(key, ScValue::Text(key) if key == name))
            .map(|(_, value)| value)
    }
}

/// `hexToStellarContractAddress`: a native strkey passes through, hex becomes
/// a contract address (`common-stellar/src/utils.ts:83-94`).
fn stellar_address_argument(value: &str) -> Result<StellarAddress, AppCoreError> {
    if value.starts_with('C') {
        return pillar_layerzero::stellar_contract_id_from_strkey(value)
            .map(StellarAddress::Contract);
    }
    if value.starts_with('G') {
        return Err(AppCoreError::Internal(format!(
            "Stellar account address {value} cannot name a contract here"
        )));
    }
    let digits = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(digits).map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AppCoreError::Internal(format!("Stellar address {value} is not 32 bytes")))?;
    Ok(StellarAddress::Contract(bytes))
}

fn xdr_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn xdr_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn xdr_opaque(out: &mut Vec<u8>, bytes: &[u8]) {
    xdr_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
    out.resize(out.len() + (4 - bytes.len() % 4) % 4, 0);
}

fn xdr_sc_address(out: &mut Vec<u8>, address: &StellarAddress) {
    match address {
        StellarAddress::Account(bytes) => {
            xdr_i32(out, 0);
            xdr_i32(out, 0);
            out.extend_from_slice(bytes);
        }
        StellarAddress::Contract(bytes) => {
            xdr_i32(out, 1);
            out.extend_from_slice(bytes);
        }
    }
}

/// A one-operation `InvokeHostFunction` envelope. Simulation never checks the
/// source account or fee, so both are fixed.
fn invoke_contract_envelope(contract: &[u8; 32], function: &str, args: &[ScArg<'_>]) -> String {
    let mut out = Vec::with_capacity(256);
    xdr_i32(&mut out, 2); // ENVELOPE_TYPE_TX
    xdr_i32(&mut out, 0); // KEY_TYPE_ED25519
    out.extend_from_slice(&[0; 32]);
    xdr_u32(&mut out, 100); // fee
    out.extend_from_slice(&1i64.to_be_bytes()); // seqNum
    xdr_i32(&mut out, 0); // PRECOND_NONE
    xdr_i32(&mut out, 0); // MEMO_NONE
    xdr_u32(&mut out, 1); // one operation
    xdr_u32(&mut out, 0); // no operation source account
    xdr_i32(&mut out, 24); // INVOKE_HOST_FUNCTION
    xdr_i32(&mut out, 0); // HOST_FUNCTION_TYPE_INVOKE_CONTRACT
    xdr_sc_address(&mut out, &StellarAddress::Contract(*contract));
    xdr_opaque(&mut out, function.as_bytes());
    xdr_u32(&mut out, args.len() as u32);
    for arg in args {
        match arg {
            ScArg::Address(address) => {
                xdr_i32(&mut out, SCV_ADDRESS);
                xdr_sc_address(&mut out, address);
            }
            ScArg::U32(value) => {
                xdr_i32(&mut out, SCV_U32);
                xdr_u32(&mut out, *value);
            }
            ScArg::Bytes(bytes) => {
                xdr_i32(&mut out, SCV_BYTES);
                xdr_opaque(&mut out, bytes);
            }
        }
    }
    xdr_u32(&mut out, 0); // no auth entries
    xdr_i32(&mut out, 0); // Transaction.ext
    xdr_u32(&mut out, 0); // no signatures
    base64::engine::general_purpose::STANDARD.encode(out)
}

struct XdrReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> XdrReader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let slice = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes(b.try_into().expect("4 bytes")))
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|value| value as i32)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
    }

    fn opaque(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let data = self.take(len)?;
        self.take((4 - len % 4) % 4)?;
        Some(data)
    }

    fn bytes32(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|b| b.try_into().expect("32 bytes"))
    }

    fn address(&mut self) -> Option<StellarAddress> {
        match self.i32()? {
            0 => {
                if self.i32()? != 0 {
                    return None;
                }
                Some(StellarAddress::Account(self.bytes32()?))
            }
            1 => Some(StellarAddress::Contract(self.bytes32()?)),
            _ => None,
        }
    }

    fn sc_value(&mut self, depth: usize) -> Option<ScValue> {
        if depth > 8 {
            return None;
        }
        Some(match self.i32()? {
            SCV_BOOL => ScValue::Bool(self.u32()? != 0),
            SCV_VOID => ScValue::Void,
            SCV_U32 => ScValue::U32(self.u32()?),
            SCV_U64 => ScValue::U64(self.u64()?),
            SCV_BYTES => ScValue::Bytes(self.opaque()?.to_vec()),
            SCV_STRING | SCV_SYMBOL => {
                ScValue::Text(String::from_utf8(self.opaque()?.to_vec()).ok()?)
            }
            SCV_VEC => {
                if self.u32()? == 0 {
                    return None;
                }
                let len = self.u32()? as usize;
                let mut items = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    items.push(self.sc_value(depth + 1)?);
                }
                ScValue::Vec(items)
            }
            SCV_MAP => {
                if self.u32()? == 0 {
                    return None;
                }
                let len = self.u32()? as usize;
                let mut entries = Vec::with_capacity(len.min(64));
                for _ in 0..len {
                    entries.push((self.sc_value(depth + 1)?, self.sc_value(depth + 1)?));
                }
                ScValue::Map(entries)
            }
            SCV_ADDRESS => ScValue::Address(self.address()?),
            _ => return None,
        })
    }
}

fn decode_sc_value(encoded: &str) -> Option<ScValue> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let mut reader = XdrReader {
        bytes: &bytes,
        offset: 0,
    };
    let value = reader.sc_value(0)?;
    (reader.offset == bytes.len()).then_some(value)
}

/// Either the simulated return value or the simulation's own error string.
enum Simulated {
    Value(ScValue),
    Failed(String),
}

async fn simulate<T>(
    transport: &T,
    url: &str,
    headers: &HashMap<String, String>,
    contract: &[u8; 32],
    function: &str,
    args: &[ScArg<'_>],
) -> Result<Simulated, RpcError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .clone()
        .post_json_scoped(
            url.to_string(),
            headers.clone(),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "simulateTransaction",
                "params": {"transaction": invoke_contract_envelope(contract, function, args)},
            }),
        )
        .await?;
    let result = response.get("result").ok_or(RpcError::Unavailable)?;
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        return Ok(Simulated::Failed(error.to_string()));
    }
    result
        .get("results")
        .and_then(Value::as_array)
        .and_then(|results| results.first())
        .and_then(|first| first.get("xdr"))
        .and_then(Value::as_str)
        .and_then(decode_sc_value)
        .map(Simulated::Value)
        .ok_or(RpcError::Unavailable)
}

/// What one provider's reads add up to. A refusal is agreed on like a verdict,
/// so honest providers that all see an invalid library settle on the error.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StellarPayloadOutcome {
    Validity(PayloadSignedValidity),
    Refused(String),
}

struct StellarPayloadQuery<'a> {
    contracts: &'a StellarPayloadContracts,
    receiver: StellarAddress,
    src_eid: u32,
    verifier: StellarAddress,
    packet_header: &'a [u8],
    payload_hash: &'a [u8; 32],
}

fn simulation_failed(error: &str) -> StellarPayloadOutcome {
    StellarPayloadOutcome::Refused(format!("Contract call simulation failed: {error}"))
}

async fn observe_stellar_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    query: StellarPayloadQuery<'_>,
) -> Result<StellarPayloadOutcome, RpcError>
where
    T: JsonRpcTransport,
{
    let contract = |strkey: &str| {
        pillar_layerzero::stellar_contract_id_from_strkey(strkey).map_err(|_| RpcError::Unavailable)
    };
    let endpoint = contract(&query.contracts.endpoint_v2)?;
    let uln = contract(&query.contracts.uln_302)?;
    let views = contract(&query.contracts.views)?;
    let pathway = [ScArg::Address(query.receiver), ScArg::U32(query.src_eid)];

    let resolved = match simulate(
        &transport,
        &url,
        &headers,
        &endpoint,
        "get_receive_library",
        &pathway,
    )
    .await?
    {
        Simulated::Value(value) => value,
        Simulated::Failed(error) => return Ok(simulation_failed(&error)),
    };
    let (Some(ScValue::Address(library)), Some(ScValue::Bool(is_default))) =
        (resolved.field("lib"), resolved.field("is_default"))
    else {
        return Err(RpcError::Unavailable);
    };
    if !is_default {
        let args = [
            ScArg::Address(query.receiver),
            ScArg::U32(query.src_eid),
            ScArg::Address(*library),
        ];
        match simulate(
            &transport,
            &url,
            &headers,
            &endpoint,
            "is_valid_receive_library",
            &args,
        )
        .await?
        {
            Simulated::Value(ScValue::Bool(true)) => {}
            Simulated::Value(ScValue::Bool(false)) => {
                return Ok(StellarPayloadOutcome::Refused(format!(
                    "Invalid ULN version for lib: {}",
                    library.strkey()
                )));
            }
            Simulated::Value(_) => return Err(RpcError::Unavailable),
            Simulated::Failed(error) => return Ok(simulation_failed(&error)),
        }
    }

    let config = match simulate(
        &transport,
        &url,
        &headers,
        &uln,
        "effective_receive_uln_config",
        &pathway,
    )
    .await?
    {
        Simulated::Value(value) => value,
        Simulated::Failed(error) => return Ok(simulation_failed(&error)),
    };
    let required = match config.field("confirmations") {
        Some(ScValue::U64(value)) => *value,
        _ => return Err(RpcError::Unavailable),
    };

    use sha3::{Digest, Keccak256};
    let header_hash: [u8; 32] = Keccak256::digest(query.packet_header).into();
    let confirmation_args = [
        ScArg::Address(query.verifier),
        ScArg::Bytes(&header_hash),
        ScArg::Bytes(query.payload_hash),
    ];
    let verifiable_args = [
        ScArg::Bytes(query.packet_header),
        ScArg::Bytes(query.payload_hash),
    ];
    let (confirmed, state) = tokio::join!(
        simulate(
            &transport,
            &url,
            &headers,
            &uln,
            "confirmations",
            &confirmation_args
        ),
        simulate(
            &transport,
            &url,
            &headers,
            &views,
            "uln_verifiable",
            &verifiable_args
        ),
    );
    let dvn_confirmed = match confirmed? {
        Simulated::Value(ScValue::Void) => false,
        Simulated::Value(ScValue::U64(confirmations)) => confirmations >= required,
        Simulated::Value(_) => return Err(RpcError::Unavailable),
        Simulated::Failed(error) => return Ok(simulation_failed(&error)),
    };
    let verified = match state? {
        Simulated::Value(ScValue::Vec(variant)) => match variant.first() {
            Some(ScValue::Text(name)) => match name.as_str() {
                "Verified" => true,
                "Verifying" | "Verifiable" | "NotInitializable" => false,
                other => {
                    return Ok(StellarPayloadOutcome::Refused(format!(
                        "Unknown VerificationState variant: '{other}'"
                    )))
                }
            },
            None => {
                return Ok(StellarPayloadOutcome::Refused(
                    "Expected Soroban enum as ['VariantName'], got empty array".to_string(),
                ))
            }
            _ => return Err(RpcError::Unavailable),
        },
        Simulated::Value(_) => return Err(RpcError::Unavailable),
        Simulated::Failed(error) => {
            let lowered = error.to_lowercase();
            if OAPP_CONFIG_ERROR_PATTERNS
                .iter()
                .any(|pattern| lowered.contains(pattern))
            {
                false
            } else {
                return Ok(simulation_failed(&error));
            }
        }
    };
    Ok(StellarPayloadOutcome::Validity(
        if verified || dvn_confirmed {
            PayloadSignedValidity::Signed
        } else {
            PayloadSignedValidity::NotSigned
        },
    ))
}

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_stellar_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        let contracts = self.stellar_payload_contracts.as_ref().ok_or_else(|| {
            AppCoreError::Internal("No Stellar payload-signed contracts configured".to_string())
        })?;
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        let receiver =
            stellar_address_argument(&pathway_extra_string_value(sent_event, "receiver")?)?;
        let verifier = stellar_address_argument(verifier_address)?;
        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
        let packet_header = hex::decode(proof.packet_header.trim_start_matches("0x"))
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let payload_hash: [u8; 32] = hex::decode(proof.payload_hash.trim_start_matches("0x"))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| AppCoreError::Internal("payload hash is not 32 bytes".to_string()))?;
        let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, dst_chain_name, quorum).await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let packet_header = packet_header.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = provider_response(
                    observe_stellar_payload_signed(
                        transport,
                        url,
                        headers,
                        StellarPayloadQuery {
                            contracts,
                            receiver,
                            src_eid,
                            verifier,
                            packet_header: &packet_header,
                            payload_hash: &payload_hash,
                        },
                    )
                    .await,
                );
                (
                    index,
                    observation.map(|value| value.map(|value| (format!("{value:?}"), value))),
                )
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        match resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
            .await?
        {
            StellarPayloadOutcome::Validity(validity) => {
                payload_signed_validation_result(validity, sent_event, dst_chain_name)
            }
            StellarPayloadOutcome::Refused(message) => Err(AppCoreError::Internal(message)),
        }
    }
}
