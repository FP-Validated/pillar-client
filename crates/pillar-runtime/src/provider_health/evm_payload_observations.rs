use super::*;

pub(crate) struct EvmPayloadSignedObservation<'a> {
    /// Every candidate receive library for the destination chain. Which one is
    /// read is decided by this provider, not by the caller, so a provider that
    /// misreports the receiver's configuration cannot silently redirect the
    /// check - the quorum has to agree on the library as well as the verdict.
    pub(crate) contracts: &'a EvmReceiveContracts,
    pub(crate) oapp: &'a str,
    pub(crate) remote_eid: u32,
    /// Destination endpoint id. Below `EVM_ENDPOINT_V2_ID_BASE` the receiver
    /// lives on a V1 endpoint, which answers a different function.
    pub(crate) dst_eid: u64,
    pub(crate) proof: &'a EvmUlnProof,
    pub(crate) verifier_address: Option<&'a str>,
}

/// `EndpointV2IdBase` (TS: `packages/common-model/src/utils/index.ts:60`).
pub(crate) const EVM_ENDPOINT_V2_ID_BASE: u64 = 30_000;

/// What one provider says the receiver's receive library is, before any
/// classification: each caller maps the address with its own table.
enum ReceiveLibraryAnswer {
    Valid(String),
    /// A non-default library the endpoint itself rejects. Upstream raises
    /// `NonRetryableError("Invalid ULN version for lib: ...")` here (TS 1.2.66:
    /// `endpoint/evm/endpointV2.ts:81-90`).
    Invalid(String),
}

/// Where the endpoint says `oapp` receives from `remote_eid`.
struct ReceiveLibraryQuery<'a> {
    contracts: &'a EvmReceiveContracts,
    oapp: &'a str,
    remote_eid: u32,
    dst_eid: u64,
}

async fn resolve_receive_library<T>(
    transport: &T,
    url: &str,
    headers: &HashMap<String, String>,
    query: ReceiveLibraryQuery<'_>,
) -> Result<ReceiveLibraryAnswer, AppCoreError>
where
    T: JsonRpcTransport,
{
    if query.dst_eid < EVM_ENDPOINT_V2_ID_BASE {
        // A V2 message addressed to a V1 endpoint. `getReceiveLibraryAddress`
        // takes no source eid and has no default/override split.
        let endpoint = query.contracts.endpoint_v1.as_deref().ok_or_else(|| {
            AppCoreError::Internal(
                "No V1 Endpoint contract configured for the destination chain".to_string(),
            )
        })?;
        let result = eth_call(
            transport.clone(),
            url.to_string(),
            headers.clone(),
            endpoint,
            &build_evm_v1_get_receive_library_address_call_data(query.oapp)?,
        )
        .await?;
        return Ok(ReceiveLibraryAnswer::Valid(decode_evm_address_result(
            &result,
        )?));
    }
    let (address, is_default) = decode_evm_receive_library_result(
        &eth_call(
            transport.clone(),
            url.to_string(),
            headers.clone(),
            &query.contracts.endpoint_v2,
            &build_evm_get_receive_library_call_data(query.oapp, query.remote_eid)?,
        )
        .await?,
    )?;
    if !is_default {
        let valid = decode_evm_bool_result(
            &eth_call(
                transport.clone(),
                url.to_string(),
                headers.clone(),
                &query.contracts.endpoint_v2,
                &build_evm_is_valid_receive_library_call_data(
                    query.oapp,
                    query.remote_eid,
                    &address,
                )?,
            )
            .await?,
        )?;
        if !valid {
            return Ok(ReceiveLibraryAnswer::Invalid(address));
        }
    }
    Ok(ReceiveLibraryAnswer::Valid(address))
}

/// The receiver's receive library as a ULN version, for routing a V2 send
/// (TS 1.2.66: `endpoint/evm/endpointV1.ts:78-111`, `endpointV2.ts:73-104`).
/// Only a V1 endpoint knows the legacy UltraLightNodeV2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiveUlnVersion {
    Known(&'static str),
    /// No row of upstream's table matches; upstream throws
    /// `NonRetryableError("Unsupported ULN version: ...")`.
    Unsupported(String),
    Invalid(String),
}

pub(crate) async fn observe_receive_uln_version<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    contracts: &EvmReceiveContracts,
    oapp: &str,
    remote_eid: u32,
    dst_eid: u64,
) -> Result<(String, ReceiveUlnVersion), AppCoreError>
where
    T: JsonRpcTransport,
{
    let query = ReceiveLibraryQuery {
        contracts,
        oapp,
        remote_eid,
        dst_eid,
    };
    let (address, version) =
        match resolve_receive_library(&transport, &url, &headers, query).await? {
            ReceiveLibraryAnswer::Invalid(address) => {
                (address.clone(), ReceiveUlnVersion::Invalid(address))
            }
            ReceiveLibraryAnswer::Valid(address) => {
                let legacy = dst_eid < EVM_ENDPOINT_V2_ID_BASE
                    && !contracts.uln_v2.is_empty()
                    && strip_hex_prefix(&contracts.uln_v2)
                        .eq_ignore_ascii_case(strip_hex_prefix(&address));
                let version = if legacy {
                    ReceiveUlnVersion::Known(ULN_VERSION_V2)
                } else {
                    match evm_uln_version_for_receive_routing(contracts, &address) {
                        Some(version) => ReceiveUlnVersion::Known(version),
                        None => ReceiveUlnVersion::Unsupported(address.clone()),
                    }
                };
                (address, version)
            }
        };
    // The quorum agrees on the library address, not only on its version.
    let address = address.to_lowercase();
    let key = match &version {
        ReceiveUlnVersion::Known(version) => format!("{address}:{version}"),
        ReceiveUlnVersion::Unsupported(_) => format!("unsupported:{address}"),
        ReceiveUlnVersion::Invalid(_) => format!("invalid:{address}"),
    };
    Ok((key, version))
}

pub(crate) async fn observe_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    observation: EvmPayloadSignedObservation<'_>,
) -> Result<(String, PayloadSignedValidity), RpcError>
where
    T: JsonRpcTransport,
{
    let query = ReceiveLibraryQuery {
        contracts: observation.contracts,
        oapp: observation.oapp,
        remote_eid: observation.remote_eid,
        dst_eid: observation.dst_eid,
    };
    let resolved = resolve_receive_library(&transport, &url, &headers, query)
        .await
        .map_err(RpcError::from)?;
    let receive_library = match resolved {
        ReceiveLibraryAnswer::Valid(address) => address,
        ReceiveLibraryAnswer::Invalid(address) => {
            return Ok((
                format!("unsupported:{}", address.to_lowercase()),
                PayloadSignedValidity::UnsupportedReceiveLibrary,
            ));
        }
    };
    let Some(receive_version) =
        evm_uln_version_from_receive_library(observation.contracts, &receive_library)
    else {
        // Agreed on by every honest provider, so the quorum settles and the
        // request is refused rather than falling through to a guess.
        return Ok((
            format!("unsupported:{}", receive_library.to_lowercase()),
            PayloadSignedValidity::UnsupportedReceiveLibrary,
        ));
    };

    let read = async {
        let (receive_contract, view_contract) =
            evm_receive_contract_pair(observation.contracts, receive_version)?;
        let verifiable_call_data = build_evm_verifiable_call_data(observation.proof)?;
        let inbound_confirmations = if receive_version == "ReadV1002" {
            0
        } else {
            let config_call_data =
                build_evm_get_uln_config_call_data(observation.oapp, observation.remote_eid)?;
            let config_result = eth_call(
                transport.clone(),
                url.clone(),
                headers.clone(),
                receive_contract,
                &config_call_data,
            )
            .await?;
            decode_evm_uln_config_confirmations(&config_result)?
        };
        let dvn_confirmed = if let Some(verifier_address) = observation.verifier_address {
            let hash_lookup_call_data =
                build_evm_hash_lookup_call_data(observation.proof, verifier_address)?;
            let hash_lookup_result = eth_call(
                transport.clone(),
                url.clone(),
                headers.clone(),
                receive_contract,
                &hash_lookup_call_data,
            )
            .await?;
            let hash_lookup = decode_evm_hash_lookup_result(receive_version, &hash_lookup_result)?;
            evm_hash_lookup_is_confirmed(inbound_confirmations, &hash_lookup)
        } else {
            // Library resolution above is mandatory without a DVN address; only
            // this duplicate-signature lookup needs the caller-supplied address.
            false
        };
        let verifiable_result = eth_call(
            transport,
            url,
            headers,
            view_contract,
            &verifiable_call_data,
        )
        .await?;
        let verification_state =
            decode_evm_verification_state(receive_version, &verifiable_result)?;
        Ok::<(bool, u64, EvmVerificationState), AppCoreError>((
            dvn_confirmed,
            inbound_confirmations,
            verification_state,
        ))
    }
    .await;

    match read {
        // The library is part of the fingerprint, not just the verdict, so two
        // providers that read different libraries fail the quorum as ambiguous
        // even when their verdicts happen to coincide.
        Ok((dvn_confirmed, inbound_confirmations, verification_state)) => {
            let validity = if dvn_confirmed || verification_state == EvmVerificationState::Verified
            {
                PayloadSignedValidity::Signed
            } else {
                PayloadSignedValidity::NotSigned
            };
            Ok((
            format!(
                "{}:{receive_version}:{dvn_confirmed}:{inbound_confirmations}:{verification_state:?}",
                receive_library.to_lowercase()
            ),
            validity,
        ))
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn eth_call<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    to: &str,
    data: &str,
) -> Result<String, AppCoreError>
where
    T: JsonRpcTransport,
{
    eth_call_at_block(transport, url, headers, to, data, json!("latest")).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadCallObservation {
    Data { value: String },
    NoCode,
    ExecutionRevert { data: Option<String> },
}

/// A provider's domain observation must remain a vote until entity quorum resolves it.
pub(crate) async fn eth_call_read_observation_at_block<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    to: &str,
    data: &str,
    block: Value,
) -> Result<(String, ReadCallObservation), AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json_scoped(
            url.clone(),
            headers.clone(),
            json!({
                "method": "eth_call",
                "params": [{"to": to, "data": data}, block],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::from)?;

    if let Some(error) = response.get("error").and_then(Value::as_object) {
        let code = error.get("code").and_then(Value::as_i64);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if code == Some(3)
            || (code == Some(-32000) && message.eq_ignore_ascii_case("execution reverted"))
        {
            let data = match error.get("data") {
                None => None,
                Some(value) => {
                    let value = value.as_str().ok_or_else(|| {
                        AppCoreError::Internal("eth_call revert DATA must be a string".into())
                    })?;
                    validate_evm_data(value, "eth_call revert")?;
                    Some(value.to_ascii_lowercase())
                }
            };
            // Absent and empty DATA both report no returned revert bytes, so they share a fingerprint.
            let fingerprint = format!("execution-revert:{}", data.as_deref().unwrap_or("0x"));
            return Ok((fingerprint, ReadCallObservation::ExecutionRevert { data }));
        }
        return Err(AppCoreError::Internal(
            "JSON-RPC eth_call returned an error".into(),
        ));
    }

    let value = response
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| AppCoreError::Internal("Missing eth_call result".into()))?;
    validate_evm_data(value, "eth_call")?;
    if value == "0x" {
        let code = eth_get_code_at_block(transport, url, headers, to, block).await?;
        if code == "0x" {
            return Ok(("no-code".into(), ReadCallObservation::NoCode));
        }
    }
    let canonical = value.to_ascii_lowercase();
    Ok((
        format!("data:{canonical}"),
        ReadCallObservation::Data { value: canonical },
    ))
}

/// `block` is a JSON-RPC block parameter: a tag string, or an EIP-1898 object
/// such as `{"blockHash": ..., "requireCanonical": true}`.
pub(crate) async fn eth_call_at_block<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    to: &str,
    data: &str,
    block: Value,
) -> Result<String, AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json_scoped(
            url,
            headers,
            json!({
                "method": "eth_call",
                "params": [{
                    "to": to,
                    "data": data,
                }, block],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::from)?;
    let result = response
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppCoreError::Internal("eth_call result must be a DATA string".to_string())
        })?;
    validate_evm_data(result, "eth_call")?;
    Ok(result.to_owned())
}

fn validate_evm_data(data: &str, method: &str) -> Result<(), AppCoreError> {
    let digits = data.strip_prefix("0x").ok_or_else(|| {
        AppCoreError::Internal(format!("{method} DATA must have a lowercase 0x prefix"))
    })?;
    if digits.len() % 2 != 0 {
        return Err(AppCoreError::Internal(format!(
            "{method} DATA must contain even-length hex octets"
        )));
    }
    if !digits.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(AppCoreError::Internal(format!(
            "{method} DATA must contain only hex octets"
        )));
    }
    Ok(())
}

/// Shares the READ call's EIP-1898 pin when validating an empty result's target code.
pub(crate) async fn eth_get_code_at_block<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    address: &str,
    block: Value,
) -> Result<String, AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json_scoped(
            url,
            headers,
            json!({
                "method": "eth_getCode",
                "params": [address, block],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::from)?;
    let result = response
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppCoreError::Internal("eth_getCode result must be a DATA string".to_string())
        })?;
    validate_evm_data(result, "eth_getCode")?;
    Ok(result.to_owned())
}

pub(crate) fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}
