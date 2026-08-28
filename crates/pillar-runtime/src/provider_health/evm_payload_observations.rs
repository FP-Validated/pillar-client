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
    pub(crate) verifier_address: &'a str,
}

/// `EndpointV2IdBase` (TS: `packages/common-model/src/utils/index.ts:60`).
pub(crate) const EVM_ENDPOINT_V2_ID_BASE: u64 = 30_000;

/// What one provider says the receiver's receive library is.
enum ResolvedReceiveLibrary {
    Known {
        address: String,
        version: &'static str,
    },
    /// The endpoint answered, but with a library this service cannot validate
    /// against - either not a known message library, or a non-default one the
    /// endpoint itself rejects. Upstream raises `NonRetryableError` here (TS:
    /// `endpoint/evm/endpointV2.ts:97-101` and `decoders/index.ts:86-88`); the
    /// equivalent is to refuse, never to fall back to a derived library.
    Unsupported { address: String },
}

async fn resolve_receive_library<T>(
    transport: &T,
    url: &str,
    headers: &HashMap<String, String>,
    observation: &EvmPayloadSignedObservation<'_>,
) -> Result<ResolvedReceiveLibrary, AppCoreError>
where
    T: JsonRpcTransport,
{
    let address = if observation.dst_eid < EVM_ENDPOINT_V2_ID_BASE {
        // A V2 message addressed to a V1 endpoint. `getReceiveLibraryAddress`
        // takes no source eid and has no default/override split.
        let endpoint = observation
            .contracts
            .endpoint_v1
            .as_deref()
            .ok_or_else(|| {
                AppCoreError::Internal(
                    "No V1 Endpoint contract configured for the destination chain".to_string(),
                )
            })?;
        let result = eth_call(
            transport.clone(),
            url.to_string(),
            headers.clone(),
            endpoint,
            &build_evm_v1_get_receive_library_address_call_data(observation.oapp)?,
        )
        .await?;
        decode_evm_address_result(&result)?
    } else {
        let (address, is_default) = decode_evm_receive_library_result(
            &eth_call(
                transport.clone(),
                url.to_string(),
                headers.clone(),
                &observation.contracts.endpoint_v2,
                &build_evm_get_receive_library_call_data(observation.oapp, observation.remote_eid)?,
            )
            .await?,
        )?;
        if !is_default {
            let valid = decode_evm_bool_result(
                &eth_call(
                    transport.clone(),
                    url.to_string(),
                    headers.clone(),
                    &observation.contracts.endpoint_v2,
                    &build_evm_is_valid_receive_library_call_data(
                        observation.oapp,
                        observation.remote_eid,
                        &address,
                    )?,
                )
                .await?,
            )?;
            if !valid {
                return Ok(ResolvedReceiveLibrary::Unsupported { address });
            }
        }
        address
    };

    match evm_uln_version_from_receive_library(observation.contracts, &address) {
        Some(version) => Ok(ResolvedReceiveLibrary::Known { address, version }),
        None => Ok(ResolvedReceiveLibrary::Unsupported { address }),
    }
}

pub(crate) async fn observe_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    observation: EvmPayloadSignedObservation<'_>,
) -> Option<(String, PayloadSignedValidity)>
where
    T: JsonRpcTransport,
{
    // `None` means this provider could not answer, and upstream's rejected
    // promise never reaches the quorum function either. It must not be folded
    // into a value: two providers that both failed have agreed on nothing, and
    // letting them agree would allow a pair of dead endpoints to decide a
    // request that a healthy endpoint could have answered.
    let resolved = match resolve_receive_library(&transport, &url, &headers, &observation).await {
        Ok(resolved) => resolved,
        Err(_) => return None,
    };
    let (receive_library, receive_version) = match resolved {
        ResolvedReceiveLibrary::Known { address, version } => (address, version),
        ResolvedReceiveLibrary::Unsupported { address } => {
            // Agreed on by every honest provider, so the quorum settles and the
            // request is refused rather than falling through to a guess.
            return Some((
                format!("unsupported:{}", address.to_lowercase()),
                PayloadSignedValidity::UnsupportedReceiveLibrary,
            ));
        }
    };

    let read = async {
        let (receive_contract, view_contract) =
            evm_receive_contract_pair(observation.contracts, receive_version)?;
        let config_call_data =
            build_evm_get_uln_config_call_data(observation.oapp, observation.remote_eid)?;
        let hash_lookup_call_data =
            build_evm_hash_lookup_call_data(observation.proof, observation.verifier_address)?;
        let verifiable_call_data = build_evm_verifiable_call_data(observation.proof)?;

        let config_result = eth_call(
            transport.clone(),
            url.clone(),
            headers.clone(),
            receive_contract,
            &config_call_data,
        )
        .await?;
        let inbound_confirmations = decode_evm_uln_config_confirmations(&config_result)?;

        let hash_lookup_result = eth_call(
            transport.clone(),
            url.clone(),
            headers.clone(),
            receive_contract,
            &hash_lookup_call_data,
        )
        .await?;
        let hash_lookup = decode_evm_hash_lookup_result(receive_version, &hash_lookup_result)?;
        let dvn_confirmed = evm_hash_lookup_is_confirmed(inbound_confirmations, &hash_lookup);

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
            Some((
                format!(
                    "{}:{receive_version}:{dvn_confirmed}:{inbound_confirmations}:{verification_state:?}",
                    receive_library.to_lowercase()
                ),
                validity,
            ))
        }
        Err(_) => None,
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
    eth_call_at_block(transport, url, headers, to, data, "latest").await
}

pub(crate) async fn eth_call_at_block<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    to: &str,
    data: &str,
    block_tag: &str,
) -> Result<String, AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json(
            url,
            headers,
            json!({
                "method": "eth_call",
                "params": [{
                    "to": to,
                    "data": data,
                }, block_tag],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    response
        .get("result")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppCoreError::Internal("Missing eth_call result".to_string()))
}

pub(crate) fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}
