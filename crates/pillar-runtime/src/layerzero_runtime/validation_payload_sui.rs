//! Sui / IOTA-move-L1 branch of `validate_payload_not_signed_with_quorum`,
//! ported from the upstream LayerZero TypeScript `UlnSuiSdk.hasPayloadSigned`
//! (TS: `packages/sdks/lz-v2-sdk/src/uln/sui/index.ts:501-522`):
//!
//! ```text
//! hasPayloadSigned = verificationState === VERIFIED || dvnConfirmed
//! ```
//!
//! Note this is stricter than TON: only `VERIFIED` counts, not `VERIFIABLE`.
//! `dvnConfirmed` is `getConfirmation(...) >= inboundUlnConfig.confirmations`
//! (TS: `:475-499`).
//!
//! Every view is a `devInspect` of a programmable transaction. Per provider:
//! 1. `endpoint_v2::get_messaging_channel(endpoint, receiver)` -> channel id
//!    (TS: `packages/sdks/lz-v2-sdk/src/utils/suimove/index.ts:47-76`)
//! 2. `uln_302_views::verifiable(uln, verification, endpoint, channel,
//!    packetHeader, payloadHash)` -> `u8` state (TS: `:540-568`)
//! 3. `bytes32::from_bytes` x2 then
//!    `uln_302::get_confirmations(verification, dvn, r0, r1)` -> `u64`; a Move
//!    abort with `sub_status` 1 (`EConfirmationsNotFound`) means zero
//!    (TS: `:583-632`, abort parsing in
//!    `packages/common-suimove/src/utils.ts:17-38`)
//! 4. `uln_302::get_effective_receive_uln_config(uln, receiver, srcEid)` ->
//!    `UlnConfig`, for the required confirmations (TS: `:889-944`)
//!
//! Object inputs must carry each shared object's `initial_shared_version` and
//! whether the Move signature takes it mutably, so the SDK's resolver steps are
//! reproduced: `getNormalizedMoveFunction` per target, then `multiGetObjects`
//! with `showOwner: true` (TS: the published resolver's `normalizeInputs` ->
//! `resolveObjectReferences`; `Reference` means immutable, anything else
//! mutable).

use super::validation_payload::payload_signed_validation_result;
use super::*;

use pillar_layerzero::{
    decode_sui_address, decode_sui_u64, decode_sui_u8, decode_sui_uln_config,
    encode_sui_transaction_kind, sui_address_from_hex, sui_pure_address, sui_pure_bytes,
    sui_pure_u32, SuiArgument, SuiCallArg, SuiMoveCall, SuiSharedObject,
    SUI_DEV_INSPECT_MOCK_SENDER,
};

use crate::layerzero_runtime::config::SuiPayloadContracts;

/// `Uln302Modules` / `EndpointV2Modules` from
/// `packages/contracts/sui-contracts/src/accountResources.ts:34-45,96-107`.
/// The endpoint module is `endpoint_v2`, not `endpoint`.
const MODULE_ULN_302_VIEWS: &str = "uln_302_views";
const MODULE_ULN_302: &str = "uln_302";
const MODULE_ENDPOINT_V2: &str = "endpoint_v2";
const MODULE_BYTES32: &str = "bytes32";

/// `VerificationState.VERIFIED` (`packages/common-model/src/v2/lzMessage.ts:116-145`).
const SUI_VERIFICATION_STATE_VERIFIED: u8 = 2;

/// `Uln302GetConfirmationsErrorCodes.EConfirmationsNotFound`
/// (`packages/sdks/lz-v2-sdk/src/uln/sui/index.ts:62-71`).
const E_CONFIRMATIONS_NOT_FOUND: i64 = 1;

/// Method-name prefix: IOTA exposes the same JSON-RPC surface under `iota_`.
fn sui_rpc_method(chain_name: &str, suffix: &str) -> String {
    let prefix = if chain_name == "iotal1" {
        "iota"
    } else {
        "sui"
    };
    format!("{prefix}_{suffix}")
}

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_sui_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        let uln_version = uln_version_value(&sent_event.lz_message_id)
            .ok_or_else(|| AppCoreError::Internal("ulnSendVersion must be a string".to_string()))?;
        // TS: `packages/sdks/lz-v2-sdk/src/uln/sui/index.ts:509-510`.
        if uln_version != "V302" {
            return Err(AppCoreError::BadRequest(format!(
                "Unsupported {dst_chain_name} payload-signed validation for {uln_version}"
            )));
        }
        let contracts = self
            .sui_payload_contracts
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Sui LayerZero contracts configured for {dst_chain_name}"
                ))
            })?
            .clone();
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        if provider_config.uris.is_empty() {
            return Err(AppCoreError::Internal(format!(
                "No provider URI for chain {dst_chain_name}"
            )));
        }

        let receiver = sui_address_from_hex(&pathway_extra_string_value(sent_event, "receiver")?)?;
        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        let verifier = sui_address_from_hex(verifier_address)?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
        let packet_header = hex::decode(proof.packet_header.trim_start_matches("0x"))
            .map_err(|error| AppCoreError::Internal(format!("packetHeader hex: {error}")))?;
        let payload_hash = hex::decode(proof.payload_hash.trim_start_matches("0x"))
            .map_err(|error| AppCoreError::Internal(format!("payloadHash hex: {error}")))?;

        let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
        let plan = plan_dispatch(
            &self.rank_tracker,
            dst_chain_name,
            &provider_config.uris,
            quorum,
        )
        .await?;

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let chain_name = dst_chain_name.to_string();
            let contracts = contracts.clone();
            let packet_header = packet_header.clone();
            let payload_hash = payload_hash.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_sui_payload_signed(
                    &transport,
                    &url,
                    headers,
                    SuiPayloadSignedObservation {
                        chain_name: &chain_name,
                        contracts: &contracts,
                        receiver: &receiver,
                        src_eid,
                        verifier: &verifier,
                        packet_header: &packet_header,
                        payload_hash: &payload_hash,
                    },
                )
                .await;
                (index, observation)
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        payload_signed_validation_result(validity, sent_event, dst_chain_name)
    }
}

struct SuiPayloadSignedObservation<'a> {
    chain_name: &'a str,
    contracts: &'a SuiPayloadContracts,
    receiver: &'a [u8; 32],
    src_eid: u32,
    verifier: &'a [u8; 32],
    packet_header: &'a [u8],
    payload_hash: &'a [u8],
}

/// One provider's full Sui payload-signed observation, fingerprinted by every
/// value it agreed on so a provider disagreeing on state, confirmations or the
/// required threshold cannot be counted as agreeing.
///
/// `None` means this provider could not answer - an object it needed was
/// unresolvable, a `devInspect` failed, or a return value would not decode.
/// Upstream's provider rejects in each of those cases, so none of them vote:
/// providers that failed have not agreed that the payload is unsigned.
async fn observe_sui_payload_signed<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    observation: SuiPayloadSignedObservation<'_>,
) -> Option<(String, PayloadSignedValidity)>
where
    T: JsonRpcTransport,
{
    let SuiPayloadSignedObservation {
        chain_name,
        contracts,
        receiver,
        src_eid,
        verifier,
        packet_header,
        payload_hash,
    } = observation;

    let endpoint_package = sui_address_from_hex(&contracts.endpoint_v2_package).ok()?;
    let uln_package = sui_address_from_hex(&contracts.uln_302_package).ok()?;
    let views_package = sui_address_from_hex(&contracts.layerzero_views_package).ok()?;
    let utils_package = sui_address_from_hex(&contracts.utils_package).ok()?;

    // 1. messaging channel for the destination OApp.
    let endpoint_object = resolve_shared_object(
        transport,
        url,
        headers.clone(),
        chain_name,
        &contracts.endpoint_v2_object,
        endpoint_package,
        MODULE_ENDPOINT_V2,
        "get_messaging_channel",
        0,
    )
    .await?;
    let channel_bytes = dev_inspect_return(
        transport,
        url,
        headers.clone(),
        chain_name,
        &[
            SuiCallArg::Shared(endpoint_object),
            SuiCallArg::Pure(sui_pure_address(receiver)),
        ],
        &[SuiMoveCall {
            package: endpoint_package,
            module: MODULE_ENDPOINT_V2.to_string(),
            function: "get_messaging_channel".to_string(),
            arguments: vec![SuiArgument::Input(0), SuiArgument::Input(1)],
        }],
    )
    .await?
    .ok()?;
    let channel_id = decode_sui_address(&channel_bytes).ok()?;

    // 2. verification state.
    let uln_object = resolve_shared_object(
        transport,
        url,
        headers.clone(),
        chain_name,
        &contracts.uln_302_object,
        views_package,
        MODULE_ULN_302_VIEWS,
        "verifiable",
        0,
    )
    .await?;
    let verification_object = resolve_shared_object(
        transport,
        url,
        headers.clone(),
        chain_name,
        &contracts.uln_302_verification_object,
        views_package,
        MODULE_ULN_302_VIEWS,
        "verifiable",
        1,
    )
    .await?;
    let endpoint_for_views = resolve_shared_object(
        transport,
        url,
        headers.clone(),
        chain_name,
        &contracts.endpoint_v2_object,
        views_package,
        MODULE_ULN_302_VIEWS,
        "verifiable",
        2,
    )
    .await?;
    let channel_object = resolve_shared_object_id(
        transport,
        url,
        headers.clone(),
        chain_name,
        &format!("0x{}", hex::encode(channel_id)),
        views_package,
        MODULE_ULN_302_VIEWS,
        "verifiable",
        3,
    )
    .await?;

    let state_bytes = dev_inspect_return(
        transport,
        url,
        headers.clone(),
        chain_name,
        &[
            SuiCallArg::Shared(uln_object),
            SuiCallArg::Shared(verification_object.clone()),
            SuiCallArg::Shared(endpoint_for_views),
            SuiCallArg::Shared(channel_object),
            SuiCallArg::Pure(sui_pure_bytes(packet_header)),
            SuiCallArg::Pure(sui_pure_bytes(payload_hash)),
        ],
        &[SuiMoveCall {
            package: views_package,
            module: MODULE_ULN_302_VIEWS.to_string(),
            function: "verifiable".to_string(),
            arguments: (0..6).map(SuiArgument::Input).collect(),
        }],
    )
    .await?
    .ok()?;
    let state = decode_sui_u8(&state_bytes).ok()?;

    // 3. this DVN's confirmations. A Move abort with sub_status 1 is "no
    //    confirmations recorded", which upstream maps to zero.
    let confirmations_verification = resolve_shared_object(
        transport,
        url,
        headers.clone(),
        chain_name,
        &contracts.uln_302_verification_object,
        uln_package,
        MODULE_ULN_302,
        "get_confirmations",
        0,
    )
    .await?;
    let confirmations_result = dev_inspect_return(
        transport,
        url,
        headers.clone(),
        chain_name,
        &[
            SuiCallArg::Shared(confirmations_verification),
            SuiCallArg::Pure(sui_pure_address(verifier)),
            SuiCallArg::Pure(sui_pure_bytes(packet_header)),
            SuiCallArg::Pure(sui_pure_bytes(payload_hash)),
        ],
        &[
            SuiMoveCall {
                package: utils_package,
                module: MODULE_BYTES32.to_string(),
                function: "from_bytes".to_string(),
                arguments: vec![SuiArgument::Input(2)],
            },
            SuiMoveCall {
                package: utils_package,
                module: MODULE_BYTES32.to_string(),
                function: "from_bytes".to_string(),
                arguments: vec![SuiArgument::Input(3)],
            },
            SuiMoveCall {
                package: uln_package,
                module: MODULE_ULN_302.to_string(),
                function: "get_confirmations".to_string(),
                arguments: vec![
                    SuiArgument::Input(0),
                    SuiArgument::Input(1),
                    SuiArgument::Result(0),
                    SuiArgument::Result(1),
                ],
            },
        ],
    )
    .await?;
    let confirmations = match confirmations_result {
        Ok(bytes) => decode_sui_u64(&bytes).ok()?,
        Err(SuiViewFailure::MoveAbort(E_CONFIRMATIONS_NOT_FOUND)) => 0,
        Err(_) => return None,
    };

    // 4. the pathway's required confirmations.
    let config_uln_object = resolve_shared_object(
        transport,
        url,
        headers.clone(),
        chain_name,
        &contracts.uln_302_object,
        uln_package,
        MODULE_ULN_302,
        "get_effective_receive_uln_config",
        0,
    )
    .await?;
    let config_bytes = dev_inspect_return(
        transport,
        url,
        headers,
        chain_name,
        &[
            SuiCallArg::Shared(config_uln_object),
            SuiCallArg::Pure(sui_pure_address(receiver)),
            SuiCallArg::Pure(sui_pure_u32(src_eid)),
        ],
        &[SuiMoveCall {
            package: uln_package,
            module: MODULE_ULN_302.to_string(),
            function: "get_effective_receive_uln_config".to_string(),
            arguments: vec![
                SuiArgument::Input(0),
                SuiArgument::Input(1),
                SuiArgument::Input(2),
            ],
        }],
    )
    .await?
    .ok()?;
    let required = decode_sui_uln_config(&config_bytes).ok()?.confirmations;

    let dvn_confirmed = confirmations >= required;
    let validity = if state == SUI_VERIFICATION_STATE_VERIFIED || dvn_confirmed {
        PayloadSignedValidity::Signed
    } else {
        PayloadSignedValidity::NotSigned
    };
    Some((format!("{state}:{confirmations}:{required}"), validity))
}

/// Why a `devInspect` produced no value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SuiViewFailure {
    /// The Move call aborted with this `sub_status`.
    MoveAbort(i64),
    /// Anything else: a transport failure, an unparsable response, or an
    /// execution error that is not an abort.
    Unusable,
}

/// Resolve one shared object input: read `initial_shared_version` from the
/// chain and take mutability from the target's normalized Move signature.
#[allow(clippy::too_many_arguments)]
async fn resolve_shared_object<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    chain_name: &str,
    object_id: &str,
    package: [u8; 32],
    module: &str,
    function: &str,
    parameter_index: usize,
) -> Option<SuiSharedObject>
where
    T: JsonRpcTransport,
{
    resolve_shared_object_id(
        transport,
        url,
        headers,
        chain_name,
        object_id,
        package,
        module,
        function,
        parameter_index,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn resolve_shared_object_id<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    chain_name: &str,
    object_id: &str,
    package: [u8; 32],
    module: &str,
    function: &str,
    parameter_index: usize,
) -> Option<SuiSharedObject>
where
    T: JsonRpcTransport,
{
    let mutable = normalized_parameter_is_mutable(
        transport,
        url,
        headers.clone(),
        chain_name,
        package,
        module,
        function,
        parameter_index,
    )
    .await?;
    let initial_shared_version =
        shared_object_initial_version(transport, url, headers, chain_name, object_id).await?;
    Some(SuiSharedObject {
        object_id: sui_address_from_hex(object_id).ok()?,
        initial_shared_version,
        mutable,
    })
}

/// `getNormalizedMoveFunction` -> is `parameters[index]` taken mutably?
///
/// A `Reference` is immutable; `MutableReference` and a by-value parameter are
/// both mutable, matching the SDK resolver's `isUsedAsMutable`.
#[allow(clippy::too_many_arguments)]
async fn normalized_parameter_is_mutable<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    chain_name: &str,
    package: [u8; 32],
    module: &str,
    function: &str,
    parameter_index: usize,
) -> Option<bool>
where
    T: JsonRpcTransport,
{
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": sui_rpc_method(chain_name, "getNormalizedMoveFunction"),
        "params": [format!("0x{}", hex::encode(package)), module, function],
    });
    let response = transport
        .post_json(url.to_string(), headers, body)
        .await
        .ok()?;
    let parameter = response
        .get("result")?
        .get("parameters")?
        .as_array()?
        .get(parameter_index)?;
    if parameter.get("Reference").is_some() {
        return Some(false);
    }
    Some(true)
}

/// `multiGetObjects` with `showOwner: true` -> the shared object's
/// `initial_shared_version`. A non-shared object is refused: the encoder only
/// supports shared inputs.
async fn shared_object_initial_version<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    chain_name: &str,
    object_id: &str,
) -> Option<u64>
where
    T: JsonRpcTransport,
{
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": sui_rpc_method(chain_name, "multiGetObjects"),
        "params": [[object_id], { "showOwner": true }],
    });
    let response = transport
        .post_json(url.to_string(), headers, body)
        .await
        .ok()?;
    let shared = response
        .get("result")?
        .as_array()?
        .first()?
        .get("data")?
        .get("owner")?
        .get("Shared")?;
    let version = shared.get("initial_shared_version")?;
    match version {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

/// `devInspectTransactionBlock` -> the last command's first return value.
async fn dev_inspect_return<T>(
    transport: &T,
    url: &str,
    headers: HashMap<String, String>,
    chain_name: &str,
    inputs: &[SuiCallArg],
    commands: &[SuiMoveCall],
) -> Option<Result<Vec<u8>, SuiViewFailure>>
where
    T: JsonRpcTransport,
{
    use base64::Engine;

    let kind = encode_sui_transaction_kind(inputs, commands);
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": sui_rpc_method(chain_name, "devInspectTransactionBlock"),
        "params": [
            SUI_DEV_INSPECT_MOCK_SENDER,
            base64::engine::general_purpose::STANDARD.encode(&kind),
            Value::Null,
            Value::Null,
        ],
    });
    let response = transport
        .post_json(url.to_string(), headers, body)
        .await
        .ok()?;
    let result = response.get("result")?;

    // An execution error is reported in the result, not as an RPC error.
    if let Some(error) = result.get("error").and_then(Value::as_str) {
        return Some(Err(move_abort_sub_status(error)
            .map(SuiViewFailure::MoveAbort)
            .unwrap_or(SuiViewFailure::Unusable)));
    }
    // `suiMoveView` reads the last command's results.
    let encoded = result
        .get("results")?
        .as_array()?
        .last()?
        .get("returnValues")?
        .as_array()?
        .first()?
        .as_array()?
        .first()?;
    Some(Ok(decode_return_value(encoded)?))
}

/// A `devInspect` return value arrives either as an array of byte numbers or as
/// a base64 string, and upstream accepts both
/// (TS: `packages/common-suimove/src/utils.ts:95-103`, which branches on
/// `typeof value === 'string' ? fromBase64(value) : Uint8Array.from(value)`).
fn decode_return_value(value: &Value) -> Option<Vec<u8>> {
    use base64::Engine;

    match value {
        Value::Array(bytes) => bytes
            .iter()
            .map(|byte| byte.as_u64().and_then(|value| u8::try_from(value).ok()))
            .collect(),
        Value::String(encoded) => base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok(),
        _ => None,
    }
}

/// Parse `major_status: ABORTED` / `sub_status: Some(N)` out of a devInspect
/// error string, as `handleError` does
/// (TS: `packages/common-suimove/src/utils.ts:17-38`).
fn move_abort_sub_status(error: &str) -> Option<i64> {
    if !error.contains("ABORTED") {
        return None;
    }
    let start = error.find("sub_status: Some(")? + "sub_status: Some(".len();
    let rest = &error[start..];
    let end = rest.find(')')?;
    rest[..end].trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_move_abort_sub_status() {
        let error =
            "MoveAbort { location: .., major_status: ABORTED, sub_status: Some(1) } in command 2";
        assert_eq!(move_abort_sub_status(error), Some(1));
        // A non-abort execution error must not read as an abort code.
        assert_eq!(move_abort_sub_status("InsufficientGas"), None);
        assert_eq!(move_abort_sub_status("major_status: ABORTED"), None);
    }

    /// The 139-byte `UlnConfig` Sui mainnet actually returned for the
    /// Ethereum(30101) -> Sui receive config, in both wire shapes.
    const LIVE_ULN_CONFIG_HEX: &str = "0f00000000000000040c12321ebe562b8fb8a74e6d29f144ea199a8f31a4cea3a417ce72477f6dfebb52aa129049de845353484868d1be6e2df6878b0ed2213d94d3c827309aeae68592128a5edf4a0f696464de66d00986ef41b37faf705ceb3d9d9a4e5c306fbf91fa35508c624925c6f341113f8f9397e5f41750b833af87d0c945a6f5682887f00000";

    #[test]
    fn decodes_return_values_in_both_wire_shapes() {
        use base64::Engine;

        let expected = hex::decode(LIVE_ULN_CONFIG_HEX).unwrap();
        // What the live mainnet fullnode returned: an array of byte numbers.
        let numeric = Value::Array(expected.iter().map(|b| Value::from(*b)).collect());
        assert_eq!(decode_return_value(&numeric).unwrap(), expected);
        // The base64 form upstream also accepts.
        let encoded = Value::String(base64::engine::general_purpose::STANDARD.encode(&expected));
        assert_eq!(decode_return_value(&encoded).unwrap(), expected);
        // Anything else is not a return value.
        assert!(decode_return_value(&Value::Null).is_none());
        assert!(decode_return_value(&Value::from(7)).is_none());
        // A byte out of range is a malformed response, not a truncation.
        assert!(decode_return_value(&json!([256])).is_none());
    }

    #[test]
    fn rpc_methods_are_namespaced_per_chain() {
        assert_eq!(
            sui_rpc_method("sui", "devInspectTransactionBlock"),
            "sui_devInspectTransactionBlock"
        );
        assert_eq!(
            sui_rpc_method("iotal1", "devInspectTransactionBlock"),
            "iota_devInspectTransactionBlock"
        );
        assert_eq!(
            sui_rpc_method("iotal1", "multiGetObjects"),
            "iota_multiGetObjects"
        );
    }
}
