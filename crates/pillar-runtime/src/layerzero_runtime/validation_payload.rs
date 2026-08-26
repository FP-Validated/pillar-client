use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        if !sent_event.extra.contains_key("guid") {
            return Ok(());
        }

        if dst_chain_name == "solana" {
            return self
                .validate_solana_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if matches!(dst_chain_name, "aptos" | "initia" | "movement") {
            return self
                .validate_move_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if dst_chain_name == "starknet" {
            return self
                .validate_starknet_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if dst_chain_name == "ton" {
            return self
                .validate_ton_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if matches!(dst_chain_name, "sui" | "iotal1") {
            return self
                .validate_sui_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if dst_chain_name == "stellar" {
            return Err(AppCoreError::Internal(format!(
                "Chain-native payload-signed validation is unavailable for {dst_chain_name}"
            )));
        }

        let snapshot = self.providers.load();
        let dispatch = snapshot
            .dispatch(&self.rank_tracker, dst_chain_name)
            .await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;

        let contracts = self
            .evm_receive_contracts_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No EVM LayerZero receive contracts for chain {dst_chain_name}"
                ))
            })?;
        let dst_eid = pathway_extra_u64(sent_event, "dstEid")?;
        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        // A V3 packet names the receiver as bytes32; the endpoint and the ULN
        // both take an `address`. Narrowed once here, so every call in the
        // observation - the endpoint reads and the existing `getUlnConfig`
        // alike - sees the same 20-byte value.
        let oapp =
            evm_address_from_pathway_value(&pathway_extra_string_value(sent_event, "receiver")?)?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let oapp = oapp.clone();
            let proof = proof.clone();
            let verifier_address = verifier_address.to_string();
            let contracts = contracts.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let (fingerprint, validity) = observe_payload_signed(
                    transport,
                    url,
                    headers,
                    EvmPayloadSignedObservation {
                        contracts: &contracts,
                        oapp: &oapp,
                        remote_eid: src_eid,
                        dst_eid,
                        proof: &proof,
                        verifier_address: &verifier_address,
                    },
                )
                .await;
                (index, Some((fingerprint, validity)))
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let agreed_validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;

        payload_signed_validation_result(agreed_validity, sent_event, dst_chain_name)
    }

    async fn validate_move_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        let uln_version = uln_version_value(&sent_event.lz_message_id)
            .ok_or_else(|| AppCoreError::Internal("ulnSendVersion must be a string".to_string()))?;
        if uln_version != "V302" {
            return Err(AppCoreError::BadRequest(format!(
                "Unsupported {dst_chain_name} payload-signed validation for {uln_version}"
            )));
        }
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        let endpoint_v2 = self
            .move_endpoint_v2_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Move EndpointV2 contract configured for {dst_chain_name}"
                ))
            })?;
        let uln_302 = self
            .move_uln_302_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Move ULN302 contract configured for {dst_chain_name}"
                ))
            })?;
        let views = self
            .move_views_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Move LayerZeroViews contract configured for {dst_chain_name}"
                ))
            })?;
        let receiver = pathway_extra_string_value(sent_event, "receiver")?;
        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
        let plan = plan_dispatch(
            &self.rank_tracker,
            dst_chain_name,
            &provider_config.uris,
            quorum,
        )
        .await?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = move_provider_uri_parts(dst_chain_name, uri);
            let transport = self.transport.clone();
            let proof = proof.clone();
            let endpoint_v2 = endpoint_v2.clone();
            let uln_302 = uln_302.clone();
            let views = views.clone();
            let receiver = receiver.clone();
            let verifier_address = verifier_address.to_string();
            let chain_name = dst_chain_name.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let (fingerprint, validity) = observe_move_payload_signed(
                    transport,
                    url,
                    headers,
                    MovePayloadSignedObservation {
                        chain_name: &chain_name,
                        endpoint_v2: &endpoint_v2,
                        uln_302: &uln_302,
                        views: &views,
                        receiver: &receiver,
                        src_eid,
                        verifier_address: &verifier_address,
                        packet_header: &proof.packet_header,
                        payload_hash: &proof.payload_hash,
                    },
                )
                .await;
                (index, Some((fingerprint, validity)))
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        payload_signed_validation_result(validity, sent_event, dst_chain_name)
    }

    async fn validate_starknet_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        if provider_config.uris.is_empty() {
            return Err(AppCoreError::Internal(format!(
                "No provider URI for chain {dst_chain_name}"
            )));
        }
        let uln_address = self.starknet_uln_302.as_deref().ok_or_else(|| {
            AppCoreError::Internal("No Starknet ULN302 contract configured".to_string())
        })?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
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
            let uln_address = uln_address.to_string();
            let verifier_address = verifier_address.to_string();
            let proof = proof.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_starknet_payload_signed(
                    transport,
                    url,
                    headers,
                    &uln_address,
                    &verifier_address,
                    &proof.packet_header,
                    &proof.payload_hash,
                )
                .await;
                (index, Some((format!("{observation:?}"), observation)))
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        payload_signed_validation_result(validity, sent_event, dst_chain_name)
    }
}

pub(crate) fn payload_signed_validation_result(
    validity: PayloadSignedValidity,
    sent_event: &LzSentEvent,
    dst_chain_name: &str,
) -> Result<(), AppCoreError> {
    match validity {
        PayloadSignedValidity::NotSigned => Ok(()),
        PayloadSignedValidity::Signed => Err(AppCoreError::BadRequest(format!(
            "{} for message {} on chain {}",
            PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX,
            serde_json::to_string(&sent_event.lz_message_id)
                .map_err(|error| AppCoreError::Internal(error.to_string()))?,
            dst_chain_name,
        ))),
        PayloadSignedValidity::Missing => Err(AppCoreError::Internal(format!(
            "Payload-signed validation unavailable for chain {dst_chain_name}"
        ))),
        // Nothing about retrying changes the receiver's configuration, so this
        // is the caller's problem to fix, the same classification upstream's
        // `NonRetryableError` gets.
        PayloadSignedValidity::UnsupportedReceiveLibrary => Err(AppCoreError::BadRequest(format!(
            "Receiver {} on chain {} receives on a library this service cannot validate; \
                 refusing to sign",
            pathway_extra_string_value(sent_event, "receiver")
                .unwrap_or_else(|_| "<unknown>".to_string()),
            dst_chain_name,
        ))),
    }
}

struct MovePayloadSignedObservation<'a> {
    chain_name: &'a str,
    endpoint_v2: &'a str,
    uln_302: &'a str,
    views: &'a str,
    receiver: &'a str,
    src_eid: u32,
    verifier_address: &'a str,
    packet_header: &'a str,
    payload_hash: &'a str,
}

async fn observe_move_payload_signed<T>(
    transport: T,
    base_url: String,
    headers: HashMap<String, String>,
    observation: MovePayloadSignedObservation<'_>,
) -> (String, PayloadSignedValidity)
where
    T: JsonRpcTransport,
{
    use sha3::{Digest, Keccak256};

    let MovePayloadSignedObservation {
        chain_name,
        endpoint_v2,
        uln_302,
        views,
        receiver,
        src_eid,
        verifier_address,
        packet_header,
        payload_hash,
    } = observation;
    let Ok(header) = hex::decode(packet_header.trim_start_matches("0x")) else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };
    let header_hash = format!("0x{}", hex::encode(Keccak256::digest(header)));
    let src_eid = src_eid.to_string();
    let config = move_view_value(
        &transport,
        chain_name,
        &base_url,
        headers.clone(),
        &format!("{endpoint_v2}::endpoint::get_config"),
        &[receiver, uln_302, &src_eid, "3"],
        &["address", "address", "u32", "u32"],
    )
    .await
    .and_then(|value| value.as_str().map(str::to_string));
    let required_confirmations = config.as_deref().and_then(move_uln_config_confirmations);
    let state = move_view_numeric(
        &transport,
        chain_name,
        &base_url,
        headers.clone(),
        &format!("{views}::uln_302::verifiable"),
        &[packet_header, payload_hash],
        &["vector<u8>", "vector<u8>"],
    )
    .await;
    let confirmations = move_view_numeric(
        &transport,
        chain_name,
        &base_url,
        headers,
        &format!("{uln_302}::msglib::get_verification_confirmations"),
        &[&header_hash, payload_hash, verifier_address],
        &["vector<u8>", "vector<u8>", "address"],
    )
    .await;
    let (Some(state), Some(confirmations), Some(required_confirmations)) =
        (state, confirmations, required_confirmations)
    else {
        return ("missing".to_string(), PayloadSignedValidity::Missing);
    };
    let validity = if state == 2 || confirmations >= required_confirmations {
        PayloadSignedValidity::Signed
    } else {
        PayloadSignedValidity::NotSigned
    };
    (
        format!("{state}:{confirmations}:{required_confirmations}"),
        validity,
    )
}

fn move_uln_config_confirmations(encoded: &str) -> Option<u64> {
    let bytes = hex::decode(encoded.trim_start_matches("0x")).ok()?;
    let confirmations = bytes.get(..8)?.try_into().ok()?;
    // Gasolina's pinned `deserializeUlnConfig` uses common-move `extractU64`,
    // which decodes this contract-owned blob in network byte order. This is not
    // generic Move BCS integer decoding.
    Some(u64::from_be_bytes(confirmations))
}

async fn move_view_value<T>(
    transport: &T,
    chain_name: &str,
    base_url: &str,
    headers: HashMap<String, String>,
    function: &str,
    arguments: &[&str],
    argument_types: &[&str],
) -> Option<Value>
where
    T: JsonRpcTransport,
{
    let response = if chain_name == "initia" {
        let mut function_parts = function.split("::");
        let account = function_parts.next()?;
        let module = function_parts.next()?;
        let function_name = function_parts.next()?;
        if function_parts.next().is_some() {
            return None;
        }
        let encoded_arguments = arguments
            .iter()
            .zip(argument_types)
            .map(|(argument, argument_type)| initia_bcs_argument(argument, argument_type))
            .collect::<Option<Vec<_>>>()?;
        transport
            .post_json(
                format!(
                    "{}/initia/move/v1/accounts/{account}/modules/{module}/view_functions/{function_name}",
                    base_url.trim_end_matches('/')
                ),
                headers,
                json!({"type_args": [], "args": encoded_arguments}),
            )
            .await
            .ok()?
    } else {
        transport
            .post_json(
                format!("{}/view", base_url.trim_end_matches('/')),
                headers,
                json!({
                    "function": function,
                    "type_arguments": [],
                    "arguments": arguments,
                }),
            )
            .await
            .ok()?
    };
    move_view_first_value(&response)
}

async fn move_view_numeric<T>(
    transport: &T,
    chain_name: &str,
    base_url: &str,
    headers: HashMap<String, String>,
    function: &str,
    arguments: &[&str],
    argument_types: &[&str],
) -> Option<u64>
where
    T: JsonRpcTransport,
{
    let value = move_view_value(
        transport,
        chain_name,
        base_url,
        headers,
        function,
        arguments,
        argument_types,
    )
    .await?;
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

fn move_view_first_value(response: &Value) -> Option<Value> {
    let decoded = response
        .get("data")
        .and_then(Value::as_str)
        .and_then(|data| serde_json::from_str::<Value>(data).ok());
    let response = decoded.as_ref().unwrap_or(response);
    response.as_array()?.first().cloned()
}

fn initia_bcs_argument(value: &str, argument_type: &str) -> Option<String> {
    use base64::Engine;

    let mut bytes = match argument_type {
        "vector<u8>" => {
            let value = hex::decode(value.trim_start_matches("0x")).ok()?;
            let mut encoded = encode_uleb128(value.len());
            encoded.extend(value);
            encoded
        }
        "address" => {
            let value = hex::decode(value.trim_start_matches("0x")).ok()?;
            if value.len() > 32 {
                return None;
            }
            let mut encoded = vec![0; 32 - value.len()];
            encoded.extend(value);
            encoded
        }
        "u32" => value.parse::<u32>().ok()?.to_le_bytes().to_vec(),
        _ => return None,
    };
    Some(base64::engine::general_purpose::STANDARD.encode(&mut bytes))
}

fn encode_uleb128(mut value: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

async fn observe_starknet_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    uln_address: &str,
    verifier_address: &str,
    packet_header: &str,
    payload_hash: &str,
) -> PayloadSignedValidity
where
    T: JsonRpcTransport,
{
    let Ok(header) = decode_bytes32_or_longer(packet_header) else {
        return PayloadSignedValidity::Missing;
    };
    let Ok(payload_hash) = decode_bytes32(payload_hash) else {
        return PayloadSignedValidity::Missing;
    };
    use sha3::{Digest, Keccak256};
    let header_hash: [u8; 32] = Keccak256::digest(header).into();
    let calldata = [
        starknet_u256_low(&header_hash),
        starknet_u256_high(&header_hash),
        starknet_u256_low(&payload_hash),
        starknet_u256_high(&payload_hash),
        normalize_starknet_felt(verifier_address),
    ];
    let response = transport
        .post_json(
            url,
            headers,
            json!({
                "method": "starknet_call",
                "params": [{
                    "contract_address": uln_address,
                    "entry_point_selector": starknet_selector("has_payload_signed"),
                    "calldata": calldata,
                }, "latest"],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await;
    match response
        .ok()
        .and_then(|response| {
            response
                .get("result")?
                .as_array()?
                .first()?
                .as_str()
                .map(str::to_string)
        })
        .as_deref()
    {
        Some("0x0" | "0") => PayloadSignedValidity::NotSigned,
        Some("0x1" | "1") => PayloadSignedValidity::Signed,
        _ => PayloadSignedValidity::Missing,
    }
}

fn decode_bytes32(value: &str) -> Result<[u8; 32], hex::FromHexError> {
    let decoded = hex::decode(value.trim_start_matches("0x"))?;
    if decoded.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    Ok(decoded.try_into().expect("length checked"))
}

fn decode_bytes32_or_longer(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let decoded = hex::decode(value.trim_start_matches("0x"))?;
    if decoded.len() < 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    Ok(decoded)
}

fn starknet_u256_low(value: &[u8; 32]) -> String {
    normalize_starknet_felt(&hex::encode(&value[16..]))
}

fn starknet_u256_high(value: &[u8; 32]) -> String {
    normalize_starknet_felt(&hex::encode(&value[..16]))
}

fn normalize_starknet_felt(value: &str) -> String {
    let normalized = value.trim_start_matches("0x").trim_start_matches('0');
    format!(
        "0x{}",
        if normalized.is_empty() {
            "0"
        } else {
            normalized
        }
    )
}

fn starknet_selector(name: &str) -> String {
    use sha3::{Digest, Keccak256};
    let mut hash: [u8; 32] = Keccak256::digest(name.as_bytes()).into();
    hash[0] &= 0x03;
    normalize_starknet_felt(&hex::encode(hash))
}
