use super::*;

pub(crate) async fn observe_uln_v2_mpt_hash_info<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
) -> Result<UlnV2HashInfoObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    let receipt = transport
        .clone()
        .post_json(
            url.clone(),
            headers.clone(),
            json!({
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    let block_hash = receipt
        .get("result")
        .filter(|result| !result.is_null())
        .and_then(|result| result.get("blockHash"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| AppCoreError::Internal("Missing receipt blockHash".to_string()))?;
    let block = transport
        .post_json(
            url,
            headers,
            json!({
                "method": "eth_getBlockByHash",
                "params": [block_hash, true],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::Internal)?;
    parse_uln_v2_mpt_hash_info_observation(&block)
}

pub(crate) async fn observe_uln_v2_inbound_proof_type<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    uln_v2_contract: &str,
    src_eid: u64,
    receiver: &str,
) -> Result<UlnV2InboundProofTypeObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    let app_config_call_data = build_evm_uln_v2_get_app_config_call_data(src_eid, receiver)?;
    let app_config_result = eth_call(
        transport.clone(),
        url.clone(),
        headers.clone(),
        uln_v2_contract,
        &app_config_call_data,
    )
    .await?;
    let app_config = decode_evm_uln_v2_app_config(&app_config_result)?;

    let proof_library_call_data = build_evm_uln_v2_inbound_proof_library_call_data(
        src_eid,
        app_config.inbound_proof_library_version,
    )?;
    let proof_library_result = eth_call(
        transport.clone(),
        url.clone(),
        headers.clone(),
        uln_v2_contract,
        &proof_library_call_data,
    )
    .await?;
    let proof_library_address = decode_evm_address_result(&proof_library_result)?;

    let utils_version_result = eth_call(
        transport.clone(),
        url.clone(),
        headers.clone(),
        &proof_library_address,
        &build_evm_validation_library_get_utils_version_call_data(),
    )
    .await?;
    let utils_version = decode_evm_uint64_result(&utils_version_result)?;

    let proof_type_result = eth_call(
        transport,
        url,
        headers,
        &proof_library_address,
        &build_evm_validation_library_get_proof_type_call_data(),
    )
    .await?;
    let proof_type = decode_evm_uint64_result(&proof_type_result)?.to_string();

    Ok(UlnV2InboundProofTypeObservation {
        fingerprint: format!(
            "{}|{}|{}|{}",
            app_config.inbound_proof_library_version,
            proof_library_address.to_ascii_lowercase(),
            utils_version,
            proof_type
        ),
        proof_type,
    })
}

pub(crate) fn parse_uln_v2_mpt_hash_info_observation(
    response: &Value,
) -> Result<UlnV2HashInfoObservation, AppCoreError> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing block".to_string()))?;
    let lookup_hash = result
        .get("hash")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| AppCoreError::Internal("Missing block hash".to_string()))?;
    let block_data = result
        .get("receiptsRoot")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| AppCoreError::Internal("Missing block receiptsRoot".to_string()))?;
    let hash_info = UlnV2HashInfo {
        lookup_hash,
        block_data,
    };
    Ok(UlnV2HashInfoObservation {
        fingerprint: format!("{}|{}", hash_info.lookup_hash, hash_info.block_data),
        hash_info,
    })
}
