use super::*;
use pillar_core::EvmSourceEvidence;

pub(crate) async fn observe_block_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    source_evidence: Option<&EvmSourceEvidence>,
    required_confirmations: i64,
    require_finalized: bool,
) -> Result<BlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    let receipt_transport = transport.clone();
    let receipt = receipt_transport.post_json_scoped(
        url.clone(),
        headers.clone(),
        json!({
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let latest_block = transport.post_json_scoped(
        url.clone(),
        headers.clone(),
        json!({
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let finalized_request = async {
        if require_finalized {
            transport
                .post_json_scoped(
                    url.clone(),
                    headers.clone(),
                    json!({
                        "method": "eth_getBlockByNumber",
                        "params": ["finalized", false],
                        "id": 1,
                        "jsonrpc": "2.0",
                    }),
                )
                .await
                .map(Some)
        } else {
            Ok(None)
        }
    };
    let (receipt_response, latest_block_response, finalized_response) =
        tokio::join!(receipt, latest_block, finalized_request);
    let receipt_response = match receipt_response {
        Err(error @ (RpcError::Admission(_) | RpcError::Configuration(_))) => return Err(error),
        response => response,
    };
    let latest_block_response = provider_response(latest_block_response)?;
    let finalized_block = finalized_response?
        .map(|response| {
            Ok::<_, RpcError>((
                parse_block_number(&response).map_err(RpcError::Remote)?,
                parse_block_hash(&response).map_err(RpcError::Remote)?,
            ))
        })
        .transpose()?;
    let receipt_value = match receipt_response {
        Ok(response) if response.get("error").is_none() && response.get("result").is_some() => {
            response
        }
        Ok(_) | Err(RpcError::Remote(_) | RpcError::Unavailable) => {
            return Err(RpcError::Remote(
                "transaction receipt unavailable".to_string(),
            ));
        }
        Err(error) => return Err(error),
    };
    let source_binding_error = source_evidence
        .and_then(|evidence| validate_receipt_binding(&receipt_value, evidence, tx_hash).err());
    if let Some(reason) = source_binding_error {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::SourceChanged(reason),
            current_confirmations: None,
        });
    }
    let Some(((receipt_block_hash, receipt_block_number), current_block_number)) =
        parse_receipt_block_placement(&receipt_value).ok().zip(
            latest_block_response
                .as_ref()
                .and_then(|block| parse_block_number(block).ok()),
        )
    else {
        return Err(RpcError::Remote(
            "receipt or latest block unavailable".to_string(),
        ));
    };

    let (Some(current_confirmations), Some(required_block_number)) = (
        current_block_number.checked_sub(receipt_block_number),
        receipt_block_number.checked_add(required_confirmations),
    ) else {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    };
    if receipt_block_number < 0 || current_block_number < 0 || required_confirmations < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    }
    let confirmations_met = current_block_number >= required_block_number;
    let finalized_behind = finalized_block
        .as_ref()
        .is_some_and(|(number, _)| *number < receipt_block_number);
    let mut finalized = !require_finalized;
    if let Some((finalized_number, finalized_hash)) = finalized_block {
        if finalized_number >= receipt_block_number {
            // The canonical header at the receipt height must be the receipt's block; a second receipt read cannot rule out a fork.
            let canonical_hash = if finalized_number == receipt_block_number {
                finalized_hash
            } else {
                let response = transport
                    .post_json_scoped(
                        url,
                        headers,
                        json!({
                            "method": "eth_getBlockByNumber",
                            "params": [format!("0x{receipt_block_number:x}"), false],
                            "id": 1,
                            "jsonrpc": "2.0",
                        }),
                    )
                    .await?;
                let canonical_number = parse_block_number(&response).map_err(RpcError::Remote)?;
                if canonical_number != receipt_block_number {
                    return Err(RpcError::Remote(format!(
                        "canonical header number {canonical_number} does not match receipt height {receipt_block_number}"
                    )));
                }
                parse_block_hash(&response).map_err(RpcError::Remote)?
            };
            if canonical_hash != receipt_block_hash {
                return Ok(BlockConfirmationObservation {
                    validity: BlockConfirmationValidity::SourceChanged(format!(
                        "canonical block hash at height {receipt_block_number} is {canonical_hash:?}, not receipt block {receipt_block_hash}"
                    )),
                    current_confirmations: None,
                });
            }
            finalized = true;
        }
    }
    let validity = if confirmations_met && finalized {
        BlockConfirmationValidity::Sufficient {
            receipt_block_hash,
            receipt_block_number,
        }
    } else {
        BlockConfirmationValidity::Insufficient {
            receipt_block_hash,
            receipt_block_number,
        }
    };
    Ok(BlockConfirmationObservation {
        validity,
        current_confirmations: Some(if finalized_behind {
            -1
        } else {
            current_confirmations.max(0)
        }),
    })
}

pub(crate) async fn observe_block_time<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    block_tag: &str,
) -> Result<BlockTimeObservation, AppCoreError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json_scoped(
            url,
            headers,
            json!({
                "method": "eth_getBlockByNumber",
                "params": [block_tag, false],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .map_err(AppCoreError::from)?;
    parse_block_time_observation(&response)
}

pub(crate) fn parse_receipt_block_placement(response: &Value) -> Result<(String, i64), String> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| "Missing transaction receipt".to_string())?;
    let block_hash = result
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing receipt blockHash".to_string())?
        .to_ascii_lowercase();
    let block_number = numeric_response(
        result
            .get("blockNumber")
            .ok_or_else(|| "Missing receipt blockNumber".to_string())?,
    )
    .ok_or_else(|| "Invalid receipt blockNumber".to_string())?
    .parse::<i64>()
    .map_err(|error| error.to_string())?;
    Ok((block_hash, block_number))
}

pub(crate) fn validate_receipt_binding(
    response: &Value,
    evidence: &EvmSourceEvidence,
    requested_tx_hash: &str,
) -> Result<(), String> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| "source receipt disappeared".to_string())?;
    let transaction_hash = result
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| "source receipt transaction hash is missing".to_string())?;
    if !evm_transaction_hash_matches(transaction_hash, requested_tx_hash)
        || !evm_transaction_hash_matches(transaction_hash, &evidence.transaction_hash)
    {
        return Err("source receipt transaction hash changed".to_string());
    }
    let block_hash = result
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| "source receipt block hash is missing".to_string())?
        .to_ascii_lowercase();
    if block_hash != evidence.block_hash.to_ascii_lowercase() {
        return Err(format!(
            "source receipt block hash changed from {} to {}",
            evidence.block_hash, block_hash
        ));
    }
    let block_number = numeric_response(
        result
            .get("blockNumber")
            .ok_or_else(|| "source receipt block number is missing".to_string())?,
    )
    .ok_or_else(|| "source receipt block number is invalid".to_string())?
    .parse::<i64>()
    .map_err(|error| error.to_string())?;
    if block_number != evidence.block_number {
        return Err(format!(
            "source receipt block number changed from {} to {}",
            evidence.block_number, block_number
        ));
    }
    let status = result
        .get("status")
        .ok_or_else(|| "source receipt execution status is missing".to_string())?;
    let status = numeric_response(status)
        .ok_or_else(|| "source receipt execution status is invalid".to_string())?;
    if status != "1" || status != evidence.status {
        return Err(format!("source receipt execution status changed: {status}"));
    }
    let logs = result
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "source receipt logs are missing".to_string())?;
    let mut matching_logs = logs.iter().filter(|log| {
        log.get("logIndex")
            .and_then(numeric_response)
            .and_then(|index| index.parse::<u64>().ok())
            == Some(evidence.packet_log_index)
    });
    let packet_log = matching_logs.next().ok_or_else(|| {
        format!(
            "source PacketSent log index {} is no longer present",
            evidence.packet_log_index
        )
    })?;
    if matching_logs.next().is_some() {
        return Err("source receipt contains duplicate PacketSent log index".to_string());
    }
    if !matches!(packet_log.get("removed"), None | Some(Value::Bool(false))) {
        return Err("source PacketSent log is removed or has an invalid removed state".to_string());
    }
    let log_tx_hash = packet_log
        .get("transactionHash")
        .and_then(Value::as_str)
        .ok_or_else(|| "source PacketSent log transaction hash is missing".to_string())?;
    let log_block_hash = packet_log
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| "source PacketSent log block hash is missing".to_string())?;
    let log_block_number = packet_log
        .get("blockNumber")
        .and_then(numeric_response)
        .ok_or_else(|| "source PacketSent log block number is missing or invalid".to_string())?
        .parse::<i64>()
        .map_err(|error| error.to_string())?;
    if !evm_transaction_hash_matches(log_tx_hash, &evidence.transaction_hash)
        || !log_block_hash.eq_ignore_ascii_case(&evidence.block_hash)
        || log_block_number != evidence.block_number
    {
        return Err("source PacketSent log placement changed".to_string());
    }
    let log_address = packet_log
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| "source PacketSent log address is missing".to_string())?;
    let log_topics = packet_log
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| "source PacketSent log topics are missing".to_string())?;
    let topics = log_topics
        .iter()
        .map(|topic| topic.as_str().map(str::to_ascii_lowercase))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "source PacketSent log has invalid topics".to_string())?;
    let data = packet_log
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| "source PacketSent log data is missing".to_string())?;
    if !log_address.eq_ignore_ascii_case(&evidence.packet_log_address)
        || topics != evidence.packet_log_topics
        || !data.eq_ignore_ascii_case(&evidence.packet_log_data)
    {
        return Err("source PacketSent log contents changed".to_string());
    }
    Ok(())
}
pub(crate) fn parse_block_number(response: &Value) -> Result<i64, String> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| "Missing block".to_string())?;
    numeric_response(
        result
            .get("number")
            .ok_or_else(|| "Missing block number".to_string())?,
    )
    .ok_or_else(|| "Invalid block number".to_string())?
    .parse::<i64>()
    .map_err(|error| error.to_string())
}

fn parse_block_hash(response: &Value) -> Result<String, String> {
    response
        .pointer("/result/hash")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| "Missing block hash".to_string())
}

pub(crate) fn parse_block_time_observation(
    response: &Value,
) -> Result<BlockTimeObservation, AppCoreError> {
    let result = response
        .get("result")
        .filter(|result| !result.is_null())
        .ok_or_else(|| AppCoreError::Internal("Missing block".to_string()))?;
    let number = numeric_response(
        result
            .get("number")
            .ok_or_else(|| AppCoreError::Internal("Missing block number".to_string()))?,
    )
    .ok_or_else(|| AppCoreError::Internal("Invalid block number".to_string()))?
    .parse::<i64>()
    .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let hash = result
        .get("hash")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| AppCoreError::Internal("Missing block hash".to_string()))?;
    let timestamp = parse_block_timestamp_seconds(response).map_err(AppCoreError::Internal)?;
    let block = BlockTime {
        number,
        hash,

        timestamp,
    };
    Ok(BlockTimeObservation {
        fingerprint: format!("{}|{}|{}", block.number, block.hash, block.timestamp),
        block,
    })
}

pub(crate) fn block_matches_resolved_timestamp(
    block: &BlockTime,
    previous_block: Option<&BlockTime>,
    target_timestamp: i64,
) -> bool {
    if block.number == 1 {
        block.timestamp == target_timestamp
    } else {
        block.timestamp >= target_timestamp
            && previous_block
                .is_some_and(|previous_block| previous_block.timestamp < target_timestamp)
    }
}
