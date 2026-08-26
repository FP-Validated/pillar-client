use super::*;

pub(crate) async fn observe_block_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> BlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    let receipt_transport = transport.clone();
    let receipt = receipt_transport.post_json(
        url.clone(),
        headers.clone(),
        json!({
            "method": "eth_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let latest_block = transport.post_json(
        url,
        headers,
        json!({
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let (receipt_response, latest_block_response) = tokio::join!(receipt, latest_block);

    let observation = receipt_response
        .ok()
        .and_then(|receipt| parse_receipt_block_placement(&receipt).ok())
        .zip(
            latest_block_response
                .ok()
                .and_then(|block| parse_block_number(&block).ok()),
        );

    let Some(((receipt_block_hash, receipt_block_number), current_block_number)) = observation
    else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };

    let (Some(current_confirmations), Some(required_block_number)) = (
        current_block_number.checked_sub(receipt_block_number),
        receipt_block_number.checked_add(required_confirmations),
    ) else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    };
    if receipt_block_number < 0 || current_block_number < 0 || required_confirmations < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    }
    let validity = if current_block_number >= required_block_number {
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
    BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    }
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
        .post_json(
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
        .map_err(AppCoreError::Internal)?;
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
