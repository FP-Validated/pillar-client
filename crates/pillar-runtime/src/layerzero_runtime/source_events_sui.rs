use super::*;

pub(crate) fn sui_rpc_method(chain_name: &str, method: &str) -> String {
    let prefix = if chain_name == "iotal1" {
        "iota"
    } else {
        "sui"
    };
    match method {
        "queryEvents" => format!("{prefix}x_queryEvents"),
        "getTransactionBlock" => format!("{prefix}_getTransactionBlock"),
        "getLatestCheckpointSequenceNumber" => {
            format!("{prefix}_getLatestCheckpointSequenceNumber")
        }
        "getCheckpoint" => format!("{prefix}_getCheckpoint"),
        _ => format!("{prefix}_{method}"),
    }
}

fn normalize_sui_address(address: &str) -> String {
    let value = strip_hex_prefix(address).to_ascii_lowercase();
    format!("0x{value:0>64}")
}

/// Upstream's Sui `getPacketSentEvents` (`lz-v2-sdk/src/endpoint/sui/index.ts:197-227`): the
/// events whose type is exactly `{package}::messaging_channel::PacketSentEvent`
/// (`sui-contracts/src/accountResources.ts:38,55`) and whose `parsedJson` is truthy, each
/// through the Aptos-family extractor with `Uint8Array.from` byte fields; none is its throw,
/// and so is the first extraction that throws.
pub(crate) fn decode_sui_packet_sent_events(
    response: &Value,
    trusted_endpoints: &HashSet<String>,
) -> Result<Vec<MovePacketSentEvent>, String> {
    let event_types = trusted_endpoints
        .iter()
        .map(|endpoint| {
            let endpoint = normalize_sui_address(endpoint);
            let event_type = format!("{endpoint}::messaging_channel::PacketSentEvent");
            (endpoint, event_type)
        })
        .collect::<Vec<_>>();
    let events = response
        .pointer("/data")
        .or_else(|| response.pointer("/result/data"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let matched = events
        .iter()
        .filter_map(|event| {
            let event_type = event.get("type").and_then(Value::as_str)?;
            let (endpoint, _) = event_types.iter().find(|(_, known)| known == event_type)?;
            let data = event.get("parsedJson").filter(|data| js_truthy(data))?;
            Some((endpoint, data))
        })
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return Err("Packet sent event not found or not valid".to_string());
    }
    matched
        .into_iter()
        .map(|(endpoint, data)| decode_event_data(endpoint, data, MoveByteFields::JsUint8Array))
        .collect()
}

fn parse_checkpoint(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str()?.parse().ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SuiBlockConfirmationValidity {
    Sufficient,
    Insufficient,
    Missing,
    InvalidRange,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SuiBlockConfirmationObservation {
    pub(crate) validity: SuiBlockConfirmationValidity,
    pub(crate) current_confirmations: Option<i64>,
}

pub(crate) fn observe_sui_block_confirmations(
    transaction: &Value,
    latest: &Value,
    required_confirmations: i64,
) -> SuiBlockConfirmationObservation {
    if required_confirmations < 0 {
        return SuiBlockConfirmationObservation {
            validity: SuiBlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    }
    let tx_checkpoint = transaction.get("checkpoint").and_then(parse_checkpoint);
    let current_checkpoint = parse_checkpoint(latest);
    let (Some(tx_checkpoint), Some(current_checkpoint)) = (tx_checkpoint, current_checkpoint)
    else {
        return SuiBlockConfirmationObservation {
            validity: SuiBlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    if tx_checkpoint < 0 || current_checkpoint < 0 {
        return SuiBlockConfirmationObservation {
            validity: SuiBlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    }
    let current_confirmations = current_checkpoint.saturating_sub(tx_checkpoint);
    SuiBlockConfirmationObservation {
        validity: if current_confirmations >= required_confirmations {
            SuiBlockConfirmationValidity::Sufficient
        } else {
            SuiBlockConfirmationValidity::Insufficient
        },
        current_confirmations: Some(current_confirmations),
    }
}

pub(crate) fn parse_sui_checkpoint_timestamp(response: &Value) -> Option<i64> {
    let timestamp_ms = response.get("timestampMs").and_then(parse_checkpoint)?;
    Some(timestamp_ms / 1000)
}

pub(crate) async fn observe_sui_block_confirmations_rpc<T>(
    transport: T,
    chain_name: &str,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> Result<SuiBlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    if required_confirmations < 0 {
        return Ok(observe_sui_block_confirmations(
            &Value::Null,
            &Value::Null,
            required_confirmations,
        ));
    }
    let transaction_response = super::validation_readiness::readiness_response(
        transport
            .post_json_scoped(
                url.clone(),
                headers.clone(),
                json!({
                    "method": sui_rpc_method(chain_name, "getTransactionBlock"),
                    "params": [tx_hash, null],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
            )
            .await,
    )?;
    let transaction = transaction_response
        .get("result")
        .cloned()
        .ok_or_else(|| RpcError::Remote("Sui transaction response has no result".to_string()))?;
    let latest_response = super::validation_readiness::readiness_response(
        transport
            .post_json_scoped(
                url,
                headers,
                json!({
                    "method": sui_rpc_method(chain_name, "getLatestCheckpointSequenceNumber"),
                    "params": [],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
            )
            .await,
    )?;
    let latest = latest_response
        .get("result")
        .cloned()
        .ok_or_else(|| RpcError::Remote("Sui checkpoint response has no result".to_string()))?;
    Ok(observe_sui_block_confirmations(
        &transaction,
        &latest,
        required_confirmations,
    ))
}

pub(crate) async fn observe_sui_block_time_rpc<T>(
    transport: T,
    chain_name: &str,
    url: String,
    headers: HashMap<String, String>,
) -> Result<i64, RpcError>
where
    T: JsonRpcTransport,
{
    let latest_response = transport.post_json_scoped(url.clone(), headers.clone(), json!({"method":sui_rpc_method(chain_name, "getLatestCheckpointSequenceNumber"),"params":[],"id":1,"jsonrpc":"2.0"})).await?;
    let latest = latest_response
        .get("result")
        .cloned()
        .ok_or(RpcError::Unavailable)?;
    let checkpoint_response = transport.post_json_scoped(url, headers, json!({"method":sui_rpc_method(chain_name, "getCheckpoint"),"params":[latest],"id":1,"jsonrpc":"2.0"})).await?;
    let checkpoint = checkpoint_response
        .get("result")
        .ok_or(RpcError::Unavailable)?;
    parse_sui_checkpoint_timestamp(checkpoint).ok_or(RpcError::Unavailable)
}
