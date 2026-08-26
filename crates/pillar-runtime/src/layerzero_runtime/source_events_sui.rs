use super::*;

#[derive(Debug, Clone)]
pub(crate) struct SuiPacketSentEvent {
    pub(crate) endpoint_address: String,
    pub(crate) packet: LzPacketV1,
    pub(crate) options: String,
    pub(crate) send_library: Option<String>,
}

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

fn decode_sui_bytes(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(if value.starts_with("0x") {
            value.clone()
        } else {
            format!("0x{value}")
        }),
        Value::Array(values) => {
            let bytes = values
                .iter()
                .map(Value::as_u64)
                .collect::<Option<Vec<_>>>()?;
            if bytes.iter().any(|byte| *byte > 255) {
                return None;
            }
            Some(format!(
                "0x{}",
                hex::encode(bytes.iter().map(|byte| *byte as u8).collect::<Vec<_>>())
            ))
        }
        _ => None,
    }
}

fn event_data(event: &Value) -> Option<&Value> {
    event.get("parsedJson").or_else(|| event.get("data"))
}

pub(crate) fn decode_sui_packet_sent_events(
    _chain_name: &str,
    response: &Value,
    trusted_endpoints: &HashSet<String>,
) -> Vec<SuiPacketSentEvent> {
    let trusted_endpoints = trusted_endpoints
        .iter()
        .map(|endpoint| normalize_sui_address(endpoint))
        .collect::<HashSet<_>>();
    let events = response
        .pointer("/data")
        .or_else(|| response.pointer("/result/data"))
        .and_then(Value::as_array);
    let Some(events) = events else {
        return Vec::new();
    };
    events
        .iter()
        .filter_map(|event| {
            let event_type = event.get("type").and_then(Value::as_str)?;
            let endpoint = event_type.split("::").next()?;
            let endpoint = normalize_sui_address(endpoint);
            if !trusted_endpoints.contains(&endpoint)
                || !event_type
                    .to_ascii_lowercase()
                    .ends_with("::messaging_channel::packetsent")
            {
                return None;
            }
            let data = event_data(event)?.as_object()?;
            let encoded_packet = data
                .get("encoded_packet")
                .or_else(|| data.get("packet"))
                .and_then(decode_sui_bytes)?;
            let packet = decode_lz_packet_v1(&encoded_packet).ok()?;
            let options = data.get("options").and_then(decode_sui_bytes)?;
            let send_library = data
                .get("send_library")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            Some(SuiPacketSentEvent {
                endpoint_address: endpoint,
                packet,
                options,
                send_library,
            })
        })
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
) -> SuiBlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    if required_confirmations < 0 {
        return observe_sui_block_confirmations(&Value::Null, &Value::Null, required_confirmations);
    }
    let transaction = transport
        .post_json(
            url.clone(),
            headers.clone(),
            json!({
                "method": sui_rpc_method(chain_name, "getTransactionBlock"),
                "params": [tx_hash, null],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .ok()
        .and_then(|response| response.get("result").cloned())
        .unwrap_or(Value::Null);
    let latest = transport
        .post_json(
            url,
            headers,
            json!({
                "method": sui_rpc_method(chain_name, "getLatestCheckpointSequenceNumber"),
                "params": [],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .ok()
        .and_then(|response| response.get("result").cloned())
        .unwrap_or(Value::Null);
    observe_sui_block_confirmations(&transaction, &latest, required_confirmations)
}

pub(crate) async fn observe_sui_block_time_rpc<T>(
    transport: T,
    chain_name: &str,
    url: String,
    headers: HashMap<String, String>,
) -> Option<i64>
where
    T: JsonRpcTransport,
{
    let latest = transport
        .post_json(
            url.clone(),
            headers.clone(),
            json!({
                "method": sui_rpc_method(chain_name, "getLatestCheckpointSequenceNumber"),
                "params": [],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .ok()?
        .get("result")
        .cloned()?;
    let checkpoint = transport
        .post_json(
            url,
            headers,
            json!({
                "method": sui_rpc_method(chain_name, "getCheckpoint"),
                "params": [latest],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await
        .ok()?
        .get("result")
        .cloned()?;
    parse_sui_checkpoint_timestamp(&checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_layerzero::encode_lz_packet_v1;
    use serde_json::json;

    fn packet() -> LzPacketV1 {
        LzPacketV1 {
            nonce: 7,
            src_eid: 30_378,
            sender: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            dst_eid: 30_101,
            receiver: "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            guid: "0x3333333333333333333333333333333333333333333333333333333333333333".into(),
            message: "0xdeadbeef".into(),
        }
    }

    fn response(endpoint: &str) -> Value {
        let encoded_packet = encode_lz_packet_v1(&packet()).unwrap();
        json!({"data": [{
            "type": format!("{endpoint}::messaging_channel::PacketSent"),
            "id": {"txDigest": "tx", "eventSeq": "0"},
            "parsedJson": {
                "encoded_packet": encoded_packet.iter().map(|byte| u64::from(*byte)).collect::<Vec<_>>(),
                "options": [1, 2, 3],
                "send_library": "0x4444"
            }
        }]})
    }

    #[test]
    fn decodes_trusted_sui_packet_sent_event() {
        let endpoint = "0xabc";
        let events = decode_sui_packet_sent_events(
            "sui",
            &response(endpoint),
            &HashSet::from([endpoint.to_string()]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].options, "0x010203");
        assert_eq!(events[0].send_library.as_deref(), Some("0x4444"));
    }

    #[test]
    fn decodes_trusted_iota_packet_sent_event() {
        let endpoint = "0xdef";
        let events = decode_sui_packet_sent_events(
            "iotal1",
            &response(endpoint),
            &HashSet::from([endpoint.to_string()]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.src_eid, 30_378);
    }

    #[test]
    fn rejects_untrusted_sui_and_iota_packet_sent_events() {
        for chain_name in ["sui", "iotal1"] {
            let events = decode_sui_packet_sent_events(
                chain_name,
                &response("0xabc"),
                &HashSet::from(["0xdef".to_string()]),
            );
            assert!(events.is_empty());
        }
    }
}
