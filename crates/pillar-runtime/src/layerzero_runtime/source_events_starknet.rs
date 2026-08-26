use super::*;

/// Starknet's EndpointV2 emits PacketSent as a Cairo event whose first key is
/// the selector for the short event name `PacketSent` (the same selector
/// requested by TS `createStarknetEventFilter`), whose second key is the
/// send-library contract address, and whose data contains two Cairo
/// `ByteArray` values (encoded packet and options).
const PACKET_SENT_EVENT_SELECTOR: &str =
    "0x1dce1b34b90259326b8f3d4fc4307bcd6f7daa7621d66d9d8ba984dea61cca9";

#[derive(Debug, Clone)]
pub(crate) struct StarknetPacketSentEvent {
    pub(crate) endpoint_address: String,
    pub(crate) send_library: String,
    pub(crate) packet: LzPacketV1,
    pub(crate) options: String,
}

pub(crate) fn decode_starknet_packet_sent_events(
    receipt: &Value,
    trusted_endpoint_addresses: &HashSet<String>,
) -> Vec<StarknetPacketSentEvent> {
    receipt
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|event| {
            let endpoint_address = event.get("from_address")?.as_str()?.to_string();
            let normalized_endpoint = normalize_starknet_address(&endpoint_address);
            if !trusted_endpoint_addresses
                .iter()
                .map(|address| normalize_starknet_address(address))
                .any(|address| address == normalized_endpoint)
            {
                return None;
            }
            let keys = event.get("keys")?.as_array()?;
            let event_selector = normalize_starknet_address(keys.first()?.as_str()?);
            if event_selector != PACKET_SENT_EVENT_SELECTOR {
                return None;
            }
            let send_library = normalize_starknet_address(keys.get(1)?.as_str()?);
            let data = event.get("data")?.as_array()?;
            let mut cursor = 0;
            let encoded_packet = decode_byte_array(data, &mut cursor)?;
            let options = decode_byte_array(data, &mut cursor)?;
            let packet =
                decode_lz_packet_v1(&format!("0x{}", hex::encode(&encoded_packet))).ok()?;
            Some(StarknetPacketSentEvent {
                endpoint_address,
                send_library,
                packet,
                options: format!("0x{}", hex::encode(options)),
            })
        })
        .collect()
}
pub(crate) fn starknet_packet_to_lz_sent_event(
    src_tx_hash: &str,
    event: StarknetPacketSentEvent,
    chain_name_by_eid: &HashMap<u32, String>,
) -> Result<LzSentEvent, AppCoreError> {
    let packet = event.packet;
    let src_chain_name = chain_name_by_eid
        .get(&packet.src_eid)
        .cloned()
        .ok_or_else(|| {
            AppCoreError::Internal(format!("No chain name for endpoint id {}", packet.src_eid))
        })?;
    let dst_chain_name = chain_name_by_eid
        .get(&packet.dst_eid)
        .cloned()
        .ok_or_else(|| {
            AppCoreError::Internal(format!("No chain name for endpoint id {}", packet.dst_eid))
        })?;
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
    pathway_extra.insert("sender".to_string(), Value::from(packet.sender.clone()));
    pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver.clone()));
    let mut extra = IndexMap::new();
    extra.insert("guid".to_string(), Value::from(packet.guid.clone()));
    extra.insert("options".to_string(), Value::from(event.options));
    extra.insert("sendLibrary".to_string(), Value::from(event.send_library));
    extra.insert(
        "packetEmitAddress".to_string(),
        Value::from(event.endpoint_address),
    );
    Ok(LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name,
                dst_chain_name,
                extra: pathway_extra,
            },
            nonce: packet.nonce,
            uln_send_version: Value::from(ULN_VERSION_V302),
        },
        message: packet.message,
        tx_hash: src_tx_hash.to_string(),
        extra,
    })
}

/// Decode the Starknet JSON-RPC representation of Cairo's `ByteArray`.
/// Serialization is: number of complete 31-byte words, those words as felts,
/// pending word, then pending byte length (0..30).
fn decode_byte_array(data: &[Value], cursor: &mut usize) -> Option<Vec<u8>> {
    let word_count = parse_small_felt(data.get(*cursor)?)?;
    *cursor = cursor.checked_add(1)?;
    let mut bytes = Vec::with_capacity(word_count.checked_mul(31)?);
    for _ in 0..word_count {
        let word = parse_felt_bytes(data.get(*cursor)?)?;
        *cursor = cursor.checked_add(1)?;
        bytes.extend_from_slice(&word[1..]);
    }
    let pending_word = parse_felt_bytes(data.get(*cursor)?)?;
    *cursor = cursor.checked_add(1)?;
    let pending_len = parse_small_felt(data.get(*cursor)?)?;
    *cursor = cursor.checked_add(1)?;
    if pending_len > 30 {
        return None;
    }
    bytes.extend_from_slice(&pending_word[32 - pending_len..]);
    Some(bytes)
}

fn parse_small_felt(value: &Value) -> Option<usize> {
    let value = value.as_str()?;
    let value = value.strip_prefix("0x").unwrap_or(value);
    usize::from_str_radix(value, 16).ok()
}

fn parse_felt_bytes(value: &Value) -> Option<[u8; 32]> {
    let value = value.as_str()?;
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() > 64 {
        return None;
    }
    let mut padded = String::with_capacity(64);
    padded.extend(std::iter::repeat_n('0', 64 - value.len()));
    padded.push_str(value);
    hex::decode(padded).ok()?.try_into().ok()
}

pub(crate) fn normalize_starknet_address(address: &str) -> String {
    let value = address.trim().strip_prefix("0x").unwrap_or(address.trim());
    let value = value.trim_start_matches('0');
    format!("0x{}", if value.is_empty() { "0" } else { value }).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_layerzero::encode_lz_packet_v1;
    use serde_json::json;

    fn byte_array(bytes: &[u8]) -> Vec<Value> {
        let words = bytes.len() / 31;
        let mut values = vec![Value::from(format!("0x{words:x}"))];
        for chunk in bytes.chunks(31).take(words) {
            let mut word = [0u8; 32];
            word[1..].copy_from_slice(chunk);
            values.push(Value::from(format!("0x{}", hex::encode(word))));
        }
        let pending = &bytes[words * 31..];
        let mut padded = [0u8; 32];
        padded[32 - pending.len()..].copy_from_slice(pending);
        values.push(Value::from(format!("0x{}", hex::encode(padded))));
        values.push(Value::from(format!("0x{:x}", pending.len())));
        values
    }

    fn receipt(endpoint: &str) -> Value {
        let packet = encode_lz_packet_v1(&LzPacketV1 {
            nonce: 7,
            src_eid: 30_500,
            sender: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            dst_eid: 30_101,
            receiver: "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            guid: "0x3333333333333333333333333333333333333333333333333333333333333333".into(),
            message: "0xdeadbeef".into(),
        })
        .unwrap();
        let mut data = byte_array(&packet);
        data.extend(byte_array(&[]));
        json!({"events": [{"from_address": endpoint, "keys": [
            PACKET_SENT_EVENT_SELECTOR, "0x1234"
        ], "data": data}]})
    }

    #[test]
    fn decodes_packet_sent_from_trusted_endpoint() {
        let endpoint = "0xabc";
        let events = decode_starknet_packet_sent_events(
            &receipt(endpoint),
            &HashSet::from(["0x0abc".to_string()]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].send_library, "0x1234");
    }

    #[test]
    fn rejects_packet_sent_from_untrusted_endpoint() {
        let events = decode_starknet_packet_sent_events(
            &receipt("0xabc"),
            &HashSet::from(["0xdef".to_string()]),
        );
        assert!(events.is_empty());
    }
}
