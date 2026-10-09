use super::*;

/// `hash.getSelectorFromName('PacketSent')` as upstream's filter renders it
/// (`common-starknet/src/events.ts:12-23`).
const PACKET_SENT_EVENT_SELECTOR: &str =
    "0x1dce1b34b90259326b8f3d4fc4307bcd6f7daa7621d66d9d8ba984dea61cca9";
/// starknet.js's event parser running out of keys or data.
const UNEXPECTED_END: &str = "Unexpected end of response";

#[derive(Debug, Clone)]
pub(crate) struct StarknetPacketSentEvent {
    pub(crate) endpoint_address: String,
    /// The `send_library` key as upstream's `.toString()` of its felt renders it: decimal.
    pub(crate) send_library: String,
    pub(crate) packet: LzPacketV1,
    pub(crate) options: String,
}

/// Upstream's `getPacketSentEventsFromTxHash` after the receipt checks
/// (`lz-v2-sdk/src/endpoint/starknet/index.ts:195-200`, `findEventsInReceipt.ts:9-36`): events
/// whose raw `keys[0]` and `from_address` equal the filter's strings exactly, each parsed with
/// the EndpointV2 ABI; the first that cannot be parsed fails the read.
pub(crate) fn decode_starknet_packet_sent_events(
    receipt: &Value,
    trusted_endpoint_addresses: &HashSet<String>,
) -> Result<Vec<StarknetPacketSentEvent>, String> {
    let filters = trusted_endpoint_addresses
        .iter()
        .map(|address| normalize_starknet_address(address))
        .collect::<HashSet<_>>();
    let events = receipt
        .get("events")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    events
        .iter()
        .filter(|event| {
            let selector = event.pointer("/keys/0").and_then(Value::as_str);
            let from = event.get("from_address").and_then(Value::as_str);
            selector == Some(PACKET_SENT_EVENT_SELECTOR)
                && from.is_some_and(|from| filters.contains(from))
        })
        .map(|event| {
            let endpoint_address = event["from_address"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let send_library = event
                .pointer("/keys/1")
                .and_then(Value::as_str)
                .and_then(felt_decimal)
                .ok_or_else(|| UNEXPECTED_END.to_string())?;
            let data = event
                .get("data")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut cursor = 0;
            let encoded_packet =
                decode_byte_array(data, &mut cursor).ok_or_else(|| UNEXPECTED_END.to_string())?;
            let options =
                decode_byte_array(data, &mut cursor).ok_or_else(|| UNEXPECTED_END.to_string())?;
            let packet = decode_lz_packet_v1(&format!("0x{}", hex::encode(&encoded_packet)))
                .map_err(|error| error.to_string())?;
            Ok(StarknetPacketSentEvent {
                endpoint_address,
                send_library,
                packet,
                options: format!("0x{}", hex::encode(options)),
            })
        })
        .collect()
}

fn felt_decimal(felt: &str) -> Option<String> {
    let digits = felt.strip_prefix("0x").unwrap_or(felt);
    num_bigint::BigUint::parse_bytes(digits.as_bytes(), 16).map(|value| value.to_string())
}

/// `getChainName(eid)` as upstream's `formatPathwayId` applies it; a configured chain keeps its
/// configured name.
pub(crate) fn chain_name_for_packet_eid(
    chain_name_by_eid: &HashMap<u32, String>,
    eid: u32,
) -> Result<String, AppCoreError> {
    chain_name_by_eid
        .get(&eid)
        .cloned()
        .or_else(|| pillar_config::layerzero_legacy_chain_name(eid).map(str::to_string))
        .ok_or_else(|| {
            AppCoreError::Internal(format!("Invariant failed: Invalid endpointId: {eid}"))
        })
}

/// Upstream's `extractLZEventFromPacketSentEvent` (`starknet/decoders/index.ts:88-120`): pathway
/// by `formatPathwayId`, always `V302`, and options decoded into relayer options.
pub(crate) fn starknet_packet_to_lz_sent_event(
    src_tx_hash: &str,
    event: StarknetPacketSentEvent,
    chain_name_by_eid: &HashMap<u32, String>,
) -> Result<Option<LzSentEvent>, AppCoreError> {
    let packet = event.packet;
    let src_chain_name = chain_name_by_eid
        .get(&packet.src_eid)
        .cloned()
        .ok_or_else(|| {
            AppCoreError::Internal(format!("No chain name for endpoint id {}", packet.src_eid))
        })?;
    let dst_chain_name = match chain_name_for_packet_eid(chain_name_by_eid, packet.dst_eid) {
        Ok(name) => name,
        Err(_) => return Ok(None),
    };
    let options = hex::decode(strip_hex_prefix(&event.options))
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let options =
        decode_move_relayer_options(&options, &dst_chain_name).map_err(AppCoreError::Internal)?;
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
    pathway_extra.insert("sender".to_string(), Value::from(packet.sender.clone()));
    pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver.clone()));
    let mut extra = IndexMap::new();
    extra.insert("guid".to_string(), Value::from(packet.guid.clone()));
    extra.insert("options".to_string(), options);
    extra.insert("sendLibrary".to_string(), Value::from(event.send_library));
    extra.insert(
        "packetEmitAddress".to_string(),
        Value::from(event.endpoint_address),
    );
    Ok(Some(LzSentEvent {
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
        source_evidence: None,
        read_block_pins: Vec::new(),
    }))
}

/// Decode the Starknet JSON-RPC representation of Cairo's `ByteArray`.
/// Serialization is: number of complete 31-byte words, those words as felts,
/// pending word, then pending byte length (0..30).
fn decode_byte_array(data: &[Value], cursor: &mut usize) -> Option<Vec<u8>> {
    let word_count = parse_small_felt(data.get(*cursor)?)?;
    *cursor = cursor.checked_add(1)?;
    // The count is provider-supplied and each word consumes one array element,
    // so the remaining elements are the ceiling. `checked_mul` alone rejects
    // only the overflow: 0x0800000000000000 * 31 fits a usize and would request
    // roughly 17 exabytes, and an allocation failure aborts the process.
    if word_count > data.len().saturating_sub(*cursor) {
        return None;
    }
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
