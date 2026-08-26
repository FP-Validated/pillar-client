use super::*;
use std::collections::{HashMap, HashSet};
use ton_core::cell::{BoC, TonCell};

const EVENT_CLASS_NAME: &str = "event";
const EVENT_OPCODE: u64 = 3_812_333_683;
const FIELD_INFO_WIDTH: usize = 18;
const T_REF: u8 = 9;

#[derive(Debug, Clone)]
pub(crate) struct TonPacketSentEvent {
    pub(crate) packet: LzPacketV1,
    pub(crate) options: Value,
    pub(crate) send_library: String,
    pub(crate) endpoint_address: String,
    pub(crate) tx_hash: String,
    pub(crate) block_number: u64,
}

/// Normalize friendly and raw TON addresses to the canonical `workchain:hash`
/// representation used by the V3 API. Invalid values are lower-cased so that
/// malformed provider data cannot accidentally match a trusted address.
pub(crate) fn normalize_ton_address(value: &str) -> String {
    value
        .parse::<ton_core::types::TonAddress>()
        .map(|address| format!("{}:{}", address.workchain, hex::encode(address.hash)))
        .unwrap_or_else(|_| value.trim().to_ascii_lowercase())
}

/// Decode LayerZero's TON action-event trace. The V3 endpoint returns one
/// transaction tree whose `in_msg` at each node may itself be a LayerZero
/// internal message; flattening every child is therefore required, matching
/// `recursiveGetMessages` in common-ton/src/events.ts:168-179.
pub(crate) fn decode_ton_packet_sent_events(
    trace: &Value,
    trusted_emitters: &HashSet<String>,
    chain_name_by_eid: &HashMap<u32, String>,
) -> Vec<TonPacketSentEvent> {
    let mut nodes = Vec::new();
    collect_trace_nodes(trace, &mut nodes);
    nodes
        .into_iter()
        .filter_map(|node| decode_ton_message(node, trusted_emitters, chain_name_by_eid))
        .collect()
}

fn collect_trace_nodes<'a>(node: &'a Value, out: &mut Vec<&'a Value>) {
    out.push(node);
    if let Some(children) = node.get("children").and_then(Value::as_array) {
        for child in children {
            collect_trace_nodes(child, out);
        }
    }
}

fn decode_ton_message(
    node: &Value,
    trusted_emitters: &HashSet<String>,
    chain_name_by_eid: &HashMap<u32, String>,
) -> Option<TonPacketSentEvent> {
    let transaction = node.get("transaction")?;
    let message = transaction.get("in_msg")?;
    if message.is_null() {
        return None;
    }
    let destination = message.get("destination").and_then(Value::as_str)?;
    let normalized_destination = normalize_ton_address(destination);
    if !trusted_emitters.iter().any(|trusted| {
        normalize_ton_address(trusted) == normalized_destination
            || trusted.eq_ignore_ascii_case(destination)
    }) {
        return None;
    }
    let body = message
        .pointer("/message_content/body")
        .and_then(Value::as_str)?;
    let root = BoC::from_base64(body).ok()?.single_root().ok()?;
    let event = root.refs().first()?.clone();
    if class_name(&event).ok()?.as_str() != EVENT_CLASS_NAME {
        return None;
    }
    let packet_sent = class_ref(&event, 1).ok()?;
    if class_name(&packet_sent).ok()?.as_str() != "pktSent" {
        return None;
    }
    let topic = class_bytes(&event, 0, 256).ok()?;
    if topic[24..].try_into().ok().map(u64::from_be_bytes) != Some(EVENT_OPCODE) {
        return None;
    }
    let packet_cell = class_ref(&packet_sent, 4).ok()?;
    let packet = decode_packet(&packet_cell).ok()?;
    let send_library = format!("0x{}", hex::encode(class_bytes(&packet_sent, 6, 256).ok()?));
    let extra_options = class_ref(&packet_sent, 2).ok()?;
    let enforced_options = class_ref(&packet_sent, 3).ok()?;
    let dst_chain_name = chain_name_by_eid.get(&packet.dst_eid)?;
    let options =
        decode_ton_relayer_options(&extra_options, &enforced_options, dst_chain_name).ok()?;
    let tx_hash = transaction.get("hash").and_then(Value::as_str)?.to_string();
    let block_number = transaction
        .get("mc_block_seqno")
        .and_then(Value::as_u64)
        .or_else(|| {
            transaction
                .get("mc_block_seqno")
                .and_then(Value::as_str)?
                .parse()
                .ok()
        })?;
    Some(TonPacketSentEvent {
        packet,
        options,
        send_library,
        endpoint_address: destination.to_string(),
        tx_hash,
        block_number,
    })
}

fn decode_packet(cell: &TonCell) -> Result<LzPacketV1, AppCoreError> {
    let mut parser = cell.parser();
    let version = parser.read_num::<u8>(8).map_err(ton_error)?;
    if version != 1 {
        return Err(AppCoreError::Internal(format!(
            "unsupported TON packet version: {version}"
        )));
    }
    let nonce = parser.read_num::<u64>(64).map_err(ton_error)?;
    let src_eid = parser.read_num::<u32>(32).map_err(ton_error)?;
    let sender = parser.read_bits(256).map_err(ton_error)?;
    let dst_eid = parser.read_num::<u32>(32).map_err(ton_error)?;
    let receiver = parser.read_bits(256).map_err(ton_error)?;
    let guid = parser.read_bits(256).map_err(ton_error)?;
    let payload = parser.read_remaining().map_err(ton_error)?;
    let mut encoded = Vec::with_capacity(113);
    encoded.push(version);
    encoded.extend_from_slice(&nonce.to_be_bytes());
    encoded.extend_from_slice(&src_eid.to_be_bytes());
    encoded.extend_from_slice(&sender);
    encoded.extend_from_slice(&dst_eid.to_be_bytes());
    encoded.extend_from_slice(&receiver);
    encoded.extend_from_slice(&guid);
    encoded.extend_from_slice(&flatten_cell_bytes(&payload)?);
    decode_lz_packet_v1(&format!("0x{}", hex::encode(encoded)))
}

fn class_name(cell: &TonCell) -> Result<String, AppCoreError> {
    let mut parser = cell.parser();
    let bytes = parser.read_bits(80).map_err(ton_error)?;
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[first_nonzero..].to_vec())
        .map_err(|error| AppCoreError::Internal(format!("invalid TON class name: {error}")))
}

fn field_info(cell: &TonCell, index: usize) -> Result<(u8, usize, usize, usize), AppCoreError> {
    let mut parser = cell.parser();
    parser
        .read_bits(80 + index * FIELD_INFO_WIDTH)
        .map_err(ton_error)?;
    let field_type = parser.read_num::<u8>(4).map_err(ton_error)?;
    let cell_index = parser.read_num::<u8>(2).map_err(ton_error)?;
    let offset = parser.read_num::<u16>(10).map_err(ton_error)? as usize;
    let ref_index = parser.read_num::<u8>(2).map_err(ton_error)?;
    Ok((field_type, cell_index as usize, offset, ref_index as usize))
}

fn class_bytes(cell: &TonCell, index: usize, width: usize) -> Result<Vec<u8>, AppCoreError> {
    let (field_type, cell_index, offset, _) = field_info(cell, index)?;
    if field_type == T_REF {
        return Err(AppCoreError::Internal(
            "TON class field is a reference".to_string(),
        ));
    }
    let target = data_cell(cell, cell_index)?;
    let mut parser = target.parser();
    parser.seek_bits(offset as i32).map_err(ton_error)?;
    parser.read_bits(width).map_err(ton_error)
}

fn class_ref(cell: &TonCell, index: usize) -> Result<TonCell, AppCoreError> {
    let (field_type, cell_index, _, ref_index) = field_info(cell, index)?;
    if field_type != T_REF {
        return Err(AppCoreError::Internal(
            "TON class field is numeric".to_string(),
        ));
    }
    let target = data_cell(cell, cell_index)?;
    target
        .refs()
        .get(ref_index)
        .cloned()
        .ok_or_else(|| AppCoreError::Internal("TON class reference missing".to_string()))
}

fn data_cell(cell: &TonCell, cell_index: usize) -> Result<TonCell, AppCoreError> {
    if cell_index == 0 {
        return Ok(cell.clone());
    }
    cell.refs()
        .get(cell_index - 1)
        .cloned()
        .ok_or_else(|| AppCoreError::Internal("TON class data cell missing".to_string()))
}

fn flatten_cell_bytes(cell: &TonCell) -> Result<Vec<u8>, AppCoreError> {
    let mut bits = Vec::new();
    flatten_bits(cell, &mut bits)?;
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (index, bit) in bits.into_iter().enumerate() {
        if bit {
            bytes[index / 8] |= 1 << (7 - index % 8);
        }
    }
    Ok(bytes)
}

fn flatten_bits(cell: &TonCell, bits: &mut Vec<bool>) -> Result<(), AppCoreError> {
    let mut parser = cell.parser();
    let count = parser.data_bits_left().map_err(ton_error)?;
    for _ in 0..count {
        bits.push(parser.read_bit().map_err(ton_error)?);
    }
    for child in cell.refs() {
        flatten_bits(child, bits)?;
    }
    Ok(())
}

fn ton_error(error: impl std::fmt::Display) -> AppCoreError {
    AppCoreError::Internal(format!("TON cell decode error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ton_core::cell::{BoC, TonCell};

    fn metadata(builder: &mut ton_core::cell::CellBuilder, fields: &[(u8, usize, usize, usize)]) {
        for index in 0..15 {
            let (field_type, cell_index, offset, ref_index) =
                fields.get(index).copied().unwrap_or((0, 0, 0, 0));
            builder.write_num(&u64::from(field_type), 4).unwrap();
            builder.write_num(&(cell_index as u64), 2).unwrap();
            builder.write_num(&(offset as u64), 10).unwrap();
            builder.write_num(&(ref_index as u64), 2).unwrap();
        }
    }

    fn class_name_bits(builder: &mut ton_core::cell::CellBuilder, name: &str) {
        let mut bytes = [0u8; 10];
        let name = name.as_bytes();
        bytes[10 - name.len()..].copy_from_slice(name);
        builder.write_bits(bytes, 80).unwrap();
    }

    fn packet_cell() -> TonCell {
        let mut builder = TonCell::builder();
        builder.write_num(&1u64, 8).unwrap();
        builder.write_num(&7u64, 64).unwrap();
        builder.write_num(&30_343u64, 32).unwrap();
        builder.write_bits([0x11u8; 32], 256).unwrap();
        builder.write_num(&30_101u64, 32).unwrap();
        builder.write_bits([0x22u8; 32], 256).unwrap();
        builder.write_bits([0x33u8; 32], 256).unwrap();
        builder.write_bits([0xde, 0xad, 0xbe, 0xef], 32).unwrap();
        builder.build().unwrap()
    }

    fn packet_sent_cell() -> TonCell {
        let mut builder = TonCell::builder();
        class_name_bits(&mut builder, "pktSent");
        metadata(
            &mut builder,
            &[
                (3, 0, 350, 3),
                (3, 0, 358, 3),
                (T_REF, 0, 1023, 0),
                (T_REF, 0, 1023, 1),
                (T_REF, 0, 1023, 2),
                (6, 0, 366, 3),
                (8, 0, 430, 3),
                (T_REF, 0, 1023, 3),
            ],
        );
        builder.write_num(&0u64, 8).unwrap();
        builder.write_num(&0u64, 8).unwrap();
        builder.write_num(&7u64, 64).unwrap();
        builder.write_bits([0x44u8; 32], 256).unwrap();
        builder
            .write_ref(TonCell::empty().clone())
            .and_then(|_| builder.write_ref(TonCell::empty().clone()))
            .and_then(|_| builder.write_ref(packet_cell()))
            .and_then(|_| builder.write_ref(TonCell::empty().clone()))
            .unwrap();
        builder.build().unwrap()
    }

    fn event_body() -> String {
        let mut event = TonCell::builder();
        class_name_bits(&mut event, "event");
        metadata(
            &mut event,
            &[(8, 0, 350, 3), (T_REF, 0, 1023, 0), (T_REF, 0, 1023, 1)],
        );
        event.write_num(&EVENT_OPCODE, 256).unwrap();
        event
            .write_ref(packet_sent_cell())
            .and_then(|_| event.write_ref(TonCell::empty().clone()))
            .unwrap();
        let event = event.build().unwrap();
        let mut root = TonCell::builder();
        root.write_ref(event).unwrap();
        BoC::new(root.build().unwrap()).to_base64(true).unwrap()
    }

    #[test]
    fn ton_options_parity_decodes_structured_empty_options() {
        let trace = json!({
            "transaction": {
                "hash": "tx",
                "mc_block_seqno": 42,
                "in_msg": {
                    "destination": "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "message_content": {"body": event_body()}
                }
            },
            "children": []
        });
        let events = decode_ton_packet_sent_events(
            &trace,
            &HashSet::from([
                "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ]),
            &HashMap::from([
                (30_343, "ton".to_string()),
                (30_101, "ethereum".to_string()),
            ]),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].packet.nonce, 7);
        assert_eq!(events[0].packet.src_eid, 30_343);
        assert_eq!(events[0].packet.dst_eid, 30_101);
        assert_eq!(events[0].packet.message, "0xdeadbeef");
        assert_eq!(events[0].send_library, format!("0x{}", "44".repeat(32)));
        assert_eq!(
            serde_json::to_value(&events[0].options).unwrap(),
            json!({"ordered": false}),
            "empty extraOptions/enforcedOptions must serialize as an empty RelayerOptions object"
        );
    }

    #[test]
    fn rejects_untrusted_ton_event_message() {
        let trace = json!({
            "transaction": {
                "hash": "tx",
                "mc_block_seqno": 42,
                "in_msg": {
                    "destination": "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "message_content": {"body": event_body()}
                }
            },
            "children": []
        });
        assert!(decode_ton_packet_sent_events(
            &trace,
            &HashSet::from([
                "0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()
            ]),
            &HashMap::from([
                (30_343, "ton".to_string()),
                (30_101, "ethereum".to_string()),
            ]),
        )
        .is_empty());
    }

    #[test]
    fn canonicalizes_friendly_ton_addresses() {
        assert_eq!(
            normalize_ton_address(
                "0:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(
            normalize_ton_address("EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH")
                .starts_with("0:")
        );
        assert_eq!(normalize_ton_address("bad"), "bad");
    }
}
