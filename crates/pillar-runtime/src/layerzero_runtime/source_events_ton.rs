use super::*;
use crate::provider_health::drop_json_value_safely;
use std::collections::{HashMap, HashSet};
use ton_core::cell::{BoC, TonCell};

const EVENT_CLASS_NAME: &str = "event";
const EVENT_OPCODE: u64 = 3_812_333_683;
/// `EVENTS.Channel_event_PACKET_SENT.stringValue` (`lz-ton-contracts/src/channel.ts:24`).
const PACKET_SENT_SUBTOPIC: &str = "Channel::event::PACKET_SENT";
const CHANNEL_CLASS_NAME: &str = "channel";
const FIELD_INFO_WIDTH: usize = 18;
const T_REF: u8 = 9;
// Each trace edge adds an object and children array to the returned JSON tree.
const MAX_TON_TRACE_OUTPUT_DEPTH: usize = 512;
const MAX_TON_TRACE_NODES: usize = 512;
const MAX_TON_TRACE_PROJECTED_STRING_BYTES: usize = 4 * 1024 * 1024;

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

/// toncenter v3 `/events` and `/traces` answer `{traces|events: [{trace, transactions}]}`;
/// upstream `TonClient3.transformToTransactionTrace` turns the first item into a
/// `{transaction, children}` tree, which `/transactionTrace` already returns.
pub(crate) fn ton_transaction_trace_tree(response: &Value) -> Option<Value> {
    let (root, transactions): (&Value, Option<&serde_json::Map<String, Value>>) =
        if response.get("transaction").is_some() {
            (response, None)
        } else {
            let item = response
                .get("traces")
                .or_else(|| response.get("events"))?
                .as_array()?
                .first()?;
            (
                item.get("trace")?,
                Some(item.get("transactions")?.as_object()?),
            )
        };
    let plan = ton_trace_preflight(root, transactions)?;
    let mut built = Vec::with_capacity(plan.len());
    for (transaction, child_count) in plan {
        let transaction = project_ton_transaction(transaction)?;
        let start = built.len().checked_sub(child_count)?;
        let child_trees = built.drain(start..).collect::<Vec<_>>();
        let mut tree = serde_json::Map::new();
        tree.insert("transaction".to_string(), transaction);
        tree.insert("children".to_string(), Value::Array(child_trees));
        built.push(Value::Object(tree));
    }
    (built.len() == 1).then(|| built.pop()).flatten()
}

fn ton_trace_children(node: &Value) -> Option<&[Value]> {
    match node.get("children") {
        None => Some(&[]),
        Some(Value::Array(children)) => Some(children),
        Some(_) => None,
    }
}

fn ton_trace_preflight<'a>(
    root: &'a Value,
    transactions: Option<&'a serde_json::Map<String, Value>>,
) -> Option<Vec<(&'a Value, usize)>> {
    enum Work<'a> {
        Visit(&'a Value, usize),
        Build(&'a Value, usize),
    }
    let mut pending = vec![Work::Visit(root, 1)];
    let mut plan = Vec::new();
    let mut seen_hashes = HashSet::new();
    let mut projected_bytes = 0usize;
    let mut discovered = 1usize;
    while let Some(work) = pending.pop() {
        match work {
            Work::Visit(node, depth) => {
                if depth.checked_mul(2)?.checked_add(2)? > MAX_TON_TRACE_OUTPUT_DEPTH {
                    return None;
                }
                let children = ton_trace_children(node)?;
                discovered = discovered.checked_add(children.len())?;
                if discovered > MAX_TON_TRACE_NODES {
                    return None;
                }
                let transaction = if let Some(transactions) = transactions {
                    let hash = node.get("tx_hash")?.as_str()?;
                    if !seen_hashes.insert(hash) {
                        return None;
                    }
                    transactions.get(hash)?
                } else {
                    node.get("transaction")?
                };
                if transactions.is_none() {
                    if let Some(hash) = transaction.get("hash") {
                        let hash = hash.as_str()?;
                        if !seen_hashes.insert(hash) {
                            return None;
                        }
                    }
                }
                account_ton_transaction(transaction, &mut projected_bytes)?;
                pending.push(Work::Build(transaction, children.len()));
                pending.extend(
                    children
                        .iter()
                        .rev()
                        .map(|child| Work::Visit(child, depth + 1)),
                );
            }
            Work::Build(transaction, child_count) => plan.push((transaction, child_count)),
        }
    }
    Some(plan)
}

fn account_ton_transaction(transaction: &Value, projected_bytes: &mut usize) -> Option<()> {
    let transaction = transaction.as_object()?;
    for field in ["hash", "mc_block_seqno"] {
        if let Some(value) = transaction.get(field) {
            account_ton_scalar(value, projected_bytes)?;
        }
    }
    if let Some(message) = transaction.get("in_msg") {
        if !message.is_null() {
            let message = message.as_object()?;
            for field in ["destination", "opcode", "source", "hash", "bounced"] {
                if let Some(value) = message.get(field) {
                    account_ton_scalar(value, projected_bytes)?;
                }
            }
            if let Some(content) = message.get("message_content") {
                let content = content.as_object()?;
                if let Some(body) = content.get("body") {
                    account_ton_scalar(body, projected_bytes)?;
                }
            }
        }
    }
    Some(())
}

fn account_ton_scalar(value: &Value, projected_bytes: &mut usize) -> Option<()> {
    let size = match value {
        Value::String(text) => text.len(),
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        Value::Array(_) | Value::Object(_) => return None,
    };
    *projected_bytes = projected_bytes.checked_add(size)?;
    (*projected_bytes <= MAX_TON_TRACE_PROJECTED_STRING_BYTES).then_some(())
}

fn project_ton_transaction(transaction: &Value) -> Option<Value> {
    let mut projected = serde_json::Map::new();
    for field in ["hash", "mc_block_seqno"] {
        if let Some(value) = transaction.get(field) {
            projected.insert(field.to_string(), clone_ton_scalar(value)?);
        }
    }
    if let Some(message) = transaction.get("in_msg") {
        if message.is_null() {
            projected.insert("in_msg".to_string(), Value::Null);
        } else {
            let mut projected_message = serde_json::Map::new();
            for field in ["destination", "opcode", "source", "hash", "bounced"] {
                if let Some(value) = message.get(field) {
                    projected_message.insert(field.to_string(), clone_ton_scalar(value)?);
                }
            }
            if let Some(body) = message.pointer("/message_content/body") {
                let mut content = serde_json::Map::new();
                content.insert("body".to_string(), clone_ton_scalar(body)?);
                projected_message.insert("message_content".to_string(), Value::Object(content));
            }
            projected.insert("in_msg".to_string(), Value::Object(projected_message));
        }
    }
    Some(Value::Object(projected))
}

fn clone_ton_scalar(value: &Value) -> Option<Value> {
    match value {
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => Some(value.clone()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// Upstream `TonClient3.getTransactionTrace`: `/events`, then `/traces`, then
/// `/transactionTrace`, taking the first that answers with a trace. `encoded_tx_hash`
/// must already have passed `encode_path_segment`.
pub(crate) async fn fetch_ton_transaction_trace<T: JsonRpcTransport>(
    transport: &T,
    endpoint: &str,
    headers: &HashMap<String, String>,
    encoded_tx_hash: &str,
) -> Result<Option<Value>, RpcError> {
    let base = endpoint.trim_end_matches('/');
    let mut observation = Ok(None);
    for url in [
        format!("{base}/events?tx_hash={encoded_tx_hash}"),
        format!("{base}/traces?tx_hash={encoded_tx_hash}"),
        format!("{base}/transactionTrace?hash={encoded_tx_hash}"),
    ] {
        observation = provider_response(transport.get_ton_json_scoped(url, headers.clone()).await)
            .map(|response| {
                response.and_then(|value| {
                    let tree = ton_transaction_trace_tree(&value);
                    drop_json_value_safely(value);
                    tree
                })
            });
        if !matches!(observation, Ok(None)) {
            break;
        }
    }
    observation
}

/// Upstream `tonTransactionTraceMessagesQuorumFn` (`multiprovider/src/ton.ts:40-54`):
/// each node's `in_msg`, pre-order, projected to address, block seqno, body, bounced,
/// emitter, hash, subtopic and topic and folded through `hashFields`, so providers
/// agree on the messages and not on unrelated trace metadata. Missing `in_msg` and
/// malformed projections return `None` and therefore cost that provider its vote;
/// explicit `in_msg: null` is skipped, as upstream's `message !== null` does.
pub(crate) fn ton_trace_quorum_fingerprint(tree: &Value) -> Option<String> {
    let mut digests = Vec::new();
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        let transaction = node.get("transaction")?;
        match transaction.get("in_msg") {
            None => return None,
            Some(Value::Null) => {}
            Some(message) => digests.push(ton_message_digest(transaction, message)?),
        }
        let children = node.get("children")?.as_array()?;
        stack.extend(children.iter().rev());
    }
    Some(hash_fields(digests.iter().map(String::as_str)))
}

fn ton_message_digest(transaction: &Value, message: &Value) -> Option<String> {
    let body = message.pointer("/message_content/body");
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body?.as_str()?).ok()?;
    if !boc_checksum_holds(&bytes) {
        return None;
    }
    let root = BoC::from_bytes(bytes).ok()?.single_root().ok()?;
    // `_message.opcode ? BigInt(_message.opcode) : -1`, so JS-falsy values are -1.
    let opcode = match message.get("opcode") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::String(text)) if text.is_empty() => None,
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => None,
        Some(_) => Some(message_opcode(message)?),
    };
    let subtopic = match opcode {
        Some(EVENT_OPCODE) => Some(ascii_of_uint(
            &class_bytes(root.refs().first()?, 0, 256).ok()?,
        )),
        _ => None,
    };
    let topic = opcode.map_or_else(|| "-1".to_string(), |opcode| opcode.to_string());
    let bounced = match message.get("bounced") {
        None | Some(Value::Null) => "true".to_string(),
        Some(value) => js_string(Some(value)),
    };
    Some(hash_fields(
        [
            js_string(message.get("destination")),
            js_string(transaction.get("mc_block_seqno")),
            js_string(body),
            bounced,
            js_string(message.get("source")),
            js_string(message.get("hash")),
            subtopic.unwrap_or_else(|| "EMPTY".to_string()),
            topic,
        ]
        .iter()
        .map(String::as_str),
    ))
}

/// `@ton/core` `Cell.fromBoc` refuses a BOC whose CRC32C flag is set and whose trailing
/// checksum does not match (`Invalid CRC32C`); `ton_core` does not check it.
fn boc_checksum_holds(bytes: &[u8]) -> bool {
    const GENERIC_MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];
    if bytes.len() < 5 || bytes[..4] != GENERIC_MAGIC || bytes[4] & 0x40 == 0 {
        return true;
    }
    let Some((payload, checksum)) = bytes.split_last_chunk::<4>() else {
        return false;
    };
    let mut crc = !0u32;
    for byte in payload {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc == u32::from_le_bytes(*checksum)
}

/// `String(value ?? 'EMPTY')` for the JSON shapes a TON v3 trace carries.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "EMPTY".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// `bigintToAsciiString`: the value's minimal hex, read as bytes two digits at a time
/// (a trailing odd digit is dropped), decoded as Node's `ascii` (high bit cleared).
fn ascii_of_uint(be: &[u8]) -> String {
    let digits = hex::encode(be);
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let (pairs, _) = digits.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .map(|byte| char::from(byte & 0x7f))
        .collect()
}

/// Upstream `hashFields`: sha256 of each field, joined with `|`, hashed again.
pub(crate) fn hash_fields<'a>(fields: impl Iterator<Item = &'a str>) -> String {
    use sha2::{Digest, Sha256};
    let joined = fields
        .map(|field| hex::encode(Sha256::digest(field.as_bytes())))
        .collect::<Vec<_>>()
        .join("|");
    hex::encode(Sha256::digest(joined.as_bytes()))
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
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        out.push(node);
        if let Some(children) = node.get("children").and_then(Value::as_array) {
            pending.extend(children.iter().rev());
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
    // Upstream `isEventValid`: only the event opcode carries an action event.
    if message_opcode(message)? != EVENT_OPCODE {
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
    let topic = class_bytes(&event, 0, 256).ok()?;
    let start = topic.iter().position(|byte| *byte != 0)?;
    if &topic[start..] != PACKET_SENT_SUBTOPIC.as_bytes() {
        return None;
    }
    let packet_sent = class_ref(&event, 1).ok()?;
    if class_name(&packet_sent).ok()?.as_str() != "pktSent" {
        return None;
    }
    let packet_cell = class_ref(&packet_sent, 4).ok()?;
    if packet_cell.refs().len() > 1 {
        return None;
    }
    let packet = decode_packet(&packet_cell).ok()?;
    let source = message.get("source").and_then(Value::as_str)?;
    if !emitted_by_controller_owned_channel(
        &class_ref(&event, 2).ok()?,
        source,
        &normalized_destination,
        &packet,
    ) {
        return None;
    }
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

fn message_opcode(message: &Value) -> Option<u64> {
    match message.get("opcode")? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => text.parse().ok(),
        },
        _ => None,
    }
}

/// Upstream `isValidContractOwnedContract` plus the PACKET_SENT custom check
/// (`common-ton/src/events.ts:31-64`, `lz-ton-contracts/src/channel.ts:20-65`): the
/// sender must be the Channel whose StateInit is this initial storage, owned by the
/// controller the event went to, and that Channel's path must be the packet's.
fn emitted_by_controller_owned_channel(
    initial_storage: &TonCell,
    source: &str,
    controller: &str,
    packet: &LzPacketV1,
) -> bool {
    static CHANNEL_CODE: std::sync::LazyLock<Option<TonCell>> = std::sync::LazyLock::new(|| {
        pillar_config::ton_code_cell("Channel")
            .and_then(|hex| pillar_layerzero::ton_boc_from_hex(hex).ok())
    });
    let Some(code) = CHANNEL_CODE.as_ref() else {
        return false;
    };
    let check = || -> Option<bool> {
        if class_name(initial_storage).ok()? != CHANNEL_CLASS_NAME {
            return Some(false);
        }
        let owner = class_bytes(&class_ref(initial_storage, 0).ok()?, 0, 256).ok()?;
        if format!("0:{}", hex::encode(owner)) != controller {
            return Some(false);
        }
        let channel = pillar_layerzero::ton_state_init_address(0, code, initial_storage).ok()?;
        if format!("0:{}", hex::encode(channel.hash.as_slice())) != normalize_ton_address(source) {
            return Some(false);
        }
        let path = class_ref(initial_storage, 1).ok()?;
        let eid = |index| -> Option<u32> {
            Some(u32::from_be_bytes(
                class_bytes(&path, index, 32).ok()?.try_into().ok()?,
            ))
        };
        let address = |index| -> Option<String> {
            Some(format!(
                "0x{}",
                hex::encode(class_bytes(&path, index, 256).ok()?)
            ))
        };
        Some(
            eid(0)? == packet.src_eid
                && address(1)?.eq_ignore_ascii_case(&packet.sender)
                && eid(2)? == packet.dst_eid
                && address(3)?.eq_ignore_ascii_case(&packet.receiver),
        )
    };
    check().unwrap_or(false)
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

/// Upstream `clGetUint`/`clGetCellRef` (`common-ton/src/class/index.ts:237-275`): data
/// cell `i > 0` is the root's `i`-th reference, counted from zero.
fn data_cell(cell: &TonCell, cell_index: usize) -> Result<TonCell, AppCoreError> {
    if cell_index == 0 {
        return Ok(cell.clone());
    }
    cell.refs()
        .get(cell_index)
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

    /// The recorded mainnet PacketSent (`tests/gasolina_parity/source_replay`), whose
    /// controller-bound message is the only event in the trace.
    const RECORDED: &str =
        include_str!("../../tests/gasolina_parity/source_replay/ton-v3-events.response.json");
    const MAINNET_CONTROLLER: &str = "EQAesrvqPYwNQv9_1g8CZMhmyTS7_3J1Jsp1nnN0yuDBZrEH";

    fn bits_of(cell: &TonCell) -> (Vec<u8>, usize) {
        let mut parser = cell.parser();
        let count = parser.data_bits_left().unwrap();
        (parser.read_bits(count).unwrap(), count)
    }

    /// Copy of `cell` with `width` bits at `offset` overwritten and/or one reference
    /// replaced; everything else, including the other references, is preserved.
    fn rebuilt(
        cell: &TonCell,
        bits: Option<(usize, usize, &[u8])>,
        reference: Option<(usize, TonCell)>,
    ) -> TonCell {
        let (mut data, count) = bits_of(cell);
        if let Some((offset, width, value)) = bits {
            for index in 0..width {
                let bit = value[index / 8] >> (7 - index % 8) & 1;
                let at = offset + index;
                data[at / 8] = data[at / 8] & !(1 << (7 - at % 8)) | bit << (7 - at % 8);
            }
        }
        let mut builder = TonCell::builder();
        builder.write_bits(&data, count).unwrap();
        for (index, child) in cell.refs().iter().enumerate() {
            let child = match &reference {
                Some((at, replacement)) if *at == index => replacement.clone(),
                _ => child.clone(),
            };
            builder.write_ref(child).unwrap();
        }
        builder.build().unwrap()
    }

    fn with_class_ref(cell: &TonCell, field: usize, replacement: TonCell) -> TonCell {
        let (_, cell_index, _, ref_index) = field_info(cell, field).unwrap();
        if cell_index == 0 {
            return rebuilt(cell, None, Some((ref_index, replacement)));
        }
        let data = rebuilt(
            &cell.refs()[cell_index],
            None,
            Some((ref_index, replacement)),
        );
        rebuilt(cell, None, Some((cell_index, data)))
    }

    fn with_class_bits(cell: &TonCell, field: usize, width: usize, value: &[u8]) -> TonCell {
        let (_, cell_index, offset, _) = field_info(cell, field).unwrap();
        if cell_index == 0 {
            return rebuilt(cell, Some((offset, width, value)), None);
        }
        let data = rebuilt(&cell.refs()[cell_index], Some((offset, width, value)), None);
        rebuilt(cell, None, Some((cell_index, data)))
    }

    /// Decodes the recorded trace after `forge` rewrites the controller-bound event
    /// (root body cell -> new root body cell). When `rederive_sender` is set the
    /// message's sender becomes the Channel address of the forged initial storage, so
    /// the sender check cannot be what refuses it.
    fn events_after(forge: impl Fn(&TonCell) -> TonCell, rederive_sender: bool) -> usize {
        let mut response: Value = serde_json::from_str(RECORDED).unwrap();
        for transaction in response["events"][0]["transactions"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            let message = &mut transaction["in_msg"];
            let to_controller = message["destination"].as_str().map(normalize_ton_address)
                == Some(normalize_ton_address(MAINNET_CONTROLLER));
            if message_opcode(message) != Some(EVENT_OPCODE) || !to_controller {
                continue;
            }
            let root = BoC::from_base64(message["message_content"]["body"].as_str().unwrap())
                .unwrap()
                .single_root()
                .unwrap();
            let event = forge(&root.refs()[0]);
            if rederive_sender {
                let code = pillar_layerzero::ton_boc_from_hex(
                    pillar_config::ton_code_cell("Channel").unwrap(),
                )
                .unwrap();
                let channel = pillar_layerzero::ton_state_init_address(
                    0,
                    &code,
                    &class_ref(&event, 2).unwrap(),
                )
                .unwrap();
                message["source"] =
                    Value::from(format!("0:{}", hex::encode(channel.hash.as_slice())));
            }
            let root = rebuilt(&root, None, Some((0, event)));
            message["message_content"]["body"] =
                Value::from(BoC::new(root).to_base64(true).unwrap());
        }
        let tree = ton_transaction_trace_tree(&response).unwrap();
        decode_ton_packet_sent_events(
            &tree,
            &HashSet::from([MAINNET_CONTROLLER.to_string()]),
            &HashMap::from([
                (30_343, "ton".to_string()),
                (30_110, "arbitrum".to_string()),
            ]),
        )
        .len()
    }

    #[test]
    fn recorded_packet_sent_survives_a_lossless_rebuild() {
        assert_eq!(events_after(|event| rebuilt(event, None, None), true), 1);
    }

    /// A Channel StateInit naming another owner, with the sender set to that forged
    /// Channel's own address: only the owner check stands between it and a signature.
    #[test]
    fn ton_packet_sent_from_a_channel_owned_by_another_controller_is_refused() {
        let forged = events_after(
            |event| {
                let storage = class_ref(event, 2).unwrap();
                let base = with_class_bits(&class_ref(&storage, 0).unwrap(), 0, 256, &[0x5a; 32]);
                with_class_ref(event, 2, with_class_ref(&storage, 0, base))
            },
            true,
        );
        assert_eq!(forged, 0);
    }

    /// A controller-owned Channel whose path is another destination than the packet's.
    #[test]
    fn ton_packet_sent_from_a_channel_for_another_path_is_refused() {
        let forged = events_after(
            |event| {
                let storage = class_ref(event, 2).unwrap();
                let path = with_class_bits(
                    &class_ref(&storage, 1).unwrap(),
                    2,
                    32,
                    &30_111u32.to_be_bytes(),
                );
                with_class_ref(event, 2, with_class_ref(&storage, 1, path))
            },
            true,
        );
        assert_eq!(forged, 0);
    }

    /// A genuine Channel event that is not PACKET_SENT.
    #[test]
    fn ton_channel_event_with_another_subtopic_is_refused() {
        let mut topic = [0u8; 32];
        let name = b"Channel::event::PACKET_BURNT";
        topic[32 - name.len()..].copy_from_slice(name);
        assert_eq!(
            events_after(|event| with_class_bits(event, 0, 256, &topic), false),
            0
        );
    }

    /// The recorded trace and variants of it, each fingerprinted by upstream's own
    /// `tonTransactionTraceMessagesQuorumFn` (`source_replay/ton-trace-quorum.json`).
    #[test]
    fn trace_quorum_fingerprint_matches_upstream_for_every_variant() {
        let upstream: Value = serde_json::from_str(include_str!(
            "../../tests/gasolina_parity/source_replay/ton-trace-quorum.json"
        ))
        .unwrap();
        let recorded =
            ton_transaction_trace_tree(&serde_json::from_str(RECORDED).unwrap()).unwrap();
        fn controller_bound(node: &mut Value) -> Option<&mut Value> {
            if node["transaction"]["in_msg"]["opcode"] == "0xe33b9873" {
                return Some(&mut node["transaction"]);
            }
            node["children"]
                .as_array_mut()?
                .iter_mut()
                .find_map(controller_bound)
        }
        fn each(node: &mut Value, change: &dyn Fn(&mut Value)) {
            change(&mut node["transaction"]);
            for child in node["children"].as_array_mut().unwrap() {
                each(child, change);
            }
        }
        type Change = Box<dyn Fn(&mut Value)>;
        let variants: [(&str, Change); 21] = [
            ("recorded", Box::new(|_| {})),
            (
                "metadataOnly",
                Box::new(|trace| {
                    each(trace, &|transaction| {
                        transaction["finality"] = json!("pending");
                        transaction["emulated"] = json!(true);
                        transaction["account_state_after"] = json!({"hash": "changed"});
                        transaction["total_fees"] = json!("1");
                    })
                }),
            ),
            (
                "seqnoAsNumber",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["mc_block_seqno"] = json!(96828301u64);
                }),
            ),
            (
                "seqnoStringVsNumber",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["mc_block_seqno"] = json!("96828301");
                }),
            ),
            (
                "seqnoChanged",
                Box::new(|trace| {
                    let t = controller_bound(trace).unwrap();
                    t["mc_block_seqno"] = json!(t["mc_block_seqno"].as_u64().unwrap() + 1);
                }),
            ),
            (
                "missingInMsg",
                Box::new(|trace| {
                    controller_bound(trace)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove("in_msg");
                }),
            ),
            (
                "nullInMsg",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"] = Value::Null;
                }),
            ),
            (
                "missingTransaction",
                Box::new(|trace| {
                    trace.as_object_mut().unwrap().remove("transaction");
                }),
            ),
            (
                "missingChildren",
                Box::new(|trace| {
                    trace.as_object_mut().unwrap().remove("children");
                }),
            ),
            (
                "nonArrayChildren",
                Box::new(|trace| {
                    trace["children"] = Value::Null;
                }),
            ),
            (
                "missingMessageContent",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]
                        .as_object_mut()
                        .unwrap()
                        .remove("message_content");
                }),
            ),
            (
                "missingBody",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["message_content"]
                        .as_object_mut()
                        .unwrap()
                        .remove("body");
                }),
            ),
            (
                "bodyChanged",
                Box::new(|trace| {
                    let t = controller_bound(trace).unwrap();
                    let mut raw = base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        t["in_msg"]["message_content"]["body"].as_str().unwrap(),
                    )
                    .unwrap();
                    *raw.last_mut().unwrap() ^= 1;
                    t["in_msg"]["message_content"]["body"] = json!(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        raw
                    ));
                }),
            ),
            (
                "sourceChanged",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["source"] =
                        json!(format!("0:{}", "11".repeat(32).to_uppercase()));
                }),
            ),
            (
                "destinationChanged",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["destination"] =
                        json!(format!("0:{}", "22".repeat(32).to_uppercase()));
                }),
            ),
            (
                "hashChanged",
                Box::new(|trace| {
                    let message = &mut controller_bound(trace).unwrap()["in_msg"];
                    let hash = message["hash"].as_str().unwrap();
                    message["hash"] = json!(format!("AAAA{}", &hash[4..]));
                }),
            ),
            (
                "bouncedNull",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["bounced"] = Value::Null;
                }),
            ),
            (
                "bouncedTrue",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["bounced"] = json!(true);
                }),
            ),
            (
                "opcodeNull",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["opcode"] = Value::Null;
                }),
            ),
            (
                "opcodeDecimal",
                Box::new(|trace| {
                    controller_bound(trace).unwrap()["in_msg"]["opcode"] = json!("3812333683");
                }),
            ),
            (
                "childDropped",
                Box::new(|trace| {
                    trace["children"].as_array_mut().unwrap().pop();
                }),
            ),
        ];
        let upstream_variants = upstream["variants"].as_object().unwrap();
        let mut names: Vec<&str> = variants.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let mut upstream_names: Vec<&str> = upstream_variants.keys().map(String::as_str).collect();
        upstream_names.sort_unstable();
        assert_eq!(
            names, upstream_names,
            "every variant has exactly one upstream result"
        );
        for (name, change) in variants {
            let mut trace = recorded.clone();
            change(&mut trace);
            let expected = &upstream_variants[name];
            let actual = ton_trace_quorum_fingerprint(&trace);
            match (expected["fingerprint"].as_str(), expected["error"].as_str()) {
                (Some(fingerprint), None) => assert_eq!(
                    actual.as_deref(),
                    Some(fingerprint),
                    "{name}: upstream {expected}"
                ),
                (None, Some(error)) => assert!(
                    actual.is_none(),
                    "{name}: upstream refuses with {error}, got {actual:?}"
                ),
                _ => panic!(
                    "{name}: upstream result is neither a fingerprint nor an error: {expected}"
                ),
            }
        }
    }
}
