use super::*;

pub(crate) fn evm_receive_contract_pair<'a>(
    contracts: &'a EvmReceiveContracts,
    receive_version: &str,
) -> Result<(&'a str, &'a str), AppCoreError> {
    match receive_version {
        ULN_VERSION_V301 => {
            if contracts.receive_uln_301.is_empty() || contracts.receive_uln_301_view.is_empty() {
                return Err(AppCoreError::Internal(
                    "Missing ReceiveUln301 contracts".to_string(),
                ));
            }
            Ok((&contracts.receive_uln_301, &contracts.receive_uln_301_view))
        }
        ULN_VERSION_V302 => Ok((&contracts.receive_uln_302, &contracts.receive_uln_302_view)),
        ULN_VERSION_READ_V1002 => Ok((
            contracts.read_lib_1002.as_deref().ok_or_else(|| {
                AppCoreError::Internal("Missing ReadLib1002 receive contract".to_string())
            })?,
            contracts.read_lib_1002_view.as_deref().ok_or_else(|| {
                AppCoreError::Internal("Missing ReadLib1002View receive contract".to_string())
            })?,
        )),
        _ => Err(AppCoreError::Internal(format!(
            "Unsupported receive UlnVersion {receive_version}"
        ))),
    }
}

pub(crate) fn pathway_extra_u64(sent_event: &LzSentEvent, key: &str) -> Result<u64, AppCoreError> {
    sent_event
        .lz_message_id
        .pathway_id
        .extra
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}")))
}

pub(crate) fn pathway_extra_u32(sent_event: &LzSentEvent, key: &str) -> Result<u32, AppCoreError> {
    let value = pathway_extra_u64(sent_event, key)?;
    u32::try_from(value)
        .map_err(|_| AppCoreError::Internal(format!("lzMessageId.pathwayId.{key} exceeds u32")))
}

pub(crate) fn pathway_extra_string_value(
    sent_event: &LzSentEvent,
    key: &str,
) -> Result<String, AppCoreError> {
    sent_event
        .lz_message_id
        .pathway_id
        .extra
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}")))
}

pub(crate) fn extra_context_sent_event_payload(sent_event: &LzSentEvent) -> Value {
    let mut value = serde_json::to_value(sent_event).unwrap_or_else(|_| json!({}));
    let Some(object) = value.as_object_mut() else {
        return value;
    };
    object.remove("txHash");
    object.insert(
        "onChainEvent".to_string(),
        json!({
            "chainName": sent_event.lz_message_id.pathway_id.src_chain_name,
            "txHash": sent_event.tx_hash,
            "blockHash": sent_event
                .extra
                .get("blockHash")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "blockNumber": sent_event
                .extra
                .get("blockNumber")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
        }),
    );
    value
}

pub(crate) fn json_value_is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EvmTransactionReceipt {
    pub(crate) logs: Vec<EvmReceiptLog>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EvmReceiptLog {
    pub(crate) address: String,
    pub(crate) topics: Vec<String>,
    pub(crate) data: String,
}

pub(crate) fn normalize_address_map(map: HashMap<String, String>) -> HashMap<String, String> {
    map.into_iter()
        .map(|(address, value)| (normalize_address(&address), value))
        .collect()
}

pub(crate) fn normalize_address(value: &str) -> String {
    value.to_ascii_lowercase()
}

pub(crate) fn lz_message_id_matches(expected: &LzMessageId, actual: &LzMessageId) -> bool {
    expected.nonce == actual.nonce
        && expected.pathway_id.src_chain_name == actual.pathway_id.src_chain_name
        && expected.pathway_id.dst_chain_name == actual.pathway_id.dst_chain_name
        && uln_version_value(expected) == uln_version_value(actual)
        && pathway_identity_matches(expected, actual)
}

fn pathway_identity_matches(expected: &LzMessageId, actual: &LzMessageId) -> bool {
    ["srcEid", "dstEid"].into_iter().all(|key| {
        expected.pathway_id.extra.get(key).and_then(Value::as_u64)
            == actual.pathway_id.extra.get(key).and_then(Value::as_u64)
            && expected.pathway_id.extra.get(key).is_some()
            && actual.pathway_id.extra.get(key).is_some()
    }) && ["sender", "receiver"].into_iter().all(|key| {
        let Some(expected) = expected.pathway_id.extra.get(key).and_then(Value::as_str) else {
            return false;
        };
        let Some(actual) = actual.pathway_id.extra.get(key).and_then(Value::as_str) else {
            return false;
        };
        match (
            normalized_address_hex(expected),
            normalized_address_hex(actual),
        ) {
            (Some(expected_hex), Some(actual_hex)) => normalized_hex_identity(&expected_hex)
                .eq_ignore_ascii_case(normalized_hex_identity(&actual_hex)),
            _ => expected == actual,
        }
    })
}

/// Canonicalizes an address to a bare hex digit string for identity comparison.
/// Accepts `0x`-prefixed hex (EVM/Move-style addresses), base58-encoded
/// 32-byte values (Solana public keys), Stellar SEP-0023 StrKey
/// account/contract addresses, TON "user-friendly" addresses, or Initia
/// (Cosmos SDK) bech32 addresses — since `LzPacketV1` always decodes
/// sender/receiver as raw 32-byte hex regardless of the native chain's
/// address encoding, and real callers (LayerZero Scan included) report
/// addresses in each chain's native format, not that raw hex.
fn normalized_address_hex(value: &str) -> Option<String> {
    if let Some(digits) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return Some(digits.to_string());
    }
    if let Some(payload) = decode_stellar_strkey_payload(value) {
        return Some(hex::encode(payload));
    }
    if let Some(payload) = decode_ton_raw_address_payload(value) {
        return Some(hex::encode(payload));
    }
    if let Some(payload) = decode_ton_friendly_address_payload(value) {
        return Some(hex::encode(payload));
    }
    if let Some(payload) = decode_initia_bech32_payload(value) {
        return Some(hex::encode(payload));
    }
    let decoded = bs58::decode(value).into_vec().ok()?;
    if decoded.len() != 32 {
        return None;
    }
    Some(hex::encode(decoded))
}

/// Decodes a TON "user-friendly" address (base64/base64url, 48 chars) into
/// its raw 32-byte account id, verifying the CRC-16/XMODEM checksum and tag
/// byte. Returns `None` for any other length, tag, or malformed input.
fn decode_ton_friendly_address_payload(value: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    if value.len() != 48 {
        return None;
    }
    let normalized = value.replace('-', "+").replace('_', "/");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(normalized)
        .ok()?;
    if decoded.len() != 36 {
        return None;
    }
    let (tag_and_workchain_and_account, checksum) = decoded.split_at(34);
    let (tag, account_id) = tag_and_workchain_and_account.split_first()?;
    if !matches!(tag & 0x7f, 0x11 | 0x51) {
        return None;
    }
    let expected_checksum = crc16_xmodem(tag_and_workchain_and_account).to_be_bytes();
    if checksum != expected_checksum {
        return None;
    }
    account_id[1..].try_into().ok()
}

/// Decodes a TON "raw" address (`<workchain>:<64 hex chars>`, e.g.
/// `0:3333...3333`) into its raw 32-byte account id. This is the format
/// this codebase's own TON fixtures already use (see
/// `pillar-layerzero::other_non_evm::ton::SOURCE_VECTOR_DVN`).
fn decode_ton_raw_address_payload(value: &str) -> Option<[u8; 32]> {
    let (workchain, hash) = value.split_once(':')?;
    if workchain.is_empty()
        || !workchain
            .strip_prefix('-')
            .unwrap_or(workchain)
            .bytes()
            .all(|b| b.is_ascii_digit())
        || hash.len() != 64
    {
        return None;
    }
    let decoded = hex::decode(hash).ok()?;
    decoded.try_into().ok()
}

/// Decodes an Initia (Cosmos SDK) bech32 address with human-readable prefix
/// `init` into its raw account-id payload. `LzPacketV1` embeds it the same
/// way EVM's 20-byte addresses are embedded (zero-padded within the 32-byte
/// field), so the leading-zero-stripping identity compare handles the width
/// difference the same way it already does for EVM.
fn decode_initia_bech32_payload(value: &str) -> Option<Vec<u8>> {
    let (hrp, payload) = bech32::decode(value).ok()?;
    if hrp.as_str() != "init" {
        return None;
    }
    Some(payload)
}

/// Decodes a Stellar SEP-0023 StrKey (`G...` ed25519 account or `C...`
/// contract address) into its raw 32-byte payload, verifying the CRC16/XModem
/// checksum. Returns `None` for any other version byte or malformed input.
fn decode_stellar_strkey_payload(value: &str) -> Option<[u8; 32]> {
    if value.len() != 56
        || !value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return None;
    }
    let decoded = base32_decode_rfc4648(value)?;
    let (version_and_payload, checksum) = decoded.split_at(33);
    let (version, payload) = version_and_payload.split_first()?;
    if *version != 6 << 3 && *version != 2 << 3 {
        return None;
    }
    let expected_checksum = crc16_xmodem(version_and_payload).to_le_bytes();
    if checksum != expected_checksum {
        return None;
    }
    payload.try_into().ok()
}

fn base32_decode_rfc4648(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u32 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::with_capacity(value.len() * 5 / 8);
    for byte in value.bytes() {
        let index = ALPHABET.iter().position(|&c| c == byte)? as u32;
        bits = (bits << 5) | index;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xff) as u8);
        }
    }
    Some(out)
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn normalized_hex_identity(value: &str) -> &str {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let normalized = digits.trim_start_matches('0');
    if normalized.is_empty() {
        "0"
    } else {
        normalized
    }
}

pub(crate) fn uln_version_value(lz_message_id: &LzMessageId) -> Option<&str> {
    lz_message_id.uln_send_version.as_str()
}

pub(crate) fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
