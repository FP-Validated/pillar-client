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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EvmTransactionReceipt {
    #[serde(rename = "blockHash")]
    pub(crate) block_hash: String,
    #[serde(rename = "blockNumber")]
    pub(crate) block_number: String,
    // Missing execution status cannot prove success, so receipt decoding fails closed.
    pub(crate) status: String,
    pub(crate) logs: Vec<EvmReceiptLog>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EvmReceiptLog {
    pub(crate) address: String,
    pub(crate) topics: Vec<String>,
    pub(crate) data: String,
    #[serde(rename = "logIndex")]
    pub(crate) log_index: String,
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

/// Upstream's own `lzMessageIdMatches` (`common-model/src/v2/lzMessage.ts:201-218`): eids,
/// sender, receiver and nonce, without the chain names or the ULN version.
pub(crate) fn lz_message_identity_matches(expected: &LzMessageId, actual: &LzMessageId) -> bool {
    expected.nonce == actual.nonce && pathway_identity_matches(expected, actual)
}

/// Upstream's `lzPathwayIdMatches` (`common-model/src/v2/lzMessage.ts:201-214`):
/// eids by number and sender/receiver by `===` against the event's addresses as
/// `formatPathwayId` renders them, the sender in the source chain's encoding and
/// the receiver in the destination's (`lz-v2-sdk/src/utils/common/index.ts:19-36`).
fn pathway_identity_matches(expected: &LzMessageId, actual: &LzMessageId) -> bool {
    let eids_match = ["srcEid", "dstEid"].into_iter().all(|key| {
        let expected = expected.pathway_id.extra.get(key).and_then(Value::as_u64);
        expected.is_some() && expected == actual.pathway_id.extra.get(key).and_then(Value::as_u64)
    });
    eids_match
        && [
            ("sender", &actual.pathway_id.src_chain_name),
            ("receiver", &actual.pathway_id.dst_chain_name),
        ]
        .into_iter()
        .all(|(key, chain_name)| {
            let requested = expected.pathway_id.extra.get(key).and_then(Value::as_str);
            let resolved = actual
                .pathway_id
                .extra
                .get(key)
                .and_then(Value::as_str)
                .and_then(|raw| address_encoded_by_chain(chain_name, raw));
            requested.is_some() && requested == resolved.as_deref()
        })
}

/// `JSON.stringify(lzEvent.lzMessageId)` of a resolved event: `formatPathwayId`'s key
/// order with each address in its chain's rendering (`lz-v2-sdk/src/utils/common/index.ts:19-36`).
pub(crate) fn resolved_message_id_json(lz_message_id: &LzMessageId) -> String {
    let pathway = &lz_message_id.pathway_id;
    let extra = |key: &str| pathway.extra.get(key).cloned().unwrap_or(Value::Null);
    let address = |key: &str, chain_name: &str| {
        let raw = extra(key);
        let raw = raw.as_str().unwrap_or_default();
        Value::from(address_encoded_by_chain(chain_name, raw).unwrap_or_else(|| raw.to_string()))
    };
    format!(
        r#"{{"pathwayId":{{"srcEid":{},"srcChainName":{},"dstEid":{},"dstChainName":{},"sender":{},"receiver":{}}},"nonce":{},"ulnSendVersion":{}}}"#,
        pillar_core::js_json(&extra("srcEid")),
        pillar_core::js_json(&Value::from(pathway.src_chain_name.clone())),
        pillar_core::js_json(&extra("dstEid")),
        pillar_core::js_json(&Value::from(pathway.dst_chain_name.clone())),
        pillar_core::js_json(&address("sender", &pathway.src_chain_name)),
        pillar_core::js_json(&address("receiver", &pathway.dst_chain_name)),
        pillar_core::js_number_f64(lz_message_id.nonce as f64),
        pillar_core::js_json(&lz_message_id.uln_send_version),
    )
}

/// Upstream's `getAddressEncodedByChain` (`static-config/src/index.ts:695-729`)
/// over a hex address the packet carries: Solana is base58, the listed 32-byte
/// chains are padded lowercase hex, and every other chain is a 20-byte EVM
/// address. `None` where upstream would throw, and where an EVM rendering would
/// drop non-zero leading bytes, which upstream (and the destination's
/// `receiverB20()`) truncate and this service refuses as a policy (SECURITY.md).
pub(crate) fn address_encoded_by_chain(chain_name: &str, raw: &str) -> Option<String> {
    let digits = raw.strip_prefix("0x").unwrap_or(raw).to_ascii_lowercase();
    if digits.len() > 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{digits:0>64}");
    match chain_name {
        "solana" => Some(bs58::encode(hex::decode(&digits).ok()?).into_string()),
        "aptos" | "movement" | "initia" | "ton" | "sui" | "iotal1" | "starknet" | "stellar"
        | "canton" => Some(format!("0x{padded}")),
        _ => {
            let (leading, address) = padded.split_at(24);
            leading
                .bytes()
                .all(|byte| byte == b'0')
                .then(|| format!("0x{address}"))
        }
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
