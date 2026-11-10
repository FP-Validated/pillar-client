use super::*;
use serde::Serialize;

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

pub(crate) fn extra_context_sent_event_payload(
    sent_event: &LzSentEvent,
) -> Result<Value, AppCoreError> {
    if sent_event.extra.contains_key("optionsError") {
        return Err(AppCoreError::BadRequest(
            "Extra context policy requires successfully decoded packet options".to_string(),
        ));
    }
    let missing_identity = || {
        AppCoreError::BadRequest(
            "Extra context policy requires a resolved transaction and source block identity"
                .to_string(),
        )
    };
    let pathway = &sent_event.lz_message_id.pathway_id;
    let canton = pathway.src_chain_name == "canton";
    let (tx_hash, block_hash, block_number) = match sent_event.source_evidence.as_ref() {
        Some(pillar_core::SourceEvidence::Evm(evidence)) => (
            evidence.transaction_hash.as_str(),
            evidence.block_hash.as_str(),
            evidence.block_number,
        ),
        Some(pillar_core::SourceEvidence::Starknet(evidence)) => (
            evidence.transaction_hash.as_str(),
            evidence.block_hash.as_str(),
            evidence.block_number,
        ),
        // Canton has no blocks: upstream sends an empty hash beside the sequencer event nonce.
        None if canton => (
            sent_event.tx_hash.as_str(),
            "",
            sent_event
                .extra
                .get("blockNumber")
                .and_then(Value::as_i64)
                .ok_or_else(missing_identity)?,
        ),
        // Solana evidence only binds readiness; the policy body reads `extra` for it.
        Some(pillar_core::SourceEvidence::Solana(_)) | None => (
            sent_event
                .extra
                .get("onChainTxHash")
                .and_then(Value::as_str)
                .ok_or_else(missing_identity)?,
            sent_event
                .extra
                .get("blockHash")
                .and_then(Value::as_str)
                .ok_or_else(missing_identity)?,
            sent_event
                .extra
                .get("blockNumber")
                .and_then(Value::as_i64)
                .ok_or_else(missing_identity)?,
        ),
    };
    let block_hash_valid = if canton {
        block_hash.is_empty()
    } else {
        block_hash.strip_prefix("0x").is_some_and(|digits| {
            !digits.is_empty()
                && digits.len() <= 64
                && (pathway.src_chain_name == "starknet" || digits.len() == 64)
                && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    };
    if tx_hash.is_empty() || tx_hash == "undefined" || block_number < 0 || !block_hash_valid {
        return Err(missing_identity());
    }
    let mut value = serde_json::to_value(sent_event)
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    for (field, chain) in [
        ("sender", pathway.src_chain_name.as_str()),
        ("receiver", pathway.dst_chain_name.as_str()),
    ] {
        let address = pathway
            .extra
            .get(field)
            .and_then(Value::as_str)
            .and_then(|raw| address_encoded_by_chain(chain, raw))
            .ok_or_else(|| AppCoreError::BadRequest(format!("Invalid policy pathway {field}")))?;
        value["lzMessageId"]["pathwayId"][field] = Value::from(address);
    }
    let object = value.as_object_mut().ok_or_else(missing_identity)?;
    object.remove("txHash");
    object.remove("onChainTxHash");
    object.insert(
        "onChainEvent".to_string(),
        json!({
            "chainName": pathway.src_chain_name,
            "txHash": tx_hash,
            "blockHash": block_hash,
            "blockNumber": block_number,
        }),
    );
    Ok(value)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct EvmTransactionReceipt {
    #[serde(rename = "transactionHash")]
    pub(crate) transaction_hash: String,
    #[serde(rename = "blockHash")]
    pub(crate) block_hash: String,
    #[serde(rename = "blockNumber")]
    pub(crate) block_number: String,
    // Missing execution status cannot prove success, so receipt decoding fails closed.
    pub(crate) status: String,
    pub(crate) logs: Vec<EvmReceiptLog>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct EvmReceiptLog {
    pub(crate) address: String,
    pub(crate) topics: Vec<String>,
    pub(crate) data: String,
    #[serde(rename = "transactionHash")]
    pub(crate) transaction_hash: String,
    #[serde(rename = "blockHash")]
    pub(crate) block_hash: String,
    #[serde(rename = "blockNumber")]
    pub(crate) block_number: String,
    #[serde(rename = "logIndex")]
    pub(crate) log_index: String,
    #[serde(default)]
    pub(crate) removed: bool,
}

fn evm_transaction_hash_body(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}

pub(crate) fn evm_transaction_hash_matches(observed: &str, expected: &str) -> bool {
    evm_transaction_hash_body(observed).eq_ignore_ascii_case(evm_transaction_hash_body(expected))
}

fn normalize_evm_transaction_hash(value: &mut String) {
    value.make_ascii_lowercase();
    if !value.starts_with("0x") {
        value.insert_str(0, "0x");
    }
}

impl EvmTransactionReceipt {
    pub(crate) fn normalize(mut self, expected_tx_hash: &str) -> Result<Self, String> {
        let quantity = |value: &str, field: &str| {
            parse_numeric_string(value).ok_or_else(|| format!("invalid receipt {field}"))
        };
        normalize_evm_transaction_hash(&mut self.transaction_hash);
        if !evm_transaction_hash_matches(&self.transaction_hash, expected_tx_hash) {
            return Err("receipt transactionHash does not match requested transaction".to_string());
        }
        self.block_hash.make_ascii_lowercase();
        self.block_number = quantity(&self.block_number, "blockNumber")?;
        self.status = quantity(&self.status, "status")?;
        for log in &mut self.logs {
            if log.removed {
                return Err("receipt contains a removed log".to_string());
            }
            normalize_evm_transaction_hash(&mut log.transaction_hash);
            log.block_hash.make_ascii_lowercase();
            log.block_number = quantity(&log.block_number, "log blockNumber")?;
            log.log_index = quantity(&log.log_index, "logIndex")?;
            if log.transaction_hash != self.transaction_hash
                || log.block_hash != self.block_hash
                || log.block_number != self.block_number
            {
                return Err("receipt log placement does not match its receipt".to_string());
            }
            log.address.make_ascii_lowercase();
            for topic in &mut log.topics {
                topic.make_ascii_lowercase();
            }
            log.data.make_ascii_lowercase();
        }
        let mut log_indices = std::collections::HashSet::with_capacity(self.logs.len());
        for log in &self.logs {
            if !log_indices.insert(log.log_index.as_str()) {
                return Err("receipt contains duplicate logIndex".to_string());
            }
        }
        // Providers list logs in their own order and number them from 0 or 1. Position in the
        // index-ordered list is the one shared coordinate, so downstream readers of the
        // retained receipt (array scans, the evidence index) see what the quorum agreed on.
        self.logs
            .sort_by_key(|log| log.log_index.parse::<u128>().unwrap_or(u128::MAX));
        for (position, log) in self.logs.iter_mut().enumerate() {
            log.log_index = position.to_string();
        }
        Ok(self)
    }
}

/// Providers number logs from 0 or 1 and list them in their own order, so the vote keeps the logs in
/// index order and not the indexes themselves.
pub(crate) fn evm_receipt_fingerprint(receipt: &EvmTransactionReceipt) -> Result<String, String> {
    let mut logs = receipt.logs.clone();
    logs.sort_by_key(|log| log.log_index.parse::<u128>().unwrap_or(u128::MAX));
    let mut value = serde_json::to_value(receipt).map_err(|error| error.to_string())?;
    let mut logs = serde_json::to_value(logs).map_err(|error| error.to_string())?;
    for log in logs.as_array_mut().into_iter().flatten() {
        if let Some(log) = log.as_object_mut() {
            log.remove("logIndex");
        }
    }
    value["logs"] = logs;
    super::canonical_json_fingerprint(&value).map_err(|error| error.to_string())
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

#[cfg(test)]
mod receipt_fingerprint_tests {
    use super::*;

    fn log(index: &str, data: &str) -> Value {
        json!({
            "address": "0x01", "topics": ["0x02"], "data": data,
            "transactionHash": "0x03", "blockHash": "0x04", "blockNumber": "0x5",
            "logIndex": index,
        })
    }

    fn fingerprint(logs: Vec<Value>) -> String {
        let receipt: EvmTransactionReceipt = serde_json::from_value(json!({
            "transactionHash": "0x03", "blockHash": "0x04", "blockNumber": "0x5",
            "status": "0x1", "logs": logs,
        }))
        .unwrap();
        evm_receipt_fingerprint(&receipt.normalize("0x03").unwrap()).unwrap()
    }

    #[test]
    fn providers_numbering_the_same_logs_from_zero_or_one_cast_the_same_vote() {
        assert_eq!(
            fingerprint(vec![log("0x0", "0xaa"), log("0x1", "0xbb")]),
            fingerprint(vec![log("0x1", "0xaa"), log("0x2", "0xbb")]),
        );
    }

    #[test]
    fn log_order_is_the_index_order_whatever_order_the_provider_lists_them() {
        assert_eq!(
            fingerprint(vec![log("0x0", "0xaa"), log("0x1", "0xbb")]),
            fingerprint(vec![log("0x1", "0xbb"), log("0x0", "0xaa")]),
        );
    }

    #[test]
    fn different_logs_are_different_votes() {
        assert_ne!(
            fingerprint(vec![log("0x0", "0xaa"), log("0x1", "0xbb")]),
            fingerprint(vec![log("0x0", "0xbb"), log("0x1", "0xaa")]),
        );
    }
}
