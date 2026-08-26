use pillar_core::{AppCoreError, LzSentEvent};
use serde_json::Value;

use crate::packet::EvmUlnProof;
use crate::types::UlnV2HashInfo;

pub(crate) fn proof_details(
    method_name: &str,
    sent_event: &LzSentEvent,
    proof: EvmUlnProof,
    extra_uln_fields: Value,
) -> Result<Value, AppCoreError> {
    let mut uln_call_data = serde_json::json!({
        "methodName": method_name,
        "proof": {
            "packetHeader": proof.packet_header,
            "payloadHash": proof.payload_hash,
        }
    });
    let object = uln_call_data
        .as_object_mut()
        .ok_or_else(|| AppCoreError::Internal("ulnCallData must be an object".to_string()))?;
    if let Some(fields) = extra_uln_fields.as_object() {
        for (key, value) in fields {
            object.insert(key.clone(), value.clone());
        }
    }
    Ok(serde_json::json!({
        "ulnCallData": uln_call_data,
        "proof": {
            "payload": sent_event.message,
            "lzMessageId": sent_event.lz_message_id,
        }
    }))
}

pub(crate) fn uln_v2_proof_details(
    method_name: &str,
    sent_event: &LzSentEvent,
    hash_info: UlnV2HashInfo,
    extra_uln_fields: Value,
) -> Result<Value, AppCoreError> {
    let mut uln_call_data = serde_json::json!({
        "methodName": method_name,
        "proof": {
            "lookupHash": hash_info.lookup_hash,
            "blockData": hash_info.block_data,
        }
    });
    let object = uln_call_data
        .as_object_mut()
        .ok_or_else(|| AppCoreError::Internal("ulnCallData must be an object".to_string()))?;
    if let Some(fields) = extra_uln_fields.as_object() {
        for (key, value) in fields {
            object.insert(key.clone(), value.clone());
        }
    }
    Ok(serde_json::json!({
        "ulnCallData": uln_call_data,
        "proof": {
            "payload": sent_event.message,
            "lzMessageId": sent_event.lz_message_id,
        }
    }))
}
