use pillar_core::{AppCoreError, LzSentEvent};
use serde_json::Value;

use super::{compute_lz_packet_v1_proof, EvmUlnProof, LzPacketV1};

pub fn compute_lz_packet_v1_proof_from_event(
    sent_event: &LzSentEvent,
) -> Result<EvmUlnProof, AppCoreError> {
    if let (Some(packet_header), Some(payload_hash)) = (
        optional_extra_string(sent_event, "packetHeader"),
        optional_extra_string(sent_event, "payloadHash"),
    ) {
        return Ok(EvmUlnProof {
            packet_header,
            payload_hash,
        });
    }
    compute_lz_packet_v1_proof(&packet_from_event(sent_event)?)
}

pub(crate) fn proof_from_event(sent_event: &LzSentEvent) -> Result<EvmUlnProof, AppCoreError> {
    compute_lz_packet_v1_proof_from_event(sent_event)
}

fn packet_from_event(sent_event: &LzSentEvent) -> Result<LzPacketV1, AppCoreError> {
    Ok(LzPacketV1 {
        nonce: sent_event.lz_message_id.nonce,
        src_eid: extra_u32(sent_event, "srcEid")?,
        sender: pathway_extra_string(sent_event, "sender")?,
        dst_eid: extra_u32(sent_event, "dstEid")?,
        receiver: pathway_extra_string(sent_event, "receiver")?,
        guid: extra_string(sent_event, "guid")?,
        message: sent_event.message.clone(),
    })
}

pub(crate) fn extra_string(sent_event: &LzSentEvent, key: &str) -> Result<String, AppCoreError> {
    optional_extra_string(sent_event, key)
        .ok_or_else(|| AppCoreError::Internal(format!("Missing sent_event.extra.{key}")))
}

pub(crate) fn optional_extra_string(sent_event: &LzSentEvent, key: &str) -> Option<String> {
    sent_event
        .extra
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

pub(crate) fn extra_u64(sent_event: &LzSentEvent, key: &str) -> Result<u64, AppCoreError> {
    sent_event
        .lz_message_id
        .pathway_id
        .extra
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}")))
}

pub(crate) fn extra_u32(sent_event: &LzSentEvent, key: &str) -> Result<u32, AppCoreError> {
    let value = extra_u64(sent_event, key)?;
    u32::try_from(value)
        .map_err(|_| AppCoreError::Internal(format!("lzMessageId.pathwayId.{key} exceeds u32")))
}

pub(crate) fn pathway_extra_string(
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

pub(crate) fn uln_send_version_string(value: &Value) -> Result<String, AppCoreError> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| AppCoreError::Internal("ulnSendVersion must be a string".to_string()))
}
