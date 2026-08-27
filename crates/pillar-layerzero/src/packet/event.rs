use pillar_core::{AppCoreError, LzSentEvent};
use serde_json::Value;

use super::{compute_lz_packet_v1_proof, EvmUlnProof, LzPacketV1};

/// Derives the ULN proof from the observed event, always by re-encoding the packet.
///
/// The proof's two fields are the only chain-derived inputs to the signed ULN call
/// data, so they are never taken from the event verbatim. `sent_event.extra` is an
/// open map (`LzSentEvent.extra` flattens unknown keys), and this function used to
/// short-circuit to `extra.packetHeader` / `extra.payloadHash` when both were
/// present. No resolver ever wrote those keys into `extra` - every producer writes
/// them into the response `details` (`abi/details.rs`, `solana.rs`, `aptos.rs`,
/// `sui.rs`, `other_non_evm/{starknet,stellar}.rs`) - so the branch was dead, but it
/// let any future producer or deserialized input choose the signed bytes directly.
///
/// Upstream has no such short-circuit either: `computeLZMessageV2Proof` always
/// re-encodes (TS: `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:63-78`, which
/// calls `encodeLZMessage` then `PacketV1Codec.fromBytes`).
pub fn compute_lz_packet_v1_proof_from_event(
    sent_event: &LzSentEvent,
) -> Result<EvmUlnProof, AppCoreError> {
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
