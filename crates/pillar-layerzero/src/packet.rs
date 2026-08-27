use pillar_core::{AppCoreError, LzSentEvent};
use sha3::{Digest, Sha3_256};

use crate::abi::{
    abi_address, abi_dynamic_bytes, address_to_bytes32, decode_hex_20, decode_hex_32,
    decode_hex_bytes, keccak256_hex, native_address_to_bytes32,
};
use crate::types::{
    UlnV2HashInfo, ENDPOINT_V2_PACKET_SENT_TOPIC, LEGACY_ULN_V2_PACKET_TOPIC,
    ULN_301_PACKET_SENT_TOPIC,
};

mod event;

pub use event::compute_lz_packet_v1_proof_from_event;
pub(crate) use event::{
    extra_string, extra_u64, pathway_extra_string, proof_from_event, uln_send_version_string,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmUlnProof {
    pub packet_header: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LzPacketV1 {
    pub nonce: u64,
    pub src_eid: u32,
    pub sender: String,
    pub dst_eid: u32,
    pub receiver: String,
    pub guid: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmPacketSent {
    pub packet: LzPacketV1,
    pub options: String,
    pub send_library: Option<String>,
}

pub fn build_evm_lz_v1_packet_payload_v2(
    nonce: u64,
    src_eid: u64,
    sender: &str,
    dst_eid: u64,
    receiver: &str,
    message: &str,
) -> Result<String, AppCoreError> {
    let src_eid = u16::try_from(src_eid)
        .map_err(|_| AppCoreError::Internal("srcEid exceeds uint16".to_string()))?;
    let dst_eid = u16::try_from(dst_eid)
        .map_err(|_| AppCoreError::Internal("dstEid exceeds uint16".to_string()))?;
    let mut out = Vec::new();
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(&src_eid.to_be_bytes());
    out.extend_from_slice(&decode_hex_20(sender)?);
    out.extend_from_slice(&dst_eid.to_be_bytes());
    out.extend_from_slice(&decode_hex_bytes(receiver)?);
    out.extend_from_slice(&decode_hex_bytes(message)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_lz_v1_packet_payload_v2_from_event(
    sent_event: &LzSentEvent,
) -> Result<String, AppCoreError> {
    build_evm_lz_v1_packet_payload_v2(
        sent_event.lz_message_id.nonce,
        extra_u64(sent_event, "srcEid")?,
        &pathway_extra_string(sent_event, "sender")?,
        extra_u64(sent_event, "dstEid")?,
        &pathway_extra_string(sent_event, "receiver")?,
        &sent_event.message,
    )
}

pub fn build_evm_feather_proof(
    packet_emit_address: &str,
    packet_payload: &str,
) -> Result<String, AppCoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&address_to_bytes32(packet_emit_address)?);
    out.extend_from_slice(&decode_hex_bytes(packet_payload)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn native_hash_by_chain_name(data: &str, dst_chain_name: &str) -> Result<String, AppCoreError> {
    let bytes = decode_hex_bytes(data)?;
    if dst_chain_name == "aptos" {
        Ok(hex::encode(Sha3_256::digest(bytes)))
    } else {
        Ok(keccak256_hex(&bytes))
    }
}

pub fn derive_evm_feather_hash_info(
    sent_event: &LzSentEvent,
    packet_emit_address: &str,
) -> Result<UlnV2HashInfo, AppCoreError> {
    let packet_payload = build_evm_lz_v1_packet_payload_v2_from_event(sent_event)?;
    let proof = build_evm_feather_proof(packet_emit_address, &packet_payload)?;
    let hash =
        native_hash_by_chain_name(&proof, &sent_event.lz_message_id.pathway_id.dst_chain_name)?;
    Ok(UlnV2HashInfo {
        lookup_hash: hash.clone(),
        block_data: hash,
    })
}

pub fn encode_lz_packet_v1(packet: &LzPacketV1) -> Result<Vec<u8>, AppCoreError> {
    let message = decode_hex_bytes(&packet.message)?;
    let mut out = Vec::with_capacity(113 + message.len());
    out.push(1);
    out.extend_from_slice(&packet.nonce.to_be_bytes());
    out.extend_from_slice(&packet.src_eid.to_be_bytes());
    out.extend_from_slice(&native_address_to_bytes32(&packet.sender)?);
    out.extend_from_slice(&packet.dst_eid.to_be_bytes());
    out.extend_from_slice(&native_address_to_bytes32(&packet.receiver)?);
    out.extend_from_slice(&decode_hex_32(&packet.guid)?);
    out.extend_from_slice(&message);
    Ok(out)
}

pub fn decode_lz_packet_v1(value: &str) -> Result<LzPacketV1, AppCoreError> {
    let bytes = decode_hex_bytes(value)?;
    if bytes.len() < 113 {
        return Err(AppCoreError::Internal(format!(
            "invalid packet length: {}",
            bytes.len()
        )));
    }
    if bytes[0] != 1 {
        return Err(AppCoreError::Internal(format!(
            "unsupported packet version: {}",
            bytes[0]
        )));
    }
    Ok(LzPacketV1 {
        nonce: u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| AppCoreError::Internal("invalid nonce".to_string()))?,
        ),
        src_eid: u32::from_be_bytes(
            bytes[9..13]
                .try_into()
                .map_err(|_| AppCoreError::Internal("invalid srcEid".to_string()))?,
        ),
        sender: format!("0x{}", hex::encode(&bytes[13..45])),
        dst_eid: u32::from_be_bytes(
            bytes[45..49]
                .try_into()
                .map_err(|_| AppCoreError::Internal("invalid dstEid".to_string()))?,
        ),
        receiver: format!("0x{}", hex::encode(&bytes[49..81])),
        guid: format!("0x{}", hex::encode(&bytes[81..113])),
        message: format!("0x{}", hex::encode(&bytes[113..])),
    })
}

/// The LayerZero read-channel endpoint ids, `ChannelId.READ_CHANNEL_1` through
/// `READ_CHANNEL_10` in `@layerzerolabs/lz-definitions@3.1.2`
/// (`dist/index.d.ts:2982-2994`): 4_294_967_295 down to 4_294_967_286. The ten
/// values are contiguous, so an inclusive range is exactly the enum's value set -
/// upstream tests membership with `Object.values(ChannelId).includes(Number(eid))`
/// (TS: `packages/common-model/src/utils/index.ts:38-40`).
const READ_CHANNEL_EID_RANGE: std::ops::RangeInclusive<u32> = 4_294_967_286..=4_294_967_295;

/// Whether a source endpoint id addresses a read channel rather than a chain.
pub fn is_lz_read_endpoint_id(endpoint_id: u32) -> bool {
    READ_CHANNEL_EID_RANGE.contains(&endpoint_id)
}

/// Splits an encoded PacketV1 into the signed header and payload hash.
///
/// The payload hash depends on the source endpoint. A read channel hashes the
/// message alone; every other source hashes `guid || message`. Upstream:
///
/// ```text
/// const payloadHash = isLzReadEndpointId(lzMessage.lzMessageId.pathwayId.srcEid)
///     ? ethers.utils.keccak256(codec.message())
///     : codec.payloadHash()
/// ```
///
/// TS: `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:68-72`. In the encoding
/// `encode_lz_packet_v1` produces, `codec.header()` is `[..81]`,
/// `codec.payloadHash()` is `keccak(guid || message)` = `keccak([81..])`, and
/// `codec.message()` is `[113..]` - guid occupies `[81..113]`.
///
/// On the read path that message is the read command, so `keccak(message)` is the
/// command hash - which upstream states outright where it consumes the value:
/// `// Proof.payloadHash is the cmdHash in ReadV1002`
/// (TS: `packages/sdks/lz-v2-sdk/src/uln/evm/index.ts:323`).
///
/// This matters because `payload_hash` is signed: it is the second `bytes32`
/// argument of both `ReceiveUln302.verify` and `ReadLib1002.verify`
/// (`read_v1002.rs:build_evm_uln_read_v1_verify_call_data`).
///
/// How a read packet gets here: `EvmPacketSentResolver` flips the two endpoint ids for
/// `ReadV1002`, exactly as upstream's decoder does (TS:
/// `packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:292-295`), so the
/// post-flip `src_eid` is the read channel. Both chain names are then mapped from
/// `dst_eid` (`formatPathwayId`, TS: `utils/common/index.ts:24-26`), because a channel
/// is not a chain and `chain_name_by_eid` only ever holds chains. That mapping is what
/// makes this branch reachable - looking `src_eid` up directly failed every read packet
/// with `No chain name for endpoint id 4294967295`. Covered end to end by
/// `runtime_evm_resolver_maps_a_read_channel_pathway_like_typescript`.
pub fn compute_lz_packet_v1_proof(packet: &LzPacketV1) -> Result<EvmUlnProof, AppCoreError> {
    let encoded = encode_lz_packet_v1(packet)?;
    let packet_header = format!("0x{}", hex::encode(&encoded[..81]));
    let payload_hash = if is_lz_read_endpoint_id(packet.src_eid) {
        keccak256_hex(&encoded[113..])
    } else {
        keccak256_hex(&encoded[81..])
    };
    Ok(EvmUlnProof {
        packet_header,
        payload_hash,
    })
}

pub fn decode_evm_packet_sent_log(
    topics: &[String],
    data: &str,
) -> Result<EvmPacketSent, AppCoreError> {
    let topic0 = topics
        .first()
        .map(|topic| topic.to_lowercase())
        .ok_or_else(|| AppCoreError::Internal("missing event topic".to_string()))?;
    let data = decode_hex_bytes(data)?;
    match topic0.as_str() {
        LEGACY_ULN_V2_PACKET_TOPIC => {
            let encoded_payload = abi_dynamic_bytes(&data, 0, 1)?;
            Ok(EvmPacketSent {
                packet: decode_evm_legacy_packet_v2_payload(&encoded_payload)?,
                options: "0x".to_string(),
                send_library: None,
            })
        }
        ENDPOINT_V2_PACKET_SENT_TOPIC => {
            let encoded_payload = abi_dynamic_bytes(&data, 0, 3)?;
            let options = abi_dynamic_bytes(&data, 1, 3)?;
            let send_library = abi_address(&data, 2, 3)?;
            Ok(EvmPacketSent {
                packet: decode_lz_packet_v1(&format!("0x{}", hex::encode(encoded_payload)))?,
                options: format!("0x{}", hex::encode(options)),
                send_library: Some(send_library),
            })
        }
        ULN_301_PACKET_SENT_TOPIC => {
            let encoded_payload = abi_dynamic_bytes(&data, 0, 4)?;
            let options = abi_dynamic_bytes(&data, 1, 4)?;
            Ok(EvmPacketSent {
                packet: decode_lz_packet_v1(&format!("0x{}", hex::encode(encoded_payload)))?,
                options: format!("0x{}", hex::encode(options)),
                send_library: None,
            })
        }
        _ => Err(AppCoreError::Internal(
            "Unsupported PacketSent event topic".to_string(),
        )),
    }
}

pub fn decode_evm_legacy_packet_v2_payload(payload: &[u8]) -> Result<LzPacketV1, AppCoreError> {
    const EVM_ADDRESS_LEN: usize = 20;
    const MIN_LEN: usize = 8 + 2 + EVM_ADDRESS_LEN + 2 + EVM_ADDRESS_LEN;
    if payload.len() < MIN_LEN {
        return Err(AppCoreError::Internal(format!(
            "invalid legacy packet payload length: {}",
            payload.len()
        )));
    }
    let nonce = u64::from_be_bytes(
        payload[0..8]
            .try_into()
            .map_err(|_| AppCoreError::Internal("invalid legacy packet nonce".to_string()))?,
    );
    let src_eid = u16::from_be_bytes(
        payload[8..10]
            .try_into()
            .map_err(|_| AppCoreError::Internal("invalid legacy packet srcEid".to_string()))?,
    ) as u32;
    let sender_start = 10;
    let sender_end = sender_start + EVM_ADDRESS_LEN;
    let dst_eid_start = sender_end;
    let dst_eid_end = dst_eid_start + 2;
    let dst_eid = u16::from_be_bytes(
        payload[dst_eid_start..dst_eid_end]
            .try_into()
            .map_err(|_| AppCoreError::Internal("invalid legacy packet dstEid".to_string()))?,
    ) as u32;
    let receiver_start = dst_eid_end;
    let receiver_end = receiver_start + EVM_ADDRESS_LEN;
    Ok(LzPacketV1 {
        nonce,
        src_eid,
        sender: format!("0x{}", hex::encode(&payload[sender_start..sender_end])),
        dst_eid,
        receiver: format!("0x{}", hex::encode(&payload[receiver_start..receiver_end])),
        guid: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        message: format!("0x{}", hex::encode(&payload[receiver_end..])),
    })
}
