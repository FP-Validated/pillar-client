use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};

use super::keccak0x;
use crate::abi::{decode_hex_32, decode_hex_bytes, u64_from_i64};
use crate::packet::{proof_from_event, EvmUlnProof};
use crate::types::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

const STARKNET_VERIFY_SELECTOR: &str =
    "0x027ea29384deca9928aa65088faae7fc2e5a99fd6512125ef320c18227e0f7d3";

#[derive(Debug, Clone)]
pub struct StarknetUlnPayloadBuilder {
    uln_302: String,
}

impl StarknetUlnPayloadBuilder {
    pub fn new(uln_302: impl Into<String>) -> Self {
        Self {
            uln_302: uln_302.into(),
        }
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for StarknetUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "Starknet only supports EndpointV2".to_string(),
        ))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for StarknetUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let proof = proof_from_event(sent_event)?;
        let calldata = verify_calldata(&proof, block_confirmation)?;
        let dvn_call_data = pack_dvn_call(&v_id, expiration, &self.uln_302, &calldata)?;
        let hash_call_data = keccak0x(&dvn_call_data);

        Ok(HashCallDataResult {
            hash_call_data,
            details: serde_json::json!({
                "dvnHashCallData": {
                    "dvnCallData": hex::encode(&dvn_call_data),
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": self.uln_302,
                    "ulnCallData": calldata.iter().map(|felt| format!("0x{}", hex::encode(felt))).collect::<Vec<_>>().join(","),
                },
                "ulnCallData": {
                    "methodName": "verify",
                    "proof": {
                        "packetHeader": proof.packet_header,
                        "payloadHash": proof.payload_hash,
                    },
                    "blockConfirmation": block_confirmation,
                },
                "proof": {
                    "payload": sent_event.message,
                    "lzMessageId": sent_event.lz_message_id,
                },
            }),
        })
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for StarknetUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "FIXME STARKNET-READ: Read DVN is not available on Starknet".to_string(),
        ))
    }
}

fn pack_dvn_call(
    v_id: &str,
    expiration: i64,
    uln_302: &str,
    calldata: &[[u8; 32]],
) -> Result<Vec<u8>, AppCoreError> {
    let vid = v_id
        .parse::<u32>()
        .map_err(|error| AppCoreError::Internal(error.to_string()))?;
    let expiration = u64_from_i64(expiration, "expiration")?;
    let mut out = Vec::with_capacity(4 + 32 + 32 + 32 + calldata.len() * 32);
    out.extend_from_slice(&vid.to_be_bytes());
    out.extend_from_slice(&felt_from_hex(uln_302)?);
    out.extend_from_slice(&u256_word(expiration));
    out.extend_from_slice(&felt_from_hex(STARKNET_VERIFY_SELECTOR)?);
    for felt in calldata {
        out.extend_from_slice(felt);
    }
    Ok(out)
}

fn verify_calldata(
    proof: &EvmUlnProof,
    block_confirmation: i64,
) -> Result<Vec<[u8; 32]>, AppCoreError> {
    let packet_header = decode_hex_bytes(&proof.packet_header)?;
    let payload_hash = decode_hex_32(&proof.payload_hash)?;
    let block_confirmation = u64_from_i64(block_confirmation, "blockConfirmation")?;
    // One split instead of chunking the header twice; the counts the upstream
    // calldata carries are exactly the chunk count and the remainder length.
    let (chunks, remainder) = packet_header.as_chunks::<31>();
    let mut calldata = Vec::with_capacity(chunks.len() + 5);
    calldata.push(u256_word(chunks.len() as u64));
    for chunk in chunks {
        calldata.push(felt_from_bytes(chunk));
    }
    calldata.push(felt_from_bytes(remainder));
    calldata.push(u256_word(remainder.len() as u64));
    calldata.push(felt_from_bytes(&payload_hash[16..]));
    calldata.push(felt_from_bytes(&payload_hash[..16]));
    calldata.push(u256_word(block_confirmation));
    Ok(calldata)
}

fn felt_from_hex(value: &str) -> Result<[u8; 32], AppCoreError> {
    Ok(felt_from_bytes(&decode_hex_bytes(value)?))
}

fn felt_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    out
}

fn u256_word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}
