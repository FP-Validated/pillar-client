use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use serde_json::Value;

use crate::abi::{decode_hex_32, encode_verify_bytes_bytes32_bytes32, proof_details};
use crate::evm::EvmUlnPayloadBuilder;
use crate::packet::{extra_string, proof_from_event, EvmUlnProof};
use crate::types::{UlnReadV1PayloadBuilder, READ_LIB_1002_VERIFY_SELECTOR};

mod command;

pub use command::{decode_evm_read_command, extract_evm_read_resolved_time_markers};

impl EvmUlnPayloadBuilder {
    pub fn build_uln_read_v1_verify_payload_from_proof(
        &self,
        sent_event: &LzSentEvent,
        proof: EvmUlnProof,
        resolved_payload: String,
        expiration: i64,
        v_id: &str,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let guid = extra_string(sent_event, "guid")?;
        let resolved_payload_hash = resolved_payload_hash(&guid, &resolved_payload)?;
        let uln_call_data = build_evm_uln_read_v1_verify_call_data(&proof, &resolved_payload_hash)?;
        self.build_dvn_call_data(
            sent_event,
            expiration,
            v_id,
            &uln_call_data,
            proof_details(
                "verify",
                sent_event,
                EvmUlnProof {
                    packet_header: proof.packet_header,
                    payload_hash: proof.payload_hash,
                },
                serde_json::json!({ "resolvedPayloadHash": resolved_payload_hash }),
            )
            .map(|mut details| {
                details["proof"]["resolvedPayload"] = Value::from(resolved_payload);
                details
            })?,
        )
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for EvmUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        resolved_payload: String,
        expiration: i64,
        v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.build_uln_read_v1_verify_payload_from_proof(
            sent_event,
            proof_from_event(sent_event)?,
            resolved_payload,
            expiration,
            &v_id,
        )
    }
}

pub fn build_evm_uln_read_v1_verify_call_data(
    proof: &EvmUlnProof,
    resolved_payload_hash: &str,
) -> Result<String, AppCoreError> {
    encode_verify_bytes_bytes32_bytes32(
        READ_LIB_1002_VERIFY_SELECTOR,
        &proof.packet_header,
        &proof.payload_hash,
        resolved_payload_hash,
    )
}

/// `keccak256(guid || resolvedPayload)`, decoding the payload in chunks rather than into a copy.
pub(crate) fn resolved_payload_hash(
    guid: &str,
    resolved_payload: &str,
) -> Result<String, AppCoreError> {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();
    hasher.update(decode_hex_32(guid)?);
    let digits = resolved_payload
        .strip_prefix("0x")
        .unwrap_or(resolved_payload)
        .as_bytes();
    // An odd-length payload decodes as if left-padded with `0`, as `decode_hex_bytes` does.
    let (head, mut rest) = match digits.len() % 2 {
        0 => (None, digits),
        _ => (Some(digits[0]), &digits[1..]),
    };
    // Error positions count from the padded string, as `decode_hex_bytes` reported them.
    let mut offset = 0;
    if let Some(digit) = head {
        let mut byte = [0u8; 1];
        hex::decode_to_slice([b'0', digit], &mut byte).map_err(|error| hex_error(error, 0))?;
        hasher.update(byte);
        offset = 2;
    }
    let mut buffer = [0u8; 4096];
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(rest.len().min(buffer.len() * 2));
        let bytes = &mut buffer[..chunk.len() / 2];
        hex::decode_to_slice(chunk, bytes).map_err(|error| hex_error(error, offset))?;
        hasher.update(&*bytes);
        offset += chunk.len();
        rest = tail;
    }
    Ok(format!("0x{}", hex::encode(hasher.finalize())))
}

fn hex_error(error: hex::FromHexError, offset: usize) -> AppCoreError {
    let error = match error {
        hex::FromHexError::InvalidHexCharacter { c, index } => {
            hex::FromHexError::InvalidHexCharacter {
                c,
                index: index + offset,
            }
        }
        other => other,
    };
    AppCoreError::Internal(error.to_string())
}
