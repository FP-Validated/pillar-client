use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use serde_json::Value;

use crate::abi::{
    decode_hex_32, decode_hex_bytes, encode_verify_bytes_bytes32_bytes32, keccak256_hex,
    proof_details,
};
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
        resolved_payload: &str,
        expiration: i64,
        v_id: &str,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let guid = extra_string(sent_event, "guid")?;
        let resolved_payload_hash = resolved_payload_hash(&guid, resolved_payload)?;
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
                details["proof"]["resolvedPayload"] = Value::from(resolved_payload.to_string());
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
            &resolved_payload,
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

pub(crate) fn resolved_payload_hash(
    guid: &str,
    resolved_payload: &str,
) -> Result<String, AppCoreError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&decode_hex_32(guid)?);
    bytes.extend_from_slice(&decode_hex_bytes(resolved_payload)?);
    Ok(keccak256_hex(&bytes))
}
