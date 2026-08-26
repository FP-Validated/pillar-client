use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};

use crate::abi::{encode_verify_bytes_bytes32_u64, proof_details};
use crate::evm::EvmUlnPayloadBuilder;
use crate::packet::{proof_from_event, EvmUlnProof};
use crate::types::{UlnV3PayloadBuilder, RECEIVE_ULN_302_VERIFY_SELECTOR};

impl EvmUlnPayloadBuilder {
    pub fn build_uln_v3_verify_payload_from_proof(
        &self,
        sent_event: &LzSentEvent,
        proof: EvmUlnProof,
        block_confirmation: i64,
        expiration: i64,
        v_id: &str,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let uln_call_data = build_evm_uln_v3_verify_call_data(&proof, block_confirmation)?;
        self.build_dvn_call_data(
            sent_event,
            expiration,
            v_id,
            &uln_call_data,
            proof_details(
                "verify",
                sent_event,
                proof,
                serde_json::json!({ "blockConfirmation": block_confirmation }),
            )?,
        )
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for EvmUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.build_uln_v3_verify_payload_from_proof(
            sent_event,
            proof_from_event(sent_event)?,
            block_confirmation,
            expiration,
            &v_id,
        )
    }
}

pub fn build_evm_uln_v3_verify_call_data(
    proof: &EvmUlnProof,
    block_confirmation: i64,
) -> Result<String, AppCoreError> {
    let block_confirmation = u64::try_from(block_confirmation).map_err(|_| {
        AppCoreError::Internal("blockConfirmation must be non-negative".to_string())
    })?;
    encode_verify_bytes_bytes32_u64(
        RECEIVE_ULN_302_VERIFY_SELECTOR,
        &proof.packet_header,
        &proof.payload_hash,
        block_confirmation,
    )
}
