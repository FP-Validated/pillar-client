use crate::abi::{decode_hex_32, function_selector, solidity_uint256, uln_v2_proof_details};
use crate::evm::EvmUlnPayloadBuilder;
use crate::packet::extra_u64;
use crate::types::UlnV2HashInfo;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};

impl EvmUlnPayloadBuilder {
    pub fn build_uln_v2_verify_payload_from_hash_info(
        &self,
        sent_event: &LzSentEvent,
        hash_info: UlnV2HashInfo,
        block_confirmation: i64,
        expiration: i64,
        v_id: &str,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let uln_call_data = build_evm_uln_v2_verify_call_data(
            extra_u64(sent_event, "srcEid")?,
            &hash_info,
            block_confirmation,
        )?;
        self.build_uln_v2_dvn_call_data(
            sent_event,
            expiration,
            v_id,
            &uln_call_data,
            uln_v2_proof_details(
                "updateHash",
                sent_event,
                hash_info,
                serde_json::json!({ "blockConfirmation": block_confirmation }),
            )?,
        )
    }
}

pub fn build_evm_uln_v2_verify_call_data(
    src_eid: u64,
    hash_info: &UlnV2HashInfo,
    block_confirmation: i64,
) -> Result<String, AppCoreError> {
    let block_confirmation = u64::try_from(block_confirmation).map_err(|_| {
        AppCoreError::Internal("blockConfirmation must be non-negative".to_string())
    })?;
    let mut out = Vec::from(function_selector(
        "updateHash(uint16,bytes32,uint256,bytes32)",
    ));
    out.extend_from_slice(&solidity_uint256(src_eid));
    out.extend_from_slice(&decode_hex_32(&hash_info.lookup_hash)?);
    out.extend_from_slice(&solidity_uint256(block_confirmation));
    out.extend_from_slice(&decode_hex_32(&hash_info.block_data)?);
    Ok(format!("0x{}", hex::encode(out)))
}
