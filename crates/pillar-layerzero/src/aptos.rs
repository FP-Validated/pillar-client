use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use std::collections::HashMap;

use crate::abi::{bytes32_hex_string, u64_from_i64};
use crate::evm::evm_receive_version_from_dst_eid;
use crate::packet::EvmUlnProof;
use crate::packet::{extra_string, extra_u64, proof_from_event, uln_send_version_string};
use crate::types::{
    UlnReadV1PayloadBuilder, UlnV2HashInfo, UlnV2PayloadBuilder, UlnV3PayloadBuilder,
    ULN_VERSION_V301, ULN_VERSION_V302,
};

mod hash;

#[cfg(test)]
pub(crate) use hash::aptos_function_signature_hash;
pub use hash::{aptos_hash_propose, aptos_hash_verify};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosReceiveContracts {
    pub v1_oracle: String,
    pub v1_uln_301: String,
    pub uln_302: String,
}

#[derive(Debug, Clone)]
pub struct AptosUlnPayloadBuilder {
    contracts_by_chain_name: HashMap<String, AptosReceiveContracts>,
}

impl AptosUlnPayloadBuilder {
    pub fn new(contracts_by_chain_name: HashMap<String, AptosReceiveContracts>) -> Self {
        Self {
            contracts_by_chain_name,
        }
    }

    pub fn build_uln_v2_verify_payload_from_hash_info(
        &self,
        sent_event: &LzSentEvent,
        hash_info: UlnV2HashInfo,
        block_confirmation: i64,
        expiration: i64,
        v_id: &str,
    ) -> Result<HashCallDataResult, AppCoreError> {
        if !v_id.is_empty() {
            return Err(AppCoreError::Internal(
                "VId is not supported on aptos yet".to_string(),
            ));
        }
        let block_confirmation = u64_from_i64(block_confirmation, "blockConfirmation")?;
        let expiration = u64_from_i64(expiration, "expiration")?;
        let target_contract = self.contracts_for_event(sent_event)?.v1_oracle.clone();
        let hash_call_data =
            aptos_hash_propose(&hash_info.lookup_hash, block_confirmation, expiration)?;
        Ok(HashCallDataResult {
            hash_call_data,
            details: serde_json::json!({
                "dvnHashCallData": {
                    "dvnCallData": "unknown in aptos",
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": target_contract,
                    "ulnCallData": "unknown in aptos",
                },
                "ulnCallData": {
                    "methodName": "hashPropose",
                    "proof": {
                        "lookupHash": hash_info.lookup_hash,
                        "blockData": hash_info.block_data,
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

    pub fn build_uln_v3_verify_payload_from_proof(
        &self,
        sent_event: &LzSentEvent,
        proof: EvmUlnProof,
        block_confirmation: i64,
        expiration: i64,
        v_id: &str,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let v_id_u32 = v_id
            .parse::<u32>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let block_confirmation = u64_from_i64(block_confirmation, "blockConfirmation")?;
        let expiration = u64_from_i64(expiration, "expiration")?;
        let target_contract = self.target_contract_for_event(sent_event)?;
        let target_bytes32 = bytes32_hex_string(&target_contract)?;
        let hash_call_data = aptos_hash_verify(
            &proof.packet_header,
            &proof.payload_hash,
            block_confirmation,
            &target_bytes32,
            v_id_u32,
            expiration,
        )?;
        Ok(HashCallDataResult {
            hash_call_data,
            details: serde_json::json!({
                "dvnHashCallData": {
                    "dvnCallData": serde_json::json!([
                        proof.packet_header,
                        proof.payload_hash,
                        block_confirmation,
                        target_bytes32,
                        v_id_u32,
                        expiration,
                    ]).to_string(),
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": target_bytes32,
                    "ulnCallData": "unknown in aptos",
                },
                "ulnCallData": {
                    "methodName": "hashPropose",
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

    fn contracts_for_event(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<&AptosReceiveContracts, AppCoreError> {
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        self.contracts_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("No Aptos receive contracts for {dst_chain_name}"))
            })
    }

    fn target_contract_for_event(&self, sent_event: &LzSentEvent) -> Result<String, AppCoreError> {
        let dst_eid = extra_u64(sent_event, "dstEid")?;
        let uln_send_version = uln_send_version_string(&sent_event.lz_message_id.uln_send_version)?;
        let contracts = self.contracts_for_event(sent_event)?;
        match evm_receive_version_from_dst_eid(dst_eid, &uln_send_version) {
            ULN_VERSION_V301 => Ok(contracts.v1_uln_301.clone()),
            ULN_VERSION_V302 => Ok(contracts.uln_302.clone()),
            _ => Err(AppCoreError::Internal("Unsupported UlnVersion".to_string())),
        }
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for AptosUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let hash_info = UlnV2HashInfo {
            lookup_hash: extra_string(sent_event, "lookupHash")?,
            block_data: extra_string(sent_event, "blockData")?,
        };
        self.build_uln_v2_verify_payload_from_hash_info(
            sent_event,
            hash_info,
            block_confirmation,
            expiration,
            &v_id,
        )
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for AptosUlnPayloadBuilder {
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

#[async_trait]
impl UlnReadV1PayloadBuilder for AptosUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        Err(AppCoreError::Internal(format!(
            "Unsupported LayerZero read destination chain type for {dst_chain_name}"
        )))
    }
}
