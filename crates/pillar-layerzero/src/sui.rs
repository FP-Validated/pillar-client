use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use std::collections::HashMap;

use crate::abi::{bytes32_hex_string, u64_from_i64};
use crate::aptos::aptos_hash_verify;
use crate::packet::proof_from_event;
use crate::types::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiReceiveContracts {
    pub uln_302_package: String,
}

#[derive(Debug, Clone)]
pub struct SuiUlnPayloadBuilder {
    contracts_by_chain_name: HashMap<String, SuiReceiveContracts>,
}

impl SuiUlnPayloadBuilder {
    pub fn new(contracts_by_chain_name: HashMap<String, SuiReceiveContracts>) -> Self {
        Self {
            contracts_by_chain_name,
        }
    }

    fn contracts_for_event(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<&SuiReceiveContracts, AppCoreError> {
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        self.contracts_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("No Sui receive contracts for {dst_chain_name}"))
            })
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for SuiUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "SUI only supports ULN V302".to_string(),
        ))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for SuiUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let proof = proof_from_event(sent_event)?;
        let v_id_u32 = v_id
            .parse::<u32>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let block_confirmation = u64_from_i64(block_confirmation, "blockConfirmation")?;
        let expiration = u64_from_i64(expiration, "expiration")?;
        let target_contract =
            bytes32_hex_string(&self.contracts_for_event(sent_event)?.uln_302_package)?;
        let hash_call_data = aptos_hash_verify(
            &proof.packet_header,
            &proof.payload_hash,
            block_confirmation,
            &target_contract,
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
                        target_contract,
                        v_id_u32,
                        expiration,
                    ]).to_string(),
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": target_contract,
                    "ulnCallData": "unknown in sui",
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
}

#[async_trait]
impl UlnReadV1PayloadBuilder for SuiUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "SUI only supports ULN V302".to_string(),
        ))
    }
}
