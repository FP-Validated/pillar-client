use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use std::collections::HashMap;

use crate::abi::{bytes32_hex_string, u64_from_i64};
use crate::evm::evm_receive_version_from_dst_eid;
use crate::packet::EvmUlnProof;
use crate::packet::{extra_u64, proof_from_event, uln_send_version_string};
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

/// The two Aptos ULN V2 oracles a vId-less proposal may target, each with the Aptos
/// EndpointV1 id its packets must name: upstream's `getAptosV1OracleAddress` for mainnet and
/// testnet. Any other destination identity is refused.
const APTOS_ULN_V2_ORACLES: [(&str, u64); 2] = [
    (
        "0xc2846ea05319c339b3b52186ceae40b43d4e9cf6c7350336c3eb0b351d9394eb",
        108,
    ),
    (
        "0x8ab85d94bf34808386b3ce0f9516db74d2b6d2f1166aa48f75ca641f3adb6c63",
        10_108,
    ),
];

#[async_trait]
impl UlnV2PayloadBuilder for AptosUlnPayloadBuilder {
    /// Upstream signs `hashPropose(lookupHash, confirmations, expiration)` for the destination's
    /// V1 oracle (`gasolinaSdk/aptos/index.ts:35-73`), the lookup hash being the native hash of
    /// `getFeatherProof(2, emitter, packet)`, i.e. of the bare V1 packet, since Aptos's inbound
    /// config is always utils version 2 (`lz-v1-sdk/src/aptos/aptos.ts:592-596`). Served only for
    /// an EVM-sent ULN V2 packet to `aptos` whose oracle and EndpointV1 id are one of the pinned
    /// pairs; a vId is upstream's own 500.
    async fn build_uln_v2_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        if !v_id.is_empty() {
            return Err(AppCoreError::Internal(
                "VId is not supported on aptos yet".to_string(),
            ));
        }
        let refuse = |reason: &str| {
            AppCoreError::BadRequest(format!(
                "ULN V2 verification without a vId is served only for an EVM-sent ULN V2 \
                 packet to the pinned Aptos oracle: {reason}"
            ))
        };
        let pathway = &sent_event.lz_message_id.pathway_id;
        if pathway.dst_chain_name != "aptos" {
            return Err(refuse("the destination is not aptos"));
        }
        if uln_send_version_string(&sent_event.lz_message_id.uln_send_version)? != "V2" {
            return Err(refuse("the packet was not sent on ULN V2"));
        }
        let oracle = &self.contracts_for_event(sent_event)?.v1_oracle;
        let endpoint_v1_id = APTOS_ULN_V2_ORACLES
            .iter()
            .find(|(pinned, _)| pinned.eq_ignore_ascii_case(oracle))
            .map(|(_, eid)| *eid)
            .ok_or_else(|| refuse("the configured oracle is not a pinned one"))?;
        if extra_u64(sent_event, "dstEid")? != endpoint_v1_id {
            return Err(refuse(
                "the packet does not name this oracle's Aptos EndpointV1 id",
            ));
        }
        let receiver = crate::abi::decode_hex_bytes(&crate::packet::pathway_extra_string(
            sent_event, "receiver",
        )?)?;
        if receiver.len() != 32 {
            return Err(refuse("the receiver is not a 32-byte Aptos account"));
        }
        let sender = crate::abi::decode_hex_bytes(&crate::packet::pathway_extra_string(
            sent_event, "sender",
        )?)?;
        if sender.len() != 20 {
            return Err(refuse("the sender is not a 20-byte EVM address"));
        }
        let packet = crate::packet::build_evm_lz_v1_packet_payload_v2_from_event(sent_event)?;
        let lookup_hash = crate::packet::native_hash_by_chain_name(&packet, "aptos")?;
        self.build_uln_v2_verify_payload_from_hash_info(
            sent_event,
            UlnV2HashInfo {
                lookup_hash: lookup_hash.clone(),
                block_data: lookup_hash,
            },
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
