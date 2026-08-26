use std::collections::HashMap;

use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use serde_json::Value;

use crate::abi::build_evm_dvn_call_data_result;
use crate::packet::extra_u64;
use crate::packet::uln_send_version_string;
use crate::types::{
    READ_LIB_1002_ADDRESS, RECEIVE_ULN_301_ADDRESS, RECEIVE_ULN_302_ADDRESS,
    ULN_VERSION_READ_V1002, ULN_VERSION_V301, ULN_VERSION_V302,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmReceiveContracts {
    /// Destination `EndpointV2`, asked which receive library the receiver OApp
    /// actually uses.
    pub endpoint_v2: String,
    /// Destination V1 `Endpoint`, for pathways whose `dstEid` is a V1 endpoint
    /// id. Absent where upstream's deployment configuration has no V1
    /// endpoint for the chain.
    pub endpoint_v1: Option<String>,
    pub uln_v2: String,
    pub receive_uln_301: String,
    pub receive_uln_301_view: String,
    pub receive_uln_302: String,
    pub receive_uln_302_view: String,
    pub read_lib_1002: Option<String>,
    pub read_lib_1002_view: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EvmUlnPayloadBuilder {
    contracts_by_chain_name: HashMap<String, EvmReceiveContracts>,
}

impl EvmUlnPayloadBuilder {
    pub fn new(contracts_by_chain_name: HashMap<String, EvmReceiveContracts>) -> Self {
        Self {
            contracts_by_chain_name,
        }
    }

    pub(crate) fn build_dvn_call_data(
        &self,
        sent_event: &LzSentEvent,
        expiration: i64,
        v_id: &str,
        uln_call_data: &str,
        details: Value,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let expiration = u64::try_from(expiration)
            .map_err(|_| AppCoreError::Internal("expiration must be non-negative".to_string()))?;
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        let contracts = self
            .contracts_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("No EVM receive contracts for {dst_chain_name}"))
            })?;
        let dst_eid = extra_u64(sent_event, "dstEid")?;
        let uln_send_version = uln_send_version_string(&sent_event.lz_message_id.uln_send_version)?;
        let target_contract = match evm_receive_version_from_dst_eid(dst_eid, &uln_send_version) {
            ULN_VERSION_V301 => {
                if contracts.receive_uln_301.is_empty() {
                    return Err(AppCoreError::Internal(format!(
                        "No ReceiveUln301 contract for {dst_chain_name}"
                    )));
                }
                &contracts.receive_uln_301
            }
            ULN_VERSION_V302 => &contracts.receive_uln_302,
            ULN_VERSION_READ_V1002 => contracts.read_lib_1002.as_ref().ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No ReadLib1002 receive contract for {dst_chain_name}"
                ))
            })?,
            _ => return Err(AppCoreError::Internal("Unsupported UlnVersion".to_string())),
        };
        build_evm_dvn_call_data_result(target_contract, uln_call_data, expiration, v_id, details)
    }

    pub(crate) fn build_uln_v2_dvn_call_data(
        &self,
        sent_event: &LzSentEvent,
        expiration: i64,
        v_id: &str,
        uln_call_data: &str,
        details: Value,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let expiration = u64::try_from(expiration)
            .map_err(|_| AppCoreError::Internal("expiration must be non-negative".to_string()))?;
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        let contracts = self
            .contracts_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("No EVM receive contracts for {dst_chain_name}"))
            })?;
        build_evm_dvn_call_data_result(&contracts.uln_v2, uln_call_data, expiration, v_id, details)
    }

    pub fn uln_v2_contract_for_chain(&self, chain_name: &str) -> Option<&str> {
        self.contracts_by_chain_name
            .get(chain_name)
            .map(|contracts| contracts.uln_v2.as_str())
            .filter(|address| !address.is_empty())
    }
}

pub fn evm_receive_contract_for_uln_version(
    uln_version: &str,
) -> Result<&'static str, AppCoreError> {
    match uln_version {
        ULN_VERSION_V301 => Ok(RECEIVE_ULN_301_ADDRESS),
        ULN_VERSION_V302 => Ok(RECEIVE_ULN_302_ADDRESS),
        ULN_VERSION_READ_V1002 => Ok(READ_LIB_1002_ADDRESS),
        _ => Err(AppCoreError::Internal("Unsupported UlnVersion".to_string())),
    }
}

/// Map a receive library address to its ULN version.
///
/// Upstream searches its three message-library getters in this order and
/// throws `Cannot get ULN Version from Address` when none match (TS:
/// `packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:44-89`). The
/// order matters only in the degenerate case of a chain deploying the same
/// address twice; it is kept identical anyway so a disagreement with upstream
/// is a data difference, never an ordering difference.
///
/// `None` is the fail-closed answer: the OApp receives on a library this
/// service cannot reason about, so it cannot know whether the payload is
/// already signed there.
pub fn evm_uln_version_from_receive_library(
    contracts: &EvmReceiveContracts,
    address: &str,
) -> Option<&'static str> {
    let address = address.trim_start_matches("0x");
    let matches = |candidate: &str| {
        !candidate.is_empty()
            && candidate
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(address)
    };
    if matches(&contracts.receive_uln_302) {
        return Some(ULN_VERSION_V302);
    }
    if matches(&contracts.receive_uln_301) {
        return Some(ULN_VERSION_V301);
    }
    if contracts.read_lib_1002.as_deref().is_some_and(matches) {
        return Some(ULN_VERSION_READ_V1002);
    }
    None
}

pub fn evm_receive_version_from_dst_eid(dst_eid: u64, uln_send_version: &str) -> &'static str {
    if uln_send_version == ULN_VERSION_READ_V1002 {
        ULN_VERSION_READ_V1002
    } else if dst_eid < 30_000 {
        ULN_VERSION_V301
    } else {
        ULN_VERSION_V302
    }
}
