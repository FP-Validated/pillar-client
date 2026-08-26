use pillar_core::{AppCoreError, HashCallDataResult};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use crate::packet::EvmUlnProof;
use crate::types::{
    EvmHashLookupResult, EvmUlnV2AppConfig, EvmVerificationState, ULN_VERSION_READ_V1002,
};

mod decode;
mod details;
mod encode;

pub(crate) use decode::{abi_address, abi_bool, abi_dynamic_bytes, abi_word, abi_word_u64};
pub(crate) use details::{proof_details, uln_v2_proof_details};
pub(crate) use encode::{
    address_to_bytes32, decode_hex_20, decode_hex_32, decode_hex_bytes,
    encode_verify_bytes_bytes32_bytes32, encode_verify_bytes_bytes32_u64, function_selector,
    native_address_to_bytes32, solidity_address_word, solidity_dynamic_bytes,
    solidity_dynamic_bytes_array, solidity_uint256,
};

pub fn pack_dvn_call_data(
    target: &str,
    call_data: &str,
    expiration: u64,
    v_id: &str,
) -> Result<Vec<u8>, AppCoreError> {
    let mut out = Vec::new();
    if !v_id.is_empty() {
        let vid = v_id
            .parse::<u32>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        out.extend_from_slice(&vid.to_be_bytes());
    }
    let target = decode_hex_20(target)?;
    out.extend_from_slice(&target);
    out.extend_from_slice(&solidity_uint256(expiration));
    out.extend_from_slice(&decode_hex_bytes(call_data)?);
    Ok(out)
}

pub fn keccak256_hex(data: &[u8]) -> String {
    let digest = Keccak256::digest(data);
    format!("0x{}", hex::encode(digest))
}

pub(crate) fn u64_from_i64(value: i64, name: &str) -> Result<u64, AppCoreError> {
    u64::try_from(value).map_err(|_| AppCoreError::Internal(format!("{name} must be non-negative")))
}

pub(crate) fn bytes32_hex_string(value: &str) -> Result<String, AppCoreError> {
    Ok(hex::encode(address_to_bytes32(value)?))
}

pub fn build_evm_dvn_call_data_result(
    target_contract: &str,
    uln_call_data: &str,
    expiration: u64,
    v_id: &str,
    mut details: Value,
) -> Result<HashCallDataResult, AppCoreError> {
    let dvn_call_data = pack_dvn_call_data(target_contract, uln_call_data, expiration, v_id)?;
    let dvn_call_data_hex = format!("0x{}", hex::encode(&dvn_call_data));
    let hash_call_data = keccak256_hex(&dvn_call_data);
    let object = details
        .as_object_mut()
        .ok_or_else(|| AppCoreError::Internal("details must be an object".to_string()))?;
    object.insert(
        "dvnHashCallData".to_string(),
        serde_json::json!({ "dvnCallData": dvn_call_data_hex }),
    );
    object.insert(
        "dvnCallData".to_string(),
        serde_json::json!({
            "expiration": expiration,
            "vid": v_id,
            "targetContract": target_contract,
            "ulnCallData": uln_call_data,
        }),
    );
    Ok(HashCallDataResult {
        hash_call_data,
        details,
    })
}

pub fn build_evm_hash_lookup_call_data(
    proof: &EvmUlnProof,
    verifier_address: &str,
) -> Result<String, AppCoreError> {
    let packet_header = decode_hex_bytes(&proof.packet_header)?;
    let packet_header_hash = Keccak256::digest(&packet_header);
    let mut out = Vec::from(function_selector("hashLookup(bytes32,bytes32,address)"));
    out.extend_from_slice(&packet_header_hash);
    out.extend_from_slice(&decode_hex_32(&proof.payload_hash)?);
    out.extend_from_slice(&solidity_address_word(verifier_address)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_verifiable_call_data(proof: &EvmUlnProof) -> Result<String, AppCoreError> {
    let mut out = Vec::from(function_selector("verifiable(bytes,bytes32)"));
    out.extend_from_slice(&solidity_uint256(64));
    out.extend_from_slice(&decode_hex_32(&proof.payload_hash)?);
    out.extend_from_slice(&solidity_dynamic_bytes(&proof.packet_header)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_get_uln_config_call_data(
    oapp: &str,
    remote_eid: u32,
) -> Result<String, AppCoreError> {
    let mut out = Vec::from(function_selector("getUlnConfig(address,uint32)"));
    out.extend_from_slice(&solidity_address_word(oapp)?);
    out.extend_from_slice(&solidity_uint256(remote_eid as u64));
    Ok(format!("0x{}", hex::encode(out)))
}

/// `EndpointV2.getReceiveLibrary(address receiver, uint32 srcEid)`, returning
/// `(address lib, bool isDefault)`.
///
/// TS: `packages/sdks/lz-v2-sdk/src/endpoint/evm/endpointV2.ts:86-90`.
/// Narrow a pathway address value to the EVM `address` ABI argument it denotes.
///
/// A V3 packet carries the receiver as `bytes32`
/// (`decode_lz_packet_v1`, `crate::packet`), and the packet header this service
/// signs over has to keep that padded form - so the narrowing belongs at the
/// lookup input, never at the producer. Normalizing the pathway itself would
/// change the header and therefore the payload hash.
///
/// Upstream narrows with `hexZeroPad(address, 32).slice(-40)`
/// (`packages/static-config/src/index.ts:723-727`), which silently discards the
/// leading 12 bytes. This refuses when they are non-zero instead: for a DVN,
/// truncating an address that was never a zero-padded EVM address means
/// attesting for a different OApp than the packet names.
pub fn evm_address_from_pathway_value(value: &str) -> Result<String, AppCoreError> {
    let bytes = decode_hex_bytes(value)?;
    match bytes.len() {
        20 => Ok(format!("0x{}", hex::encode(bytes))),
        32 => {
            let (padding, address) = bytes.split_at(12);
            if padding.iter().any(|byte| *byte != 0) {
                return Err(AppCoreError::BadRequest(format!(
                    "{value} is not an EVM address: the leading 12 bytes are not zero"
                )));
            }
            Ok(format!("0x{}", hex::encode(address)))
        }
        length => Err(AppCoreError::BadRequest(format!(
            "{value} is not an EVM address: {length} bytes"
        ))),
    }
}

pub fn build_evm_get_receive_library_call_data(
    receiver: &str,
    src_eid: u32,
) -> Result<String, AppCoreError> {
    let mut out = Vec::from(function_selector("getReceiveLibrary(address,uint32)"));
    out.extend_from_slice(&solidity_address_word(receiver)?);
    out.extend_from_slice(&solidity_uint256(src_eid as u64));
    Ok(format!("0x{}", hex::encode(out)))
}

/// `EndpointV2.isValidReceiveLibrary(address receiver, uint32 srcEid, address lib)`.
///
/// Only consulted when `getReceiveLibrary` reports a non-default library, which
/// is the one case upstream re-checks before trusting it
/// (TS: `endpointV2.ts:91-102`).
pub fn build_evm_is_valid_receive_library_call_data(
    receiver: &str,
    src_eid: u32,
    library: &str,
) -> Result<String, AppCoreError> {
    let mut out = Vec::from(function_selector(
        "isValidReceiveLibrary(address,uint32,address)",
    ));
    out.extend_from_slice(&solidity_address_word(receiver)?);
    out.extend_from_slice(&solidity_uint256(src_eid as u64));
    out.extend_from_slice(&solidity_address_word(library)?);
    Ok(format!("0x{}", hex::encode(out)))
}

/// `Endpoint.getReceiveLibraryAddress(address receiver)` on a V1 endpoint,
/// which has neither the `srcEid` argument nor the default/override split.
///
/// TS: `packages/sdks/lz-v2-sdk/src/endpoint/evm/endpointV1.ts:90-93`.
pub fn build_evm_v1_get_receive_library_address_call_data(
    receiver: &str,
) -> Result<String, AppCoreError> {
    let mut out = Vec::from(function_selector("getReceiveLibraryAddress(address)"));
    out.extend_from_slice(&solidity_address_word(receiver)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_uln_v2_get_app_config_call_data(
    src_eid: u64,
    receiver: &str,
) -> Result<String, AppCoreError> {
    let src_eid = u16::try_from(src_eid)
        .map_err(|_| AppCoreError::Internal("srcEid exceeds uint16".to_string()))?;
    let mut out = Vec::from(function_selector("getAppConfig(uint16,address)"));
    out.extend_from_slice(&solidity_uint256(src_eid as u64));
    out.extend_from_slice(&solidity_address_word(receiver)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_uln_v2_inbound_proof_library_call_data(
    src_eid: u64,
    proof_library_version: u64,
) -> Result<String, AppCoreError> {
    let src_eid = u16::try_from(src_eid)
        .map_err(|_| AppCoreError::Internal("srcEid exceeds uint16".to_string()))?;
    let proof_library_version = u16::try_from(proof_library_version).map_err(|_| {
        AppCoreError::Internal("inboundProofLibraryVersion exceeds uint16".to_string())
    })?;
    let mut out = Vec::from(function_selector("inboundProofLibrary(uint16,uint16)"));
    out.extend_from_slice(&solidity_uint256(src_eid as u64));
    out.extend_from_slice(&solidity_uint256(proof_library_version as u64));
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_validation_library_get_utils_version_call_data() -> String {
    format!("0x{}", hex::encode(function_selector("getUtilsVersion()")))
}

pub fn build_evm_validation_library_get_proof_type_call_data() -> String {
    format!("0x{}", hex::encode(function_selector("getProofType()")))
}

pub fn build_evm_lz_map_call_data(request: &str, response: &str) -> Result<String, AppCoreError> {
    let request = solidity_dynamic_bytes(request)?;
    let response = solidity_dynamic_bytes(response)?;
    let mut out = Vec::from(function_selector("lzMap(bytes,bytes)"));
    out.extend_from_slice(&solidity_uint256(64));
    out.extend_from_slice(&solidity_uint256(64 + request.len() as u64));
    out.extend_from_slice(&request);
    out.extend_from_slice(&response);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn build_evm_lz_reduce_call_data(
    cmd: &str,
    responses: &[String],
) -> Result<String, AppCoreError> {
    let cmd = solidity_dynamic_bytes(cmd)?;
    let response_array = solidity_dynamic_bytes_array(responses)?;
    let mut out = Vec::from(function_selector("lzReduce(bytes,bytes[])"));
    out.extend_from_slice(&solidity_uint256(64));
    out.extend_from_slice(&solidity_uint256(64 + cmd.len() as u64));
    out.extend_from_slice(&cmd);
    out.extend_from_slice(&response_array);
    Ok(format!("0x{}", hex::encode(out)))
}

pub fn decode_evm_bytes_result(result: &str) -> Result<String, AppCoreError> {
    let bytes = decode_hex_bytes(result)?;
    Ok(format!(
        "0x{}",
        hex::encode(abi_dynamic_bytes(&bytes, 0, 1)?)
    ))
}

pub fn decode_evm_uint64_result(result: &str) -> Result<u64, AppCoreError> {
    abi_word_u64(&decode_hex_bytes(result)?, 0)
}

pub fn decode_evm_address_result(result: &str) -> Result<String, AppCoreError> {
    abi_address(&decode_hex_bytes(result)?, 0, 1)
}

/// `(address lib, bool isDefault)`.
pub fn decode_evm_receive_library_result(result: &str) -> Result<(String, bool), AppCoreError> {
    let bytes = decode_hex_bytes(result)?;
    Ok((abi_address(&bytes, 0, 2)?, abi_bool(&bytes, 1)?))
}

pub fn decode_evm_bool_result(result: &str) -> Result<bool, AppCoreError> {
    abi_bool(&decode_hex_bytes(result)?, 0)
}

pub fn decode_evm_uln_v2_app_config(result: &str) -> Result<EvmUlnV2AppConfig, AppCoreError> {
    let bytes = decode_hex_bytes(result)?;
    Ok(EvmUlnV2AppConfig {
        inbound_proof_library_version: abi_word_u64(&bytes, 0)?,
        inbound_block_confirmations: abi_word_u64(&bytes, 1)?,
        relayer: abi_address(&bytes, 2, 6)?,
        outbound_proof_type: abi_word_u64(&bytes, 3)?,
        outbound_block_confirmations: abi_word_u64(&bytes, 4)?,
        oracle: abi_address(&bytes, 5, 6)?,
    })
}

pub fn decode_evm_hash_lookup_result(
    uln_version: &str,
    result: &str,
) -> Result<EvmHashLookupResult, AppCoreError> {
    let bytes = decode_hex_bytes(result)?;
    if uln_version == ULN_VERSION_READ_V1002 {
        let payload_hash = abi_word(&bytes, 0)?;
        return Ok(EvmHashLookupResult::Read {
            payload_hash: format!("0x{}", hex::encode(payload_hash)),
        });
    }
    Ok(EvmHashLookupResult::Message {
        submitted: abi_bool(&bytes, 0)?,
        confirmations: abi_word_u64(&bytes, 1)?,
    })
}

pub fn evm_hash_lookup_is_confirmed(
    inbound_confirmations: u64,
    result: &EvmHashLookupResult,
) -> bool {
    match result {
        EvmHashLookupResult::Message {
            submitted,
            confirmations,
        } => *submitted && *confirmations >= inbound_confirmations,
        EvmHashLookupResult::Read { payload_hash } => {
            payload_hash != "0x0000000000000000000000000000000000000000000000000000000000000000"
        }
    }
}

pub fn decode_evm_verification_state(
    uln_version: &str,
    result: &str,
) -> Result<EvmVerificationState, AppCoreError> {
    match abi_word_u64(&decode_hex_bytes(result)?, 0)? {
        0 => Ok(EvmVerificationState::Verifying),
        1 => Ok(EvmVerificationState::Verifiable),
        2 => Ok(EvmVerificationState::Verified),
        3 => Ok(EvmVerificationState::NotInitializable),
        4 if uln_version == ULN_VERSION_READ_V1002 => Ok(EvmVerificationState::Reorged),
        4 => Ok(EvmVerificationState::VerifiableButCapExceeded),
        state => Err(AppCoreError::Internal(format!(
            "Unknown delivery state: {state}"
        ))),
    }
}

pub fn decode_evm_uln_config_confirmations(result: &str) -> Result<u64, AppCoreError> {
    let bytes = decode_hex_bytes(result)?;
    if bytes.len() >= 64 && abi_word_u64(&bytes, 0)? == 32 {
        abi_word_u64(&bytes, 1)
    } else {
        abi_word_u64(&bytes, 0)
    }
}
