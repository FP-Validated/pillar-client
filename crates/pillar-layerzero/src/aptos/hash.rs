use pillar_core::AppCoreError;
use sha3::{Digest, Keccak256};

use crate::abi::decode_hex_bytes;

pub fn aptos_hash_propose(
    lookup_hash: &str,
    block_confirmation: u64,
    expiration: u64,
) -> Result<String, AppCoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&aptos_function_signature_hash("propose"));
    out.extend_from_slice(&decode_hex_bytes(lookup_hash)?);
    out.extend_from_slice(&block_confirmation.to_be_bytes());
    out.extend_from_slice(&expiration.to_be_bytes());
    Ok(keccak256_hex_unprefixed(&out))
}

pub fn aptos_hash_verify(
    packet_header: &str,
    payload_hash: &str,
    confirmations: u64,
    target: &str,
    v_id: u32,
    expiration: u64,
) -> Result<String, AppCoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&aptos_function_signature_hash("verify"));
    out.extend_from_slice(&decode_hex_bytes(packet_header)?);
    out.extend_from_slice(&decode_hex_bytes(payload_hash)?);
    out.extend_from_slice(&confirmations.to_be_bytes());
    out.extend_from_slice(&decode_hex_bytes(target)?);
    out.extend_from_slice(&v_id.to_be_bytes());
    out.extend_from_slice(&expiration.to_be_bytes());
    Ok(keccak256_hex_unprefixed(&out))
}

pub(crate) fn aptos_function_signature_hash(function_name: &str) -> [u8; 4] {
    let mut bcs_bytes = Vec::new();
    bcs_bytes.extend_from_slice(&uleb128(function_name.len() as u64));
    bcs_bytes.extend_from_slice(function_name.as_bytes());
    let digest = Keccak256::digest(&bcs_bytes);
    [digest[0], digest[1], digest[2], digest[3]]
}

fn keccak256_hex_unprefixed(data: &[u8]) -> String {
    hex::encode(Keccak256::digest(data))
}

fn uleb128(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}
