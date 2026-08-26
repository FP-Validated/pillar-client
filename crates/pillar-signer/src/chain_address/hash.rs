use sha2::Sha256;
use sha3::{Digest as CryptoDigest, Keccak256};

use crate::kms_signature::raw_ecdsa_public_key;
use crate::types::SignerError;

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn ethers_hash_message(data: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", data.len());
    let mut hasher = Keccak256::new();
    CryptoDigest::update(&mut hasher, prefix.as_bytes());
    CryptoDigest::update(&mut hasher, data);
    hasher.finalize().into()
}

pub(crate) fn evm_address_from_public_key(public_key: &[u8]) -> Result<String, SignerError> {
    let key = evm_public_key_body(public_key)?;
    let hash = Keccak256::digest(key);
    Ok(to_checksum_address(&hash[12..]))
}

pub(crate) fn evm_public_key_body(public_key: &[u8]) -> Result<&[u8], SignerError> {
    match public_key {
        [0x04, 0xca, body @ ..] if body.len() == 64 => Ok(body),
        _ => raw_ecdsa_public_key(public_key),
    }
}

pub(crate) fn evm_signer_info_public_key(public_key: &[u8], is_kms: bool) -> &[u8] {
    match public_key {
        [0x04, 0xca, body @ ..] if body.len() == 64 => body,
        [0x04, body @ ..] if is_kms && body.len() == 64 => body,
        _ => strip_public_key_prefix(public_key),
    }
}

pub(crate) fn compress_ecdsa_public_key(public_key: &[u8]) -> Result<Vec<u8>, SignerError> {
    let key = match public_key.len() {
        65 if public_key[0] == 0x04 => &public_key[1..],
        64 => public_key,
        33 if public_key[0] == 0x02 || public_key[0] == 0x03 => return Ok(public_key.to_vec()),
        other => {
            return Err(SignerError::Message(format!(
            "ECDSA public key must be 64 raw, 65 uncompressed, or 33 compressed bytes, got {other}"
        )))
        }
    };
    let mut compressed = Vec::with_capacity(33);
    compressed.push(if key[63] % 2 == 0 { 0x02 } else { 0x03 });
    compressed.extend_from_slice(&key[..32]);
    Ok(compressed)
}

fn to_checksum_address(address: &[u8]) -> String {
    let lower = bytes_to_hex(address);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut checksummed = String::from("0x");
    for (index, ch) in lower.chars().enumerate() {
        let byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            (byte >> 4) & 0x0f
        } else {
            byte & 0x0f
        };
        if ch.is_ascii_hexdigit() && ch.is_ascii_alphabetic() && nibble >= 8 {
            checksummed.push(ch.to_ascii_uppercase());
        } else {
            checksummed.push(ch);
        }
    }
    checksummed
}

pub(crate) fn strip_public_key_prefix(public_key: &[u8]) -> &[u8] {
    if public_key.len() > 32 {
        &public_key[1..]
    } else {
        public_key
    }
}

pub(crate) fn ton_public_key_cell_hash(public_key: &[u8]) -> Result<[u8; 32], SignerError> {
    if public_key.len() != 64 {
        return Err(SignerError::Message(format!(
            "TON public key cell stores exactly 64 bytes, got {}",
            public_key.len()
        )));
    }
    let mut repr = Vec::with_capacity(66);
    repr.push(0);
    repr.push(128);
    repr.extend_from_slice(public_key);
    Ok(Sha256::digest(&repr).into())
}
