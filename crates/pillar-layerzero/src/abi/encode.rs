use pillar_core::AppCoreError;
use sha3::{Digest, Keccak256};

pub(crate) fn decode_hex_20(value: &str) -> Result<[u8; 20], AppCoreError> {
    let bytes = decode_hex_bytes(value)?;
    if bytes.len() != 20 {
        return Err(AppCoreError::Internal(format!(
            "invalid address length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn solidity_uint256(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

pub(crate) fn solidity_address_word(value: &str) -> Result<[u8; 32], AppCoreError> {
    let address = decode_hex_20(value)?;
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    Ok(out)
}

pub(crate) fn function_selector(signature: &str) -> [u8; 4] {
    let digest = Keccak256::digest(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

pub(crate) fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, AppCoreError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len().is_multiple_of(2) {
        hex::decode(value).map_err(|error| AppCoreError::Internal(error.to_string()))
    } else {
        hex::decode(format!("0{value}")).map_err(|error| AppCoreError::Internal(error.to_string()))
    }
}

pub(crate) fn decode_hex_32(value: &str) -> Result<[u8; 32], AppCoreError> {
    let bytes = decode_hex_bytes(value)?;
    if bytes.len() != 32 {
        return Err(AppCoreError::Internal(format!(
            "invalid bytes32 length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn solidity_dynamic_bytes(value: &str) -> Result<Vec<u8>, AppCoreError> {
    let bytes = decode_hex_bytes(value)?;
    let mut out = Vec::new();
    out.extend_from_slice(&solidity_uint256(bytes.len() as u64));
    out.extend_from_slice(&bytes);
    let padding = (32 - (bytes.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0, padding));
    Ok(out)
}

pub(crate) fn solidity_dynamic_bytes_array(values: &[String]) -> Result<Vec<u8>, AppCoreError> {
    let elements = values
        .iter()
        .map(|value| solidity_dynamic_bytes(value))
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    out.extend_from_slice(&solidity_uint256(elements.len() as u64));
    let mut offset = (elements.len() * 32) as u64;
    for element in &elements {
        out.extend_from_slice(&solidity_uint256(offset));
        offset += element.len() as u64;
    }
    for element in elements {
        out.extend_from_slice(&element);
    }
    Ok(out)
}

pub(crate) fn encode_verify_bytes_bytes32_u64(
    selector: [u8; 4],
    bytes_value: &str,
    bytes32_value: &str,
    uint64_value: u64,
) -> Result<String, AppCoreError> {
    let mut out = Vec::from(selector);
    out.extend_from_slice(&solidity_uint256(96));
    out.extend_from_slice(&decode_hex_32(bytes32_value)?);
    out.extend_from_slice(&solidity_uint256(uint64_value));
    out.extend_from_slice(&solidity_dynamic_bytes(bytes_value)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub(crate) fn encode_verify_bytes_bytes32_bytes32(
    selector: [u8; 4],
    bytes_value: &str,
    bytes32_value: &str,
    second_bytes32_value: &str,
) -> Result<String, AppCoreError> {
    let mut out = Vec::from(selector);
    out.extend_from_slice(&solidity_uint256(96));
    out.extend_from_slice(&decode_hex_32(bytes32_value)?);
    out.extend_from_slice(&decode_hex_32(second_bytes32_value)?);
    out.extend_from_slice(&solidity_dynamic_bytes(bytes_value)?);
    Ok(format!("0x{}", hex::encode(out)))
}

pub(crate) fn address_to_bytes32(value: &str) -> Result<[u8; 32], AppCoreError> {
    let bytes = decode_hex_bytes(value)?;
    if bytes.len() > 32 {
        return Err(AppCoreError::Internal(format!(
            "invalid address length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Decodes a source/destination OApp address into its raw 32-byte packet
/// representation, accepting `0x`-hex (EVM/Move-style, left-padded like
/// [`address_to_bytes32`]) or base58 (Solana public keys). `LzPacketV1`
/// always stores `sender`/`receiver` in the caller's native chain format —
/// `encode_lz_packet_v1` needs this to build the packet header for any
/// currently-supported non-EVM destination whose resolver hasn't already
/// pre-computed `packetHeader`/`payloadHash`.
pub(crate) fn native_address_to_bytes32(value: &str) -> Result<[u8; 32], AppCoreError> {
    address_to_bytes32(value).or_else(|_| {
        let bytes = bs58::decode(value)
            .into_vec()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        if bytes.len() != 32 {
            return Err(AppCoreError::Internal(format!(
                "invalid address length: {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    })
}
