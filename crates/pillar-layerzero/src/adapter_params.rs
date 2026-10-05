//! ULNv2 adapter params as upstream reads them to rebuild a V1 send for a V3 receive
//! library: only their gas reaches the hydrated event, as `options.lzReceive.gas`.

use num_bigint::BigUint;
use pillar_core::AppCoreError;

use crate::abi::{abi_dynamic_bytes, abi_word};

/// `RelayerParams(bytes adapterParams, uint16 outboundProofType)` on UltraLightNodeV2.
pub const ULN_V2_RELAYER_PARAMS_TOPIC: &str =
    "0xb0c632f55f1e1b3b2c3d82f41ee4716bb4c00f0f5d84cdafc141581bb8757a4f";
/// `Packet(bytes payload)` on UltraLightNodeV2.
pub const ULN_V2_PACKET_TOPIC: &str =
    "0xe9bded5f24a4168e4f3bf44e00298c993b22376aad8c58c7dda9718a54cbea82";
const DEFAULT_ADAPTER_PARAMS_SELECTOR: &str = "2a819bbf";

/// The `RelayerParams` log's adapter params and outbound proof type; the proof type is
/// masked to 16 bits as an ABI decoder does.
pub fn decode_uln_v2_relayer_params_log(data: &[u8]) -> Result<(Vec<u8>, u16), AppCoreError> {
    let adapter_params = abi_dynamic_bytes(data, 0, 2)?;
    let word = abi_word(data, 1)?;
    Ok((adapter_params, u16::from_be_bytes([word[30], word[31]])))
}

/// `UltraLightNodeV2.defaultAdapterParams(uint16 chainId, uint16 proofType)` call data.
pub fn encode_uln_v2_default_adapter_params_call(dst_eid: u16, proof_type: u16) -> String {
    format!(
        "0x{DEFAULT_ADAPTER_PARAMS_SELECTOR}{:064x}{:064x}",
        dst_eid, proof_type
    )
}

/// The `bytes` an ABI function returns.
pub fn decode_abi_bytes_return(data: &[u8]) -> Result<Vec<u8>, AppCoreError> {
    abi_dynamic_bytes(data, 0, 1)
}

/// `decodeAdapterParams` on an EVM source (`lz-v1-sdk/src/evm/decoders/adapterParams.ts`):
/// a 2-byte version then up to 32 bytes of gas. Either slice being empty is ethers'
/// `invalid BigNumber string`, so fewer than three bytes cannot be decoded.
pub fn evm_adapter_params_gas(raw: &[u8]) -> Option<String> {
    if raw.len() < 3 {
        return None;
    }
    let end = raw.len().min(34);
    Some(BigUint::from_bytes_be(&raw[2..end]).to_string())
}

/// Aptos V1 adapter params: gas, and for type 2 the native drop amount and receiver bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptosAdapterParams {
    pub kind: u16,
    pub gas: u64,
    pub airdrop_amount: u64,
    pub airdrop_address: Vec<u8>,
}

/// `decodeAdapterParams` on Aptos (`common-aptos/src/utils.ts:395-419`): type 1 is
/// exactly 10 bytes, type 2 more than 18, anything else is refused; amounts are u64.
pub fn decode_aptos_adapter_params(raw: &[u8]) -> Result<AptosAdapterParams, AppCoreError> {
    let invalid = || AppCoreError::Internal("invalid adapter params".to_string());
    let kind = match raw {
        [high, low, ..] => u16::from(*high) * 256 + u16::from(*low),
        _ => return Err(invalid()),
    };
    let valid = match kind {
        1 => raw.len() == 10,
        2 => raw.len() > 18,
        _ => false,
    };
    if !valid {
        return Err(invalid());
    }
    let u64_at = |start: usize| -> Result<u64, AppCoreError> {
        Ok(u64::from_be_bytes(
            raw[start..start + 8].try_into().map_err(|_| invalid())?,
        ))
    };
    Ok(AptosAdapterParams {
        kind,
        gas: u64_at(2)?,
        airdrop_amount: if kind == 2 { u64_at(10)? } else { 0 },
        airdrop_address: if kind == 2 {
            raw[18..].to_vec()
        } else {
            Vec::new()
        },
    })
}

/// The gas `decodeAdapterParams` reads on Aptos.
pub fn aptos_adapter_params_gas(raw: &[u8]) -> Result<String, AppCoreError> {
    Ok(decode_aptos_adapter_params(raw)?.gas.to_string())
}

/// Node's `Buffer.from(hex, 'hex')`: pairs are read until the first one that is not
/// hexadecimal, and a trailing half pair is dropped.
pub fn node_buffer_from_hex(hex: &str) -> Vec<u8> {
    let digits = hex.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    for [high, low] in digits.as_chunks::<2>().0 {
        let nibble = |digit: u8| (digit as char).to_digit(16);
        match (nibble(*high), nibble(*low)) {
            (Some(high), Some(low)) => out.push((high * 16 + low) as u8),
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_gas_needs_a_version_and_a_gas_byte() {
        assert_eq!(evm_adapter_params_gas(&[0, 1]), None);
        assert_eq!(evm_adapter_params_gas(&[0, 1, 5]).as_deref(), Some("5"));
        let mut v2 = vec![0, 2];
        v2.extend_from_slice(&[0; 29]);
        v2.extend_from_slice(&[0x03, 0x0d, 0x40]);
        v2.extend_from_slice(&[0xff; 52]);
        assert_eq!(evm_adapter_params_gas(&v2).as_deref(), Some("200000"));
    }

    #[test]
    fn aptos_gas_follows_the_type_lengths() {
        let v1 = [0, 1, 0, 0, 0, 0, 0, 3, 0x0d, 0x40];
        assert_eq!(aptos_adapter_params_gas(&v1).unwrap(), "200000");
        assert!(aptos_adapter_params_gas(&v1[..9]).is_err());
        assert!(
            aptos_adapter_params_gas(&[0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1])
                .is_err()
        );
        assert!(aptos_adapter_params_gas(&[0, 3]).is_err());
        assert!(aptos_adapter_params_gas(&[]).is_err());
    }

    #[test]
    fn node_hex_stops_at_the_first_bad_pair() {
        assert_eq!(node_buffer_from_hex("0001zz02"), vec![0, 1]);
        assert_eq!(node_buffer_from_hex("abc"), vec![0xab]);
    }
}
