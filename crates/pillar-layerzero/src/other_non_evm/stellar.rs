use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};

use super::keccak0x;
use crate::abi::{address_to_bytes32, decode_hex_bytes, u64_from_i64};
use crate::packet::{proof_from_event, EvmUlnProof};
use crate::types::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

const STELLAR_CONTRACT_VERSION: u8 = 0x10;
const STELLAR_STRKEY_LENGTH: usize = 56;

/// Decodes a Soroban contract strkey (`C...`) into its 32-byte contract id.
pub fn stellar_contract_id_from_strkey(value: &str) -> Result<[u8; 32], AppCoreError> {
    if value.len() != STELLAR_STRKEY_LENGTH {
        return Err(AppCoreError::Internal(format!(
            "Stellar contract strkey must be {STELLAR_STRKEY_LENGTH} characters, got {}",
            value.len()
        )));
    }

    let mut decoded = [0u8; 35];
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut decoded_len = 0usize;
    for character in value.bytes() {
        let digit = match character {
            b'A'..=b'Z' => character - b'A',
            b'2'..=b'7' => character - b'2' + 26,
            _ => {
                return Err(AppCoreError::Internal(format!(
                    "Stellar contract strkey contains non-base32 character: {character}"
                )))
            }
        };
        buffer = (buffer << 5) | u32::from(digit);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if decoded_len >= decoded.len() {
                return Err(AppCoreError::Internal(
                    "Stellar contract strkey decoded length exceeds 35 bytes".to_string(),
                ));
            }
            decoded[decoded_len] = (buffer >> bits) as u8;
            decoded_len += 1;
            if bits == 0 {
                buffer = 0;
            } else {
                buffer &= (1u32 << bits) - 1;
            }
        }
    }

    if decoded_len != decoded.len() {
        return Err(AppCoreError::Internal(format!(
            "Stellar contract strkey decoded to {decoded_len} bytes, expected 35"
        )));
    }
    if decoded[0] != STELLAR_CONTRACT_VERSION {
        return Err(AppCoreError::Internal(format!(
            "Stellar strkey has unsupported version byte 0x{:02x}, expected 0x10",
            decoded[0]
        )));
    }

    let mut crc = 0u16;
    for byte in &decoded[..33] {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    let expected_crc = u16::from(decoded[33]) | (u16::from(decoded[34]) << 8);
    if crc != expected_crc {
        return Err(AppCoreError::Internal(format!(
            "Stellar contract strkey checksum mismatch: expected 0x{expected_crc:04x}, calculated 0x{crc:04x}"
        )));
    }

    let mut contract_id = [0u8; 32];
    contract_id.copy_from_slice(&decoded[1..33]);
    Ok(contract_id)
}

#[derive(Debug, Clone)]
pub struct StellarUlnPayloadBuilder {
    uln_302: String,
    uln_302_id: [u8; 32],
}

impl StellarUlnPayloadBuilder {
    pub fn new(uln_302: impl Into<String>) -> Result<Self, AppCoreError> {
        let uln_302 = uln_302.into();
        let uln_302_id = stellar_contract_id_from_strkey(&uln_302)?;
        Ok(Self {
            uln_302,
            uln_302_id,
        })
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for StellarUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "Stellar only supports EndpointV2".to_string(),
        ))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for StellarUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let dvn_address = dvn_address.ok_or_else(|| {
            AppCoreError::Internal(
                "Stellar: DVN Address is required for verify payload".to_string(),
            )
        })?;
        let proof = proof_from_event(sent_event)?;
        let vid = v_id
            .parse::<u32>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let expiration = u64_from_i64(expiration, "expiration")?;
        let block_confirmation = u64_from_i64(block_confirmation, "blockConfirmation")?;
        let dvn_call_data = pack_dvn_call(
            vid,
            expiration,
            &proof,
            dvn_address,
            block_confirmation,
            &self.uln_302_id,
        )?;
        let hash_call_data = keccak0x(&dvn_call_data);

        Ok(HashCallDataResult {
            hash_call_data,
            details: serde_json::json!({
                "dvnHashCallData": {
                    "dvnCallData": hex::encode(&dvn_call_data),
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": self.uln_302,
                    // Rendered on one line, exactly as upstream renders it
                    // (TS: `apps/gasolina/src/app/sdks/gasolinaSdk/stellar/index.ts:183`),
                    // so the debug envelope this service returns is comparable to
                    // Gasolina's rather than merely equivalent.
                    "ulnCallData": format!(
                        "execute_transaction([{{ to: {}, func: verify, args: [{dvn_address}, {}, {}, {block_confirmation}] }}])",
                        self.uln_302, proof.packet_header, proof.payload_hash
                    ),
                },
                "ulnCallData": {
                    "methodName": "verify",
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
impl UlnReadV1PayloadBuilder for StellarUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(AppCoreError::Internal(
            "Read DVN is not available on Stellar".to_string(),
        ))
    }
}

fn pack_dvn_call(
    vid: u32,
    expiration: u64,
    proof: &EvmUlnProof,
    dvn_address: &str,
    block_confirmation: u64,
    uln_302_id: &[u8; 32],
) -> Result<Vec<u8>, AppCoreError> {
    let mut out = Vec::new();
    out.extend_from_slice(&vid.to_be_bytes());
    out.extend_from_slice(&expiration.to_be_bytes());
    out.extend_from_slice(&calls_xdr(
        proof,
        dvn_address,
        block_confirmation,
        uln_302_id,
    )?);
    Ok(out)
}

fn calls_xdr(
    proof: &EvmUlnProof,
    dvn_address: &str,
    block_confirmation: u64,
    uln_302_id: &[u8; 32],
) -> Result<Vec<u8>, AppCoreError> {
    let packet_header = decode_hex_bytes(&proof.packet_header)?;
    let payload_hash = decode_hex_bytes(&proof.payload_hash)?;
    let dvn = address_to_bytes32(dvn_address)?;
    let verify_call = call_xdr(
        uln_302_id,
        "verify",
        &[
            address_xdr(&dvn),
            bytes_xdr(&packet_header),
            bytes_xdr(&payload_hash),
            u64_xdr(block_confirmation),
        ],
    );
    let inner = vec_xdr(&[verify_call]);
    let execute = call_xdr(&dvn, "execute_transaction", &[inner]);
    Ok(vec_xdr(&[execute]))
}

fn call_xdr(to: &[u8], func: &str, args: &[Vec<u8>]) -> Vec<u8> {
    map_xdr(&[
        (symbol_xdr("args"), vec_xdr(args)),
        (symbol_xdr("func"), symbol_xdr(func)),
        (symbol_xdr("to"), address_xdr(to)),
    ])
}

fn address_xdr(address: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&18_u32.to_be_bytes());
    out.extend_from_slice(&1_u32.to_be_bytes());
    out.extend_from_slice(address);
    out
}

fn bytes_xdr(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&13_u32.to_be_bytes());
    opaque_xdr(bytes, &mut out);
    out
}

fn u64_xdr(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&5_u32.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
    out
}

fn symbol_xdr(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&15_u32.to_be_bytes());
    opaque_xdr(value.as_bytes(), &mut out);
    out
}

fn vec_xdr(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&16_u32.to_be_bytes());
    out.extend_from_slice(&1_u32.to_be_bytes());
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

fn map_xdr(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&17_u32.to_be_bytes());
    out.extend_from_slice(&1_u32.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (key, value) in entries {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }
    out
}

fn opaque_xdr(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    let padding = (4 - (bytes.len() % 4)) % 4;
    out.extend(std::iter::repeat_n(0, padding));
}
