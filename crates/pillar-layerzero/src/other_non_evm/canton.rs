use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::abi::{decode_hex_32, decode_hex_bytes, u64_from_i64};
use crate::packet::proof_from_event;
use crate::types::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

const SECP256K1_SPKI_DER_HEADER: [u8; 23] = [
    0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct CantonVerifyDigestInput<'a> {
    pub dvn: &'a [u8; 32],
    pub packet_header: &'a [u8],
    pub payload_hash: &'a [u8; 32],
    pub confirmations: u64,
    pub target: &'a [u8; 32],
    pub vid: u32,
    pub expiration: u64,
}

pub fn canton_hash_verify(input: CantonVerifyDigestInput<'_>) -> [u8; 32] {
    let selector = Keccak256::digest(b"Verify");
    let mut hash = Keccak256::new();
    hash.update(&selector[..4]);
    hash.update(input.dvn);
    hash.update(input.packet_header);
    hash.update(input.payload_hash);
    hash.update(input.confirmations.to_be_bytes());
    hash.update(input.target);
    hash.update(input.vid.to_be_bytes());
    hash.update(input.expiration.to_be_bytes());
    hash.finalize().into()
}

/// Canton key fingerprint (upstream `computeCantonFingerprint`): purpose-12 multihash
/// of the SPKI DER key. This is not the signer address Gasolina publishes; see
/// `canton_gasolina_signer_address`.
pub fn canton_key_fingerprint(uncompressed_public_key: &[u8]) -> Result<String, &'static str> {
    if uncompressed_public_key.len() != 65 || uncompressed_public_key[0] != 0x04 {
        return Err("invalid uncompressed SEC1 secp256k1 public key");
    }
    let mut der = [0; SECP256K1_SPKI_DER_HEADER.len() + 65];
    der[..SECP256K1_SPKI_DER_HEADER.len()].copy_from_slice(&SECP256K1_SPKI_DER_HEADER);
    der[SECP256K1_SPKI_DER_HEADER.len()..].copy_from_slice(uncompressed_public_key);
    Ok(canton_multihash(12, &der))
}

/// Upstream `GasolinaCantonSignerAdapter.getSignerAddress`: the provider's public key
/// with its first byte dropped, whatever its shape. For a SEC1 key that is `x || y`;
/// for a bare 64-byte key it also drops the first byte of `x`, which upstream does too
/// (`tests/gasolina_parity/canton_signer_address.json`).
pub fn canton_gasolina_signer_address(public_key: &[u8]) -> Result<String, &'static str> {
    let (_, rest) = public_key
        .split_first()
        .ok_or("empty Canton signer public key")?;
    Ok(format!("0x{}", hex::encode(rest)))
}

pub fn canton_party_namespace(owner_fingerprints: &[&str]) -> String {
    let mut owners = owner_fingerprints
        .iter()
        .map(|owner| owner.trim_start_matches("0x"))
        .collect::<Vec<_>>();
    owners.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(37u32.to_be_bytes());
    for owner in owners {
        hash.update((owner.len() as u32).to_be_bytes());
        hash.update(owner.as_bytes());
    }
    format!("1220{}", hex::encode(hash.finalize()))
}

fn canton_multihash(purpose: u32, data: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(purpose.to_be_bytes());
    hash.update(data);
    format!("1220{}", hex::encode(hash.finalize()))
}

/// Gasolina's Canton builder (TS 1.2.66: `gasolinaSdk/canton/index.ts`): ULN302
/// only, the DVN address inside the digest, the target fixed by
/// `STATIC_VE3_CONTRACT_ADDRESSES.uln302`.
#[derive(Debug, Clone)]
pub struct CantonUlnPayloadBuilder {
    uln_302: String,
}

impl CantonUlnPayloadBuilder {
    pub fn new(uln_302: impl Into<String>) -> Self {
        Self {
            uln_302: uln_302.into(),
        }
    }
}

fn only_v302() -> AppCoreError {
    AppCoreError::Internal("Canton only supports ULN V302".to_string())
}

/// `getAddressAsBytes32HexString` over a hex string: `hexZeroPad(address, 32)`,
/// which keeps the caller's letter case.
fn bytes32_hex_preserving_case(address: &str) -> Result<String, AppCoreError> {
    let digits = address
        .strip_prefix("0x")
        .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| AppCoreError::Internal(format!("Invalid input for address {address}")))?;
    if digits.len() > 64 {
        return Err(AppCoreError::Internal(format!(
            "Invalid input for address {address}"
        )));
    }
    Ok(format!("0x{digits:0>64}"))
}

#[async_trait]
impl UlnV2PayloadBuilder for CantonUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(only_v302())
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for CantonUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let dvn_address = dvn_address.filter(|address| !address.is_empty()).ok_or_else(|| {
            AppCoreError::Internal(
                "Canton buildULNV3VerifyPayload requires the dvnAddress: it is part of the signed verify digest"
                    .to_string(),
            )
        })?;
        let proof = proof_from_event(sent_event)?;
        let dvn = bytes32_hex_preserving_case(dvn_address)?;
        let uln = bytes32_hex_preserving_case(&self.uln_302)?;
        let vid = v_id
            .parse::<u32>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let confirmations = u64_from_i64(block_confirmation, "blockConfirmation")?;
        let expiration_u64 = u64_from_i64(expiration, "expiration")?;
        let digest = canton_hash_verify(CantonVerifyDigestInput {
            dvn: &decode_hex_32(&dvn)?,
            packet_header: &decode_hex_bytes(&proof.packet_header)?,
            payload_hash: &decode_hex_32(&proof.payload_hash)?,
            confirmations,
            target: &decode_hex_32(&uln)?,
            vid,
            expiration: expiration_u64,
        });
        Ok(HashCallDataResult {
            hash_call_data: format!("0x{}", hex::encode(digest)),
            details: serde_json::json!({
                "dvnHashCallData": {
                    "dvnCallData": serde_json::json!([
                        dvn,
                        proof.packet_header,
                        proof.payload_hash,
                        block_confirmation,
                        uln,
                        vid,
                        expiration,
                    ]).to_string(),
                },
                "dvnCallData": {
                    "expiration": expiration,
                    "vid": v_id,
                    "targetContract": uln,
                    "ulnCallData": "unknown in canton",
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
impl UlnReadV1PayloadBuilder for CantonUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(only_v302())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        canton_gasolina_signer_address, canton_hash_verify, canton_key_fingerprint,
        canton_party_namespace, CantonVerifyDigestInput,
    };

    fn bytes32(value: &str) -> [u8; 32] {
        let decoded = hex::decode(value.strip_prefix("0x").unwrap_or(value)).unwrap();
        decoded.try_into().unwrap()
    }

    #[test]
    fn matches_gasolina_canton_digest_and_key_fingerprint_fixtures() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/gasolina_parity/canton_digest.json"
        ))
        .unwrap();
        let target = bytes32(fixture["vectors"][0]["target"].as_str().unwrap());
        let dvn = bytes32(fixture["vectors"][0]["dvn"].as_str().unwrap());
        let signer_key = hex::decode(
            fixture["vectors"][0]["signerPublicKey"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
        )
        .unwrap();
        let fingerprint = canton_key_fingerprint(&signer_key).unwrap();
        assert_eq!(
            fingerprint,
            fixture["vectors"][0]["keyFingerprint"].as_str().unwrap()
        );
        assert_eq!(
            canton_party_namespace(&[&fingerprint]),
            fixture["vectors"][0]["partyNamespace"].as_str().unwrap()
        );

        for vector in fixture["vectors"].as_array().unwrap() {
            let header = hex::decode(
                vector["packetHeader"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0x")
                    .unwrap(),
            )
            .unwrap();
            let actual = canton_hash_verify(CantonVerifyDigestInput {
                dvn: &dvn,
                packet_header: &header,
                payload_hash: &bytes32(vector["payloadHash"].as_str().unwrap()),
                confirmations: vector["input"]["confirmations"].as_u64().unwrap(),
                target: &target,
                vid: vector["input"]["vid"].as_u64().unwrap() as u32,
                expiration: vector["input"]["expiration"].as_u64().unwrap(),
            });
            assert_eq!(
                hex::encode(actual),
                vector["hashCallData"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                "{}",
                vector["id"]
            );
        }
    }

    #[test]
    fn rejects_non_uncompressed_canton_fingerprint_keys() {
        assert!(canton_key_fingerprint(&[0; 33]).is_err());
        assert!(canton_key_fingerprint(&[0x02; 65]).is_err());
    }

    /// Upstream's own adapter over a 65-byte SEC1 key and the same point as a bare
    /// 64-byte key; neither result is the key fingerprint.
    #[test]
    fn matches_gasolina_canton_signer_address_vectors() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/gasolina_parity/canton_signer_address.json"
        ))
        .unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 2);
        for vector in vectors {
            let key = hex::decode(&vector["publicKey"].as_str().unwrap()[2..]).unwrap();
            let address = canton_gasolina_signer_address(&key).unwrap();
            assert_eq!(
                address,
                vector["signerAddress"].as_str().unwrap(),
                "{}",
                vector["id"]
            );
            if key.len() == 65 {
                assert_ne!(address, canton_key_fingerprint(&key).unwrap());
            }
        }
    }
}
