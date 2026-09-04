use blake2::{
    digest::{Update as BlakeUpdate, VariableOutput},
    Blake2bVar,
};
use ripemd::Ripemd160;
use sha2::Sha256;
use sha3::{Digest as CryptoDigest, Sha3_256};

use crate::chain_address::{
    bytes_to_hex, compress_ecdsa_public_key, ethers_hash_message, evm_address_from_public_key,
    evm_signer_info_public_key, ton_public_key_cell_hash, ChainAddress,
};
use crate::types::{ChainType, SeedKind, SignatureType, SignerError};

#[derive(Clone)]
pub struct EvmChain;

impl ChainAddress for EvmChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        evm_address_from_public_key(public_key)
    }

    fn transform_recovery_id(&self) -> bool {
        true
    }

    fn prepare_data(&self, data: &[u8]) -> Vec<u8> {
        ethers_hash_message(data).to_vec()
    }

    fn signer_info_public_key<'a>(&self, public_key: &'a [u8], is_kms: bool) -> &'a [u8] {
        evm_signer_info_public_key(public_key, is_kms)
    }
}

#[derive(Clone)]
pub struct EvmAddressChain;

impl ChainAddress for EvmAddressChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        evm_address_from_public_key(public_key)
    }

    fn signer_info_public_key<'a>(&self, public_key: &'a [u8], is_kms: bool) -> &'a [u8] {
        evm_signer_info_public_key(public_key, is_kms)
    }
}

#[derive(Clone)]
pub struct AptosChain;

impl ChainAddress for AptosChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        let public_key = match public_key.len() {
            65 if public_key[0] == 0x04 => public_key,
            other => {
                return Err(SignerError::Message(format!(
                    "Aptos secp256k1 public key must be 65 uncompressed bytes, got {other}"
                )))
            }
        };
        let mut auth_key_input = Vec::with_capacity(public_key.len() + 3);
        auth_key_input.push(0x01);
        auth_key_input.push(public_key.len() as u8);
        auth_key_input.extend_from_slice(public_key);
        auth_key_input.push(0x02);
        Ok(format!(
            "0x{}",
            bytes_to_hex(&Sha3_256::digest(&auth_key_input))
        ))
    }

    fn private_key_signature_type(&self, is_kms: bool) -> SignatureType {
        if is_kms {
            SignatureType::Ecdsa
        } else {
            SignatureType::Ed25519
        }
    }

    fn address_private_key_signature_type(&self, _is_kms: bool) -> SignatureType {
        SignatureType::Ecdsa
    }
}

#[derive(Clone)]
pub struct SolanaChain;

impl ChainAddress for SolanaChain {
    // The address is the X coordinate, and it has to be X whatever shape the provider
    // returned the key in. Upstream reads the first 32 bytes with no prefix handling
    // (`gasolina-signer-adapter/src/solana/index.ts:9-11`), which is only correct
    // because its Azure adapter hands back a bare 64-byte `X||Y`
    // (`azureKmsSignerAdapter.ts:185-187`). This crate's Azure adapter returns
    // SEC1-uncompressed `04||X||Y` instead (`azure/adapter.rs:163-166`), so copying
    // upstream's slice published `04 || X[..31]` — a real, different Solana address
    // (`KhLrwX6F…` instead of the registered `EboBSUoo…`), which is the same class of
    // defect LayerZero reported on 2026-07-10 for the TypeScript service. The
    // registered key is the authority, not upstream's slice: it sits at offset 17 of
    // the mainnet DVN config account `EqkXVEeapm7JqrS1W3AGeN5ZwCRLDUHtr1XY9TuVr4rD`
    // and is pinned by `solana_address_matches_the_registered_mainnet_dvn_key`.
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        // Derive from the same canonical bytes `/signer-info` advertises, so the
        // address and the published public key can never disagree again.
        let public_key = solana_signer_info_public_key(public_key);
        if public_key.len() < 32 {
            return Err(SignerError::Message(format!(
                "Solana public key must be at least 32 bytes, got {}",
                public_key.len()
            )));
        }
        Ok(bs58::encode(&public_key[..32]).into_string())
    }

    fn private_key_signature_type(&self, is_kms: bool) -> SignatureType {
        if is_kms {
            SignatureType::Ecdsa
        } else {
            SignatureType::Ed25519
        }
    }

    fn signer_info_public_key<'a>(&self, public_key: &'a [u8], is_kms: bool) -> &'a [u8] {
        if is_kms {
            solana_signer_info_public_key(public_key)
        } else {
            public_key
        }
    }
}

fn solana_signer_info_public_key(public_key: &[u8]) -> &[u8] {
    match public_key {
        [0x04, body @ ..] if body.len() == 64 => body,
        _ => public_key,
    }
}

#[derive(Clone)]
pub struct SuiChain;

impl ChainAddress for SuiChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        let compressed = compress_ecdsa_public_key(public_key)?;
        let mut hasher =
            Blake2bVar::new(32).map_err(|error| SignerError::Message(error.to_string()))?;
        BlakeUpdate::update(&mut hasher, &[1]);
        BlakeUpdate::update(&mut hasher, &compressed);
        let mut digest = [0u8; 32];
        hasher
            .finalize_variable(&mut digest)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        Ok(format!("0x{}", bytes_to_hex(&digest)))
    }

    fn private_key_signature_type(&self, is_kms: bool) -> SignatureType {
        if is_kms {
            SignatureType::Ecdsa
        } else {
            SignatureType::Ed25519
        }
    }

    fn address_private_key_signature_type(&self, _is_kms: bool) -> SignatureType {
        SignatureType::Ecdsa
    }
}

#[derive(Clone)]
pub struct TonChain;

impl ChainAddress for TonChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        let public_key = match public_key.len() {
            65 if public_key[0] == 0x04 => &public_key[1..],
            64 => public_key,
            other => {
                return Err(SignerError::Message(format!(
                "TON ECDSA public key must be 64 raw bytes or 65 uncompressed bytes, got {other}"
            )))
            }
        };
        let hash = ton_public_key_cell_hash(public_key)?;
        Ok(format!("0x{}", bytes_to_hex(&hash)))
    }

    fn private_key_signature_type(&self, is_kms: bool) -> SignatureType {
        if is_kms {
            SignatureType::Ecdsa
        } else {
            SignatureType::Ed25519
        }
    }

    fn seed_kind(&self) -> SeedKind {
        SeedKind::Ton
    }
}

#[derive(Clone)]
pub struct InitiaChain;

impl ChainAddress for InitiaChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        let compressed = compress_ecdsa_public_key(public_key)?;
        let raw_address = Ripemd160::digest(Sha256::digest(&compressed));
        let hrp =
            bech32::Hrp::parse("init").map_err(|error| SignerError::Message(error.to_string()))?;
        bech32::encode::<bech32::Bech32>(hrp, &raw_address)
            .map_err(|error| SignerError::Message(error.to_string()))
    }

    // No key-type override, deliberately. Upstream's Initia adapter declares neither
    // `privateKeySignatureType` nor an address-specific one
    // (`gasolina-signer-adapter/src/initia/index.ts`), so it inherits the ECDSA base
    // for both signing and the address. Aptos, Solana, Sui and TON do override;
    // Initia is the one Move-adjacent chain that does not.
}

#[derive(Clone)]
pub struct PlainChain(pub ChainType);

impl ChainAddress for PlainChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        Ok(format!("{:?}:{}", self.0, bytes_to_hex(public_key)))
    }
}
