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
use crate::types::{ChainType, KmsProvider, SeedKind, SignatureType, SignerError};

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

/// Upstream `GasolinaCantonSignerAdapter`: a raw ECDSA signature over the raw
/// digest, no recovery-id transformation, and the provider's public key with
/// its first byte dropped, whatever its shape, as both address and signer-info
/// key (TS 1.2.66: `gasolina-signer-adapter/src/canton/index.ts:15-23`,
/// `gasolinaSignerAdapter.ts:59-66`).
#[derive(Clone)]
pub struct CantonChain;

impl ChainAddress for CantonChain {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        public_key
            .split_first()
            .map(|(_, rest)| format!("0x{}", bytes_to_hex(rest)))
            .ok_or_else(|| SignerError::Message("empty Canton signer public key".to_string()))
    }

    fn signer_info_public_key<'a>(&self, public_key: &'a [u8], _is_kms: bool) -> &'a [u8] {
        public_key.get(1..).unwrap_or_default()
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
    // Upstream's Solana adapter answers `base58(publicKey.subarray(0, 32))`
    // (`gasolina-signer-adapter/src/solana/index.ts:9-11`) over the 65-byte SEC1 key every
    // 1.2.66 signer hands it (mnemonic, AWS and GCP SPKI), i.e. `base58(04 || X[..31])`. The
    // DVN verifies the 64-byte `X || Y` (`signer-info.publicKey`), never this string, so the
    // address is only a response representation. A bare `X || Y` is normalized to SEC1 first.
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError> {
        self.signer_address_for_provider(public_key, None)
    }

    // An Azure key answers base58(X), the key registered for the mainnet DVN (`ded0f97`);
    // 1.2.66 has no Azure adapter, so the upstream slice above does not bind it.
    fn signer_address_for_provider(
        &self,
        public_key: &[u8],
        kms_provider: Option<KmsProvider>,
    ) -> Result<String, SignerError> {
        let sec1 = solana_sec1_public_key(public_key)?;
        let start = usize::from(kms_provider == Some(KmsProvider::Azure));
        Ok(bs58::encode(&sec1[start..start + 32]).into_string())
    }

    fn private_key_signature_type(&self, is_kms: bool) -> SignatureType {
        if is_kms {
            SignatureType::Ecdsa
        } else {
            SignatureType::Ed25519
        }
    }

    // Upstream drops the first byte of the provider's key (`gasolinaSignerAdapter.ts:61-66`),
    // which on SEC1 leaves `X || Y`.
    fn signer_info_public_key<'a>(&self, public_key: &'a [u8], _is_kms: bool) -> &'a [u8] {
        match public_key {
            [0x04, body @ ..] if body.len() == 64 => body,
            _ => public_key,
        }
    }
}

/// The secp256k1 key as 65-byte SEC1 `04 || X || Y`; a bare 64-byte `X || Y` gains the prefix.
fn solana_sec1_public_key(public_key: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, SignerError> {
    match public_key.len() {
        65 if public_key[0] == 0x04 => Ok(std::borrow::Cow::Borrowed(public_key)),
        64 => {
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(public_key);
            Ok(std::borrow::Cow::Owned(sec1))
        }
        other => Err(SignerError::Message(format!(
            "Solana signer public key must be a 65-byte SEC1 or 64-byte X||Y secp256k1 key, got {other} bytes"
        ))),
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
