use async_trait::async_trait;
use bip32::{DerivationPath, XPrv};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

use crate::factory::RawSignerAdapterFactory;
use crate::types::{
    chain_type_ts_name, ChainType, ChainTypeWalletDefinition, KmsProvider, LocalMnemonic,
    PublicKeyRequest, RawSignerAdapter, SeedKind, SignRequest, SignatureType, SignerError,
};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone)]
pub struct LocalMnemonicRawSignerAdapter {
    pub(crate) mnemonic: LocalMnemonic,
}

impl LocalMnemonicRawSignerAdapter {
    pub fn new(mnemonic: LocalMnemonic) -> Self {
        Self { mnemonic }
    }

    fn ecdsa_signing_key(&self, seed_kind: SeedKind) -> Result<EcdsaSigningKey, SignerError> {
        let seed = self.seed(seed_kind)?;
        let path = DerivationPath::from_str(&self.mnemonic.path)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        let child_xprv = XPrv::derive_from_path(&seed, &path)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        Ok(child_xprv.private_key().clone())
    }

    fn ecdsa_public_key(&self, seed_kind: SeedKind) -> Result<Vec<u8>, SignerError> {
        let signing_key = self.ecdsa_signing_key(seed_kind)?;
        Ok(signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    /// Returns `Zeroizing` so the BIP-39 or TON seed is wiped when the caller's
    /// binding drops. These buffers used to be plain `Vec<u8>`/`[u8; N]` derived
    /// once per signature and dropped unwiped, leaving the signing seed in freed
    /// memory and in any core dump.
    fn seed(&self, seed_kind: SeedKind) -> Result<Zeroizing<Vec<u8>>, SignerError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.mnemonic.mnemonic)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        match seed_kind {
            SeedKind::Bip39 => Ok(Zeroizing::new(mnemonic.to_seed("").to_vec())),
            SeedKind::Ton => Ok(Zeroizing::new(
                ton_hd_seed(&self.mnemonic.mnemonic, "")?.to_vec(),
            )),
        }
    }

    fn ed25519_seed(&self, seed_kind: SeedKind) -> Result<Zeroizing<[u8; 32]>, SignerError> {
        derive_ed25519_seed(&self.seed(seed_kind)?, &self.mnemonic.path)
    }

    fn ed25519_signing_key(&self, seed_kind: SeedKind) -> Result<Ed25519SigningKey, SignerError> {
        Ok(Ed25519SigningKey::from_bytes(
            &*self.ed25519_seed(seed_kind)?,
        ))
    }

    fn ed25519_public_key(&self, seed_kind: SeedKind) -> Result<Vec<u8>, SignerError> {
        Ok(self
            .ed25519_signing_key(seed_kind)?
            .verifying_key()
            .to_bytes()
            .to_vec())
    }

    fn ecdsa_signing_key_from_ed25519_seed(
        &self,
        seed_kind: SeedKind,
    ) -> Result<EcdsaSigningKey, SignerError> {
        EcdsaSigningKey::from_slice(self.ed25519_seed(seed_kind)?.as_slice())
            .map_err(|error| SignerError::Message(error.to_string()))
    }
}

#[async_trait]
impl RawSignerAdapter for LocalMnemonicRawSignerAdapter {
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        match (request.signature_type, request.private_key_signature_type) {
            (SignatureType::Ecdsa, SignatureType::Ecdsa) => {
                let signing_key = self.ecdsa_signing_key(request.seed_kind)?;
                let (signature, recovery_id) = signing_key
                    .sign_prehash_recoverable(&request.data)
                    .map_err(|error| SignerError::Message(error.to_string()))?;
                let mut result = signature.to_bytes().to_vec();
                let recovery_id = if request.transform_recovery_id {
                    recovery_id.to_byte() + 27
                } else {
                    recovery_id.to_byte()
                };
                result.push(recovery_id);
                Ok(result)
            }
            (SignatureType::Ed25519, SignatureType::Ecdsa) => Err(SignerError::Message(
                "Bad keypair generation: only mismatch allowed is Ed25519 pk -> ECDSA key pair"
                    .to_string(),
            )),
            (SignatureType::Ecdsa, SignatureType::Ed25519) => {
                let signing_key = self.ecdsa_signing_key_from_ed25519_seed(request.seed_kind)?;
                let (signature, recovery_id) = signing_key
                    .sign_prehash_recoverable(&request.data)
                    .map_err(|error| SignerError::Message(error.to_string()))?;
                let mut result = signature.to_bytes().to_vec();
                let recovery_id = if request.transform_recovery_id {
                    recovery_id.to_byte() + 27
                } else {
                    recovery_id.to_byte()
                };
                result.push(recovery_id);
                Ok(result)
            }
            (SignatureType::Ed25519, SignatureType::Ed25519) => {
                let signature = self
                    .ed25519_signing_key(request.seed_kind)?
                    .sign(&request.data);
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        match (request.signature_type, request.private_key_signature_type) {
            (SignatureType::Ecdsa, SignatureType::Ecdsa) => {
                self.ecdsa_public_key(request.seed_kind)
            }
            (SignatureType::Ed25519, SignatureType::Ecdsa) => Err(SignerError::Message(
                "Bad keypair generation: only mismatch allowed is Ed25519 pk -> ECDSA key pair"
                    .to_string(),
            )),
            (SignatureType::Ecdsa, SignatureType::Ed25519) => {
                let signing_key = self.ecdsa_signing_key_from_ed25519_seed(request.seed_kind)?;
                Ok(signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec())
            }
            (SignatureType::Ed25519, SignatureType::Ed25519) => {
                self.ed25519_public_key(request.seed_kind)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalMnemonicRawSignerAdapterFactory {
    wallet_to_mnemonic_map: HashMap<String, LocalMnemonic>,
}

impl LocalMnemonicRawSignerAdapterFactory {
    pub fn new(wallet_to_mnemonic_map: HashMap<String, LocalMnemonic>) -> Self {
        Self {
            wallet_to_mnemonic_map,
        }
    }

    fn mapping_key(wallet_name: &str, chain_type: ChainType) -> String {
        format!("{wallet_name}-{}", chain_type_ts_name(chain_type))
    }
}

#[async_trait]
impl RawSignerAdapterFactory for LocalMnemonicRawSignerAdapterFactory {
    async fn mnemonic(
        &self,
        wallet_name: &str,
        chain_type: ChainType,
        _definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        let key = Self::mapping_key(wallet_name, chain_type);
        let mnemonic = self
            .wallet_to_mnemonic_map
            .get(&key)
            .cloned()
            .ok_or_else(|| SignerError::Message("No mapping found".to_string()))?;
        Ok(Arc::new(LocalMnemonicRawSignerAdapter::new(mnemonic)))
    }

    async fn kms(
        &self,
        provider: KmsProvider,
        _definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        Err(SignerError::UnsupportedKmsProvider(provider))
    }
}

fn derive_ed25519_seed(seed: &[u8], path: &str) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|error| SignerError::Message(error.to_string()))?;
    Mac::update(&mut mac, seed);
    let master = mac.finalize().into_bytes();
    let mut key = slice_to_32(&master[..32])?;
    let mut chain_code = slice_to_32(&master[32..])?;

    for segment in parse_hardened_ed25519_path(path)? {
        let index = segment
            .checked_add(0x8000_0000)
            .ok_or_else(|| SignerError::Message("Invalid derivation path".to_string()))?;
        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        Mac::update(&mut mac, &[0]);
        Mac::update(&mut mac, &key);
        Mac::update(&mut mac, &index.to_be_bytes());
        let child = mac.finalize().into_bytes();
        key = slice_to_32(&child[..32])?;
        chain_code = slice_to_32(&child[32..])?;
    }

    // The chain code is key-derivation material and does not leave this
    // function, so wipe it rather than letting the stack copy persist.
    chain_code.zeroize();
    Ok(Zeroizing::new(key))
}

pub(crate) fn ton_hd_seed(
    mnemonic: &str,
    password: &str,
) -> Result<Zeroizing<[u8; 64]>, SignerError> {
    let mut mac = HmacSha512::new_from_slice(mnemonic.as_bytes())
        .map_err(|error| SignerError::Message(error.to_string()))?;
    Mac::update(&mut mac, password.as_bytes());
    let entropy = mac.finalize().into_bytes();
    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(&entropy, b"TON HD Keys seed", 100_000, &mut seed);
    Ok(Zeroizing::new(seed))
}

fn parse_hardened_ed25519_path(path: &str) -> Result<Vec<u32>, SignerError> {
    let Some(rest) = path.strip_prefix("m/") else {
        return Err(SignerError::Message("Invalid derivation path".to_string()));
    };
    if rest.is_empty() {
        return Err(SignerError::Message("Invalid derivation path".to_string()));
    }

    rest.split('/')
        .map(|segment| {
            let number = segment
                .strip_suffix('\'')
                .ok_or_else(|| SignerError::Message("Invalid derivation path".to_string()))?;
            if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
                return Err(SignerError::Message("Invalid derivation path".to_string()));
            }
            number
                .parse::<u32>()
                .map_err(|_| SignerError::Message("Invalid derivation path".to_string()))
        })
        .collect()
}

fn slice_to_32(value: &[u8]) -> Result<[u8; 32], SignerError> {
    value
        .try_into()
        .map_err(|_| SignerError::Message("Expected 32 bytes".to_string()))
}

#[cfg(test)]
mod factory_tests;
#[cfg(test)]
mod tests;
