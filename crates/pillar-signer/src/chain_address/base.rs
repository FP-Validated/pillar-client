use pillar_core::Signature;
use std::sync::Arc;

use crate::chain_address::{bytes_to_hex, strip_public_key_prefix};
use crate::types::{
    PublicKeyRequest, RawSignerAdapter, SeedKind, SignRequest, SignatureType, SignerError,
};

pub trait ChainAddress: Send + Sync + 'static {
    fn signer_address(&self, public_key: &[u8]) -> Result<String, SignerError>;

    fn private_key_signature_type(&self, _is_kms: bool) -> SignatureType {
        SignatureType::Ecdsa
    }

    fn address_private_key_signature_type(&self, is_kms: bool) -> SignatureType {
        self.private_key_signature_type(is_kms)
    }

    fn transform_recovery_id(&self) -> bool {
        false
    }

    fn seed_kind(&self) -> SeedKind {
        SeedKind::Bip39
    }

    fn prepare_data(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn signer_info_public_key<'a>(&self, public_key: &'a [u8], _is_kms: bool) -> &'a [u8] {
        strip_public_key_prefix(public_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    pub address: String,
    pub public_key: String,
}

pub struct PillarSignerAdapter<C> {
    signer_adapter: Arc<dyn RawSignerAdapter>,
    chain: C,
    is_kms: bool,
    cached_address: tokio::sync::Mutex<Option<String>>,
}

impl<C> PillarSignerAdapter<C>
where
    C: ChainAddress,
{
    pub fn new(signer_adapter: Arc<dyn RawSignerAdapter>, chain: C, is_kms: bool) -> Self {
        Self {
            signer_adapter,
            chain,
            is_kms,
            cached_address: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn pillar_sign(&self, data: &[u8]) -> Result<Signature, SignerError> {
        let prepared = self.chain.prepare_data(data);
        let signature = self
            .signer_adapter
            .sign(SignRequest {
                data: prepared,
                signature_type: SignatureType::Ecdsa,
                private_key_signature_type: self.chain.private_key_signature_type(self.is_kms),
                transform_recovery_id: self.chain.transform_recovery_id(),
                seed_kind: self.chain.seed_kind(),
            })
            .await?;
        let address = self.cached_address().await?;
        Ok(Signature {
            signature: ensure_0x_prefixed(&bytes_to_hex(&signature)),
            address,
        })
    }

    pub async fn get_signer_info(&self) -> Result<SignerInfo, SignerError> {
        let address = self.cached_address().await?;
        let public_key = self.get_public_key().await?;
        let public_key = self.chain.signer_info_public_key(&public_key, self.is_kms);
        Ok(SignerInfo {
            address,
            public_key: format!("0x{}", bytes_to_hex(public_key)),
        })
    }

    async fn cached_address(&self) -> Result<String, SignerError> {
        if let Some(address) = self.cached_address.lock().await.clone() {
            return Ok(address);
        }
        let public_key = self.get_address_public_key().await?;
        let address = self.chain.signer_address(&public_key)?;
        *self.cached_address.lock().await = Some(address.clone());
        Ok(address)
    }

    async fn get_public_key(&self) -> Result<Vec<u8>, SignerError> {
        self.signer_adapter
            .get_public_key(PublicKeyRequest {
                signature_type: SignatureType::Ecdsa,
                private_key_signature_type: self.chain.private_key_signature_type(self.is_kms),
                seed_kind: self.chain.seed_kind(),
            })
            .await
    }

    async fn get_address_public_key(&self) -> Result<Vec<u8>, SignerError> {
        self.signer_adapter
            .get_public_key(PublicKeyRequest {
                signature_type: SignatureType::Ecdsa,
                private_key_signature_type: self
                    .chain
                    .address_private_key_signature_type(self.is_kms),
                seed_kind: self.chain.seed_kind(),
            })
            .await
    }
}

fn ensure_0x_prefixed(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_string()
    } else {
        format!("0x{value}")
    }
}

#[cfg(test)]
mod tests;
