use async_trait::async_trait;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use std::{collections::HashMap, sync::Arc};

use crate::factory::RawSignerAdapterFactory;
use crate::kms_signature::{
    ecdsa_public_key_from_spki_der, ed25519_public_key_from_spki_der,
    kms_ecdsa_signature_to_recoverable, KmsEcdsaSignatureEncoding,
};
use crate::types::{
    ChainType, ChainTypeWalletDefinition, KmsProvider, PublicKeyRequest, RawSignerAdapter,
    SignRequest, SignatureType, SignerError,
};

#[async_trait]
pub trait AwsKmsClient: Send + Sync + 'static {
    async fn sign_ecdsa_sha256_digest(
        &self,
        key_id: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError>;
    async fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, SignerError>;
    async fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, SignerError>;
}

#[derive(Clone)]
pub struct AwsSdkKmsClient {
    client: aws_sdk_kms::Client,
}

impl AwsSdkKmsClient {
    pub fn new(client: aws_sdk_kms::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AwsKmsClient for AwsSdkKmsClient {
    async fn sign_ecdsa_sha256_digest(
        &self,
        key_id: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let response = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|error| SignerError::Message(error.to_string()))?;
        response
            .signature()
            .map(|signature| signature.as_ref().to_vec())
            .ok_or_else(|| SignerError::Message("AWS KMS: sign() failed".to_string()))
    }

    async fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let response = self
            .client
            .sign()
            .key_id(key_id)
            .message(Blob::new(message.to_vec()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::Ed25519Sha512)
            .send()
            .await
            .map_err(|error| SignerError::Message(error.to_string()))?;
        response
            .signature()
            .map(|signature| signature.as_ref().to_vec())
            .ok_or_else(|| SignerError::Message("AWS KMS: sign() failed".to_string()))
    }

    async fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, SignerError> {
        let response = self
            .client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|error| SignerError::Message(error.to_string()))?;
        response
            .public_key()
            .map(|public_key| public_key.as_ref().to_vec())
            .ok_or_else(|| {
                SignerError::Message(format!(
                    "AWS KMS: getPublicKey() failed, public key is undefined, keyId: {key_id}"
                ))
            })
    }
}

pub struct AwsKmsRawSignerAdapter<C> {
    key_id: String,
    client: Arc<C>,
    public_key_by_signature_type: tokio::sync::Mutex<HashMap<SignatureType, Vec<u8>>>,
}

impl<C> AwsKmsRawSignerAdapter<C>
where
    C: AwsKmsClient,
{
    pub fn new(key_id: String, client: Arc<C>) -> Self {
        Self {
            key_id,
            client,
            public_key_by_signature_type: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<C> RawSignerAdapter for AwsKmsRawSignerAdapter<C>
where
    C: AwsKmsClient,
{
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        match request.signature_type {
            SignatureType::Ecdsa => {
                let public_key = self
                    .get_public_key(PublicKeyRequest {
                        signature_type: SignatureType::Ecdsa,
                        private_key_signature_type: SignatureType::Ecdsa,
                        seed_kind: request.seed_kind,
                    })
                    .await?;
                let der_signature = self
                    .client
                    .sign_ecdsa_sha256_digest(&self.key_id, &request.data)
                    .await?;
                kms_ecdsa_signature_to_recoverable(
                    &der_signature,
                    KmsEcdsaSignatureEncoding::Der,
                    &request.data,
                    &public_key,
                    request.transform_recovery_id,
                )
            }
            SignatureType::Ed25519 => {
                if request.private_key_signature_type != SignatureType::Ed25519 {
                    return Err(SignerError::Message(
                        "AWS KMS Ed25519 signing requires an Ed25519 key".to_string(),
                    ));
                }
                self.client
                    .sign_ed25519_raw(&self.key_id, &request.data)
                    .await
            }
        }
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        if let Some(cached) = self
            .public_key_by_signature_type
            .lock()
            .await
            .get(&request.signature_type)
            .cloned()
        {
            return Ok(cached);
        }
        let der = self.client.get_public_key_der(&self.key_id).await?;
        let public_key = match request.signature_type {
            SignatureType::Ecdsa => ecdsa_public_key_from_spki_der(&der)?,
            SignatureType::Ed25519 => ed25519_public_key_from_spki_der(&der)?,
        };
        self.public_key_by_signature_type
            .lock()
            .await
            .insert(request.signature_type, public_key.clone());
        Ok(public_key)
    }
}

pub struct AwsKmsRawSignerAdapterFactory<C> {
    client: Arc<C>,
}

impl<C> AwsKmsRawSignerAdapterFactory<C>
where
    C: AwsKmsClient,
{
    pub fn new(client: Arc<C>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<C> RawSignerAdapterFactory for AwsKmsRawSignerAdapterFactory<C>
where
    C: AwsKmsClient,
{
    async fn mnemonic(
        &self,
        _wallet_name: &str,
        _chain_type: ChainType,
        _definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        Err(SignerError::UnsupportedSignerType("MNEMONIC".to_string()))
    }

    async fn kms(
        &self,
        provider: KmsProvider,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        if provider != KmsProvider::Aws {
            return Err(SignerError::UnsupportedKmsProvider(provider));
        }
        Ok(Arc::new(AwsKmsRawSignerAdapter::new(
            definition.secret_name.clone(),
            self.client.clone(),
        )))
    }
}

#[cfg(test)]
mod tests;
