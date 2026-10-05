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

pub struct AwsPublicKey {
    pub key_id: String,
    pub der: Vec<u8>,
}
fn immutable_key_id(id: &str) -> bool {
    id.starts_with("arn:")
        && id.split(':').nth(2) == Some("kms")
        && id
            .split(':')
            .nth(5)
            .is_some_and(|part| part.starts_with("key/") && part.len() > 4)
}
#[async_trait]
pub trait AwsKmsClient: Send + Sync + 'static {
    async fn sign_ecdsa_sha256_digest(
        &self,
        key_id: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError>;
    async fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, SignerError>;
    async fn get_public_key_der(&self, key_id: &str) -> Result<AwsPublicKey, SignerError>;
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
        if immutable_key_id(key_id) && response.key_id() != Some(key_id) {
            return Err(SignerError::Message(
                "AWS KMS: signing key identity changed".into(),
            ));
        }
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
        if immutable_key_id(key_id) && response.key_id() != Some(key_id) {
            return Err(SignerError::Message(
                "AWS KMS: signing key identity changed".into(),
            ));
        }
        response
            .signature()
            .map(|signature| signature.as_ref().to_vec())
            .ok_or_else(|| SignerError::Message("AWS KMS: sign() failed".to_string()))
    }

    async fn get_public_key_der(&self, key_id: &str) -> Result<AwsPublicKey, SignerError> {
        let response = self
            .client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|error| SignerError::Message(error.to_string()))?;
        let resolved = response
            .key_id()
            .filter(|id| immutable_key_id(id))
            .ok_or_else(|| SignerError::Message("AWS KMS: immutable key identity missing".into()))?
            .to_owned();
        response
            .public_key()
            .map(|public_key| AwsPublicKey {
                key_id: resolved,
                der: public_key.as_ref().to_vec(),
            })
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
    public_key_by_signature_type: tokio::sync::Mutex<HashMap<SignatureType, Arc<ResolvedAwsKey>>>,
}

struct ResolvedAwsKey {
    id: String,
    public_key: Vec<u8>,
}
impl ResolvedAwsKey {
    fn identity(&self) -> Option<pillar_core::audit::EffectiveKey> {
        pillar_core::audit::enabled().then(|| {
            let hash = pillar_core::audit::fingerprint(&self.public_key);
            pillar_core::audit::EffectiveKey {
                backend: "aws",
                reference: self.id.clone(),
                version: hash.clone(),
                public_key_hash: hash,
            }
        })
    }
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
    async fn resolved_key(
        &self,
        signature_type: SignatureType,
    ) -> Result<Arc<ResolvedAwsKey>, SignerError> {
        let mut cache = self.public_key_by_signature_type.lock().await;
        if let Some(key) = cache.get(&signature_type) {
            return Ok(key.clone());
        }
        let reference = cache
            .values()
            .next()
            .map(|key| key.id.as_str())
            .unwrap_or(&self.key_id);
        let key =
            crate::effects::kms_operation(reference, self.client.get_public_key_der(reference))
                .await?;
        if !immutable_key_id(&key.key_id) {
            return Err(SignerError::Message(
                "AWS KMS: unresolved mutable key identity".into(),
            ));
        }
        let public_key = match signature_type {
            SignatureType::Ecdsa => ecdsa_public_key_from_spki_der(&key.der)?,
            SignatureType::Ed25519 => ed25519_public_key_from_spki_der(&key.der)?,
        };
        let key = Arc::new(ResolvedAwsKey {
            id: key.key_id,
            public_key,
        });
        cache.insert(signature_type, key.clone());
        Ok(key)
    }
}

#[async_trait]
impl<C> RawSignerAdapter for AwsKmsRawSignerAdapter<C>
where
    C: AwsKmsClient,
{
    fn supports_durable_audit(&self) -> bool {
        true
    }
    fn kms_provider(&self) -> Option<KmsProvider> {
        Some(KmsProvider::Aws)
    }
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        match request.signature_type {
            SignatureType::Ecdsa => {
                let key = self.resolved_key(SignatureType::Ecdsa).await?;
                let der_signature = if pillar_core::audit::enabled() {
                    let digest = crate::effects::owned_digest(&request.data)?;
                    let client = self.client.clone();
                    let owned_key = key.clone();
                    crate::effects::sign_owned_effect(
                        &key.id,
                        key.identity(),
                        &request.data,
                        "ecdsa",
                        async move {
                            client
                                .sign_ecdsa_sha256_digest(&owned_key.id, &digest)
                                .await
                        },
                    )
                    .await?
                } else {
                    crate::effects::sign_effect(
                        &key.id,
                        None,
                        &request.data,
                        "ecdsa",
                        self.client.sign_ecdsa_sha256_digest(&key.id, &request.data),
                    )
                    .await?
                };
                kms_ecdsa_signature_to_recoverable(
                    &der_signature,
                    KmsEcdsaSignatureEncoding::Der,
                    &request.data,
                    &key.public_key,
                    request.transform_recovery_id,
                )
            }
            SignatureType::Ed25519 => {
                if request.private_key_signature_type != SignatureType::Ed25519 {
                    return Err(SignerError::Message(
                        "AWS KMS Ed25519 signing requires an Ed25519 key".to_string(),
                    ));
                }
                let cached = self
                    .public_key_by_signature_type
                    .lock()
                    .await
                    .get(&SignatureType::Ed25519)
                    .cloned();
                let key = if pillar_core::audit::enabled() {
                    Some(self.resolved_key(SignatureType::Ed25519).await?)
                } else {
                    cached
                };
                let reference = key
                    .as_ref()
                    .map(|key| key.id.as_str())
                    .unwrap_or(&self.key_id);
                if pillar_core::audit::enabled() {
                    let digest = crate::effects::owned_digest(&request.data)?;
                    let client = self.client.clone();
                    let owned_key = key.as_ref().expect("audit resolved key").clone();
                    crate::effects::sign_owned_effect(
                        reference,
                        key.as_ref().and_then(|key| key.identity()),
                        &request.data,
                        "ed25519",
                        async move { client.sign_ed25519_raw(&owned_key.id, &digest).await },
                    )
                    .await
                } else {
                    crate::effects::sign_effect(
                        reference,
                        None,
                        &request.data,
                        "ed25519",
                        self.client.sign_ed25519_raw(reference, &request.data),
                    )
                    .await
                }
            }
        }
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        Ok(self
            .resolved_key(request.signature_type)
            .await?
            .public_key
            .clone())
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
