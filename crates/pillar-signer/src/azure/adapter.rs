use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

use crate::azure::{parse_azure_kms_key_id, AzureKmsClient, AzureKmsKeyId};
use crate::kms_signature::{kms_ecdsa_signature_to_recoverable, KmsEcdsaSignatureEncoding};
use crate::types::{
    KmsProvider, PublicKeyRequest, RawSignerAdapter, SignRequest, SignatureType, SignerError,
};

const AZURE_KMS_SIGN_HEDGE_DELAY: Duration = Duration::from_millis(750);
const EC_COORDINATE_BYTES: usize = 32;

fn left_pad_ec_coordinate(coordinate: &[u8]) -> Result<[u8; EC_COORDINATE_BYTES], SignerError> {
    if coordinate.is_empty() {
        return Err(SignerError::Message(
            "Azure Key Vault: P-256K public key coordinate must not be empty".to_string(),
        ));
    }
    if coordinate.len() > EC_COORDINATE_BYTES {
        return Err(SignerError::Message(format!(
            "Azure Key Vault: P-256K public key coordinate must be at most {EC_COORDINATE_BYTES} bytes, got {}",
            coordinate.len()
        )));
    }
    let mut padded = [0; EC_COORDINATE_BYTES];
    let offset = EC_COORDINATE_BYTES - coordinate.len();
    padded[offset..].copy_from_slice(coordinate);
    Ok(padded)
}

pub(crate) async fn sign_azure_es256k_digest_with_hedge<C>(
    client: &C,
    key_id: &AzureKmsKeyId,
    reference: &str,
    digest: &[u8],
    hedge_delay: Duration,
) -> Result<Vec<u8>, SignerError>
where
    C: AzureKmsClient,
{
    let primary = crate::effects::sign_effect(
        reference,
        None,
        digest,
        "ecdsa",
        client.sign_es256k_digest(key_id, digest),
    );
    tokio::pin!(primary);

    tokio::select! {
        result = &mut primary => {
            match result {
                Ok(signature) => Ok(signature),
                Err(error) if matches!(&error, SignerError::Admission(_) | SignerError::Audit(_)) => Err(error),
                Err(error) => match crate::effects::try_sign_effect(reference, digest, client.sign_es256k_digest(key_id, digest)).await { Ok(Some(signature)) => Ok(signature), Ok(None) => Err(error), Err(error) => Err(error) },
            }
        }
        () = tokio::time::sleep(hedge_delay) => {
            let hedge = crate::effects::try_sign_effect(reference, digest, client.sign_es256k_digest(key_id, digest));
            tokio::pin!(hedge);
            tokio::select! {
                result = &mut primary => {
                    match result {
                        Ok(signature) => Ok(signature),
                        Err(error) => match hedge.await { Ok(Some(signature)) => Ok(signature), Ok(None) => Err(error), Err(error) => Err(error) },
                    }
                }
                result = &mut hedge => {
                    match result {
                        Ok(Some(signature)) => Ok(signature),
                        Ok(None) => primary.await,
                        Err(error) => {
                            match primary.await {
                                Ok(signature) => Ok(signature),
                                Err(_) => Err(error),
                            }
                        }
                    }
                }
            }
        }
    }
}

pub struct AzureKmsRawSignerAdapter<C> {
    original_key_id: String,
    parsed_key_id: AzureKmsKeyId,
    client: Arc<C>,
    public_key: tokio::sync::Mutex<Option<Arc<ResolvedAzureKey>>>,
}
struct ResolvedAzureKey {
    id: AzureKmsKeyId,
    reference: String,
    public_key: Vec<u8>,
}

impl<C> AzureKmsRawSignerAdapter<C>
where
    C: AzureKmsClient,
{
    pub fn new(key_id: String, client: Arc<C>) -> Result<Self, SignerError> {
        let parsed_key_id = parse_azure_kms_key_id(&key_id)?;
        Ok(Self {
            original_key_id: key_id,
            parsed_key_id,
            client,
            public_key: tokio::sync::Mutex::new(None),
        })
    }
    async fn resolved_key(&self) -> Result<Arc<ResolvedAzureKey>, SignerError> {
        let mut cached = self.public_key.lock().await;
        if let Some(key) = cached.as_ref() {
            return Ok(key.clone());
        }
        let key = crate::effects::kms_operation(
            &self.original_key_id,
            self.client
                .get_ec_public_key_coordinates(&self.parsed_key_id),
        )
        .await?;
        if key.key_id.version.is_none()
            || key.key_id.name != self.parsed_key_id.name
            || self
                .parsed_key_id
                .version
                .as_ref()
                .is_some_and(|version| Some(version) != key.key_id.version.as_ref())
        {
            return Err(SignerError::Message(
                "Azure Key Vault: unresolved effective key version".into(),
            ));
        }
        let x = left_pad_ec_coordinate(&key.x)?;
        let y = left_pad_ec_coordinate(&key.y)?;
        let mut public_key = Vec::with_capacity(1 + 2 * EC_COORDINATE_BYTES);
        public_key.push(0x04);
        public_key.extend_from_slice(&x);
        public_key.extend_from_slice(&y);
        let key = Arc::new(ResolvedAzureKey {
            id: key.key_id,
            reference: key.reference,
            public_key,
        });
        *cached = Some(key.clone());
        Ok(key)
    }
}

#[async_trait]
impl<C> RawSignerAdapter for AzureKmsRawSignerAdapter<C>
where
    C: AzureKmsClient,
{
    fn supports_durable_audit(&self) -> bool {
        true
    }
    fn kms_provider(&self) -> Option<KmsProvider> {
        Some(KmsProvider::Azure)
    }
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        if request.signature_type != SignatureType::Ecdsa {
            return Err(SignerError::Message(format!(
                "Unsupported signature type: {:?}",
                request.signature_type
            )));
        }
        let key = self.resolved_key().await?;
        let signature = if pillar_core::audit::enabled() {
            let digest = crate::effects::owned_digest(&request.data)?;
            let client = self.client.clone();
            let owned_key = key.clone();
            crate::effects::sign_owned_effect(
                &key.reference,
                crate::effects::identity(
                    "azure",
                    &key.reference,
                    || key.id.version.as_deref().unwrap_or(""),
                    &key.public_key,
                ),
                &request.data,
                "ecdsa",
                async move { client.sign_es256k_digest(&owned_key.id, &digest).await },
            )
            .await?
        } else {
            sign_azure_es256k_digest_with_hedge(
                self.client.as_ref(),
                &key.id,
                &key.reference,
                &request.data,
                AZURE_KMS_SIGN_HEDGE_DELAY,
            )
            .await?
        };
        let encoding = if signature.len() == 64 {
            KmsEcdsaSignatureEncoding::Raw
        } else {
            KmsEcdsaSignatureEncoding::Der
        };
        kms_ecdsa_signature_to_recoverable(
            &signature,
            encoding,
            &request.data,
            &key.public_key,
            request.transform_recovery_id,
        )
    }

    async fn get_public_key(&self, request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        if request.signature_type != SignatureType::Ecdsa {
            return Err(SignerError::Message(format!(
                "Unsupported signature type: {:?}",
                request.signature_type
            )));
        }
        Ok(self.resolved_key().await?.public_key.clone())
    }
}
