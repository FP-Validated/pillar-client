use async_trait::async_trait;
use std::{sync::Arc, time::Duration};

use crate::azure::{parse_azure_kms_key_id, AzureKmsClient, AzureKmsKeyId};
use crate::kms_signature::{kms_ecdsa_signature_to_recoverable, KmsEcdsaSignatureEncoding};
use crate::types::{PublicKeyRequest, RawSignerAdapter, SignRequest, SignatureType, SignerError};

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
    digest: &[u8],
    hedge_delay: Duration,
) -> Result<Vec<u8>, SignerError>
where
    C: AzureKmsClient,
{
    let primary = client.sign_es256k_digest(key_id, digest);
    tokio::pin!(primary);

    tokio::select! {
        result = &mut primary => {
            match result {
                Ok(signature) => Ok(signature),
                Err(_) => client.sign_es256k_digest(key_id, digest).await,
            }
        }
        () = tokio::time::sleep(hedge_delay) => {
            let hedge = client.sign_es256k_digest(key_id, digest);
            tokio::pin!(hedge);
            tokio::select! {
                result = &mut primary => {
                    match result {
                        Ok(signature) => Ok(signature),
                        Err(_) => hedge.await,
                    }
                }
                result = &mut hedge => {
                    match result {
                        Ok(signature) => Ok(signature),
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
    public_key: tokio::sync::Mutex<Option<Vec<u8>>>,
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
}

#[async_trait]
impl<C> RawSignerAdapter for AzureKmsRawSignerAdapter<C>
where
    C: AzureKmsClient,
{
    async fn sign(&self, request: SignRequest) -> Result<Vec<u8>, SignerError> {
        if request.signature_type != SignatureType::Ecdsa {
            return Err(SignerError::Message(format!(
                "Unsupported signature type: {:?}",
                request.signature_type
            )));
        }
        let public_key = self
            .get_public_key(PublicKeyRequest {
                signature_type: SignatureType::Ecdsa,
                private_key_signature_type: SignatureType::Ecdsa,
                seed_kind: request.seed_kind,
            })
            .await?;
        let signature = sign_azure_es256k_digest_with_hedge(
            self.client.as_ref(),
            &self.parsed_key_id,
            &request.data,
            AZURE_KMS_SIGN_HEDGE_DELAY,
        )
        .await?;
        let encoding = if signature.len() == 64 {
            KmsEcdsaSignatureEncoding::Raw
        } else {
            KmsEcdsaSignatureEncoding::Der
        };
        kms_ecdsa_signature_to_recoverable(
            &signature,
            encoding,
            &request.data,
            &public_key,
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
        if let Some(cached) = self.public_key.lock().await.clone() {
            return Ok(cached);
        }
        let (x, y) = self
            .client
            .get_ec_public_key_coordinates(&self.parsed_key_id)
            .await
            .map_err(|error| match error {
                SignerError::Message(message)
                    if message.contains("P-256K public key coordinates") =>
                {
                    SignerError::Message(format!(
                        "Azure Key Vault: cannot find P-256K public key coordinates for {}",
                        self.original_key_id
                    ))
                }
                other => other,
            })?;
        let x = left_pad_ec_coordinate(&x)?;
        let y = left_pad_ec_coordinate(&y)?;
        let mut public_key = Vec::with_capacity(1 + 2 * EC_COORDINATE_BYTES);
        public_key.push(0x04);
        public_key.extend_from_slice(&x);
        public_key.extend_from_slice(&y);
        *self.public_key.lock().await = Some(public_key.clone());
        Ok(public_key)
    }
}
