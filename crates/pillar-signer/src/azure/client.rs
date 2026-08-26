use async_trait::async_trait;
use azure_core::http::RequestContent;
use azure_security_keyvault_keys::{
    models::{KeyClientGetKeyOptions, KeyClientSignOptions, SignParameters, SignatureAlgorithm},
    KeyClient as AzureKeyClient,
};

use crate::azure::AzureKmsKeyId;
use crate::types::SignerError;

#[async_trait]
pub trait AzureKmsClient: Send + Sync + 'static {
    async fn sign_es256k_digest(
        &self,
        key_id: &AzureKmsKeyId,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError>;

    async fn get_ec_public_key_coordinates(
        &self,
        key_id: &AzureKmsKeyId,
    ) -> Result<(Vec<u8>, Vec<u8>), SignerError>;
}

pub struct AzureKeyVaultKmsClient {
    client: AzureKeyClient,
}

impl AzureKeyVaultKmsClient {
    pub fn new(client: AzureKeyClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AzureKmsClient for AzureKeyVaultKmsClient {
    async fn sign_es256k_digest(
        &self,
        key_id: &AzureKmsKeyId,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let parameters = SignParameters {
            algorithm: Some(SignatureAlgorithm::Es256K),
            value: Some(digest.to_vec()),
        };
        let content: RequestContent<SignParameters> = parameters
            .try_into()
            .map_err(|error: azure_core::Error| SignerError::Message(error.to_string()))?;
        let response = self
            .client
            .sign(
                &key_id.name,
                content,
                Some(KeyClientSignOptions {
                    key_version: key_id.version.clone(),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|error| SignerError::Message(error.to_string()))?
            .into_model()
            .map_err(|error| SignerError::Message(error.to_string()))?;
        response
            .result
            .ok_or_else(|| SignerError::Message("Azure Key Vault: sign() failed".to_string()))
    }

    async fn get_ec_public_key_coordinates(
        &self,
        key_id: &AzureKmsKeyId,
    ) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        let key = self
            .client
            .get_key(
                &key_id.name,
                Some(KeyClientGetKeyOptions {
                    key_version: key_id.version.clone(),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|error| SignerError::Message(error.to_string()))?
            .into_model()
            .map_err(|error| SignerError::Message(error.to_string()))?;
        let jwk = key.key.ok_or_else(|| {
            SignerError::Message(format!(
                "Azure Key Vault: cannot find P-256K public key coordinates for {}",
                key_id.display()
            ))
        })?;
        let x = jwk.x.ok_or_else(|| {
            SignerError::Message(format!(
                "Azure Key Vault: cannot find P-256K public key coordinates for {}",
                key_id.display()
            ))
        })?;
        let y = jwk.y.ok_or_else(|| {
            SignerError::Message(format!(
                "Azure Key Vault: cannot find P-256K public key coordinates for {}",
                key_id.display()
            ))
        })?;
        Ok((x, y))
    }
}
