use async_trait::async_trait;
use azure_core::http::RequestContent;
use azure_security_keyvault_keys::{
    models::{KeyClientGetKeyOptions, KeyClientSignOptions, SignParameters, SignatureAlgorithm},
    KeyClient as AzureKeyClient,
};

use crate::azure::{parse_azure_kms_key_id, AzureKmsKeyId};
use crate::types::SignerError;

pub struct AzureEcPublicKey {
    pub key_id: AzureKmsKeyId,
    pub reference: String,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}
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
    ) -> Result<AzureEcPublicKey, SignerError>;
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
        if let Some(reference) = response.kid.as_deref() {
            if parse_azure_kms_key_id(reference)? != *key_id {
                return Err(SignerError::Message(
                    "Azure Key Vault: signing key identity changed".into(),
                ));
            }
        } else if pillar_core::audit::enabled() {
            return Err(SignerError::Message(
                "durable audit: Azure signing key identity missing".into(),
            ));
        }
        response
            .result
            .ok_or_else(|| SignerError::Message("Azure Key Vault: sign() failed".to_string()))
    }

    async fn get_ec_public_key_coordinates(
        &self,
        key_id: &AzureKmsKeyId,
    ) -> Result<AzureEcPublicKey, SignerError> {
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
        let reference = jwk.kid.ok_or_else(|| {
            SignerError::Message("Azure Key Vault: effective key version missing".into())
        })?;
        let resolved = parse_azure_kms_key_id(&reference)?;
        if resolved.version.is_none()
            || resolved.name != key_id.name
            || key_id
                .version
                .as_ref()
                .is_some_and(|version| Some(version) != resolved.version.as_ref())
        {
            return Err(SignerError::Message(
                "Azure Key Vault: public key identity changed".into(),
            ));
        }
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
        Ok(AzureEcPublicKey {
            key_id: resolved,
            reference,
            x,
            y,
        })
    }
}
