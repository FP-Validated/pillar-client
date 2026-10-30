use async_trait::async_trait;
use bytes::Bytes;
use google_cloud_auth::credentials::{CacheableResource, Credentials};
use google_cloud_kms_v1::model::{
    AsymmetricSignRequest, AsymmetricSignResponse, Digest, PublicKey as GcpPublicKey,
};
use std::{sync::Arc, time::Duration};

use crate::factory::RawSignerAdapterFactory;
use crate::kms_signature::{
    ecdsa_public_key_from_pem, kms_ecdsa_signature_to_recoverable, KmsEcdsaSignatureEncoding,
};
use crate::types::{
    ChainType, ChainTypeWalletDefinition, KmsProvider, PublicKeyRequest, RawSignerAdapter,
    SignRequest, SignatureType, SignerError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpKmsOptions {
    pub project_id: String,
    pub location_id: String,
    pub key_ring_id: String,
    pub key_version: String,
}

impl GcpKmsOptions {
    pub fn version_name(&self, key_id: &str) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
            self.project_id, self.location_id, self.key_ring_id, key_id, self.key_version
        )
    }
}

#[async_trait]
pub trait GcpKmsClient: Send + Sync + 'static {
    async fn asymmetric_sign_sha256_digest(
        &self,
        version_name: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError>;
    async fn get_public_key_pem(&self, version_name: &str) -> Result<String, SignerError>;
}

#[derive(Clone)]
pub struct GoogleCloudKmsClient {
    client: reqwest::Client,
    credentials: Credentials,
    endpoint: reqwest::Url,
}

impl GoogleCloudKmsClient {
    pub async fn from_default_credentials() -> Result<Self, SignerError> {
        let credentials = google_cloud_auth::credentials::Builder::default()
            .build()
            .map_err(|error| SignerError::Message(error.to_string()))?;
        let credential_domain = credentials
            .universe_domain()
            .await
            .unwrap_or_else(|| "googleapis.com".into());
        let domain = std::env::var("GOOGLE_CLOUD_UNIVERSE_DOMAIN")
            .unwrap_or_else(|_| "googleapis.com".into());
        if credential_domain != domain {
            return Err(SignerError::Message(
                "GCP credential universe domain does not match the client".into(),
            ));
        }
        if domain.is_empty()
            || !domain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(SignerError::Message("Invalid GCP universe domain".into()));
        }
        let endpoint = reqwest::Url::parse(&format!("https://cloudkms.{domain}/"))
            .map_err(|error| SignerError::Message(error.to_string()))?;
        Ok(Self {
            client: Self::http_client(false)?,
            credentials,
            endpoint,
        })
    }

    fn http_client(no_proxy: bool) -> Result<reqwest::Client, SignerError> {
        let builder = reqwest::Client::builder()
            .http1_only()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        let builder = if no_proxy {
            builder.no_proxy()
        } else {
            builder
        };
        builder
            .build()
            .map_err(|error| SignerError::Message(error.to_string()))
    }

    #[cfg(feature = "test-support")]
    pub fn for_local_e2e(endpoint: &str) -> Result<Self, SignerError> {
        let endpoint = reqwest::Url::parse(endpoint)
            .map_err(|error| SignerError::Message(error.to_string()))?;
        if endpoint.scheme() != "http"
            || !endpoint
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|address| address.is_loopback())
        {
            return Err(SignerError::Message(
                "GCP E2E endpoint must be literal loopback".into(),
            ));
        }
        Ok(Self {
            client: Self::http_client(true)?,
            credentials: google_cloud_auth::credentials::anonymous::Builder::new().build(),
            endpoint,
        })
    }

    fn resource_url(&self, name: &str, sign: bool) -> Result<reqwest::Url, SignerError> {
        let parts: Vec<_> = name.split('/').collect();
        if parts.len() != 10
            || parts[0] != "projects"
            || parts[2] != "locations"
            || parts[4] != "keyRings"
            || parts[6] != "cryptoKeys"
            || parts[8] != "cryptoKeyVersions"
            || parts.iter().skip(1).step_by(2).any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return Err(SignerError::Message(
                "Invalid GCP KMS key version name".into(),
            ));
        }
        let mut url = self.endpoint.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| SignerError::Message("Invalid GCP KMS endpoint".into()))?;
            path.clear().push("v1");
            for part in &parts[..9] {
                path.push(part);
            }
            if sign {
                path.push(&format!("{}:asymmetricSign", parts[9]));
            } else {
                path.push(parts[9]).push("publicKey");
            }
        }
        Ok(url)
    }

    async fn request(
        &self,
        name: &str,
        body: Option<&AsymmetricSignRequest>,
    ) -> Result<serde_json::Value, SignerError> {
        let url = self.resource_url(name, body.is_some())?;
        let headers = match self.credentials.headers(http::Extensions::new()).await {
            Ok(CacheableResource::New { data, .. }) => data,
            Ok(CacheableResource::NotModified) => {
                return Err(SignerError::Message(
                    "GCP credential headers unavailable".into(),
                ))
            }
            Err(error) => return Err(SignerError::Message(error.to_string())),
        };
        let request = if let Some(body) = body {
            self.client.post(url).headers(headers).json(body)
        } else {
            self.client.get(url).headers(headers)
        };
        let mut response = request
            .send()
            .await
            .map_err(|error| SignerError::Message(error.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(SignerError::Message(format!(
                "GCP KMS returned HTTP {}",
                response.status()
            )));
        }
        const MAX_RESPONSE: usize = 256 * 1024;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| SignerError::Message(error.without_url().to_string()))?
        {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|len| len > MAX_RESPONSE)
            {
                return Err(SignerError::Message("GCP KMS response too large".into()));
            }
            bytes.extend_from_slice(&chunk);
        }
        pillar_core::json::parse_value_slice(&bytes)
            .map_err(|error| SignerError::Message(error.to_string()))
    }
}

pub(crate) fn response_identity_matches(name: &str, expected: &str) -> bool {
    (name.is_empty() && !pillar_core::audit::enabled()) || name == expected
}

#[async_trait]
impl GcpKmsClient for GoogleCloudKmsClient {
    async fn asymmetric_sign_sha256_digest(
        &self,
        version_name: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let request = AsymmetricSignRequest::new()
            .set_name(version_name)
            .set_digest(Digest::new().set_sha256(Bytes::copy_from_slice(digest)));
        let response: AsymmetricSignResponse =
            serde_json::from_value(self.request(version_name, Some(&request)).await?)
                .map_err(|error| SignerError::Message(error.to_string()))?;
        if !response_identity_matches(&response.name, version_name) {
            return Err(SignerError::Message(
                "GCP KMS: signing key identity changed".into(),
            ));
        }
        if response.signature.is_empty() {
            return Err(SignerError::Message(
                "GCP KMS: asymmetricSign() failed".to_string(),
            ));
        }
        Ok(response.signature.to_vec())
    }

    async fn get_public_key_pem(&self, version_name: &str) -> Result<String, SignerError> {
        let public_key: GcpPublicKey =
            serde_json::from_value(self.request(version_name, None).await?)
                .map_err(|error| SignerError::Message(error.to_string()))?;
        if !response_identity_matches(&public_key.name, version_name) {
            return Err(SignerError::Message(
                "GCP KMS: public key identity changed".into(),
            ));
        }
        if public_key.pem.is_empty() {
            return Err(SignerError::Message(format!(
                "Cannot find public key: {version_name}"
            )));
        }
        Ok(public_key.pem)
    }
}

pub struct GcpKmsRawSignerAdapter<C> {
    version_name: String,
    client: Arc<C>,
    public_key: tokio::sync::Mutex<Option<Vec<u8>>>,
}

impl<C> GcpKmsRawSignerAdapter<C>
where
    C: GcpKmsClient,
{
    pub fn new(version_name: String, client: Arc<C>) -> Self {
        Self {
            version_name,
            client,
            public_key: tokio::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl<C> RawSignerAdapter for GcpKmsRawSignerAdapter<C>
where
    C: GcpKmsClient,
{
    fn supports_durable_audit(&self) -> bool {
        true
    }
    fn kms_provider(&self) -> Option<KmsProvider> {
        Some(KmsProvider::Gcp)
    }
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
        let identity = crate::effects::identity(
            "gcp",
            &self.version_name,
            || {
                self.version_name
                    .rsplit_once("/cryptoKeyVersions/")
                    .map(|(_, version)| version)
                    .filter(|version| version.parse::<u64>().is_ok_and(|value| value > 0))
                    .unwrap_or("")
            },
            &public_key,
        );
        let der_signature = if pillar_core::audit::enabled() {
            let digest = crate::effects::owned_digest(&request.data)?;
            let client = self.client.clone();
            let version_name = self.version_name.clone();
            crate::effects::sign_owned_effect(
                &self.version_name,
                identity,
                &request.data,
                "ecdsa",
                async move {
                    client
                        .asymmetric_sign_sha256_digest(&version_name, &digest)
                        .await
                },
            )
            .await?
        } else {
            crate::effects::sign_effect(
                &self.version_name,
                None,
                &request.data,
                "ecdsa",
                self.client
                    .asymmetric_sign_sha256_digest(&self.version_name, &request.data),
            )
            .await?
        };
        kms_ecdsa_signature_to_recoverable(
            &der_signature,
            KmsEcdsaSignatureEncoding::Der,
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
        if pillar_core::audit::enabled()
            && !self
                .version_name
                .rsplit_once("/cryptoKeyVersions/")
                .is_some_and(|(_, version)| version.parse::<u64>().is_ok_and(|value| value > 0))
        {
            return Err(SignerError::Message(
                "durable audit: unresolved GCP key version".into(),
            ));
        }
        let mut cached = self.public_key.lock().await;
        if let Some(public_key) = cached.as_ref() {
            return Ok(public_key.clone());
        }
        let pem = crate::effects::kms_operation(
            &self.version_name,
            self.client.get_public_key_pem(&self.version_name),
        )
        .await?;
        let public_key = ecdsa_public_key_from_pem(&pem)?;
        *cached = Some(public_key.clone());
        Ok(public_key)
    }
}

pub struct GcpKmsRawSignerAdapterFactory<C> {
    options: GcpKmsOptions,
    client: Arc<C>,
}

impl<C> GcpKmsRawSignerAdapterFactory<C>
where
    C: GcpKmsClient,
{
    pub fn new(options: GcpKmsOptions, client: Arc<C>) -> Self {
        Self { options, client }
    }
}

#[async_trait]
impl<C> RawSignerAdapterFactory for GcpKmsRawSignerAdapterFactory<C>
where
    C: GcpKmsClient,
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
        if provider != KmsProvider::Gcp {
            return Err(SignerError::UnsupportedKmsProvider(provider));
        }
        Ok(Arc::new(GcpKmsRawSignerAdapter::new(
            self.options.version_name(&definition.secret_name),
            self.client.clone(),
        )))
    }
}

#[cfg(test)]
mod tests;
