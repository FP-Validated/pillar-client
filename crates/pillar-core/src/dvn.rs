//! DVN wire v1 and the capability required at every runtime signing boundary.
use crate::{AppCoreError, LzSentEvent, SentEventResolver, SigningContext};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const REGISTRY_SCHEMA: &str = "pillar.dvn-registry/v1";
pub const PERMIT_SCHEMA: &str = "pillar.dvn-permit/v1";
pub const MAX_PERMIT_TTL_MS: u64 = 2_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 250;
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Mainnet,
    Testnet,
}
impl Environment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainBinding {
    pub eid: u32,
    pub name: String,
    pub address_format: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AssetCodec {
    OftV1,
    Opaque,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetBinding {
    pub id: String,
    pub asset_id: String,
    pub asset_group: String,
    pub src_eid: u32,
    pub dst_eid: u32,
    pub src_oapp: String,
    pub dst_oapp: String,
    pub codec: AssetCodec,
    pub shared_decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub schema_version: String,
    pub environment: Environment,
    pub revision: u64,
    pub chains: Vec<ChainBinding>,
    pub asset_bindings: Vec<AssetBinding>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RequestKind {
    Message,
    Read,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Subject {
    pub environment: Environment,
    pub protocol: String,
    pub request_kind: RequestKind,
    pub src_eid: u32,
    pub dst_eid: u32,
    /// Native packet endpoints, including READ channels; physical EIDs above are policy scope.
    pub src_endpoint_id: u32,
    pub dst_endpoint_id: u32,
    pub src_oapp: String,
    pub dst_oapp: String,
    pub nonce: String,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    pub source_evidence_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_binding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_shared_units: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizeRequest {
    pub instance_id: String,
    pub boot_id: String,
    pub registry_revision: u64,
    pub subject: Subject,
    pub intent_digest: String,
    pub wallet_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedEnvelope {
    pub payload: String,
    pub sha256: String,
    pub signature: String,
    pub key_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AuthorizeResponse {
    Allow { permit: SignedEnvelope },
    Deny { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permit {
    pub schema_version: String,
    pub decision_id: String,
    pub environment: Environment,
    pub workload_id: String,
    pub instance_id: String,
    pub boot_id: String,
    pub request_sha256: String,
    pub intent_digest: String,
    pub policy_revision: u64,
    pub safety_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Only the core workflow can construct this, after all ordinary validation and
/// exact hash-call-data construction have succeeded. It is never deserialized.
pub struct VerifiedEnvelope<'a> {
    event: &'a LzSentEvent,
    context: &'a SigningContext,
}
impl<'a> VerifiedEnvelope<'a> {
    pub(crate) fn new(event: &'a LzSentEvent, context: &'a SigningContext) -> Self {
        Self { event, context }
    }
    pub fn event(&self) -> &LzSentEvent {
        self.event
    }
    pub fn context(&self) -> &SigningContext {
        self.context
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct SigningScope {
    pub chain_name: String,
    pub wallet_name: String,
    pub backend: String,
}

#[async_trait]
pub trait SigningPolicy: Send + Sync + 'static {
    async fn authorize(
        &self,
        envelope: &VerifiedEnvelope<'_>,
        resolver: &dyn SentEventResolver,
        hash_call_data: &str,
        scopes: Vec<SigningScope>,
    ) -> Result<SigningAuthorization, AppCoreError>;
}

/// A missing gate is an explicit denial, including manually composed applications.
pub struct DenySigningPolicy;
#[async_trait]
impl SigningPolicy for DenySigningPolicy {
    async fn authorize(
        &self,
        _: &VerifiedEnvelope<'_>,
        _: &dyn SentEventResolver,
        _: &str,
        _: Vec<SigningScope>,
    ) -> Result<SigningAuthorization, AppCoreError> {
        Err(policy_error("DVN Gate is not configured"))
    }
}

pub struct TokenSenderEvidence {
    pub address: String,
    pub evidence_digest: String,
}

/// Shared observations revoke already-issued permits before queued effects start.
#[derive(Default)]
pub struct RevisionFence {
    pub policy_revision: AtomicU64,
    pub safety_epoch: AtomicU64,
    pub registry_revision: AtomicU64,
}

#[derive(Clone)]
struct PermitFence {
    current: Arc<RevisionFence>,
    policy_revision: u64,
    safety_epoch: u64,
    registry_revision: u64,
}
impl PermitFence {
    fn check(&self) -> Result<(), AppCoreError> {
        if self.current.policy_revision.load(Ordering::Acquire) != self.policy_revision
            || self.current.safety_epoch.load(Ordering::Acquire) != self.safety_epoch
            || self.current.registry_revision.load(Ordering::Acquire) != self.registry_revision
        {
            return Err(policy_error("DVN permit superseded before signing"));
        }
        Ok(())
    }
}

/// Not Clone/Deserialize; construction requires a verified, request-bound permit.
/// The runtime checks it before adapter/key resolution and again just before signing.
pub struct SigningAuthorization {
    hash_call_data: String,
    scopes: Vec<SigningScope>,
    expires_at_ms: u64,
    deadline: Instant,
    fence: Option<PermitFence>,
}
impl SigningAuthorization {
    pub fn check(
        &self,
        chain: &str,
        wallet: &str,
        backend: &str,
        hash_call_data: &str,
    ) -> Result<(), AppCoreError> {
        if let Some(fence) = &self.fence {
            fence.check()?;
        }
        if Instant::now() >= self.deadline || now_ms()? >= self.expires_at_ms {
            return Err(policy_error("DVN permit expired before signing"));
        }
        if self.hash_call_data != hash_call_data
            || !self.scopes.iter().any(|scope| {
                scope.chain_name == chain && scope.wallet_name == wallet && scope.backend == backend
            })
        {
            return Err(policy_error("DVN permit signing scope mismatch"));
        }
        Ok(())
    }

    pub fn with_revision_fence(
        mut self,
        current: Arc<RevisionFence>,
        policy_revision: u64,
        safety_epoch: u64,
        registry_revision: u64,
    ) -> Self {
        self.fence = Some(PermitFence {
            current,
            policy_revision,
            safety_epoch,
            registry_revision,
        });
        self
    }

    pub async fn scope_effect<F: Future>(&self, future: F) -> F::Output {
        EFFECT_LEASE
            .scope(
                SigningLease {
                    expires_at_ms: self.expires_at_ms,
                    deadline: self.deadline,
                    fence: self.fence.clone(),
                },
                future,
            )
            .await
    }
}

/// Carries the already-verified permit deadline through KMS admission and audit workers.
/// Construction is private; low-level crypto primitives do not create authorizations.
#[derive(Clone)]
pub struct SigningLease {
    expires_at_ms: u64,
    deadline: Instant,
    fence: Option<PermitFence>,
}
impl SigningLease {
    pub fn check(&self) -> Result<(), AppCoreError> {
        if let Some(fence) = &self.fence {
            fence.check()?;
        }
        if Instant::now() >= self.deadline || now_ms()? >= self.expires_at_ms {
            return Err(policy_error("DVN permit expired before backend invocation"));
        }
        Ok(())
    }
}
tokio::task_local! {
    static EFFECT_LEASE: SigningLease;
}
pub fn current_signing_lease() -> Option<SigningLease> {
    EFFECT_LEASE.try_with(Clone::clone).ok()
}

pub struct EnvelopeVerifier {
    key_id: String,
    key: VerifyingKey,
}
impl EnvelopeVerifier {
    pub fn new(key_id: String, public_key_base64: &str) -> Result<Self, AppCoreError> {
        let bytes = STANDARD
            .decode(public_key_base64)
            .map_err(|_| policy_error("Invalid DVN public key encoding"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| policy_error("DVN public key must be 32 bytes"))?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| policy_error("Invalid DVN public key"))?;
        if key_id.is_empty() || key.is_weak() {
            return Err(policy_error("Invalid DVN verification key"));
        }
        Ok(Self { key_id, key })
    }

    pub fn verify<T: DeserializeOwned>(
        &self,
        envelope: &SignedEnvelope,
        schema: &str,
    ) -> Result<T, AppCoreError> {
        if envelope.key_id != self.key_id || envelope.payload.len() > MAX_ENVELOPE_BYTES {
            return Err(policy_error("DVN signed envelope key or size mismatch"));
        }
        let payload = STANDARD
            .decode(&envelope.payload)
            .map_err(|_| policy_error("Invalid DVN envelope encoding"))?;
        if envelope.sha256 != sha256_hex(&payload) {
            return Err(policy_error("DVN envelope digest mismatch"));
        }
        let signature = STANDARD
            .decode(&envelope.signature)
            .map_err(|_| policy_error("Invalid DVN signature encoding"))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| policy_error("Invalid DVN signature length"))?;
        let mut signed = Vec::with_capacity(schema.len() + 1 + payload.len());
        signed.extend_from_slice(schema.as_bytes());
        signed.push(0);
        signed.extend_from_slice(&payload);
        self.key
            .verify_strict(&signed, &signature)
            .map_err(|_| policy_error("Invalid DVN signature"))?;
        let text =
            std::str::from_utf8(&payload).map_err(|_| policy_error("Invalid DVN payload text"))?;
        crate::json::from_str(text).map_err(|_| policy_error("Invalid DVN payload schema"))
    }

    pub fn authorize(
        &self,
        envelope: &SignedEnvelope,
        expected: &PermitExpectation<'_>,
        hash_call_data: &str,
        scopes: Vec<SigningScope>,
        now: u64,
    ) -> Result<(SigningAuthorization, Permit), AppCoreError> {
        let permit: Permit = self.verify(envelope, PERMIT_SCHEMA)?;
        let ttl = permit.expires_at_ms.checked_sub(permit.issued_at_ms);
        if permit.schema_version != PERMIT_SCHEMA
            || permit.decision_id.is_empty()
            || permit.environment != expected.request.subject.environment
            || permit.workload_id != expected.workload_id
            || permit.instance_id != expected.request.instance_id
            || permit.boot_id != expected.request.boot_id
            || permit.request_sha256 != sha256_hex(expected.raw_request)
            || permit.intent_digest != expected.request.intent_digest
            || permit.intent_digest != intent_digest(hash_call_data, &scopes)?
            || permit.policy_revision == 0
            || permit.policy_revision < expected.minimum_policy_revision
            || permit.safety_epoch < expected.minimum_safety_epoch
            || ttl.is_none_or(|ttl| ttl == 0 || ttl > MAX_PERMIT_TTL_MS)
            || permit.issued_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
            || permit.expires_at_ms <= now
        {
            return Err(policy_error(
                "DVN permit binding, revision or lifetime mismatch",
            ));
        }
        let remaining = (permit.expires_at_ms - now).min(MAX_PERMIT_TTL_MS);
        Ok((
            SigningAuthorization {
                hash_call_data: hash_call_data.to_string(),
                scopes,
                expires_at_ms: permit.expires_at_ms,
                deadline: Instant::now() + Duration::from_millis(remaining),
                fence: None,
            },
            permit,
        ))
    }
}

pub struct PermitExpectation<'a> {
    pub request: &'a AuthorizeRequest,
    pub raw_request: &'a [u8],
    pub workload_id: &'a str,
    pub minimum_policy_revision: u64,
    pub minimum_safety_epoch: u64,
}

pub fn intent_digest(
    hash_call_data: &str,
    scopes: &[SigningScope],
) -> Result<String, AppCoreError> {
    let data = hex::decode(hash_call_data.strip_prefix("0x").unwrap_or(hash_call_data))
        .map_err(|_| policy_error("Invalid signing intent hash"))?;
    if data.is_empty() || scopes.is_empty() {
        return Err(policy_error("Invalid signing intent scope"));
    }
    let mut canonical = scopes.iter().collect::<Vec<_>>();
    canonical.sort_unstable();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(policy_error("Duplicate signing wallet scope"));
    }
    let mut hash = Sha256::new();
    hash.update(b"pillar.dvn-intent/v1\0");
    hash.update(data);
    hash.update(serde_json::to_vec(&canonical).map_err(|_| policy_error("Invalid signing scope"))?);
    Ok(hex::encode(hash.finalize()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Hash evidence without allocating a second copy of a complete packet or receipt.
pub fn json_sha256(value: &impl Serialize) -> Result<String, AppCoreError> {
    struct HashWriter(Sha256);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| policy_error("DVN evidence encoding failed"))?;
    Ok(hex::encode(writer.0.finalize()))
}

pub fn now_ms() -> Result<u64, AppCoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .ok_or_else(|| policy_error("DVN clock unavailable"))
}

pub fn policy_error(message: &str) -> AppCoreError {
    AppCoreError::Internal(message.to_string())
}

#[cfg(test)]
pub(crate) struct TestSigningPolicy;
#[cfg(test)]
#[async_trait]
impl SigningPolicy for TestSigningPolicy {
    async fn authorize(
        &self,
        _: &VerifiedEnvelope<'_>,
        _: &dyn SentEventResolver,
        hash_call_data: &str,
        scopes: Vec<SigningScope>,
    ) -> Result<SigningAuthorization, AppCoreError> {
        Ok(SigningAuthorization {
            hash_call_data: hash_call_data.to_string(),
            scopes,
            expires_at_ms: now_ms()? + 60_000,
            deadline: Instant::now() + Duration::from_secs(60),
            fence: None,
        })
    }
}

#[cfg(test)]
mod tests;
