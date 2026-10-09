use crate::{AppCoreError, LzSentEvent, PillarApiRequestV2, Signature};
use async_trait::async_trait;
use parking_lot::Mutex;
use sha3::{Digest, Keccak256};
use std::{future::Future, sync::Arc};
#[path = "audit_workers.rs"]
mod workers;
pub use workers::AuditWorkers;

pub fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(Keccak256::digest(bytes))
}
#[derive(Clone)]
pub struct ValidatedIntent {
    pub packet_hash: String,
    pub request_hash: String,
    pub validation_hash: String,
    pub source_chain: String,
    pub destination_chain: String,
    pub expiration: i64,
    pub provider_generation: u64,
}
#[derive(Clone)]
pub struct EffectiveKey {
    pub backend: &'static str,
    pub reference: String,
    pub version: String,
    pub public_key_hash: String,
}
#[derive(Clone)]
pub struct AttemptIntent {
    pub validated: ValidatedIntent,
    pub key: EffectiveKey,
    pub wallet_hash: String,
    pub signed_digest: String,
    pub algorithm: &'static str,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    ExternalReturned,
    OutcomeUnknown,
    WalletReturned,
}
impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExternalReturned => "external_returned",
            Self::OutcomeUnknown => "outcome_unknown",
            Self::WalletReturned => "wallet_returned",
        }
    }
}
#[async_trait]
pub trait SigningAuditStore: Send + Sync + 'static {
    async fn begin(&self, intent: &AttemptIntent) -> Result<i64, String>;
    async fn record(
        &self,
        attempt: i64,
        kind: EvidenceKind,
        signature_hash: Option<&str>,
    ) -> Result<(), String>;
    async fn healthy(&self) -> bool;
}
#[derive(Clone)]
struct Root {
    store: Option<Arc<dyn SigningAuditStore>>,
    workers: Option<Arc<AuditWorkers>>,
    generation: u64,
}
#[derive(Clone)]
struct IntentScope {
    store: Arc<dyn SigningAuditStore>,
    intent: ValidatedIntent,
}
struct WalletScope {
    intent: IntentScope,
    wallet_hash: String,
    attempts: Mutex<Vec<i64>>,
}
tokio::task_local! {
    static ROOT: Root;
    static INTENT: IntentScope;
    static WALLET: Arc<WalletScope>;
    static EFFECT_GENERATION: u64;
}
pub fn enabled() -> bool {
    ROOT.try_with(|root| root.store.is_some()).unwrap_or(false)
        || EFFECT_GENERATION.try_with(|_| true).unwrap_or(false)
}
pub fn provider_generation() -> u64 {
    ROOT.try_with(|root| root.generation)
        .or_else(|_| EFFECT_GENERATION.try_with(|generation| *generation))
        .unwrap_or(0)
}

pub async fn scope_external_effect<F: Future>(generation: u64, future: F) -> F::Output {
    EFFECT_GENERATION.scope(generation, future).await
}
pub async fn scope_root<F: Future>(
    store: Option<Arc<dyn SigningAuditStore>>,
    workers: Option<Arc<AuditWorkers>>,
    generation: u64,
    future: F,
) -> F::Output {
    ROOT.scope(
        Root {
            store,
            workers,
            generation,
        },
        future,
    )
    .await
}
pub fn current_workers() -> Result<Arc<AuditWorkers>, String> {
    ROOT.try_with(|root| root.workers.clone())
        .ok()
        .flatten()
        .ok_or_else(|| "durable audit: completion worker ownership unavailable".into())
}
pub async fn scope_intent<F: Future>(intent: ValidatedIntent, future: F) -> F::Output {
    match ROOT.try_with(|root| root.store.clone()).ok().flatten() {
        Some(store) => INTENT.scope(IntentScope { store, intent }, future).await,
        None => future.await,
    }
}
pub fn prepare(
    request: &PillarApiRequestV2,
    event: &LzSentEvent,
    hash_call_data: &str,
) -> Result<Option<ValidatedIntent>, AppCoreError> {
    if !enabled() {
        return Ok(None);
    }
    fn canonical<T: serde::Serialize>(value: &T) -> Result<String, AppCoreError> {
        let mut value = serde_json::to_value(value).map_err(|_| {
            AppCoreError::Internal("durable audit: intent serialization failed".into())
        })?;
        value.sort_all_objects();
        serde_json::to_vec(&value)
            .map(|bytes| fingerprint(&bytes))
            .map_err(|_| {
                AppCoreError::Internal("durable audit: intent serialization failed".into())
            })
    }
    let pins = event
        .read_block_pins
        .iter()
        .map(|pin| (&pin.chain_name, pin.block_number, &pin.block_hash))
        .collect::<Vec<_>>();
    let expiration = match &request.signing_context {
        crate::SigningContext::Message { expiration, .. }
        | crate::SigningContext::Read { expiration, .. } => *expiration,
    };
    Ok(Some(ValidatedIntent {
        packet_hash: canonical(&(&event.lz_message_id, &event.tx_hash))?,
        request_hash: canonical(request)?,
        validation_hash: canonical(&(event, &event.source_evidence, pins, hash_call_data))?,
        source_chain: request.lz_message_id.pathway_id.src_chain_name.clone(),
        destination_chain: request.lz_message_id.pathway_id.dst_chain_name.clone(),
        expiration,
        provider_generation: provider_generation(),
    }))
}
pub async fn scope_prepared<F: Future>(intent: Option<ValidatedIntent>, future: F) -> F::Output {
    match intent {
        Some(intent) => scope_intent(intent, future).await,
        None => future.await,
    }
}
pub async fn sign_wallet<F>(wallet: &str, future: F) -> Result<Signature, AppCoreError>
where
    F: Future<Output = Result<Signature, AppCoreError>>,
{
    let Ok(intent) = INTENT.try_with(Clone::clone) else {
        return future.await;
    };
    let scope = Arc::new(WalletScope {
        intent,
        wallet_hash: fingerprint(wallet.as_bytes()),
        attempts: Mutex::new(Vec::new()),
    });
    let result = WALLET.scope(scope.clone(), future).await;
    let attempts = scope.attempts.lock().clone();
    if result.is_ok() && attempts.is_empty() {
        return Err(AppCoreError::Internal(
            "durable audit: signer emitted no auditable wallet attempt".into(),
        ));
    }
    let hash = result
        .as_ref()
        .ok()
        .map(|signature| fingerprint(signature.signature.as_bytes()));
    let kind = if result.is_ok() {
        EvidenceKind::WalletReturned
    } else {
        EvidenceKind::OutcomeUnknown
    };
    for id in attempts {
        scope
            .intent
            .store
            .record(id, kind, hash.as_deref())
            .await
            .map_err(AppCoreError::Internal)?;
    }
    result
}
pub struct EffectRecord {
    store: Arc<dyn SigningAuditStore>,
    id: i64,
}
impl EffectRecord {
    pub async fn returned(&self, signature: &[u8]) -> Result<(), String> {
        self.store
            .record(
                self.id,
                EvidenceKind::ExternalReturned,
                Some(&fingerprint(signature)),
            )
            .await
    }
    pub async fn unknown(&self) -> Result<(), String> {
        self.store
            .record(self.id, EvidenceKind::OutcomeUnknown, None)
            .await
    }
}
pub async fn begin_effect(
    key: EffectiveKey,
    signed_data: &[u8],
    algorithm: &'static str,
) -> Result<Option<EffectRecord>, String> {
    if !enabled() {
        return Ok(None);
    }
    let scope = WALLET.try_with(Arc::clone).map_err(|_| {
        "durable audit: external signing attempted outside validated wallet scope".to_string()
    })?;
    if key.reference.is_empty()
        || key.reference.len() > 4096
        || key.version.is_empty()
        || key.version.len() > 512
        || key.public_key_hash.len() != 64
        || !key.public_key_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || signed_data.len() != 32
        || !matches!(algorithm, "ecdsa" | "ed25519")
    {
        return Err(
            "durable audit: unresolved effective key identity or unsupported signing input".into(),
        );
    }
    let intent = AttemptIntent {
        validated: scope.intent.intent.clone(),
        key,
        wallet_hash: scope.wallet_hash.clone(),
        signed_digest: hex::encode(signed_data),
        algorithm,
    };
    let id = scope.intent.store.begin(&intent).await?;
    scope.attempts.lock().push(id);
    Ok(Some(EffectRecord {
        store: scope.intent.store.clone(),
        id,
    }))
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
