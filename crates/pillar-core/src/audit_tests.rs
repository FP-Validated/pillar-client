use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct FaultStore {
    fail_begin: bool,
    fail_result: bool,
    begins: AtomicUsize,
    events: parking_lot::Mutex<Vec<EvidenceKind>>,
}
#[async_trait::async_trait]
impl SigningAuditStore for FaultStore {
    async fn begin(&self, _: &AttemptIntent) -> Result<i64, String> {
        if self.fail_begin {
            return Err("synthetic store unavailable".into());
        }
        self.begins.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }
    async fn record(&self, _: i64, event: EvidenceKind, _: Option<&str>) -> Result<(), String> {
        if self.fail_result {
            return Err("synthetic result commit unavailable".into());
        }
        self.events.lock().push(event);
        Ok(())
    }
    async fn healthy(&self) -> bool {
        true
    }
}
fn intent() -> ValidatedIntent {
    ValidatedIntent {
        packet_hash: fingerprint(b"packet"),
        request_hash: fingerprint(b"request"),
        validation_hash: fingerprint(b"validated"),
        source_chain: "ethereum".into(),
        destination_chain: "bsc".into(),
        expiration: 123,
        provider_generation: 1,
    }
}
fn key() -> EffectiveKey {
    EffectiveKey {
        backend: "azure",
        reference: "key/version-one".into(),
        version: "version-one".into(),
        public_key_hash: fingerprint(b"public"),
    }
}
async fn wallet(
    store: Arc<FaultStore>,
    calls: Arc<AtomicUsize>,
) -> Result<crate::Signature, crate::AppCoreError> {
    scope_root(Some(store), None, 1, async {
        scope_intent(
            intent(),
            sign_wallet("synthetic-wallet", async {
                let effect = begin_effect(key(), &[7; 32], "ecdsa")
                    .await
                    .map_err(crate::AppCoreError::Internal)?;
                calls.fetch_add(1, Ordering::SeqCst);
                if let Some(effect) = effect {
                    effect
                        .returned(&[8; 64])
                        .await
                        .map_err(crate::AppCoreError::Internal)?;
                }
                Ok(crate::Signature {
                    signature: "0x0102".into(),
                    address: "synthetic-address".into(),
                })
            }),
        )
        .await
    })
    .await
}
#[tokio::test]
async fn audit_precommit_failure_has_zero_effects_and_no_memory_fallback() {
    let store = Arc::new(FaultStore {
        fail_begin: true,
        fail_result: false,
        begins: AtomicUsize::new(0),
        events: parking_lot::Mutex::new(Vec::new()),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(wallet(store.clone(), calls.clone()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(store.begins.load(Ordering::SeqCst), 0);
    println!("AUDIT_PRECOMMIT_ARTIFACT effects=0 fallback=false");
}
#[tokio::test]
async fn audit_result_commit_failure_cannot_return_success() {
    let store = Arc::new(FaultStore {
        fail_begin: false,
        fail_result: true,
        begins: AtomicUsize::new(0),
        events: parking_lot::Mutex::new(Vec::new()),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    assert!(wallet(store.clone(), calls.clone()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.begins.load(Ordering::SeqCst), 1);
    println!("AUDIT_RESULT_ARTIFACT possible_effects=1 success=false durable_intent_retained=true");
}
#[tokio::test]
async fn audit_success_commits_external_and_wallet_hashes_before_return() {
    let store = Arc::new(FaultStore {
        fail_begin: false,
        fail_result: false,
        begins: AtomicUsize::new(0),
        events: parking_lot::Mutex::new(Vec::new()),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    wallet(store.clone(), calls).await.unwrap();
    assert_eq!(
        *store.events.lock(),
        vec![EvidenceKind::ExternalReturned, EvidenceKind::WalletReturned]
    );
    println!("AUDIT_SUCCESS_ARTIFACT external_and_wallet_results_committed=true");
}
