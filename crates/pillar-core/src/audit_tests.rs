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

fn store() -> Arc<FaultStore> {
    Arc::new(FaultStore {
        fail_begin: false,
        fail_result: false,
        begins: AtomicUsize::new(0),
        events: parking_lot::Mutex::new(Vec::new()),
    })
}
async fn dropped_after_begin(store: Arc<FaultStore>, returned_first: bool) -> Arc<AuditWorkers> {
    let workers = Arc::new(AuditWorkers::new(1));
    let signing = scope_root(
        Some(store),
        Some(workers.clone()),
        1,
        scope_intent(
            intent(),
            sign_wallet("synthetic-wallet", async move {
                let effect = begin_effect(key(), &[7; 32], "ecdsa")
                    .await
                    .map_err(crate::AppCoreError::Internal)?
                    .expect("audit is enabled");
                if returned_first {
                    effect
                        .returned(&[8; 64])
                        .await
                        .map_err(crate::AppCoreError::Internal)?;
                }
                std::future::pending::<Result<crate::Signature, crate::AppCoreError>>().await
            }),
        ),
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), signing)
            .await
            .is_err(),
        "the signer never completes, so the caller gives up"
    );
    workers
}
#[tokio::test]
async fn a_signer_dropped_mid_effect_leaves_an_unknown_outcome_not_an_open_attempt() {
    let store = store();
    let _workers = dropped_after_begin(store.clone(), false).await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while store.events.lock().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the guard records the outcome");
    assert_eq!(*store.events.lock(), vec![EvidenceKind::OutcomeUnknown]);
}
#[tokio::test]
async fn a_drop_after_the_effect_was_recorded_adds_no_unknown_outcome() {
    let store = store();
    let _workers = dropped_after_begin(store.clone(), true).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(*store.events.lock(), vec![EvidenceKind::ExternalReturned]);
}
