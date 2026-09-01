use super::*;

pub struct RuntimeServerApp<T> {
    pub(super) runtime_config: RuntimeConfig,
    /// The generation now serving. `/available-chains` reads it rather than a
    /// roster fixed at startup, so what the process advertises cannot outlive
    /// the configuration it would sign with. It only ever shrinks - see
    /// `provider_snapshot`'s chain-set invariant.
    pub(super) providers: ProviderSnapshotHandle,
    pub(super) provider_health_cache: ProviderHealthCache<RpcProviderHealthSource<T>>,
    /// The loops this process spawned, aborted on drop.
    ///
    /// Dropping a `JoinHandle` in tokio *detaches* the task rather than
    /// stopping it, so the previous `_provider_rank_refresh` field controlled
    /// nothing: both loops kept issuing RPC after the server stopped serving.
    /// `RemoteProviderConfigOwner` already aborts its own refresh in `Drop`;
    /// this is the same contract for the other two.
    pub(super) background_tasks: Vec<tokio::task::JoinHandle<()>>,
    pub(super) provider_health_source: RpcProviderHealthSource<T>,
    pub(super) _remote_provider_config: Option<RemoteProviderConfigOwner>,
    pub(super) signing_app: Option<Arc<dyn ServerApp>>,
    pub(super) startup_report: StartupReport,
    /// `/provider-health` is served from `provider_health_cache`, but
    /// `/provider-health/report` used to call the source directly on every
    /// request: one authenticated call fanned out to every provider of every
    /// chain with no cache, no dedup and no concurrency cap, so repeated calls
    /// aimed an amplifier at the operator's own fleet and could trip the rate
    /// limits the signing path depends on. This gives the report the same
    /// treatment: one short TTL plus a single-flight lock, keyed on the provider
    /// generation so a refresh invalidates it.
    pub(super) provider_health_report_cache: ProviderHealthReportCache,
}

/// TTL for the cached report. Matches `PROVIDER_HEALTH_CACHE_TTL_MS` so the two
/// health routes cannot disagree about how stale "now" is.
pub(super) const PROVIDER_HEALTH_REPORT_TTL_MS: u64 = PROVIDER_HEALTH_CACHE_TTL_MS;

#[derive(Clone)]
pub(super) struct ProviderHealthReportCache {
    state: Arc<Mutex<Option<CachedProviderHealthReport>>>,
    refresh_lock: Arc<Mutex<()>>,
}

struct CachedProviderHealthReport {
    value: Value,
    checked_at_unix_ms: u64,
    generation: u64,
}

impl ProviderHealthReportCache {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Returns the cached report when it is fresh and describes the current
    /// provider generation.
    pub(super) async fn fresh(&self, now_unix_ms: u64, generation: u64) -> Option<Value> {
        let state = self.state.lock().await;
        let cached = state.as_ref()?;
        let age = now_unix_ms.saturating_sub(cached.checked_at_unix_ms);
        // `<=`, matching `ProviderHealthCache::read`. The constant alone is not
        // enough for the two health routes to agree about staleness: an exclusive
        // comparison here against the sibling's inclusive one left a one
        // millisecond window where `/provider-health` served a cached value and
        // `/provider-health/report` re-probed.
        (cached.generation == generation && age <= PROVIDER_HEALTH_REPORT_TTL_MS)
            .then(|| cached.value.clone())
    }

    pub(super) async fn store(&self, value: Value, now_unix_ms: u64, generation: u64) {
        *self.state.lock().await = Some(CachedProviderHealthReport {
            value,
            checked_at_unix_ms: now_unix_ms,
            generation,
        });
    }

    /// Serialises the fan-out so concurrent callers wait for one probe round
    /// instead of each starting their own.
    pub(super) async fn single_flight(&self) -> OwnedMutexGuard<()> {
        self.refresh_lock.clone().lock_owned().await
    }
}

impl<T> RuntimeServerApp<T> {
    pub fn startup_report(&self) -> &StartupReport {
        &self.startup_report
    }

    /// Abort handles that outlive the app, so a test can observe what `Drop`
    /// did to the tasks after the app that owned them is gone.
    #[cfg(test)]
    pub(crate) fn background_abort_handles(&self) -> Vec<tokio::task::AbortHandle> {
        self.background_tasks
            .iter()
            .map(tokio::task::JoinHandle::abort_handle)
            .collect()
    }
}

impl<T> Drop for RuntimeServerApp<T> {
    fn drop(&mut self) {
        for task in self.background_tasks.drain(..) {
            task.abort();
        }
    }
}
