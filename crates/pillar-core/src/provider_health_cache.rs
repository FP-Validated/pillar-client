use async_trait::async_trait;
use indexmap::IndexMap;
use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

pub type ProviderHealthSnapshot = IndexMap<String, bool>;

pub const PROVIDER_HEALTH_CACHE_TTL_MS: u64 = 15_000;

/// How many times a probe overtaken by a configuration refresh is retried.
const PROBE_GENERATION_ATTEMPTS: usize = 3;
pub const PROVIDER_HEALTH_CACHE_STALE_ALLOWANCE_MS: u64 = 105_000;
pub const PROVIDER_HEALTH_CACHE_STALE_MS: u64 =
    PROVIDER_HEALTH_CACHE_TTL_MS + PROVIDER_HEALTH_CACHE_STALE_ALLOWANCE_MS;

#[async_trait]
pub trait ProviderHealthSource: Send + Sync + 'static {
    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String>;

    /// Identifies the provider configuration a probe result describes.
    ///
    /// The cache serves a value for up to two minutes. A configuration refresh
    /// inside that window changes which endpoints exist, so a value probed
    /// before it describes providers that may no longer be configured - and
    /// `/provider-health` and `/ready` are computed from exactly this value.
    /// Returning a number that changes with the configuration is what lets the
    /// cache treat those values as expired instead of serving them out.
    /// Sources whose configuration cannot change return a constant.
    fn configuration_generation(&self) -> u64;
}

#[derive(Debug, Clone)]
struct CachedHealth {
    value: ProviderHealthSnapshot,
    checked_at_unix_ms: u64,
    generation: u64,
}

pub struct ProviderHealthCache<S> {
    source: Arc<S>,
    state: Arc<Mutex<Option<CachedHealth>>>,
    refresh_lock: Arc<Mutex<()>>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl<S> Clone for ProviderHealthCache<S> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            state: self.state.clone(),
            refresh_lock: self.refresh_lock.clone(),
            now: self.now.clone(),
        }
    }
}

impl<S> ProviderHealthCache<S>
where
    S: ProviderHealthSource,
{
    pub fn new(source: S, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self {
            source: Arc::new(source),
            state: Arc::new(Mutex::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
            now: Arc::new(now),
        }
    }
    /// Seeds the cache with a report the caller already produced.
    ///
    /// `generation` is the configuration that report describes, which the
    /// caller has to have read *before* producing it - the same reason
    /// `refresh_with_guard` does. Passing what is serving now would mislabel a
    /// startup probe that a first refresh had already overtaken.
    pub async fn warm(&self, value: ProviderHealthSnapshot, generation: u64) {
        *self.state.lock().await = Some(CachedHealth {
            value,
            checked_at_unix_ms: (self.now)(),
            generation,
        });
    }

    pub async fn read(&self) -> Result<ProviderHealthSnapshot, String> {
        let now = (self.now)();
        let cached = self
            .state
            .lock()
            .await
            .clone()
            .filter(|cached| cached.generation == self.source.configuration_generation());
        if let Some(cached) = cached {
            let age = now.saturating_sub(cached.checked_at_unix_ms);
            if age <= PROVIDER_HEALTH_CACHE_TTL_MS {
                return Ok(cached.value);
            }
            if age <= PROVIDER_HEALTH_CACHE_STALE_MS {
                if let Ok(guard) = self.refresh_lock.clone().try_lock_owned() {
                    let this = self.clone();
                    tokio::spawn(async move {
                        let _ = this.refresh_with_guard(guard).await;
                    });
                }
                return Ok(cached.value);
            }
        }
        self.refresh().await
    }

    async fn refresh(&self) -> Result<ProviderHealthSnapshot, String> {
        let guard = self.refresh_lock.clone().lock_owned().await;
        self.refresh_with_guard(guard).await
    }

    async fn refresh_with_guard(
        &self,
        _guard: OwnedMutexGuard<()>,
    ) -> Result<ProviderHealthSnapshot, String> {
        for _ in 0..PROBE_GENERATION_ATTEMPTS {
            // Read before probing, not after. A refresh can be published while
            // the probe is in flight, and the probe already read the endpoints
            // of the generation it started under; tagging it with whatever is
            // serving when it returns would label an observation of the
            // replaced provider set as describing the new one, and then serve
            // it for the whole TTL.
            let generation = self.source.configuration_generation();
            if let Some(cached) = self.fresh_enough_for(generation).await {
                let age = (self.now)().saturating_sub(cached.checked_at_unix_ms);
                if age <= PROVIDER_HEALTH_CACHE_TTL_MS {
                    return Ok(cached.value);
                }
            }

            let probe = self.source.get_provider_health().await;

            // One gate for both outcomes. If the configuration moved under the
            // probe then nothing decided under it describes what is serving -
            // neither the observation, nor the stale value the failure path
            // would otherwise fall back to.
            if self.source.configuration_generation() != generation {
                continue;
            }

            match probe {
                Ok(value) => {
                    self.publish(value.clone(), generation).await;
                    return Ok(value);
                }
                Err(error) => {
                    // A failed probe may still be covered by a stale value, but
                    // only one describing the configuration now serving.
                    if let Some(cached) = self.fresh_enough_for(generation).await {
                        let age = (self.now)().saturating_sub(cached.checked_at_unix_ms);
                        if age <= PROVIDER_HEALTH_CACHE_STALE_MS {
                            return Ok(cached.value);
                        }
                    }
                    return Err(error);
                }
            }
        }

        // Refreshes landing faster than a probe completes, repeatedly. The
        // interval is sixty seconds, so this is not reachable in a running
        // deployment. Failing is the honest answer: the process cannot say
        // which providers are healthy without describing a configuration that
        // is no longer serving, and `/ready` reporting that beats reporting a
        // provider set that has been replaced three times over.
        Err(
            "provider health could not be observed: the provider configuration was \
             replaced under every probe"
                .to_string(),
        )
    }

    async fn publish(&self, value: ProviderHealthSnapshot, generation: u64) {
        *self.state.lock().await = Some(CachedHealth {
            value,
            checked_at_unix_ms: (self.now)(),
            generation,
        });
    }

    /// The cached value, but only if it describes `generation`.
    async fn fresh_enough_for(&self, generation: u64) -> Option<CachedHealth> {
        self.state
            .lock()
            .await
            .clone()
            .filter(|cached| cached.generation == generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;

    struct CountingSource {
        calls: Arc<AtomicUsize>,
        values: Vec<ProviderHealthSnapshot>,
    }

    #[async_trait]
    impl ProviderHealthSource for CountingSource {
        fn configuration_generation(&self) -> u64 {
            0
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.values[index.min(self.values.len() - 1)].clone())
        }
    }

    struct FailingAfterFirstSource {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProviderHealthSource for FailingAfterFirstSource {
        fn configuration_generation(&self) -> u64 {
            0
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(snapshot(true)),
                _ => Err("refresh failed".to_string()),
            }
        }
    }

    struct DelayedSource {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProviderHealthSource for DelayedSource {
        fn configuration_generation(&self) -> u64 {
            0
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(25)).await;
            Ok(snapshot(true))
        }
    }

    /// A source whose provider configuration can be swapped under the cache,
    /// the way an accepted remote refresh swaps it in production.
    struct RefreshableSource {
        calls: Arc<AtomicUsize>,
        generation: Arc<AtomicU64>,
        healthy: Arc<AtomicU64>,
    }

    #[async_trait]
    impl ProviderHealthSource for RefreshableSource {
        fn configuration_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(snapshot(self.healthy.load(Ordering::SeqCst) == 1))
        }
    }

    fn snapshot(value: bool) -> ProviderHealthSnapshot {
        let mut map = ProviderHealthSnapshot::new();
        map.insert("ethereum".to_string(), value);
        map
    }

    #[tokio::test]
    async fn serves_fresh_provider_health_from_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(
            CountingSource {
                calls: calls.clone(),
                values: vec![snapshot(true)],
            },
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(1_000, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn returns_stale_cache_while_refreshing_in_background() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(
            CountingSource {
                calls: calls.clone(),
                values: vec![snapshot(true), snapshot(false)],
            },
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(31_000, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.read().await.unwrap(), snapshot(false));
    }

    #[tokio::test]
    async fn stale_on_error_cache_does_not_hide_refresh_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(FailingAfterFirstSource { calls }, {
            let now = now.clone();
            move || now.load(Ordering::SeqCst)
        });

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(PROVIDER_HEALTH_CACHE_STALE_MS + 1, Ordering::SeqCst);

        assert_eq!(cache.read().await.unwrap_err(), "refresh failed");
    }

    #[tokio::test]
    async fn coalesces_in_flight_provider_health_cache_refreshes() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = ProviderHealthCache::new(
            DelayedSource {
                calls: calls.clone(),
            },
            || 0,
        );

        let (first, second) = tokio::join!(cache.read(), cache.read());

        assert_eq!(first.unwrap(), snapshot(true));
        assert_eq!(second.unwrap(), snapshot(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn provider_health_cache_parity_uses_fifteen_second_fresh_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(
            CountingSource {
                calls: calls.clone(),
                values: vec![snapshot(true), snapshot(false)],
            },
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(15_000, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        now.store(15_001, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        tokio::task::yield_now().await;
        assert_eq!(cache.read().await.unwrap(), snapshot(false));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn provider_health_cache_parity_uses_one_hundred_twenty_second_stale_window() {
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(
            FailingAfterFirstSource {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(120_000, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
    }

    #[tokio::test]
    async fn provider_health_cache_parity_warms_at_startup_and_refreshes_every_fifteen_seconds() {
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(
            CountingSource {
                calls: Arc::new(AtomicUsize::new(0)),
                values: vec![snapshot(true), snapshot(false)],
            },
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(15_001, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        tokio::task::yield_now().await;
        assert_eq!(cache.read().await.unwrap(), snapshot(false));
    }

    #[tokio::test]
    async fn provider_health_cache_parity_coalesces_concurrent_refresh_with_failure_fallback() {
        let now = Arc::new(AtomicU64::new(0));
        let cache = ProviderHealthCache::new(
            FailingAfterFirstSource {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            {
                let now = now.clone();
                move || now.load(Ordering::SeqCst)
            },
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        now.store(15_000, Ordering::SeqCst);
        let (first, second) = tokio::join!(cache.read(), cache.read());
        assert_eq!(first.unwrap(), snapshot(true));
        assert_eq!(second.unwrap(), snapshot(true));
        tokio::task::yield_now().await;
        now.store(120_000, Ordering::SeqCst);
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
    }

    #[tokio::test]
    async fn a_configuration_refresh_expires_health_probed_before_it() {
        // The stale window is two minutes. Without a generation the cache would
        // keep answering with providers the refresh replaced, and `/ready` is
        // computed from exactly this value.
        let calls = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(AtomicU64::new(7));
        let healthy = Arc::new(AtomicU64::new(1));
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let cache = ProviderHealthCache::new(
            RefreshableSource {
                calls: calls.clone(),
                generation: generation.clone(),
                healthy: healthy.clone(),
            },
            move || clock.load(Ordering::SeqCst),
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Same generation, inside the TTL: still cached.
        assert_eq!(cache.read().await.unwrap(), snapshot(true));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // An accepted refresh lands, and the new provider set is unhealthy.
        generation.store(8, Ordering::SeqCst);
        healthy.store(0, Ordering::SeqCst);

        assert_eq!(cache.read().await.unwrap(), snapshot(false));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // ...and the clock never moved, so only the generation could have
        // expired it.
        assert_eq!(now.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failed_probe_after_a_refresh_does_not_fall_back_to_the_old_configuration() {
        let calls = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(AtomicU64::new(1));
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let cache = ProviderHealthCache::new(
            FailingAfterFirstGeneration {
                calls: calls.clone(),
                generation: generation.clone(),
            },
            move || clock.load(Ordering::SeqCst),
        );

        assert_eq!(cache.read().await.unwrap(), snapshot(true));

        generation.store(2, Ordering::SeqCst);
        let error = cache.read().await.unwrap_err();
        assert_eq!(error, "refresh failed");
    }

    /// Answers once, then fails - and reports whichever generation it is told
    /// to, so the stale fallback can be aimed at the wrong one.
    struct FailingAfterFirstGeneration {
        calls: Arc<AtomicUsize>,
        generation: Arc<AtomicU64>,
    }

    #[async_trait]
    impl ProviderHealthSource for FailingAfterFirstGeneration {
        fn configuration_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(snapshot(true)),
                _ => Err("refresh failed".to_string()),
            }
        }
    }

    /// Publishes a new generation *while the first probe is in flight*, the way
    /// an accepted refresh does: the probe already read the old endpoints.
    struct RefreshesDuringProbeSource {
        calls: Arc<AtomicUsize>,
        generation: Arc<AtomicU64>,
    }

    #[async_trait]
    impl ProviderHealthSource for RefreshesDuringProbeSource {
        fn configuration_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                // Observed the old provider set, and by the time it returns a
                // refresh has landed.
                0 => {
                    self.generation.fetch_add(1, Ordering::SeqCst);
                    Ok(snapshot(true))
                }
                // The configuration now serving is not healthy.
                _ => Ok(snapshot(false)),
            }
        }
    }

    /// Tagging a probe with the generation read *after* it finished would label
    /// an observation of the old provider set as describing the new one, and
    /// then serve it for the whole TTL - which is the failure the generation
    /// key exists to prevent, just moved into the concurrent case.
    #[tokio::test]
    async fn a_refresh_landing_mid_probe_does_not_publish_the_old_observation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(AtomicU64::new(1));
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let cache = ProviderHealthCache::new(
            RefreshesDuringProbeSource {
                calls: calls.clone(),
                generation: generation.clone(),
            },
            move || clock.load(Ordering::SeqCst),
        );

        assert_eq!(
            cache.read().await.unwrap(),
            snapshot(false),
            "the value served must describe the configuration now serving"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the observation of the replaced configuration must be discarded and re-probed"
        );

        // And what was stored is the re-probe, not the discarded observation.
        assert_eq!(cache.read().await.unwrap(), snapshot(false));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the re-probe is what got cached"
        );
    }

    /// Answers once, then fails - and publishes a new generation as it fails,
    /// so the stale fallback is aimed at a configuration that has just been
    /// replaced.
    struct FailsWhileRefreshingSource {
        calls: Arc<AtomicUsize>,
        generation: Arc<AtomicU64>,
    }

    #[async_trait]
    impl ProviderHealthSource for FailsWhileRefreshingSource {
        fn configuration_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            match self.calls.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(snapshot(true)),
                1 => {
                    // The refresh lands as this probe fails.
                    self.generation.fetch_add(1, Ordering::SeqCst);
                    Err("probe failed".to_string())
                }
                _ => Ok(snapshot(false)),
            }
        }
    }

    /// The failure path has to obey the same generation rule as the success
    /// path. A probe that failed while the configuration was being replaced
    /// tells us nothing about either configuration, so it must be retried
    /// against the one now serving instead of surfacing as a failure - or, if
    /// the stale window still covered it, resurrecting the value from before
    /// the replacement.
    ///
    /// Driven past the stale window so `read` awaits the probe: inside the
    /// window it deliberately answers from the cache without waiting, and at
    /// that instant the generation still matched, so that value was correctly
    /// labelled.
    #[tokio::test]
    async fn a_probe_failing_during_a_refresh_is_retried_against_what_is_serving() {
        let calls = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(AtomicU64::new(1));
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let cache = ProviderHealthCache::new(
            FailsWhileRefreshingSource {
                calls: calls.clone(),
                generation: generation.clone(),
            },
            move || clock.load(Ordering::SeqCst),
        );

        // Generation 1 observed healthy and cached.
        assert_eq!(cache.read().await.unwrap(), snapshot(true));

        now.store(PROVIDER_HEALTH_CACHE_STALE_MS + 1, Ordering::SeqCst);

        assert_eq!(
            cache.read().await.unwrap(),
            snapshot(false),
            "the failed probe raced a refresh, so it must be retried under the \
             generation now serving rather than reported as a failure"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(generation.load(Ordering::SeqCst), 2);
    }

    /// Never stops being replaced.
    struct AlwaysRefreshingSource {
        calls: Arc<AtomicUsize>,
        generation: Arc<AtomicU64>,
    }

    #[async_trait]
    impl ProviderHealthSource for AlwaysRefreshingSource {
        fn configuration_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.generation.fetch_add(1, Ordering::SeqCst);
            Ok(snapshot(true))
        }
    }

    /// Unreachable at a sixty-second refresh interval, but if the retries are
    /// exhausted the answer must be an error rather than an observation of a
    /// configuration that is not serving.
    #[tokio::test]
    async fn exhausting_the_retries_reports_failure_rather_than_a_replaced_observation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let cache = ProviderHealthCache::new(
            AlwaysRefreshingSource {
                calls: calls.clone(),
                generation: Arc::new(AtomicU64::new(1)),
            },
            move || clock.load(Ordering::SeqCst),
        );

        let error = cache.read().await.unwrap_err();
        assert!(
            error.contains("replaced under every probe"),
            "the failure has to say why: {error}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            PROBE_GENERATION_ATTEMPTS,
            "bounded, not a spin"
        );
    }

    /// The startup path seeds the cache with a report the composition root
    /// probed itself, and the refresh loop is already running by then. If that
    /// seed were labelled with whatever is serving when it is handed over
    /// rather than with the configuration it was probed under, a first refresh
    /// that overtook it would leave the startup observation serving for the
    /// whole TTL under the new generation's name.
    #[tokio::test]
    async fn a_startup_probe_overtaken_by_a_refresh_is_not_served() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(0));
        let clock = now.clone();
        let cache = ProviderHealthCache::new(
            RefreshableSource {
                calls: calls.clone(),
                // A refresh has landed since the startup probe was taken.
                generation: Arc::new(AtomicU64::new(2)),
                healthy: Arc::new(AtomicU64::new(0)),
            },
            move || clock.load(Ordering::SeqCst),
        );

        cache.warm(snapshot(true), 1).await;

        assert_eq!(
            cache.read().await.unwrap(),
            snapshot(false),
            "a seed describing a replaced configuration must not be served"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "it had to be reprobed");
    }
}
