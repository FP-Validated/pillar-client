//! One immutable provider generation, shared by every request-time consumer.
//!
//! Before this existed, the provider configuration reached the process in two
//! unrelated ways. `/provider-health` read the map the refresh loop wrote,
//! while every signing-path component - the packet resolver, the read payload
//! resolver, the TON and ULN V2 builders and the validator - held a
//! `ProviderConfigs` *cloned at startup*. A remote refresh therefore moved
//! health and left signing on the configuration the process booted with, and
//! the two could disagree indefinitely. Both now read the same handle, so an
//! accepted refresh is visible everywhere or nowhere.
//!
//! Two invariants are structural rather than documented-and-hoped-for:
//!
//! * **The chain set is fixed for the process lifetime.** Signing capability is
//!   assembled once at startup - wallets, signer backends, chain types,
//!   contract tables and builders are all fixed then - so only the URIs and
//!   quorums behind those chains can change.
//!
//!   Removals are refused before they reach here: the refresh read is
//!   restricted by the same roster as the startup load, so a file that no
//!   longer carries a required chain fails the read and the previous
//!   configuration keeps serving. That is upstream's behaviour too
//!   (`checkForMissingChainNames` runs on every poll,
//!   `packages/dynamic-config/src/providerConfig/index.ts:129-134`).
//!
//!   Additions are dropped here, which *is* a deliberate divergence: upstream
//!   builds its chain SDKs per request, so a chain appearing in a later write
//!   is immediately serveable there. This process cannot - it has no signer,
//!   no chain type and no contract table for it - so advertising one would
//!   promise something it must then refuse. [`candidate`] therefore restricts
//!   every later generation to the chain set captured at construction.
//!
//! * **One generation per dispatch decision.** [`RuntimeProviderSnapshot::dispatch`]
//!   resolves the chain's configuration, its quorum and its rank-ordered
//!   dispatch plan together, from one generation, so a plan can never be built
//!   from one configuration's URIs and another's quorum.
//!
//! [`candidate`]: ProviderSnapshotHandle::candidate

use crate::provider_health::ProviderRankTracker;
use crate::provider_health::{plan_dispatch, required_provider_quorum, DispatchEntry};
use pillar_config::{ProviderConfig, ProviderConfigs};
use pillar_core::AppCoreError;
use std::sync::{Arc, RwLock};

tokio::task_local! {
    /// The generation pinned for the request running on this task.
    static PINNED_SNAPSHOT: PinnedSnapshot;
}

/// A pin plus the identity of the handle it came from.
struct PinnedSnapshot {
    slot: usize,
    snapshot: Arc<RuntimeProviderSnapshot>,
}

/// An immutable provider configuration generation.
///
/// Handed out as an `Arc` so a caller that needs several reads to agree - a
/// request - takes one and keeps it for the duration instead of re-reading a
/// shared map that a refresh may have replaced in between.
pub struct RuntimeProviderSnapshot {
    generation: u64,
    provider_configs: ProviderConfigs,
    available_chain_names: Vec<String>,
}

impl RuntimeProviderSnapshot {
    /// Which generation this is. Starts at 0 and increments on every accepted
    /// refresh, so a consumer can tell whether a value it cached still belongs
    /// to the configuration now serving.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn provider_configs(&self) -> &ProviderConfigs {
        &self.provider_configs
    }

    /// The chains this generation advertises, in the order fixed at startup.
    ///
    /// Always the startup chain set - see the module invariant. Held per
    /// generation rather than once, so there is a single source of truth that
    /// `/available-chains` and the signing gate cannot drift apart on.
    pub fn available_chain_names(&self) -> &[String] {
        &self.available_chain_names
    }

    pub(crate) fn provider_config(
        &self,
        chain_name: &str,
    ) -> Result<&ProviderConfig, AppCoreError> {
        self.provider_configs.get(chain_name).ok_or_else(|| {
            AppCoreError::Internal(format!("No provider config for chain {chain_name}"))
        })
    }

    /// The configuration, quorum and rank-ordered dispatch plan for one chain.
    ///
    /// The three are resolved together so they cannot come from different
    /// generations: the quorum a plan was sized for is the quorum of the URIs
    /// it dispatches to.
    pub(crate) async fn dispatch<'a>(
        &'a self,
        rank_tracker: &ProviderRankTracker,
        chain_name: &str,
    ) -> Result<ChainDispatch<'a>, AppCoreError> {
        let config = self.provider_config(chain_name)?;
        let quorum = required_provider_quorum(config, chain_name)?;
        let plan = plan_dispatch(rank_tracker, chain_name, &config.uris, quorum).await?;
        Ok(ChainDispatch {
            config,
            quorum,
            plan,
        })
    }
}

/// One chain's dispatch decision, all of it from a single generation.
pub(crate) struct ChainDispatch<'a> {
    pub(crate) config: &'a ProviderConfig,
    pub(crate) quorum: usize,
    pub(crate) plan: Vec<DispatchEntry<'a>>,
}

/// The handle every consumer holds: a slot containing the generation now
/// serving.
///
/// `std::sync::RwLock` rather than `tokio::sync::RwLock` because the critical
/// section is a single `Arc` clone or swap with no `.await` inside it, so an
/// async lock would buy nothing and cost a scheduler interaction on the
/// signing path. It also keeps [`load`] callable from the synchronous
/// `get_available_chain_names`. A panic cannot leave the slot logically
/// inconsistent - the guarded value is only ever replaced whole - so poisoning
/// is recovered from rather than propagated.
///
/// [`load`]: ProviderSnapshotHandle::load
#[derive(Clone)]
pub struct ProviderSnapshotHandle {
    current: Arc<RwLock<Arc<RuntimeProviderSnapshot>>>,
    /// The chain set signing capability was assembled for. Every published
    /// generation is restricted to it.
    startup_chain_names: Arc<[String]>,
}

impl ProviderSnapshotHandle {
    /// Builds the generation-0 handle from the configuration the process
    /// validated at startup.
    ///
    /// `available_chain_names` is the roster the composition root computed and
    /// assembled signers for; it becomes the ceiling for every later
    /// generation.
    pub fn new(provider_configs: ProviderConfigs, available_chain_names: Vec<String>) -> Self {
        let startup_chain_names: Arc<[String]> = available_chain_names.clone().into();
        Self {
            current: Arc::new(RwLock::new(Arc::new(RuntimeProviderSnapshot {
                generation: 0,
                provider_configs,
                available_chain_names,
            }))),
            startup_chain_names,
        }
    }

    /// A handle over a configuration that cannot change: the LOCAL provider
    /// file, and the fixtures in tests. Every chain present is in the roster,
    /// since nothing later restricts it.
    pub fn from_getter(getter: &impl pillar_config::ProviderConfigGetter) -> Self {
        let provider_configs = getter.get_provider_configs().clone();
        let chain_names = provider_configs.keys().cloned().collect();
        Self::new(provider_configs, chain_names)
    }

    /// The generation to use for everything that must agree.
    ///
    /// Inside [`pin_for_request`] this returns the generation pinned when the
    /// request started, so a resolver, a validator and a builder in the same
    /// request cannot straddle a refresh. Outside one - the health probe loop,
    /// the rank reprobe loop, `/available-chains` - it returns whatever is
    /// serving now, which is what those callers want.
    ///
    /// [`pin_for_request`]: ProviderSnapshotHandle::pin_for_request
    pub fn load(&self) -> Arc<RuntimeProviderSnapshot> {
        let slot = self.slot();
        PINNED_SNAPSHOT
            .try_with(|pinned| (pinned.slot == slot).then(|| pinned.snapshot.clone()))
            .ok()
            .flatten()
            .unwrap_or_else(|| self.serving())
    }

    /// Runs an operation against exactly one generation.
    ///
    /// A sign request fans out to several independent consumers - the packet
    /// resolver, four concurrent validations, a payload builder - and each one
    /// reads the handle for itself. Without this they could read either side of
    /// a refresh that lands mid-request and, say, resolve the event from one
    /// provider set while checking whether the payload was already signed
    /// against another. The pin is a task-local rather than an argument because
    /// the consumers are reached through `pillar-core`'s traits, whose
    /// signatures are a compatibility surface; nothing on this path spawns, so
    /// `tokio::join!` and the `FuturesUnordered` fan-outs all poll inside the
    /// scope.
    ///
    /// Keyed by handle identity, so a nested scope from a *different* handle -
    /// only tests build more than one - reads its own configuration instead of
    /// inheriting this one.
    pub async fn pin_for_request<F>(&self, request: F) -> F::Output
    where
        F: std::future::Future,
    {
        let pinned = PinnedSnapshot {
            slot: self.slot(),
            snapshot: self.serving(),
        };
        PINNED_SNAPSHOT.scope(pinned, request).await
    }

    /// Which generation this caller is working from.
    ///
    /// Pin-aware, like [`load`], and it has to be: the health cache reads this
    /// to decide whether a cached probe still describes what is serving, and
    /// probes through the same handle. If the two disagreed, a probe taken
    /// inside a pinned scope would be tagged with the unpinned generation -
    /// exactly the mislabelling the generation key exists to prevent.
    ///
    /// [`load`]: ProviderSnapshotHandle::load
    pub fn generation(&self) -> u64 {
        self.load().generation
    }

    fn serving(&self) -> Arc<RuntimeProviderSnapshot> {
        self.read().clone()
    }

    fn slot(&self) -> usize {
        Arc::as_ptr(&self.current) as *const () as usize
    }

    /// What a freshly loaded configuration would serve, restricted to the
    /// startup chain set.
    ///
    /// Separate from [`publish`] so the admission gate can validate the
    /// configuration *as it would actually serve* rather than as it arrived: a
    /// candidate whose only usable chains are ones this process has no signer
    /// for must be rejected, not published as an empty roster. Constructing a
    /// candidate is the only way to reach `publish`, so the restriction cannot
    /// be skipped.
    ///
    /// [`publish`]: ProviderSnapshotHandle::publish
    pub(crate) fn candidate(&self, provider_configs: ProviderConfigs) -> ProviderCandidate {
        let mut provider_configs = provider_configs;
        provider_configs.retain(|chain_name, _| {
            self.startup_chain_names
                .iter()
                .any(|allowed| allowed == chain_name)
        });
        let available_chain_names = self
            .startup_chain_names
            .iter()
            .filter(|chain_name| provider_configs.contains_key(chain_name.as_str()))
            .cloned()
            .collect();
        ProviderCandidate {
            provider_configs,
            available_chain_names,
        }
    }

    /// Publishes an admitted candidate as the next generation.
    ///
    /// Returns what is now serving. Chains outside the startup set were dropped
    /// from the map by [`candidate`], not merely hidden from the roster, so a
    /// chain this process has no signer for cannot be reached by naming it in a
    /// request either.
    ///
    /// [`candidate`]: ProviderSnapshotHandle::candidate
    pub(crate) fn publish(&self, candidate: ProviderCandidate) -> Arc<RuntimeProviderSnapshot> {
        let ProviderCandidate {
            provider_configs,
            available_chain_names,
        } = candidate;
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = Arc::new(RuntimeProviderSnapshot {
            generation: current.generation + 1,
            provider_configs,
            available_chain_names,
        });
        *current = next.clone();
        next
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Arc<RuntimeProviderSnapshot>> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Lets the signing gate ask the serving generation, so admitting a request and
/// advertising a chain cannot disagree.
impl pillar_core::AvailableChains for ProviderSnapshotHandle {
    fn contains(&self, chain_name: &str) -> bool {
        self.load()
            .available_chain_names()
            .iter()
            .any(|available| available == chain_name)
    }

    fn names(&self) -> Vec<String> {
        self.load().available_chain_names().to_vec()
    }
}

/// A loaded configuration already restricted to the startup chain set, waiting
/// on the admission gate.
///
/// Only [`ProviderSnapshotHandle::candidate`] constructs one, which is what
/// makes the chain-set ceiling unskippable.
pub(crate) struct ProviderCandidate {
    provider_configs: ProviderConfigs,
    available_chain_names: Vec<String>,
}

impl ProviderCandidate {
    pub(crate) fn available_chain_names(&self) -> &[String] {
        &self.available_chain_names
    }
}

/// Lets the admission gate run the same helpers it runs at startup against the
/// restricted candidate.
impl pillar_config::ProviderConfigGetter for ProviderCandidate {
    fn get_provider_config(&self, chain_name: &str) -> Option<&ProviderConfig> {
        self.provider_configs.get(chain_name)
    }

    fn get_provider_configs(&self) -> &ProviderConfigs {
        &self.provider_configs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_config::ProviderUri;

    fn configs(entries: &[(&str, &[&str], Option<u64>)]) -> ProviderConfigs {
        entries
            .iter()
            .map(|(chain_name, uris, quorum)| {
                (
                    (*chain_name).to_string(),
                    ProviderConfig {
                        uris: uris
                            .iter()
                            .map(|uri| ProviderUri::Uri((*uri).to_string()))
                            .collect(),
                        quorum: *quorum,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn published_generations_cannot_add_a_chain_the_process_has_no_signer_for() {
        let handle = ProviderSnapshotHandle::new(
            configs(&[("bsc", &["https://bsc-1"], Some(1))]),
            vec!["bsc".to_string()],
        );

        let serving = handle.publish(handle.candidate(configs(&[
            ("bsc", &["https://bsc-2"], Some(1)),
            ("ethereum", &["https://eth-1"], Some(1)),
        ])));

        assert_eq!(serving.available_chain_names(), ["bsc".to_string()]);
        assert!(serving.provider_configs().get("ethereum").is_none());
        // The URI change for a chain that *is* assembled still lands.
        assert_eq!(
            serving.provider_config("bsc").unwrap().uris,
            vec![ProviderUri::Uri("https://bsc-2".to_string())]
        );
    }

    #[test]
    fn loads_taken_before_a_publish_keep_serving_their_own_generation() {
        let handle = ProviderSnapshotHandle::new(
            configs(&[("bsc", &["https://bsc-1"], Some(1))]),
            vec!["bsc".to_string()],
        );
        let in_flight = handle.load();

        handle.publish(handle.candidate(configs(&[("bsc", &["https://bsc-2"], Some(1))])));

        assert_eq!(in_flight.generation(), 0);
        assert_eq!(
            in_flight.provider_config("bsc").unwrap().uris,
            vec![ProviderUri::Uri("https://bsc-1".to_string())]
        );
        assert_eq!(handle.generation(), 1);
    }

    #[tokio::test]
    async fn dispatch_sizes_the_quorum_from_the_same_generation_it_plans() {
        let handle = ProviderSnapshotHandle::new(
            configs(&[("bsc", &["https://bsc-1", "https://bsc-2"], Some(2))]),
            vec!["bsc".to_string()],
        );
        let tracker = ProviderRankTracker::new();

        let snapshot = handle.load();
        let dispatch = snapshot.dispatch(&tracker, "bsc").await.unwrap();
        assert_eq!(dispatch.quorum, 2);
        assert_eq!(dispatch.config.uris.len(), 2);

        // A generation that narrows the URI list narrows the quorum with it,
        // instead of leaving a plan sized for the wider one.
        let snapshot =
            handle.publish(handle.candidate(configs(&[("bsc", &["https://bsc-9"], Some(1))])));
        let dispatch = snapshot.dispatch(&tracker, "bsc").await.unwrap();
        assert_eq!(dispatch.quorum, 1);
        assert_eq!(dispatch.config.uris.len(), 1);
    }

    #[tokio::test]
    async fn a_request_reads_one_generation_even_when_a_refresh_lands_mid_flight() {
        let handle = ProviderSnapshotHandle::new(
            configs(&[("bsc", &["https://bsc-1"], Some(1))]),
            vec!["bsc".to_string()],
        );

        let pinned_after_refresh = handle
            .pin_for_request(async {
                // What every consumer sees at the start of the request.
                let first = handle.load();

                // A refresh lands while the request is still running.
                handle.publish(handle.candidate(configs(&[("bsc", &["https://bsc-2"], Some(1))])));

                // A later consumer in the same request must not see it.
                let second = handle.load();
                assert_eq!(first.generation(), second.generation());
                second
            })
            .await;

        assert_eq!(pinned_after_refresh.generation(), 0);
        assert_eq!(
            pinned_after_refresh.provider_config("bsc").unwrap().uris,
            vec![ProviderUri::Uri("https://bsc-1".to_string())]
        );
        // The next request picks the refresh up.
        assert_eq!(handle.load().generation(), 1);
        assert_eq!(
            handle.load().provider_config("bsc").unwrap().uris,
            vec![ProviderUri::Uri("https://bsc-2".to_string())]
        );
    }

    #[tokio::test]
    async fn a_pin_does_not_leak_into_a_different_handle() {
        let signing = ProviderSnapshotHandle::new(
            configs(&[("bsc", &["https://signing"], Some(1))]),
            vec!["bsc".to_string()],
        );
        let unrelated = ProviderSnapshotHandle::new(
            configs(&[("bsc", &["https://unrelated"], Some(1))]),
            vec!["bsc".to_string()],
        );

        signing
            .pin_for_request(async {
                assert_eq!(
                    unrelated.load().provider_config("bsc").unwrap().uris,
                    vec![ProviderUri::Uri("https://unrelated".to_string())],
                    "a pin is keyed by handle identity, not global"
                );
            })
            .await;
    }
}
