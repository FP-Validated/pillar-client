use super::*;
use std::time::Duration;

#[derive(Default)]
struct HealthObservations {
    chains: HashMap<String, ChainObservation>,
}

/// The last fully observed verdict for a chain. It is valid only for the provider configuration
/// it was measured against, so a refresh that leaves a chain's providers alone keeps it.
struct ChainObservation {
    generation: u64,
    at_unix_ms: u64,
    healthy: bool,
    config: pillar_config::ProviderConfig,
}

struct RetainedProviderHealthReport {
    generation: u64,
    started_at_unix_ms: u64,
    /// Staleness is counted from here, as `ProviderHealthCache` counts it from publication.
    completed_at_unix_ms: u64,
    report: Arc<ProviderHealthReport>,
}

#[derive(Clone)]
pub struct RpcProviderHealthSource<T> {
    pub(super) providers: crate::provider_snapshot::ProviderSnapshotHandle,
    pub(super) transport: T,
    pub(super) now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(super) chain_type_by_chain_name: HashMap<String, String>,
    execution: Option<Arc<pillar_core::execution::ExecutionResources>>,
    pub(super) canton_ledger_auth: crate::layerzero_runtime::CantonLedgerAuth,
    observations: Arc<tokio::sync::Mutex<HealthObservations>>,
    retained_report: Arc<tokio::sync::Mutex<Option<RetainedProviderHealthReport>>>,
}

impl<T> RpcProviderHealthSource<T>
where
    T: JsonRpcTransport,
{
    pub fn from_getter(
        getter: &impl ProviderConfigGetter,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        Self::from_getter_with_chain_types(getter, transport, now_unix_ms, HashMap::new())
    }

    pub fn from_getter_with_chain_types(
        getter: &impl ProviderConfigGetter,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
        chain_type_by_chain_name: HashMap<String, String>,
    ) -> Self {
        Self {
            providers: crate::provider_snapshot::ProviderSnapshotHandle::from_getter(getter),
            transport,
            now_unix_ms: Arc::new(now_unix_ms),
            chain_type_by_chain_name,
            execution: None,
            canton_ledger_auth: Default::default(),
            observations: Arc::new(tokio::sync::Mutex::new(HealthObservations::default())),
            retained_report: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Probes whatever generation is serving, so `/provider-health` and the
    /// signing path describe the same configuration.
    pub fn from_serving_snapshot(
        providers: crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
        chain_type_by_chain_name: HashMap<String, String>,
    ) -> Self {
        Self {
            providers,
            transport,
            now_unix_ms: Arc::new(now_unix_ms),
            chain_type_by_chain_name,
            execution: None,
            canton_ledger_auth: Default::default(),
            observations: Arc::new(tokio::sync::Mutex::new(HealthObservations::default())),
            retained_report: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub(crate) fn now_unix_ms(&self) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        self.now_unix_ms.clone()
    }
    pub fn with_execution_resources(
        mut self,
        resources: Arc<pillar_core::execution::ExecutionResources>,
    ) -> Self {
        self.execution = Some(resources);
        self
    }
    /// The ledger reads' authentication: a Canton probe is the same authenticated read
    /// dispatch would make, or its health would describe an endpoint nobody calls.
    pub(crate) fn with_canton_ledger_auth(
        mut self,
        auth: crate::layerzero_runtime::CantonLedgerAuth,
    ) -> Self {
        self.canton_ledger_auth = auth;
        self
    }
    /// The newest successful report, if it describes `generation` and is within the stale
    /// allowance `/provider-health` also serves.
    pub(crate) async fn retained_report(
        &self,
        generation: u64,
        now_unix_ms: u64,
    ) -> Option<Arc<ProviderHealthReport>> {
        let retained = self.retained_report.lock().await;
        let retained = retained.as_ref()?;
        (retained.generation == generation
            && now_unix_ms.saturating_sub(retained.completed_at_unix_ms)
                <= pillar_core::PROVIDER_HEALTH_CACHE_STALE_MS)
            .then(|| retained.report.clone())
    }
    pub async fn get_provider_health_report(&self) -> Result<ProviderHealthReport, RpcError> {
        use pillar_core::execution::{current, RequestContext};
        let parent = current();
        let mut context = RequestContext::background();
        context.resources = self
            .execution
            .clone()
            .or_else(|| parent.as_ref().and_then(|parent| parent.resources.clone()));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        context.deadline = Some(
            parent
                .and_then(|parent| parent.deadline)
                .map_or(deadline, |parent| parent.min(deadline)),
        );
        context.scope(self.probe_report()).await
    }
    async fn probe_report(&self) -> Result<ProviderHealthReport, RpcError> {
        let snapshot = self.providers.load();
        let generation = snapshot.generation();
        let probe_started_at_unix_ms = (self.now_unix_ms)();
        let chains = snapshot.provider_configs().len().max(1);
        let capacity = super::source_probes::background_probe_capacity();
        let concurrent = capacity.map_or(chains, |capacity| capacity.clamp(1, chains));
        // Each running chain owns a fixed share, so a stalled pool cannot wait out another chain's admission.
        let share = capacity.map(|capacity| (capacity / concurrent).max(1));
        let requests = snapshot
            .provider_configs()
            .iter()
            .map(|(chain_name, config)| async move {
                let checked_at_unix_ms = (self.now_unix_ms)();
                let providers = crate::provider_health::rpc_scope(
                    chain_name,
                    super::source_probes::with_probe_share(share, async {
                        match self.chain_type_for_provider_health(chain_name) {
                            "EVM" => self.probe_evm_provider_health(chain_name, config).await,
                            "APTOS" => self.probe_aptos_provider_health(chain_name, config).await,
                            "SOLANA" => self.probe_solana_provider_health(chain_name, config).await,
                            "SUI" | "IOTAMOVE" => {
                                self.probe_sui_provider_health(chain_name, config).await
                            }
                            "STARKNET" => {
                                self.probe_starknet_provider_health(chain_name, config)
                                    .await
                            }
                            "STELLAR" => {
                                self.probe_stellar_provider_health(chain_name, config).await
                            }
                            "TON" => self.probe_ton_provider_health(chain_name, config).await,
                            "INITIA" => self.probe_initia_provider_health(chain_name, config).await,
                            "TRON" => self.probe_tron_provider_health(chain_name, config).await,
                            "CANTON" => self.probe_canton_provider_health(chain_name, config).await,
                            _ => Ok(non_evm_provider_health_entries(chain_name, config)),
                        }
                    }),
                )
                .await?;
                let primary_count = providers.iter().filter(|entry| !entry.diagnostic).count();
                let observed = primary_count > 0
                    && providers
                        .iter()
                        .filter(|entry| !entry.diagnostic)
                        .all(|entry| entry.observed);
                let mut observations = self.observations.lock().await;
                let measured_healthy = primary_count > 0
                    && providers
                        .iter()
                        .filter(|entry| !entry.diagnostic && entry.observed)
                        .all(|entry| entry.healthy);
                let previous = observations.chains.get(chain_name);
                let healthy = measured_healthy
                    && (observed
                        || previous.is_some_and(|previous| {
                            previous.config == *config
                                && previous.healthy
                                && checked_at_unix_ms.saturating_sub(previous.at_unix_ms)
                                    <= pillar_core::PROVIDER_HEALTH_CACHE_STALE_MS
                        }));
                // Overlapping rounds can finish out of order: the newer generation, then the
                // later probe, wins.
                if observed
                    && previous.is_none_or(|previous| {
                        if previous.config == *config {
                            checked_at_unix_ms >= previous.at_unix_ms
                        } else {
                            generation > previous.generation
                        }
                    })
                {
                    observations.chains.insert(
                        chain_name.clone(),
                        ChainObservation {
                            generation,
                            at_unix_ms: checked_at_unix_ms,
                            healthy,
                            config: config.clone(),
                        },
                    );
                }
                Ok::<_, RpcError>((
                    chain_name.clone(),
                    ChainProviderHealthReport {
                        healthy,
                        checked_at_unix_ms,
                        providers,
                    },
                ))
            })
            .collect::<Vec<_>>();
        let report: ProviderHealthReport = futures::stream::iter(requests)
            .buffer_unordered(concurrent)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .collect();
        let completed = Arc::new(report.clone());
        let completed_at_unix_ms = (self.now_unix_ms)();
        let mut retained = self.retained_report.lock().await;
        // Overlapping rounds (refresh and rank loops) can finish out of order.
        if retained.as_ref().is_none_or(|retained| {
            (generation, probe_started_at_unix_ms)
                >= (retained.generation, retained.started_at_unix_ms)
        }) {
            *retained = Some(RetainedProviderHealthReport {
                generation,
                started_at_unix_ms: probe_started_at_unix_ms,
                completed_at_unix_ms,
                report: completed,
            });
        }
        Ok(report)
    }
}

#[async_trait]
impl<T> ProviderHealthSource for RpcProviderHealthSource<T>
where
    T: JsonRpcTransport,
{
    fn configuration_generation(&self) -> u64 {
        self.providers.generation()
    }

    async fn get_provider_health(&self) -> Result<ProviderHealthSnapshot, String> {
        let report = self
            .get_provider_health_report()
            .await
            .map_err(|error| error.to_string())?;
        Ok(provider_health_snapshot_from_report(&report))
    }

    fn scope_refresh(
        &self,
        refresh: pillar_core::ProviderHealthRefresh,
    ) -> pillar_core::ProviderHealthRefresh {
        self.providers.carry_pin(refresh)
    }
}

pub(crate) fn provider_health_snapshot_from_report(
    report: &ProviderHealthReport,
) -> ProviderHealthSnapshot {
    report
        .iter()
        .map(|(chain_name, chain_report)| {
            let healthy = chain_report.providers.is_empty() || chain_report.healthy;
            (chain_name.clone(), healthy)
        })
        .collect()
}

/// Fallback for a chain type with no probe of its own.
///
/// `chain_type_for_provider_health` defaults an unknown chain name to `"EVM"`, and
/// `no_non_evm_chain_falls_through_to_the_unregistered_health_probe` holds every non-EVM
/// chain of the static table to its own arm. It exists because the dispatch is on a `&str`.
///
/// It fails closed by construction: `normalize_provider_health_entry` sets
/// `healthy` from whether the response parses as a number, and this response is
/// not numeric, so a chain that ever did reach here reports unhealthy rather than
/// inventing health for endpoints nobody probed.
pub(crate) fn non_evm_provider_health_entries(
    chain_name: &str,
    config: &pillar_config::ProviderConfig,
) -> Vec<ProviderHealthEntry> {
    config
        .uris
        .iter()
        .map(|uri| {
            let (url, _) = provider_uri_parts(uri);
            let mut entry = normalize_provider_health_entry(
                url,
                Value::String(format!(
                    "No provider health probe is registered for the chain type of {chain_name}"
                )),
                None,
            );
            entry.rank_key = provider_rank_key(chain_name, uri);
            entry
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{JsonRpcTransport, RpcProviderHealthSource};
    use crate::provider_snapshot::ProviderSnapshotHandle;
    use async_trait::async_trait;
    use pillar_config::{ProviderConfig, ProviderConfigGetter, ProviderConfigs};
    use pillar_core::ProviderHealthSource;
    use serde_json::Value;
    use std::collections::HashMap;

    #[derive(Clone)]
    struct NoopTransport;

    #[async_trait]
    impl JsonRpcTransport for NoopTransport {
        async fn post_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
            _body: Value,
        ) -> Result<Value, String> {
            unreachable!("the empty provider probe must not perform RPC calls")
        }

        async fn get_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            unreachable!("the empty provider probe must not perform RPC calls")
        }
    }

    struct EmptyProbeGetter {
        configs: ProviderConfigs,
    }

    impl ProviderConfigGetter for EmptyProbeGetter {
        fn get_provider_config(&self, chain_name: &str) -> Option<&ProviderConfig> {
            self.configs.get(chain_name)
        }

        fn get_provider_configs(&self) -> &ProviderConfigs {
            &self.configs
        }
    }

    #[tokio::test]
    async fn provider_health_cache_parity_distinguishes_empty_snapshot_from_report() {
        let getter = EmptyProbeGetter {
            configs: indexmap::IndexMap::from([(
                "unsupported-chain".to_string(),
                ProviderConfig::with_distinct_entities(Vec::new(), 1),
            )]),
        };
        let source = RpcProviderHealthSource::from_getter(&getter, NoopTransport, || 42);

        let report = source.get_provider_health_report().await.unwrap();
        assert!(!report["unsupported-chain"].healthy);

        let snapshot = source.get_provider_health().await.unwrap();
        assert!(snapshot["unsupported-chain"]);
    }
    #[tokio::test]
    async fn retained_report_is_unavailable_after_provider_generation_changes() {
        // The roster serving differs from the empty candidate, so the publish is a real change
        // while the probe still has no provider to dial.
        let providers =
            ProviderSnapshotHandle::new(ProviderConfigs::new(), vec!["bsc".to_string()]);
        let source = RpcProviderHealthSource::from_serving_snapshot(
            providers.clone(),
            NoopTransport,
            || 42,
            HashMap::new(),
        );
        source.get_provider_health_report().await.unwrap();
        assert!(source.retained_report(0, 42).await.is_some());

        providers.publish(providers.candidate(ProviderConfigs::new()));
        assert!(source
            .retained_report(providers.generation(), 42)
            .await
            .is_none());
    }
}
