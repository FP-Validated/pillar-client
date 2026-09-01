use super::*;

#[derive(Clone)]
pub struct RpcProviderHealthSource<T> {
    pub(super) providers: crate::provider_snapshot::ProviderSnapshotHandle,
    pub(super) transport: T,
    pub(super) now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub(super) chain_type_by_chain_name: HashMap<String, String>,
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
        }
    }

    pub(crate) fn now_unix_ms(&self) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        self.now_unix_ms.clone()
    }
    pub async fn get_provider_health_report(&self) -> ProviderHealthReport {
        let snapshot = self.providers.load();
        let provider_configs = snapshot.provider_configs().iter().collect::<Vec<_>>();
        join_all(
            provider_configs
                .into_iter()
                .map(|(chain_name, config)| async move {
                    let checked_at_unix_ms = (self.now_unix_ms)();
                    let providers = match self.chain_type_for_provider_health(chain_name) {
                        "EVM" => self.probe_evm_provider_health(config).await,
                        "APTOS" => self.probe_aptos_provider_health(chain_name, config).await,
                        "SOLANA" => self.probe_solana_provider_health(config).await,
                        "SUI" | "IOTAMOVE" => {
                            self.probe_sui_provider_health(chain_name, config).await
                        }
                        "STARKNET" => self.probe_starknet_provider_health(config).await,
                        "STELLAR" => self.probe_stellar_provider_health(config).await,
                        "TON" => self.probe_ton_provider_health(config).await,
                        "INITIA" => self.probe_initia_provider_health(config).await,
                        "TRON" => self.probe_tron_provider_health(chain_name, config).await,
                        _ => non_evm_provider_health_entries(chain_name, config),
                    };
                    let healthy =
                        !providers.is_empty() && providers.iter().all(|entry| entry.healthy);
                    (
                        chain_name.clone(),
                        ChainProviderHealthReport {
                            healthy,
                            checked_at_unix_ms,
                            providers,
                        },
                    )
                }),
        )
        .await
        .into_iter()
        .collect()
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
        let report = self.get_provider_health_report().await;
        Ok(provider_health_snapshot_from_report(&report))
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
/// Unreachable for every chain in the static table: `chain_type_for_provider_health`
/// defaults an unknown chain name to `"EVM"` before the dispatch, and every chain
/// type the table actually contains - EVM, APTOS, SOLANA, SUI, IOTAMOVE,
/// STARKNET, STELLAR, TON, INITIA, TRON - has an explicit arm. It exists because
/// the dispatch is on a `&str` and must be exhaustive.
///
/// It fails closed by construction: `normalize_provider_health_entry` sets
/// `healthy` from whether the response parses as a number, and this response is
/// not numeric, so a chain that ever did reach here reports unhealthy rather than
/// inventing health for endpoints nobody probed. The message used to read "is not
/// wired in Rust runtime yet", which described a porting roadmap rather than the
/// state, in a branch no chain reaches.
pub(crate) fn non_evm_provider_health_entries(
    chain_name: &str,
    config: &pillar_config::ProviderConfig,
) -> Vec<ProviderHealthEntry> {
    config
        .uris
        .iter()
        .map(|uri| {
            let (url, _) = provider_uri_parts(uri);
            normalize_provider_health_entry(
                url,
                Value::String(format!(
                    "No provider health probe is registered for the chain type of {chain_name}"
                )),
                None,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{JsonRpcTransport, RpcProviderHealthSource};
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
                ProviderConfig {
                    uris: Vec::new(),
                    quorum: Some(1),
                },
            )]),
        };
        let source = RpcProviderHealthSource::from_getter(&getter, NoopTransport, || 42);

        let report = source.get_provider_health_report().await;
        assert!(!report["unsupported-chain"].healthy);

        let snapshot = source.get_provider_health().await.unwrap();
        assert!(snapshot["unsupported-chain"]);
    }
}
