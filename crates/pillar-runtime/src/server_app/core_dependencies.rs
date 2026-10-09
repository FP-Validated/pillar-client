use super::*;

fn warn_mainnet_provider_uris(provider_config: &impl ProviderConfigGetter, chain_names: &[String]) {
    for chain_name in chain_names {
        if provider_config
            .get_provider_config(chain_name)
            .is_some_and(|config| {
                config.uris.iter().any(|provider| {
                    let uri = match provider {
                        pillar_config::ProviderUri::Uri(uri)
                        | pillar_config::ProviderUri::UriWithHeaders { uri, .. } => uri,
                    };
                    reqwest::Url::parse(uri).map_or(true, |url| {
                        url.scheme() != "https"
                            && !(url.scheme() == "http"
                                && url
                                    .host_str()
                                    .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                                    .is_some_and(|ip| ip.is_loopback()))
                    })
                })
            })
        {
            tracing::warn!(chain = %chain_name, "mainnet provider config contains a non-HTTPS RPC URI");
        }
    }
}

impl<T> RuntimeServerApp<T>
where
    T: JsonRpcTransport,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn from_env_map_with_core_dependencies(
        vars: HashMap<String, String>,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
        dependencies: RuntimeCoreAppDependencies,
        chain_type_by_chain_name: HashMap<String, String>,
        mode: RuntimeMode,
        rank_tracker: Arc<ProviderRankTracker>,
        remote_provider_config: Option<RemoteProviderConfigOwner>,
        providers: ProviderSnapshotHandle,
        metrics: Arc<Mutex<PillarMetrics>>,
    ) -> Result<Self, String> {
        let runtime_config = load_from_map(vars.clone()).map_err(|error| error.to_string())?;
        let serving_generation = providers.load();
        let provider_config = pillar_config::StaticProviderConfig::new(
            serving_generation.provider_configs().clone(),
            None,
        )
        .map_err(|error| error.to_string())?;
        let available_chain_names = serving_generation.available_chain_names().to_vec();
        let controls =
            crate::execution::RuntimeControls::new(&runtime_config, &available_chain_names).await?;
        metrics
            .lock()
            .await
            .attach_execution(controls.resources.clone());
        metrics
            .lock()
            .await
            .attach_audit(controls.audit_health.clone());
        let provider_health_source = RpcProviderHealthSource::from_serving_snapshot(
            providers.clone(),
            transport,
            now_unix_ms,
            chain_type_by_chain_name.clone(),
        )
        .with_execution_resources(controls.resources.clone());
        let now = provider_health_source.now_unix_ms();
        let provider_health_cache =
            ProviderHealthCache::new(provider_health_source.clone(), move || now());
        let signer_config = runtime_signer_config_from_env_map(
            &vars,
            &available_chain_names,
            &chain_type_by_chain_name,
        )?;
        let wallets_by_chain_name = signer_config.wallets_by_chain_name.clone();
        let signer_assembly = controls
            .scope(
                providers.generation(),
                runtime_signer_assembly_from_config_with_metrics(
                    signer_config,
                    typed_chain_type_by_chain_name(&chain_type_by_chain_name)?,
                    metrics.clone(),
                ),
            )
            .await?;
        // Read before probing, for the same reason the cache's own refresh
        // does: the refresh loop is already running, so a first refresh could
        // overtake this startup probe and the report would then be labelled as
        // describing a configuration it never saw.
        let probed_generation = providers.generation();
        let provider_health_report = controls
            .scope(
                probed_generation,
                provider_health_source.get_provider_health_report(),
            )
            .await
            .unwrap_or_else(|_| {
                tracing::warn!("startup provider health was not observed");
                pillar_core::ProviderHealthReport::new()
            });
        let provider_health = provider_health_snapshot_from_report(&provider_health_report);
        provider_health_cache
            .warm(provider_health.clone(), probed_generation)
            .await;
        seed_provider_rank_if_current(
            &rank_tracker,
            &providers,
            probed_generation,
            &provider_health_report,
        )
        .await;
        let single_provider_chains = available_chain_names
            .iter()
            .filter_map(|chain_name| {
                provider_config
                    .get_provider_config(chain_name)
                    .filter(|config| config.single_entity_trust_root())
                    .map(|_| chain_name.as_str())
            })
            .collect::<Vec<_>>();
        metrics
            .lock()
            .await
            .set_provider_single_entity_chains(single_provider_chains.len());
        if !single_provider_chains.is_empty() {
            tracing::warn!(
                target: "pillar_runtime",
                chains = ?single_provider_chains,
                "configured chains let one provider entity alone satisfy the quorum strategy"
            );
        }
        if runtime_config.environment.as_deref() == Some("mainnet") {
            warn_mainnet_provider_uris(&provider_config, &available_chain_names);
        }
        let signing_app = core_api_app_from_runtime_parts(RuntimeCoreAppParts {
            runtime_config: runtime_config.clone(),
            available_chain_names: Arc::new(providers.clone()),
            wallets_by_chain_name,
            signer_getter: signer_assembly.signer_getter,
            signer_info: signer_assembly.signer_info,
            provider_health,
            provider_health_report: serde_json::to_value(&provider_health_report)
                .map_err(|error| error.to_string())?,
            dependencies,
            metrics: metrics.clone(),
        });
        let startup_report = StartupReport::from_parts(
            &vars,
            &runtime_config,
            &provider_config,
            &available_chain_names,
            mode,
        )?;

        // Spawned last, after every fallible step above. A `?` between the
        // spawn and `Ok(Self { .. })` would return before the struct exists, so
        // `Drop` would never run and both loops would leak - detached, probing
        // providers, for the life of the process. `StartupReport::from_parts`
        // and the report serialisation are exactly such steps.
        let rank_refresh_source = provider_health_source.clone();
        let rank_refresh_tracker = rank_tracker.clone();
        let rank_refresh_providers = providers.clone();
        let (rank_heartbeat, cache_heartbeat) = {
            let mut registry = metrics.lock().await;
            (
                registry.register_background_task(PROVIDER_RANK_REFRESH_TASK),
                registry.register_background_task(PROVIDER_HEALTH_CACHE_REFRESH_TASK),
            )
        };
        let rank_controls = controls.clone();
        let provider_rank_refresh = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(150)).await;
                rank_heartbeat.stamp();
                let probed_generation = rank_refresh_providers.generation();
                let report = rank_controls
                    .scope(
                        probed_generation,
                        rank_refresh_source.get_provider_health_report(),
                    )
                    .await;
                if let Ok(report) = report {
                    seed_provider_rank_if_current(
                        &rank_refresh_tracker,
                        &rank_refresh_providers,
                        probed_generation,
                        &report,
                    )
                    .await;
                }
            }
        });
        let refresh_cache = provider_health_cache.clone();
        let cache_controls = controls.clone();
        let provider_health_cache_refresh = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    pillar_core::PROVIDER_HEALTH_CACHE_TTL_MS,
                ))
                .await;
                cache_heartbeat.stamp();
                let _ = cache_controls.scope(0, refresh_cache.read()).await;
            }
        });

        Ok(Self {
            controls,
            runtime_config,
            providers,
            provider_health_cache,
            background_tasks: vec![provider_rank_refresh, provider_health_cache_refresh],
            provider_health_source,
            _remote_provider_config: remote_provider_config,
            signing_app: Some(Arc::new(signing_app)),
            startup_report,
            provider_health_report_cache: ProviderHealthReportCache::new(),
        })
    }

    pub async fn from_env_map_with_core_dependencies_inferred_chain_types(
        vars: HashMap<String, String>,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
        dependencies: RuntimeCoreAppDependencies,
    ) -> Result<Self, String> {
        let runtime_config = load_from_map(vars.clone()).map_err(|error| error.to_string())?;
        let remote_provider_config =
            RemoteProviderConfigOwner::from_env_map(&vars, &runtime_config).await?;
        let provider_config = match &remote_provider_config {
            Some(owner) => owner.snapshot()?,
            None => runtime_provider_config_from_env_map(&vars, &runtime_config).await?,
        };
        let available_chain_names = filtered_available_chain_names(
            &provider_config,
            runtime_config.available_chain_names.as_deref(),
        );
        let chain_type_by_chain_name =
            infer_chain_type_by_chain_name_from_signer_env_map(&vars, &available_chain_names)?;
        let metrics = Arc::new(Mutex::new(PillarMetrics::new()));
        let mut remote_provider_config = remote_provider_config;
        let providers = serving_provider_snapshot(
            &mut remote_provider_config,
            &provider_config,
            &available_chain_names,
            vars.get(pillar_config::LZ_AVAILABLE_CHAIN_NAMES)
                .map(String::as_str),
            metrics.clone(),
        )
        .await?;
        Self::from_env_map_with_core_dependencies(
            vars,
            transport,
            now_unix_ms,
            dependencies,
            chain_type_by_chain_name,
            RuntimeMode::Development,
            Arc::new(ProviderRankTracker::new()),
            remote_provider_config,
            providers,
            metrics,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[derive(Clone)]
    struct Buffer(Arc<parking_lot::Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn mainnet_http_provider_uri_emits_a_warning() {
        let raw = r#"{"bsc":{"uris":["http://bsc-rpc.example"],"quorum":1}}"#;
        let config = pillar_config::StaticProviderConfig::new(
            pillar_config::test_support::provider_configs_from_uris_json(raw),
            None,
        )
        .unwrap();
        // Register the warning callsite before `set_default`, so a racing first registration
        // on another test thread cannot cache it as disabled for this subscriber.
        warn_mainnet_provider_uris(&config, &["bsc".to_string()]);
        let logs = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let writer = Buffer(logs.clone());
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_writer(move || writer.clone())
                .finish(),
        );
        warn_mainnet_provider_uris(&config, &["bsc".to_string()]);
        let output = String::from_utf8(logs.lock().clone()).unwrap();
        assert!(
            output.contains("mainnet provider config contains a non-HTTPS RPC URI"),
            "{output}"
        );
        assert!(output.contains("bsc"), "{output}");
    }
}
