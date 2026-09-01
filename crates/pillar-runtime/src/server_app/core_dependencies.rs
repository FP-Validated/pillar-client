use super::*;

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
        let provider_config = match &remote_provider_config {
            Some(owner) => owner.snapshot()?,
            None => runtime_provider_config_from_env_map(&vars, &runtime_config).await?,
        };
        // The roster the handle was published with, not a recomputation: the
        // signers assembled below must match the chains actually serving.
        let available_chain_names = providers.load().available_chain_names().to_vec();
        let provider_health_source = RpcProviderHealthSource::from_serving_snapshot(
            providers.clone(),
            transport,
            now_unix_ms,
            chain_type_by_chain_name.clone(),
        );
        let now = provider_health_source.now_unix_ms();
        let provider_health_cache =
            ProviderHealthCache::new(provider_health_source.clone(), move || now());
        let signer_config = runtime_signer_config_from_env_map(
            &vars,
            &available_chain_names,
            &chain_type_by_chain_name,
        )?;
        let wallets_by_chain_name = signer_config.wallets_by_chain_name.clone();
        let signer_assembly = runtime_signer_assembly_from_config_with_metrics(
            signer_config,
            typed_chain_type_by_chain_name(&chain_type_by_chain_name)?,
            metrics.clone(),
        )
        .await?;
        // Read before probing, for the same reason the cache's own refresh
        // does: the refresh loop is already running, so a first refresh could
        // overtake this startup probe and the report would then be labelled as
        // describing a configuration it never saw.
        let probed_generation = providers.generation();
        let provider_health_report = provider_health_source.get_provider_health_report().await;
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
                    .filter(|config| config.quorum.unwrap_or(1).max(1) == 1)
                    .map(|_| chain_name.as_str())
            })
            .collect::<Vec<_>>();
        if !single_provider_chains.is_empty() {
            tracing::warn!(
                target: "pillar_runtime",
                chains = ?single_provider_chains,
                "configured chains use quorum=1 single-provider trust roots"
            );
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
        let provider_rank_refresh = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(150)).await;
                let probed_generation = rank_refresh_providers.generation();
                let report = rank_refresh_source.get_provider_health_report().await;
                seed_provider_rank_if_current(
                    &rank_refresh_tracker,
                    &rank_refresh_providers,
                    probed_generation,
                    &report,
                )
                .await;
                // Stamped on completion: a probe that hangs must not publish a
                // fresh-looking heartbeat on its way in.
                rank_heartbeat.stamp();
            }
        });
        let refresh_cache = provider_health_cache.clone();
        let provider_health_cache_refresh = tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    pillar_core::PROVIDER_HEALTH_CACHE_TTL_MS,
                ))
                .await;
                let _ = refresh_cache.read().await;
                cache_heartbeat.stamp();
            }
        });

        Ok(Self {
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
