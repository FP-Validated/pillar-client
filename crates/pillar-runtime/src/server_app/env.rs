use super::*;

impl RuntimeServerApp<ReqwestJsonRpcTransport> {
    pub async fn from_env() -> Result<Self, String> {
        Self::from_env_with_runtime_core().await
    }

    pub async fn from_env_without_runtime_core() -> Result<Self, String> {
        Self::from_env_map(
            env::vars().collect(),
            ReqwestJsonRpcTransport::new()?,
            unix_time_ms,
        )
        .await
    }

    pub async fn from_env_with_runtime_core() -> Result<Self, String> {
        Self::from_env_map_with_runtime_core(
            env::vars().collect(),
            ReqwestJsonRpcTransport::new()?,
            unix_time_ms,
        )
        .await
    }
}

impl<T> RuntimeServerApp<T>
where
    T: JsonRpcTransport,
{
    pub async fn from_env_map(
        vars: HashMap<String, String>,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let runtime_config = load_from_map(vars.clone()).map_err(|error| error.to_string())?;
        let required_chain_names = runtime_config.available_chain_names.as_deref();
        let provider_config = provider_config_from_env_map(
            &vars,
            &runtime_config.provider_config_type,
            required_chain_names,
        )
        .map_err(|error| error.to_string())?;
        let available_chain_names =
            filtered_available_chain_names(&provider_config, required_chain_names);
        let providers = serving_provider_snapshot(
            &mut None,
            &provider_config,
            &available_chain_names,
            vars.get(pillar_config::LZ_AVAILABLE_CHAIN_NAMES)
                .map(String::as_str),
            Arc::new(Mutex::new(PillarMetrics::new())),
        )
        .await?;
        let chain_type_by_chain_name =
            static_chain_type_by_chain_name(&available_chain_names).unwrap_or_default();
        let provider_health_source = RpcProviderHealthSource::from_getter_with_chain_types(
            &provider_config,
            transport,
            now_unix_ms,
            chain_type_by_chain_name,
        );
        let now = provider_health_source.now_unix_ms();
        let provider_health_cache =
            ProviderHealthCache::new(provider_health_source.clone(), move || now());
        let startup_report = StartupReport::from_parts(
            &vars,
            &runtime_config,
            &provider_config,
            &available_chain_names,
            RuntimeMode::Development,
        )?;

        Ok(Self {
            runtime_config,
            providers,
            provider_health_cache,
            background_tasks: Vec::new(),
            _remote_provider_config: None,
            provider_health_source,
            signing_app: None,
            startup_report,
        })
    }
}
