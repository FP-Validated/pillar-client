use super::*;

impl<T> RuntimeServerApp<T>
where
    T: JsonRpcTransport,
{
    pub async fn from_env_map_with_runtime_core(
        vars: HashMap<String, String>,
        transport: T,
        now_unix_ms: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let runtime_config = load_from_map(vars.clone()).map_err(|error| error.to_string())?;
        enforce_runtime_core_signer_production_policy(&vars)?;
        let environment = runtime_config
            .environment
            .clone()
            .ok_or_else(|| format!("{LZ_ENV} is required for runtime core wiring"))?;
        let mut remote_provider_config =
            RemoteProviderConfigOwner::from_env_map(&vars, &runtime_config).await?;
        let provider_config = match &remote_provider_config {
            Some(owner) => owner.snapshot()?,
            None => runtime_provider_config_from_env_map(&vars, &runtime_config).await?,
        };
        let available_chain_names = filtered_available_chain_names(
            &provider_config,
            runtime_config.available_chain_names.as_deref(),
        );
        let chain_type_by_chain_name = static_chain_type_by_chain_name(&available_chain_names)
            .map_err(|error| error.to_string())?;
        let chain_name_by_eid =
            runtime_chain_name_by_endpoint_id(&environment, &available_chain_names)
                .map_err(|error| error.to_string())?;
        let rank_tracker = Arc::new(ProviderRankTracker::new());
        // One registry for the whole process: the signer, the packet resolver,
        // the provider-config refresh loop and the `/metrics` endpoint all
        // record into this object. Anything that builds its own would count
        // into a registry nothing renders.
        let metrics = Arc::new(Mutex::new(PillarMetrics::new()));
        // Built before anything that reads provider configuration, so the
        // builders, the resolvers and the health source below all share one
        // generation.
        let providers = serving_provider_snapshot(
            &mut remote_provider_config,
            &provider_config,
            &available_chain_names,
            vars.get(pillar_config::LZ_AVAILABLE_CHAIN_NAMES)
                .map(String::as_str),
            metrics.clone(),
        )
        .await?;
        let mut validation_checks = runtime_rpc_validation_checks_from_evm_config(
            &providers,
            transport.clone(),
            &environment,
            &available_chain_names,
        )
        .map_err(|error| error.to_string())?
        .with_rank_tracker(rank_tracker.clone())
        .with_extra_context(RuntimeExtraContextConfig::from_runtime_config(
            &runtime_config,
        ));
        if runtime_config.extra_context_aws_lambda_name.is_some() {
            let region = vars
                .get(LZ_CDK_DEPLOY_REGION)
                .filter(|value| !value.is_empty())
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "{LZ_CDK_DEPLOY_REGION} is required when EXTRA_CONTEXT_AWS_LAMBDA_NAME is provided"
                    )
                })?;
            validation_checks = validation_checks.with_extra_context_lambda_client(Arc::new(
                AwsSdkLambdaInvokeClient::from_region(Some(region)).await?,
            ));
        }
        let legacy_chain_name_resolver =
            RuntimeLegacyChainNameResolver::new(chain_name_by_eid.clone());
        let uln_v2_payload_builder = RuntimeEvmUlnV2PayloadBuilder::new(
            &providers,
            transport.clone(),
            runtime_evm_uln_payload_builder(&environment, &available_chain_names)
                .map_err(|error| error.to_string())?,
        )
        .with_rank_tracker(rank_tracker.clone());
        let read_payload_resolver =
            RuntimeEvmReadPayloadResolver::new(&providers, transport.clone(), chain_name_by_eid);
        let dependencies = runtime_core_dependencies_from_layerzero_parts(
            runtime_layerzero_parts_from_evm_config(
                &providers,
                transport.clone(),
                &environment,
                &available_chain_names,
                RuntimeLayerZeroDependencyInputs {
                    uln_v2_payload_builder: Arc::new(uln_v2_payload_builder),
                    read_payload_resolver: Arc::new(read_payload_resolver),
                    validation_checks: Arc::new(validation_checks),
                    legacy_chain_name_resolver: Arc::new(legacy_chain_name_resolver),
                    metrics: metrics.clone(),
                },
            )
            .map_err(|error| error.to_string())?,
            environment,
            &runtime_config.supported_uln_versions,
        );

        Self::from_env_map_with_core_dependencies(
            vars,
            transport,
            now_unix_ms,
            dependencies,
            chain_type_by_chain_name,
            RuntimeMode::Production,
            rank_tracker,
            remote_provider_config,
            providers,
            metrics,
        )
        .await
    }

    pub fn with_signing_app(mut self, signing_app: Arc<dyn ServerApp>) -> Self {
        self.signing_app = Some(signing_app);
        self
    }
}
