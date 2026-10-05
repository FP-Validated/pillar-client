use super::*;

pub struct RuntimeCoreAppParts {
    pub runtime_config: RuntimeConfig,
    /// Asked per request, so admitting a chain and advertising it agree even
    /// after a provider-config refresh.
    pub available_chain_names: Arc<dyn pillar_core::AvailableChains>,
    pub wallets_by_chain_name: HashMap<String, Vec<WalletRef>>,
    pub signer_getter: Arc<dyn SignerGetter>,
    pub signer_info: BTreeMap<String, Vec<SignerInfo>>,
    pub provider_health: ProviderHealthSnapshot,
    pub provider_health_report: Value,
    pub dependencies: RuntimeCoreAppDependencies,
    pub metrics: Arc<tokio::sync::Mutex<PillarMetrics>>,
}

pub fn core_api_app_from_runtime_parts(parts: RuntimeCoreAppParts) -> CoreApiApp {
    CoreApiApp::with_metrics(
        PillarApp {
            available_chain_names: parts.available_chain_names,
            wallets_by_chain_name: parts.wallets_by_chain_name,
            hash_call_data_builders: parts.dependencies.hash_call_data_builders,
            sent_event_resolver: parts.dependencies.sent_event_resolver,
            validator: parts.dependencies.validator,
            signer_getter: parts.signer_getter,
            legacy_chain_name_resolver: parts.dependencies.legacy_chain_name_resolver,
            // The same registry the HTTP surface renders, so a sign request's
            // stage timings reach `/metrics`. A no-op here leaves the
            // documented `pillar_sign_stage_duration_seconds` family rendering
            // its HELP and TYPE lines with no samples under them, forever,
            // which reads to an operator as "no signing happened".
            stage_observer: Arc::new(PillarMetricsStageObserver::new(parts.metrics.clone())),
            debug_mode: parts.runtime_config.debug_mode,
        },
        parts
            .runtime_config
            .environment
            .unwrap_or_else(|| "unknown".to_string()),
        parts.signer_info,
        parts.provider_health,
        parts.provider_health_report,
        parts.metrics,
    )
}

pub fn runtime_core_dependencies_from_layerzero_parts<C>(
    parts: RuntimeLayerZeroDependencyParts<C>,
    v_id_by_chain_name: HashMap<String, String>,
) -> RuntimeCoreAppDependencies
where
    C: RuntimeValidationChecks,
{
    let hash_call_data_builders = build_hash_call_data_builders(
        parts.uln_v2_payload_builder,
        parts.uln_v3_payload_builder,
        parts.uln_read_v1_payload_builder,
        parts.read_payload_resolver,
        v_id_by_chain_name,
    );
    RuntimeCoreAppDependencies {
        hash_call_data_builders,
        sent_event_resolver: Arc::new(UlnV2SdkFactoryResolver {
            inner: parts.sent_event_resolver,
        }),
        validator: Arc::new(RuntimeAppValidator::new(parts.validation_checks)),
        legacy_chain_name_resolver: parts.legacy_chain_name_resolver,
    }
}

/// Upstream's legacy V1-sdk factory, which a V2 request reaches before any RPC:
/// an EVM sdk for EVM and TRON sources, an Aptos sdk for APTOS, and a throw for
/// every other chain type (TS 1.2.66: `lz-v1-sdk/src/factory.ts:21-45`).
struct UlnV2SdkFactoryResolver {
    inner: Arc<dyn SentEventResolver>,
}

#[async_trait::async_trait]
impl SentEventResolver for UlnV2SdkFactoryResolver {
    async fn get_lz_sent_event(
        &self,
        src_tx_hash: &str,
        lz_message_id: &pillar_core::LzMessageId,
    ) -> Result<pillar_core::LzSentEvent, AppCoreError> {
        if lz_message_id.uln_send_version == "V2" {
            match pillar_config::static_chain_type_name(&lz_message_id.pathway_id.src_chain_name) {
                Ok("EVM" | "TRON" | "APTOS") | Err(_) => {}
                Ok(chain_type) => {
                    return Err(AppCoreError::Internal(format!(
                        "Unsupported chain type: {chain_type}"
                    )))
                }
            }
        }
        self.inner
            .get_lz_sent_event(src_tx_hash, lz_message_id)
            .await
    }

    async fn refresh_uln_v2_sent_event(
        &self,
        sent_event: &pillar_core::LzSentEvent,
    ) -> Result<Option<pillar_core::UlnV2RefreshedEvent>, AppCoreError> {
        self.inner.refresh_uln_v2_sent_event(sent_event).await
    }
}
