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
    supported_uln_versions: &[String],
) -> RuntimeCoreAppDependencies
where
    C: RuntimeValidationChecks,
{
    let mut hash_call_data_builders = build_hash_call_data_builders(
        parts.uln_v2_payload_builder,
        parts.uln_v3_payload_builder,
        parts.uln_read_v1_payload_builder,
        parts.read_payload_resolver,
        v_id_by_chain_name,
    );
    // The variable only gates the legacy `V2` and `V301` builders; `V302` and
    // `ReadV1002` are always kept, so any other entry silently does nothing.
    // Upstream validates no further than "the array is non-empty" (TS:
    // `packages/dynamic-config/src/boostrapConfig/index.ts:169-175`), so
    // rejecting an unrecognised value would diverge - name it instead, because
    // a typo here disables both legacy builders without saying so.
    let ineffective = supported_uln_versions
        .iter()
        .filter(|version| !matches!(version.as_str(), "V2" | "V301"))
        .collect::<Vec<_>>();
    if !ineffective.is_empty() {
        tracing::warn!(
            target: "pillar_runtime",
            entries = ?ineffective,
            "LAYERZERO_SUPPORTED_ULN_VERSIONS entries have no effect: the variable only gates V2 and V301"
        );
    }
    hash_call_data_builders.retain(|version, _| {
        !matches!(version.as_str(), "V2" | "V301")
            || supported_uln_versions
                .iter()
                .any(|supported| supported == version)
    });
    RuntimeCoreAppDependencies {
        hash_call_data_builders,
        sent_event_resolver: parts.sent_event_resolver,
        validator: Arc::new(RuntimeAppValidator::new(parts.validation_checks)),
        legacy_chain_name_resolver: parts.legacy_chain_name_resolver,
    }
}
