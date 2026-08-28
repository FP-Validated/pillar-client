use async_trait::async_trait;
use pillar_api::{AppError, ServerApp, SignerInfo};
use pillar_config::{
    load_from_map, provider_config_from_env_map, static_chain_type_by_chain_name,
    ProviderConfigGetter, RuntimeConfig, LZ_CDK_DEPLOY_REGION, LZ_ENV,
};
use pillar_core::{
    PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, ProviderHealthCache,
    ProviderHealthSnapshot,
};
use pillar_metrics::PillarMetrics;
use serde_json::Value;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::Mutex;

use crate::config_loader::{
    enforce_runtime_core_signer_production_policy, runtime_provider_config_from_env_map,
    RemoteProviderConfigOwner,
};
use crate::layerzero_runtime::{
    core_api_app_from_runtime_parts, runtime_chain_name_by_endpoint_id,
    runtime_core_dependencies_from_layerzero_parts, runtime_evm_uln_payload_builder,
    runtime_layerzero_parts_from_evm_config, runtime_rpc_validation_checks_from_evm_config,
    runtime_v_id_by_chain_name, RuntimeCoreAppDependencies, RuntimeCoreAppParts,
    RuntimeEvmReadPayloadResolver, RuntimeEvmUlnV2PayloadBuilder, RuntimeExtraContextConfig,
    RuntimeLayerZeroDependencyInputs, RuntimeLegacyChainNameResolver,
};
use crate::provider_health::{
    provider_health_snapshot_from_report, unix_time_ms, AwsSdkLambdaInvokeClient, JsonRpcTransport,
    ProviderRankTracker, ReqwestJsonRpcTransport, RpcProviderHealthSource,
};
use crate::provider_snapshot::ProviderSnapshotHandle;
use crate::signer_runtime::{
    infer_chain_type_by_chain_name_from_signer_env_map,
    runtime_signer_assembly_from_config_with_metrics, runtime_signer_config_from_env_map,
    typed_chain_type_by_chain_name,
};
use crate::startup_report::{RuntimeMode, StartupReport};

mod core_dependencies;
#[path = "env.rs"]
mod environment;
mod runtime_core;
mod server_trait;
mod types;

pub use types::RuntimeServerApp;

pub(crate) fn filtered_available_chain_names(
    provider_config: &impl ProviderConfigGetter,
    requested: Option<&[String]>,
) -> Vec<String> {
    provider_config
        .get_provider_configs()
        .keys()
        .filter(|name| {
            requested.is_none_or(|requested| requested.iter().any(|candidate| candidate == *name))
        })
        .cloned()
        .collect()
}

/// Refuses a chain selection or provider configuration this process could never
/// sign with, and names anything the CSV silently discarded.
///
/// Readiness does not catch it: the snapshot reports a chain with an empty
/// provider list as healthy. That is upstream behaviour - the snapshot leaves
/// `results[chainName] = true` when the probe list is empty (TS:
/// `apps/gasolina/src/app/app.ts:318`) while the report requires a non-empty
/// list (TS: `:245-247`) - and this port keeps both halves, so the guard belongs
/// at the configuration boundary instead of in the snapshot. Reusing
/// `required_provider_quorum` is what keeps this gate and the request-time check
/// from drifting apart. Every constructor has to call it, because
/// `from_env_map` and `from_env_map_with_core_dependencies` assemble
/// independently.
/// Publishes the startup generation and returns the one handle every
/// request-time consumer reads.
///
/// Exists because the handle must be created exactly once per process. Both
/// production constructors need it - `runtime_core` to build the LayerZero
/// builders and resolvers, `core_dependencies` to build the health source -
/// and two handles would restore precisely the split-brain the snapshot
/// removes: signing on one generation while `/provider-health` describes
/// another. Validating here rather than after means no refresh can start
/// against a roster startup would have rejected.
/// Records a health report into the rank tracker, unless a refresh landed under
/// the probe that produced it.
///
/// Rank is keyed by `(chain, url)` and describes a URL's transport health, which
/// is why a refresh does not invalidate the tracker wholesale: an observation of
/// a URL that both generations configure stays true, and one of a URL the new
/// generation dropped is simply never looked up again.
///
/// A probe that *straddles* a refresh is different. The URIs it dialled came
/// from the old generation, and the rank key is the URL alone - headers are
/// stripped (`rank_key_url`) - so an operator who rotates the credentials on an
/// endpoint would have the failures observed under the old ones recorded
/// against the fixed one, and `plan_dispatch` would keep excluding it until the
/// entry ages out. Requests for a chain whose quorum then cannot be met fail
/// closed, so a configuration fix would not take effect for up to a reprobe
/// interval. Discarding the observation instead leaves those URLs unranked,
/// which `rank_of` reports as `Normal` - the documented pre-ranking default -
/// so dispatch tries them and the quorum itself decides.
/// `task` labels the background heartbeats render under. Named here rather than
/// at each spawn so the set of loops this process runs is readable in one place.
pub(crate) const PROVIDER_RANK_REFRESH_TASK: &str = "provider_rank_refresh";
pub(crate) const PROVIDER_HEALTH_CACHE_REFRESH_TASK: &str = "provider_health_cache_refresh";

pub(crate) async fn seed_provider_rank_if_current(
    rank_tracker: &ProviderRankTracker,
    providers: &ProviderSnapshotHandle,
    probed_generation: u64,
    report: &pillar_core::ProviderHealthReport,
) {
    if providers.generation() != probed_generation {
        return;
    }
    rank_tracker.seed_from_report(report).await;
}

pub(crate) async fn serving_provider_snapshot(
    remote_provider_config: &mut Option<RemoteProviderConfigOwner>,
    provider_config: &impl ProviderConfigGetter,
    available_chain_names: &[String],
    requested_csv: Option<&str>,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<ProviderSnapshotHandle, String> {
    validate_operational_chains(provider_config, available_chain_names, requested_csv)?;
    Ok(match remote_provider_config {
        // LOCAL has no refresh loop, so it registers no age: a configuration
        // that is never refreshed is not stale, and rendering an unbounded age
        // for it would make every local deployment look overdue.
        Some(owner) => owner.serve(available_chain_names.to_vec(), metrics).await,
        None => ProviderSnapshotHandle::new(
            provider_config.get_provider_configs().clone(),
            available_chain_names.to_vec(),
        ),
    })
}

pub(crate) fn validate_operational_chains(
    provider_config: &impl ProviderConfigGetter,
    available_chain_names: &[String],
    requested_csv: Option<&str>,
) -> Result<(), String> {
    if available_chain_names.is_empty() {
        return Err(
            "no operational chains remain: LAYERZERO_AVAILABLE_CHAIN_NAMES selected \
                    nothing present in the provider configuration"
                .to_string(),
        );
    }
    // Upstream matches the CSV verbatim - `new Set(raw.split(','))` with no trim
    // (TS: `apps/gasolina/src/index.ts:288-292`) - so ` bsc` is a different name
    // from `bsc` and simply never matches. Keeping that parsing keeps parity,
    // but a silently dropped chain is an operational trap, so name every entry
    // that selected nothing.
    if let Some(requested_csv) = requested_csv {
        let dropped = requested_csv
            .split(',')
            .filter(|entry| !available_chain_names.iter().any(|name| name == entry))
            .collect::<Vec<_>>();
        if !dropped.is_empty() {
            tracing::warn!(
                target: "pillar_runtime",
                entries = ?dropped,
                "LAYERZERO_AVAILABLE_CHAIN_NAMES entries matched no configured chain"
            );
        }
    }
    let errors = available_chain_names
        .iter()
        .filter_map(|chain_name| {
            let config = provider_config.get_provider_config(chain_name)?;
            // `required_provider_quorum` coerces a zero quorum up to 1, so it
            // can never report one. A zero quorum asks for a signature with no
            // provider agreement at all; for a signer that is a typo, not a
            // configuration.
            if config.quorum == Some(0) {
                return Some(format!("Provider quorum 0 for chain {chain_name}"));
            }
            crate::provider_health::required_provider_quorum(config, chain_name)
                .err()
                .map(|error| error.to_string())
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_chains_come_from_filtered_provider_keys() {
        let provider_config = pillar_config::StaticProviderConfig::new(
            serde_json::from_str(
                r#"{
                    "ethereum": {"uris": ["https://eth.example"], "quorum": 1},
                    "bsc": {"uris": ["https://bsc.example"], "quorum": 1}
                }"#,
            )
            .unwrap(),
            None,
        )
        .unwrap();
        let requested = vec![
            "missing".to_string(),
            "bsc".to_string(),
            "bsc".to_string(),
            "ethereum".to_string(),
        ];
        assert_eq!(
            filtered_available_chain_names(&provider_config, Some(&requested)),
            vec!["ethereum".to_string(), "bsc".to_string()]
        );
    }
}
