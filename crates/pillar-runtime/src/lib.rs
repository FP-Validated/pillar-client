mod config_loader;
mod layerzero_runtime;
mod provider_health;
mod provider_snapshot;
mod server_app;
mod signer_runtime;
mod startup_report;
mod validation;

/// Highest Solana transaction version the JSON-RPC read paths opt into.
///
/// `getTransaction` fails with `-32015` for any transaction newer than this, so
/// reading v1 (SIMD-0385, feature `txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL`)
/// requires the integer `1`; a string would fail request validation with `-32602`
/// on every call. Older nodes only compare `version <= max`, so raising the
/// ceiling stays compatible with providers that cannot serve v1 yet. This is a
/// deliberate divergence from upstream TypeScript, which still pins `0`
/// (`packages/sdks/rpc-sdk/src/solana/index.ts:58,167`).
/// Reading v1 is not signing or building it: no payload, hash or signer change.
pub(crate) const SOLANA_MAX_SUPPORTED_TRANSACTION_VERSION: u8 = 1;

pub use layerzero_runtime::{
    core_api_app_from_runtime_parts, runtime_aptos_layerzero_config,
    runtime_core_dependencies_from_layerzero_parts, runtime_evm_layerzero_config,
    runtime_evm_uln_payload_builder, runtime_layerzero_parts_from_evm_config,
    runtime_rpc_validation_checks_from_evm_config, runtime_v_id_by_chain_name,
    EvmPacketSentResolver, EvmPacketSentResolverConfig, RuntimeAptosLayerZeroConfig,
    RuntimeCoreAppDependencies, RuntimeCoreAppParts, RuntimeEvmLayerZeroConfig,
    RuntimeExtraContextConfig, RuntimeLayerZeroDependencyParts, RuntimeRpcValidationChecks,
};
pub use provider_health::{
    normalize_provider_health_entry, AwsLambdaInvokeClient, AwsSdkLambdaInvokeClient,
    JsonRpcTransport, ReqwestJsonRpcTransport, RpcProviderHealthSource,
};
pub use provider_snapshot::{ProviderSnapshotHandle, RuntimeProviderSnapshot};
pub use server_app::RuntimeServerApp;
pub use signer_runtime::{
    aws_mnemonic_signer_assembly_from_config, aws_mnemonic_signer_assembly_from_secret_client,
    infer_chain_type_by_chain_name_from_signer_env_map, kms_signer_assembly_from_config,
    kms_signer_assembly_from_raw_factory, local_mnemonic_signer_assembly_from_config,
    production_aws_mnemonic_secret_client, production_kms_raw_signer_factory_from_options,
    runtime_signer_assembly_from_config, runtime_signer_config_from_env_map,
    signer_chain_type_from_config, signer_local_mnemonic_map_from_config,
    signer_wallet_definitions_from_config, AwsMnemonicSecretClient,
    AwsSecretsManagerMnemonicClient, KmsCredentialFlags, KmsSignerAssembly, KmsSignerGetter,
    LocalMnemonicSignerAssembly, LocalMnemonicSignerGetter, RuntimeSignerAssembly,
    RuntimeSignerConfig, RuntimeSignerMaterial,
};
pub use startup_report::{
    startup_report_from_env_map, RuntimeMode, StartupChainReport, StartupReport,
};
pub use validation::{
    ExpirationValidRange, RuntimeAppValidator, RuntimeValidationChecks,
    DEFAULT_MAXIMUM_EXPIRATION_GRACE_PERIOD_SECONDS, DEFAULT_MAXIMUM_EXPIRATION_SECONDS,
};

#[cfg(test)]
mod tests;
