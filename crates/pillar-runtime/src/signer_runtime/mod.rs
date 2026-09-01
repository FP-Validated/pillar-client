use async_trait::async_trait;
use pillar_api::SignerInfo;
use pillar_config::{
    build_wallets_by_chain_name, kms_signer_adapter_factory_options_from_env_map,
    kms_wallet_definitions_from_env_map, static_chain_type_by_chain_name,
    wallet_definitions_from_env_map, wallet_definitions_from_file_path_env_map,
    wallet_to_mnemonic_map_from_env_map, wallet_to_mnemonic_map_from_file_path_env_map,
    KmsSignerAdapterFactoryOptions, SignerSdkFactoryType, WalletToMnemonicMap,
    LZ_CDK_DEPLOY_REGION, LZ_WALLETS_FILE_PATH, LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH, SIGNER_TYPE,
};
use pillar_core::{AppCoreError, Signature, SignerGetter, WalletRef};
use pillar_metrics::PillarMetrics;
use pillar_signer::{
    AwsKmsRawSignerAdapterFactory, AwsSdkKmsClient, AzureKeyVaultKmsClient,
    AzureKmsRawSignerAdapterFactory, ChainType, ChainTypeWalletDefinition, GcpKmsOptions,
    GcpKmsRawSignerAdapterFactory, GoogleCloudKmsClient, KmsProvider,
    LocalMnemonic as SignerLocalMnemonic, LocalMnemonicRawSignerAdapterFactory,
    PillarSignerAdapterKind, RawSignerAdapterFactory, SignerAdapterFactory, WalletDefinition,
    WalletSignerKind,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::sync::Mutex;

mod assembly;
mod aws_secret;
mod chain_types;
mod config;
mod getters;
mod types;

pub use assembly::{
    aws_mnemonic_signer_assembly_from_config, aws_mnemonic_signer_assembly_from_secret_client,
    kms_signer_assembly_from_config, kms_signer_assembly_from_raw_factory,
    local_mnemonic_signer_assembly_from_config, production_aws_mnemonic_secret_client,
    production_kms_raw_signer_factory_from_options, runtime_signer_assembly_from_config,
    runtime_signer_assembly_from_config_with_metrics,
};
#[cfg(test)]
pub(crate) use aws_secret::AwsMnemonicSecret;
pub use aws_secret::{AwsMnemonicSecretClient, AwsSecretsManagerMnemonicClient};
pub use chain_types::signer_chain_type_from_config;
pub(crate) use chain_types::{
    has_env, signer_chain_type_ts_name, signer_kind_from_config, typed_chain_type_by_chain_name,
};
pub use config::{
    infer_chain_type_by_chain_name_from_signer_env_map, runtime_signer_config_from_env_map,
    signer_local_mnemonic_map_from_config, signer_wallet_definitions_from_config,
    RuntimeSignerConfig, RuntimeSignerMaterial,
};
pub(crate) use getters::kms_credentials_flags;
pub use getters::{KmsCredentialFlags, KmsSignerGetter};
pub use types::{
    KmsSignerAssembly, LocalMnemonicSignerAssembly, LocalMnemonicSignerGetter,
    RuntimeSignerAssembly,
};
