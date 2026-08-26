use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fmt, fs, path::Path};

mod generated_layerzero_environment;
mod generated_layerzero_evm;
mod generated_ton_layerzero;
pub mod provider_validation;

#[cfg(test)]
mod provider_validation_tests;

pub const LZ_WALLETS: &str = "LAYERZERO_WALLETS";
pub const LZ_WALLETS_FILE_PATH: &str = "LAYERZERO_WALLETS_FILE_PATH";
pub const LZ_WALLET_MNEMONIC_MAPPING: &str = "LAYERZERO_WALLET_MNEMONIC_MAPPING";
pub const LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH: &str =
    "LAYERZERO_WALLET_MNEMONIC_MAPPING_FILE_PATH";
pub const LZ_ENV: &str = "LAYERZERO_ENVIRONMENT";
pub const LZ_CDK_DEPLOY_REGION: &str = "LAYERZERO_CDK_DEPLOY_REGION";
pub const LZ_DEBUG_MODE: &str = "LAYERZERO_DEBUG_MODE";
pub const LZ_AVAILABLE_CHAIN_NAMES: &str = "LAYERZERO_AVAILABLE_CHAIN_NAMES";
pub const LZ_SUPPORTED_ULN_VERSIONS: &str = "LAYERZERO_SUPPORTED_ULN_VERSIONS";
pub const LZ_PROVIDER_CONFIG_TYPE: &str = "PROVIDER_CONFIG_TYPE";
pub const LZ_PROVIDER_CONFIG: &str = "LAYERZERO_PROVIDER_CONFIG";
pub const LZ_PROVIDER_CONFIG_FILE_PATH: &str = "LAYERZERO_PROVIDER_CONFIG_FILE_PATH";
pub const LZ_PROVIDER_BUCKET: &str = "CONFIG_BUCKET_NAME";
pub const LZ_PROVIDER_CONFIG_REMOTE_KEY: &str = "providers.json";
pub const EXTRA_CONTEXT_REQUEST_URL: &str = "EXTRA_CONTEXT_REQUEST_URL";
pub const EXTRA_CONTEXT_REQUEST_AUTH_TOKEN: &str = "EXTRA_CONTEXT_REQUEST_AUTH_TOKEN";
pub const EXTRA_CONTEXT_AWS_LAMBDA_NAME: &str = "EXTRA_CONTEXT_AWS_LAMBDA_NAME";
pub const LZ_KMS_CLOUD_TYPE: &str = "KMS_CLOUD_TYPE";
pub const LZ_KMS_IDS: &str = "LAYERZERO_KMS_IDS";
pub const AZURE_KEY_VAULT_URL: &str = "AZURE_KEY_VAULT_URL";
pub const SIGNER_TYPE: &str = "SIGNER_TYPE";
pub const GCP_PROJECT_ID: &str = "GCP_PROJECT_ID";
pub const GCP_KEY_RING_ID: &str = "GCP_KEY_RING_ID";
pub const SERVER_PORT: &str = "SERVER_PORT";
pub const PILLAR_IMAGE_VERSION: &str = "PILLAR_IMAGE_VERSION";
pub const PILLAR_API_AUTH_TOKENS: &str = "PILLAR_API_AUTH_TOKENS";
pub const PILLAR_MAX_CONNECTIONS: &str = "PILLAR_MAX_CONNECTIONS";
pub const PILLAR_SHUTDOWN_GRACE_SECONDS: &str = "PILLAR_SHUTDOWN_GRACE_SECONDS";

pub const ENV_VAR_NAMES: &[(&str, &str)] = &[
    ("LZ_WALLETS", LZ_WALLETS),
    ("LZ_WALLETS_FILE_PATH", LZ_WALLETS_FILE_PATH),
    ("LZ_WALLET_MNEMONIC_MAPPING", LZ_WALLET_MNEMONIC_MAPPING),
    (
        "LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH",
        LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH,
    ),
    ("LZ_ENV", LZ_ENV),
    ("LZ_CDK_DEPLOY_REGION", LZ_CDK_DEPLOY_REGION),
    ("LZ_DEBUG_MODE", LZ_DEBUG_MODE),
    ("LZ_AVAILABLE_CHAIN_NAMES", LZ_AVAILABLE_CHAIN_NAMES),
    ("LZ_SUPPORTED_ULN_VERSIONS", LZ_SUPPORTED_ULN_VERSIONS),
    ("LZ_PROVIDER_CONFIG_TYPE", LZ_PROVIDER_CONFIG_TYPE),
    ("LZ_PROVIDER_CONFIG", LZ_PROVIDER_CONFIG),
    ("LZ_PROVIDER_CONFIG_FILE_PATH", LZ_PROVIDER_CONFIG_FILE_PATH),
    ("LZ_PROVIDER_BUCKET", LZ_PROVIDER_BUCKET),
    ("EXTRA_CONTEXT_REQUEST_URL", EXTRA_CONTEXT_REQUEST_URL),
    (
        "EXTRA_CONTEXT_REQUEST_AUTH_TOKEN",
        EXTRA_CONTEXT_REQUEST_AUTH_TOKEN,
    ),
    (
        "EXTRA_CONTEXT_AWS_LAMBDA_NAME",
        EXTRA_CONTEXT_AWS_LAMBDA_NAME,
    ),
    ("LZ_KMS_CLOUD_TYPE", LZ_KMS_CLOUD_TYPE),
    ("LZ_KMS_IDS", LZ_KMS_IDS),
    ("AZURE_KEY_VAULT_URL", AZURE_KEY_VAULT_URL),
    ("SIGNER_TYPE", SIGNER_TYPE),
    ("GCP_PROJECT_ID", GCP_PROJECT_ID),
    ("GCP_KEY_RING_ID", GCP_KEY_RING_ID),
    ("PILLAR_IMAGE_VERSION", PILLAR_IMAGE_VERSION),
    ("PILLAR_API_AUTH_TOKENS", PILLAR_API_AUTH_TOKENS),
    ("PILLAR_MAX_CONNECTIONS", PILLAR_MAX_CONNECTIONS),
    (
        "PILLAR_SHUTDOWN_GRACE_SECONDS",
        PILLAR_SHUTDOWN_GRACE_SECONDS,
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderConfigType {
    S3,
    GCS,
    LOCAL,
}

impl ProviderConfigType {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "S3" => Ok(Self::S3),
            "GCS" => Ok(Self::GCS),
            "LOCAL" => Ok(Self::LOCAL),
            other => Err(ConfigError::InvalidProviderConfigType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub server_port: u16,
    pub provider_config_type: ProviderConfigType,
    pub environment: Option<String>,
    pub available_chain_names: Option<Vec<String>>,
    pub supported_uln_versions: Vec<String>,
    pub debug_mode: bool,
    pub extra_context_request_url: Option<String>,
    pub extra_context_request_auth_token: Option<String>,
    pub extra_context_aws_lambda_name: Option<String>,
    pub image_version: Option<String>,
    pub api_auth_tokens: Vec<String>,
    pub max_connections: usize,
    pub shutdown_grace_seconds: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("Missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("PILLAR_API_AUTH_TOKENS is required and must contain at least one token")]
    MissingAuthTokens,
    #[error("PILLAR_API_AUTH_TOKENS contains a token shorter than 32 characters")]
    InvalidAuthToken,
    #[error("Invalid SERVER_PORT: {0}")]
    InvalidPort(String),
    #[error("Invalid PILLAR_MAX_CONNECTIONS: {0}")]
    InvalidMaxConnections(String),
    #[error("Invalid PILLAR_SHUTDOWN_GRACE_SECONDS: {0}")]
    InvalidShutdownGraceSeconds(String),
    #[error("Unknown provider config type: {0}")]
    InvalidProviderConfigType(String),
    #[error("Invalid {LZ_SUPPORTED_ULN_VERSIONS}: {0}")]
    InvalidSupportedUlnVersions(String),
    #[error("No ULN versions provided")]
    NoSupportedUlnVersions,
    #[error("Unsupported provider config type: {0}")]
    UnsupportedProviderConfigType(String),
    #[error("{0}")]
    RemoteProviderConfig(String),
    #[error("At least one of LAYERZERO_PROVIDER_CONFIG or LAYERZERO_PROVIDER_CONFIG_FILE_PATH must be provided")]
    MissingLocalProviderConfig,
    #[error("EXTRA_CONTEXT_REQUEST_URL need to be provided if EXTRA_CONTEXT_REQUEST_AUTH_TOKEN is provided")]
    ExtraContextAuthWithoutUrl,
    #[error("Cannot provide both EXTRA_CONTEXT_REQUEST_URL and EXTRA_CONTEXT_AWS_LAMBDA_NAME")]
    ConflictingExtraContext,
    #[error("{0} must be a valid absolute URL")]
    InvalidServiceUrl(&'static str),
    #[error("{0} must use HTTPS outside exact loopback development")]
    InsecureServiceUrl(&'static str),
    #[error("{0} must not contain URL userinfo")]
    ServiceUrlUserinfo(&'static str),
    #[error("missing config for required chainNames: [{0}]")]
    MissingChainNames(String),
    #[error("{0}")]
    ProviderValidation(String),
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Json(String),
    #[error("No walletDefinition found in {0}")]
    NoWalletDefinition(&'static str),
    #[error("No mnemonic definition found in {0}")]
    NoMnemonicDefinition(&'static str),
    #[error("No kms ids found in LAYERZERO_KMS_IDS")]
    NoKmsIds,
    #[error("Unknown KMS cloud type: {0}")]
    UnknownKmsCloudType(String),
    #[error("Unknown signer type: {0}")]
    UnknownSignerType(String),
    #[error("Unknown static chain name: {0}")]
    UnknownStaticChainName(String),
    #[error("Unknown LayerZero environment: {0}")]
    UnknownLayerZeroEnvironment(String),
    #[error("Invalid LayerZero {chain_name} ULN address for {environment}: {address}")]
    InvalidNonEvmUlnAddress {
        environment: String,
        chain_name: String,
        address: String,
    },
    #[error("No LayerZero endpoint id for {environment}:{chain_name}")]
    MissingLayerZeroEndpointId {
        environment: String,
        chain_name: String,
    },
    #[error("No LayerZero contract address for {environment}:{chain_name}:{contract_name}")]
    MissingLayerZeroContractAddress {
        environment: String,
        chain_name: String,
        contract_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerZeroChainCapability {
    pub environment: &'static str,
    pub uln_version: &'static str,
    pub chain_name: &'static str,
    pub status: &'static str,
    pub source_line: u32,
}

fn canonical_layerzero_environment(environment: &str) -> Result<&str, ConfigError> {
    match environment {
        "mainnet" | "testnet" | "sandbox" => Ok(environment),
        "localnet" => Ok("sandbox"),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

pub fn layerzero_chain_capabilities(
    environment: &str,
) -> Result<Vec<LayerZeroChainCapability>, ConfigError> {
    let environment = canonical_layerzero_environment(environment)?;
    Ok(
        generated_layerzero_environment::LZ_ENVIRONMENT_ULN_CHAIN_STATUS
            .iter()
            .filter_map(
                |(candidate_environment, uln_version, chain_name, status, source_line)| {
                    (*candidate_environment == environment).then_some(LayerZeroChainCapability {
                        environment: candidate_environment,
                        uln_version,
                        chain_name,
                        status,
                        source_line: *source_line,
                    })
                },
            )
            .collect(),
    )
}

pub fn layerzero_available_chain_names(environment: &str) -> Result<Vec<String>, ConfigError> {
    let mut available = Vec::new();
    for capability in layerzero_chain_capabilities(environment)? {
        if matches!(capability.uln_version, "V2" | "V302")
            && capability.status != "DEPRECATED"
            && !available
                .iter()
                .any(|chain_name| chain_name == capability.chain_name)
        {
            available.push(capability.chain_name.to_string());
        }
    }
    Ok(available)
}

pub fn layerzero_rollout_block_reason(environment: &str, chain_name: &str) -> Option<&'static str> {
    match (environment, chain_name) {
        ("mainnet" | "testnet", "stellar") => {
            Some("Stellar deployment addresses require operator and on-chain confirmation")
        }
        ("testnet", "moninet") => {
            Some("moninet-testnet deployment addresses require operator and on-chain confirmation")
        }
        // Every chain-native payload-signed observer has read a real verdict for
        // a genuinely delivered packet, using that message's own on-chain
        // arguments — but only on **mainnet**:
        //
        // * TON: `committableView` on the deployed `UlnConnection`, whose packet
        //   came from that contract's inbound `MdObj` message.
        // * Sui: `uln_302_views::verifiable` replaying the packet header of the
        //   `uln_302::verify` transaction that delivered it.
        // * IOTA: the same read on its own deployment.
        //
        // Sui and IOTA were then proven on their testnets the same way, against
        // those deployments' own packages and objects.
        //
        // TON testnet is different, and not for want of capability: it has no
        // `UlnConnection` at all. Sweeping 800 transactions across both testnet
        // `uln` contracts turns up only managers and a price-feed proxy, so no
        // pathway has ever been opened there and there is no delivered message
        // whose verdict could be read. It stays fail-closed until one exists.
        //
        // Evidence: `local/smoke/ton-live/`, `local/smoke/sui-live/`.
        ("testnet", "ton") => {
            Some("no UlnConnection exists on TON testnet, so no delivered packet can be observed")
        }
        _ => None,
    }
}

pub fn layerzero_operational_chain_names(
    environment: &str,
    requested: Option<&[String]>,
) -> Result<Vec<String>, ConfigError> {
    let canonical_environment = canonical_layerzero_environment(environment)?;
    Ok(layerzero_available_chain_names(canonical_environment)?
        .into_iter()
        .filter(|chain_name| {
            layerzero_rollout_block_reason(canonical_environment, chain_name).is_none()
                && requested.is_none_or(|requested| {
                    requested.iter().any(|candidate| candidate == chain_name)
                })
        })
        .collect())
}

pub fn load_from_env() -> Result<RuntimeConfig, ConfigError> {
    load_from_map(env::vars())
}

pub fn load_from_map<I, K, V>(vars: I) -> Result<RuntimeConfig, ConfigError>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let map = vars
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect::<HashMap<_, _>>();
    let server_port_raw = required(&map, SERVER_PORT)?;
    let server_port = server_port_raw
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidPort(server_port_raw.to_string()))?;
    let auth_raw = required(&map, PILLAR_API_AUTH_TOKENS)?;
    let api_auth_tokens = auth_raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if api_auth_tokens.is_empty() {
        return Err(ConfigError::MissingAuthTokens);
    }
    if api_auth_tokens
        .iter()
        .any(|token| token.chars().count() < 32)
    {
        return Err(ConfigError::InvalidAuthToken);
    }
    let max_connections = optional(&map, PILLAR_MAX_CONNECTIONS)
        .unwrap_or_else(|| "1024".to_string())
        .parse::<usize>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            ConfigError::InvalidMaxConnections(
                map.get(PILLAR_MAX_CONNECTIONS).cloned().unwrap_or_default(),
            )
        })?;
    let shutdown_grace_seconds = optional(&map, PILLAR_SHUTDOWN_GRACE_SECONDS)
        .unwrap_or_else(|| "25".to_string())
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            ConfigError::InvalidShutdownGraceSeconds(
                map.get(PILLAR_SHUTDOWN_GRACE_SECONDS)
                    .cloned()
                    .unwrap_or_default(),
            )
        })?;
    let provider_config_type = ProviderConfigType::parse(required(&map, LZ_PROVIDER_CONFIG_TYPE)?)?;
    let extra_context_request_url = optional(&map, EXTRA_CONTEXT_REQUEST_URL);
    let extra_context_request_auth_token = optional(&map, EXTRA_CONTEXT_REQUEST_AUTH_TOKEN);
    let extra_context_aws_lambda_name = optional(&map, EXTRA_CONTEXT_AWS_LAMBDA_NAME);
    if extra_context_request_url.is_none() && extra_context_request_auth_token.is_some() {
        return Err(ConfigError::ExtraContextAuthWithoutUrl);
    }
    if extra_context_request_url.is_some() && extra_context_aws_lambda_name.is_some() {
        return Err(ConfigError::ConflictingExtraContext);
    }
    let environment = required(&map, LZ_ENV)?.to_string();
    let requested_chain_names = optional(&map, LZ_AVAILABLE_CHAIN_NAMES)
        .map(|value| value.split(',').map(str::to_string).collect::<Vec<_>>());
    let available_chain_names =
        layerzero_operational_chain_names(&environment, requested_chain_names.as_deref())?;
    let supported_uln_versions_raw = required(&map, LZ_SUPPORTED_ULN_VERSIONS)?;
    let supported_uln_versions = serde_json::from_str::<Vec<String>>(supported_uln_versions_raw)
        .map_err(|error| ConfigError::InvalidSupportedUlnVersions(error.to_string()))?;
    if supported_uln_versions.is_empty() {
        return Err(ConfigError::NoSupportedUlnVersions);
    }

    Ok(RuntimeConfig {
        server_port,
        provider_config_type,
        environment: Some(environment),
        available_chain_names: Some(available_chain_names),
        supported_uln_versions,
        debug_mode: optional(&map, LZ_DEBUG_MODE).as_deref() == Some("true"),
        extra_context_request_url,
        extra_context_request_auth_token,
        extra_context_aws_lambda_name,
        image_version: optional(&map, PILLAR_IMAGE_VERSION),
        api_auth_tokens,
        max_connections,
        shutdown_grace_seconds,
    })
}

fn required<'a>(
    map: &'a HashMap<String, String>,
    key: &'static str,
) -> Result<&'a str, ConfigError> {
    map.get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::MissingEnv(key))
}

fn optional(map: &HashMap<String, String>, key: &'static str) -> Option<String> {
    map.get(key).filter(|value| !value.is_empty()).cloned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerSdkFactoryType {
    AwsMnemonic,
    LocalMnemonic,
    Kms,
}

impl SignerSdkFactoryType {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "MNEMONIC" => Ok(Self::AwsMnemonic),
            "LOCAL_MNEMONIC" => Ok(Self::LocalMnemonic),
            "KMS" => Ok(Self::Kms),
            other => Err(ConfigError::UnknownSignerType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignerType {
    KMS,
    Mnemonic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KmsProvider {
    AWS,
    GCP,
    AZURE,
}

impl KmsProvider {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "AWS" => Ok(Self::AWS),
            "GCP" => Ok(Self::GCP),
            "AZURE" => Ok(Self::AZURE),
            other => Err(ConfigError::UnknownKmsCloudType(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsSignerAdapterFactoryOptions {
    Aws {
        region: Option<String>,
    },
    Gcp {
        project_id: String,
        location_id: String,
        key_ring_id: String,
        key_version: String,
    },
    Azure {
        vault_url: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletSignerConfig {
    pub secret_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<SignerType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_provider: Option<KmsProvider>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletDefinition {
    pub name: String,
    pub by_chain_type: HashMap<String, WalletSignerConfig>,
    pub wallet_set_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_chain_names: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_restrictions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Mnemonic {
    pub mnemonic: String,
    pub path: String,
}

pub type WalletToMnemonicMap = HashMap<String, Mnemonic>;

pub fn wallet_definitions_from_env_map(
    vars: &HashMap<String, String>,
) -> Result<Vec<WalletDefinition>, ConfigError> {
    let raw = required(vars, LZ_WALLETS)?;
    let wallets = serde_json::from_str::<Vec<WalletDefinition>>(raw)
        .map_err(|error| ConfigError::Json(error.to_string()))?;
    if wallets.is_empty() {
        Err(ConfigError::NoWalletDefinition(LZ_WALLETS))
    } else {
        Ok(wallets)
    }
}

pub fn wallet_definitions_from_file_path_env_map(
    vars: &HashMap<String, String>,
) -> Result<Vec<WalletDefinition>, ConfigError> {
    let path = required(vars, LZ_WALLETS_FILE_PATH)?;
    let raw = fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))?;
    let wallets = serde_json::from_str::<Vec<WalletDefinition>>(&raw)
        .map_err(|error| ConfigError::Json(error.to_string()))?;
    if wallets.is_empty() {
        Err(ConfigError::NoWalletDefinition(LZ_WALLETS_FILE_PATH))
    } else {
        Ok(wallets)
    }
}

pub fn wallet_to_mnemonic_map_from_env_map(
    vars: &HashMap<String, String>,
) -> Result<WalletToMnemonicMap, ConfigError> {
    let raw = required(vars, LZ_WALLET_MNEMONIC_MAPPING)?;
    let mapping = serde_json::from_str::<WalletToMnemonicMap>(raw)
        .map_err(|error| ConfigError::Json(error.to_string()))?;
    if mapping.is_empty() {
        Err(ConfigError::NoMnemonicDefinition(
            LZ_WALLET_MNEMONIC_MAPPING,
        ))
    } else {
        Ok(mapping)
    }
}

pub fn wallet_to_mnemonic_map_from_file_path_env_map(
    vars: &HashMap<String, String>,
) -> Result<WalletToMnemonicMap, ConfigError> {
    let path = required(vars, LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH)?;
    let raw = fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))?;
    let mapping = serde_json::from_str::<WalletToMnemonicMap>(&raw)
        .map_err(|error| ConfigError::Json(error.to_string()))?;
    if mapping.is_empty() {
        Err(ConfigError::NoMnemonicDefinition(
            LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH,
        ))
    } else {
        Ok(mapping)
    }
}

pub fn build_wallets_by_chain_name(
    wallet_definitions: &[WalletDefinition],
    chain_names: &[String],
) -> HashMap<String, Vec<String>> {
    chain_names
        .iter()
        .map(|chain_name| {
            let wallets = wallet_definitions
                .iter()
                .filter(|wallet| {
                    wallet
                        .supported_chain_names
                        .as_ref()
                        .is_none_or(|supported| {
                            supported.iter().any(|supported| supported == chain_name)
                        })
                })
                .map(|wallet| wallet.name.clone())
                .collect::<Vec<_>>();
            (chain_name.clone(), wallets)
        })
        .collect()
}

pub fn kms_signer_adapter_factory_options_from_env_map(
    vars: &HashMap<String, String>,
) -> Result<KmsSignerAdapterFactoryOptions, ConfigError> {
    let kms_provider = KmsProvider::parse(required(vars, LZ_KMS_CLOUD_TYPE)?)?;
    match kms_provider {
        KmsProvider::AWS => Ok(KmsSignerAdapterFactoryOptions::Aws {
            region: optional(vars, LZ_CDK_DEPLOY_REGION),
        }),
        KmsProvider::GCP => Ok(KmsSignerAdapterFactoryOptions::Gcp {
            project_id: required(vars, GCP_PROJECT_ID)?.to_string(),
            location_id: "global".to_string(),
            key_ring_id: required(vars, GCP_KEY_RING_ID)?.to_string(),
            key_version: "1".to_string(),
        }),
        KmsProvider::AZURE => Ok(KmsSignerAdapterFactoryOptions::Azure {
            vault_url: required(vars, AZURE_KEY_VAULT_URL)?.to_string(),
        }),
    }
}

pub fn kms_wallet_definitions_from_env_map(
    vars: &HashMap<String, String>,
    chain_names: &[String],
    chain_type_by_chain_name: &HashMap<String, String>,
) -> Result<Vec<WalletDefinition>, ConfigError> {
    let key_ids = required(vars, LZ_KMS_IDS)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if key_ids.is_empty() {
        return Err(ConfigError::NoKmsIds);
    }
    let kms_provider = KmsProvider::parse(required(vars, LZ_KMS_CLOUD_TYPE)?)?;
    Ok(key_ids
        .into_iter()
        .enumerate()
        .map(|(index, key_id)| {
            let by_chain_type = chain_names
                .iter()
                .filter_map(|chain_name| chain_type_by_chain_name.get(chain_name))
                .map(|chain_type| {
                    (
                        chain_type.clone(),
                        WalletSignerConfig {
                            secret_name: key_id.clone(),
                            signer_type: Some(SignerType::KMS),
                            kms_provider: Some(kms_provider.clone()),
                            address: None,
                        },
                    )
                })
                .collect::<HashMap<_, _>>();
            WalletDefinition {
                name: format!("KmsWallet{index}"),
                by_chain_type,
                wallet_set_name: format!("KmsWalletSetName{index}"),
                supported_chain_names: None,
                wallet_restrictions: None,
            }
        })
        .collect())
}

const STATIC_CHAIN_TYPE_NAMES: &[(&str, &str)] = &[
    ("aavegotchi", "EVM"),
    ("abstract", "EVM"),
    ("adi", "EVM"),
    ("adiri", "EVM"),
    ("amoy", "EVM"),
    ("animechain", "EVM"),
    ("ape", "EVM"),
    ("apexfusionnexus", "EVM"),
    ("aptos", "APTOS"),
    ("arbitrum", "EVM"),
    ("arbsep", "EVM"),
    ("arc", "EVM"),
    ("astar", "EVM"),
    ("atlanticocean", "EVM"),
    ("ault", "EVM"),
    ("aurora", "EVM"),
    ("avalanche", "EVM"),
    ("bahamut", "EVM"),
    ("bartio", "EVM"),
    ("base", "EVM"),
    ("basesep", "EVM"),
    ("bb1", "EVM"),
    ("bepolia", "EVM"),
    ("bera", "EVM"),
    ("besu1", "EVM"),
    ("bevm", "EVM"),
    ("bitlayer", "EVM"),
    ("bl2", "EVM"),
    ("bl3", "EVM"),
    ("bl6", "EVM"),
    ("blast", "EVM"),
    ("ble", "EVM"),
    ("blockgen", "EVM"),
    ("bob", "EVM"),
    ("bokuto", "EVM"),
    ("botanix", "EVM"),
    ("bouncebit", "EVM"),
    ("bsc", "EVM"),
    ("camp", "EVM"),
    ("canto", "EVM"),
    ("cathay", "EVM"),
    ("celo", "EVM"),
    ("chiliz", "EVM"),
    ("chilizspicy", "EVM"),
    ("citrea", "EVM"),
    ("codex", "EVM"),
    ("concrete", "EVM"),
    ("conflux", "EVM"),
    ("converge", "EVM"),
    ("coredao", "EVM"),
    ("cronosevm", "EVM"),
    ("cronoszkevm", "EVM"),
    ("curtis", "EVM"),
    ("cyber", "EVM"),
    ("degen", "EVM"),
    ("dexalot", "EVM"),
    ("dfk", "EVM"),
    ("dinari", "EVM"),
    ("dm2verse", "EVM"),
    ("doma", "EVM"),
    ("dos", "EVM"),
    ("ebi", "EVM"),
    ("edu", "EVM"),
    ("eon", "EVM"),
    ("ethereal", "EVM"),
    ("ethereal2", "EVM"),
    ("ethereum", "EVM"),
    ("etherlink", "EVM"),
    ("etherlinkshadownet", "EVM"),
    ("exocore", "EVM"),
    ("fantom", "EVM"),
    ("fi", "EVM"),
    ("flare", "EVM"),
    ("flow", "EVM"),
    ("form", "EVM"),
    ("frame", "EVM"),
    ("fraxtal", "EVM"),
    ("fuse", "EVM"),
    ("gameswift", "EVM"),
    ("gate", "EVM"),
    ("gatelayer", "EVM"),
    ("gensyn", "EVM"),
    ("glue", "EVM"),
    ("gnosis", "EVM"),
    ("goat", "EVM"),
    ("goerli", "EVM"),
    ("gravity", "EVM"),
    ("gunz", "EVM"),
    ("gunzilla", "EVM"),
    ("harmony", "EVM"),
    ("hedera", "EVM"),
    ("hemi", "EVM"),
    ("holesky", "EVM"),
    ("homeverse", "EVM"),
    ("hoodi", "EVM"),
    ("horizen", "EVM"),
    ("hubble", "EVM"),
    ("humanity", "EVM"),
    ("hyperliquid", "EVM"),
    ("idex", "EVM"),
    ("initia", "INITIA"),
    ("injective", "EVM"),
    ("injective1439", "EVM"),
    ("injectiveevm", "EVM"),
    ("ink", "EVM"),
    ("intain", "EVM"),
    ("iota", "EVM"),
    ("iotal1", "IOTAMOVE"),
    ("irys", "EVM"),
    ("islander", "EVM"),
    ("joc", "EVM"),
    ("jovay", "EVM"),
    ("katana", "EVM"),
    ("kava", "EVM"),
    ("kevnet", "EVM"),
    ("kite", "EVM"),
    ("kiwi", "EVM"),
    ("kiwi2", "EVM"),
    ("klaytn", "EVM"),
    ("lens", "EVM"),
    ("lif3", "EVM"),
    ("lightlink", "EVM"),
    ("lineasep", "EVM"),
    ("lisk", "EVM"),
    ("ll1", "EVM"),
    ("loot", "EVM"),
    ("lyra", "EVM"),
    ("lzjk", "EVM"),
    ("manta", "EVM"),
    ("mantasep", "EVM"),
    ("mantle", "EVM"),
    ("mantlesep", "EVM"),
    ("masa", "EVM"),
    ("megaeth", "EVM"),
    ("megaeth2", "EVM"),
    ("memecoreformicarium", "EVM"),
    ("meritcircle", "EVM"),
    ("merlin", "EVM"),
    ("meter", "EVM"),
    ("metis", "EVM"),
    ("metissep", "EVM"),
    ("minato", "EVM"),
    ("moca", "EVM"),
    ("mode", "EVM"),
    ("moderato", "EVM"),
    ("moksha", "EVM"),
    ("monad", "EVM"),
    ("monad2", "EVM"),
    ("moninet", "EVM"),
    ("moonbeam", "EVM"),
    ("moonriver", "EVM"),
    ("morph", "EVM"),
    ("movement", "APTOS"),
    ("mp1", "EVM"),
    ("neox", "EVM"),
    ("nexera", "EVM"),
    ("nibiru", "EVM"),
    ("nova", "EVM"),
    ("odyssey", "EVM"),
    ("og", "EVM"),
    ("oggalileo", "EVM"),
    ("okx", "EVM"),
    ("olive", "EVM"),
    ("ondo", "EVM"),
    ("onemoney", "EVM"),
    ("opbnb", "EVM"),
    ("opencampus", "EVM"),
    ("openledger", "EVM"),
    ("optimism", "EVM"),
    ("optsep", "EVM"),
    ("orderly", "EVM"),
    ("otherworld", "EVM"),
    ("ozean", "EVM"),
    ("peaq", "EVM"),
    ("pgn", "EVM"),
    ("pharos", "EVM"),
    ("plasma", "EVM"),
    ("plasma2", "EVM"),
    ("plasma3", "EVM"),
    ("plume", "EVM"),
    ("plume2", "EVM"),
    ("plume4", "EVM"),
    ("plumephoenix", "EVM"),
    ("polygon", "EVM"),
    ("polygoncdk", "EVM"),
    ("rarible", "EVM"),
    ("rayls", "EVM"),
    ("raylsdevnet", "EVM"),
    ("rc1", "EVM"),
    ("real", "EVM"),
    ("redbelly", "EVM"),
    ("reya", "EVM"),
    ("rise", "EVM"),
    ("ritual", "EVM"),
    ("robinhood", "EVM"),
    ("root", "EVM"),
    ("rootstock", "EVM"),
    ("sagaevm", "EVM"),
    ("sanko", "EVM"),
    ("scroll", "EVM"),
    ("sei", "EVM"),
    ("sei2", "EVM"),
    ("seismic", "EVM"),
    ("sepolia", "EVM"),
    ("shimmer", "EVM"),
    ("shrapnel", "EVM"),
    ("silicon", "EVM"),
    ("siliconsepolia", "EVM"),
    ("skale", "EVM"),
    ("solana", "SOLANA"),
    ("somnia", "EVM"),
    ("somniashannon", "EVM"),
    ("soneium", "EVM"),
    ("sonic", "EVM"),
    ("sophon", "EVM"),
    ("sophonos", "EVM"),
    ("space", "EVM"),
    ("stable", "EVM"),
    ("stabledevnet", "EVM"),
    ("starknet", "STARKNET"),
    ("stellar", "STELLAR"),
    ("story", "EVM"),
    ("subtensorevm", "EVM"),
    ("sui", "SUI"),
    ("superposition", "EVM"),
    ("swell", "EVM"),
    ("swimmer", "EVM"),
    ("tac", "EVM"),
    ("tacspb", "EVM"),
    ("taiko", "EVM"),
    ("tangible", "EVM"),
    ("telos", "EVM"),
    ("tempo", "EVM"),
    ("tempodev1", "EVM"),
    ("tenet", "EVM"),
    ("tiltyard", "EVM"),
    ("tomo", "EVM"),
    ("ton", "TON"),
    ("treasure", "EVM"),
    ("tron", "TRON"),
    ("unichain", "EVM"),
    ("unreal", "EVM"),
    ("vanar", "EVM"),
    ("venn", "EVM"),
    ("worldchain", "EVM"),
    ("worldcoin", "EVM"),
    ("xai", "EVM"),
    ("xchain", "EVM"),
    ("xdc", "EVM"),
    ("xlayer", "EVM"),
    ("xlayer2", "EVM"),
    ("xpla", "EVM"),
    ("zama", "EVM"),
    ("zircuit", "EVM"),
    ("zkastar", "EVM"),
    ("zkatana", "EVM"),
    ("zkconsensys", "EVM"),
    ("zklink", "EVM"),
    ("zkpolygon", "EVM"),
    ("zkpolygonsep", "EVM"),
    ("zksync", "EVM"),
    ("zksyncsep", "EVM"),
    ("zkverify", "EVM"),
    ("zora", "EVM"),
    ("zorasep", "EVM"),
];

pub fn static_chain_type_name(chain_name: &str) -> Result<&'static str, ConfigError> {
    STATIC_CHAIN_TYPE_NAMES
        .binary_search_by_key(&chain_name, |(name, _)| *name)
        .map(|index| STATIC_CHAIN_TYPE_NAMES[index].1)
        .map_err(|_| ConfigError::UnknownStaticChainName(chain_name.to_string()))
}

pub fn static_chain_type_by_chain_name(
    chain_names: &[String],
) -> Result<HashMap<String, String>, ConfigError> {
    chain_names
        .iter()
        .map(|chain_name| {
            Ok((
                chain_name.clone(),
                static_chain_type_name(chain_name)?.to_string(),
            ))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerZeroEvmContracts {
    /// V1 `Endpoint`. Absent where upstream's deployment configuration has no
    /// V1 endpoint for the chain.
    pub endpoint_v1: Option<String>,
    pub endpoint_v2: String,
    pub endpoint_v2_view: String,
    pub uln_v2: String,
    pub receive_uln_301: String,
    pub receive_uln_301_view: String,
    pub receive_uln_302: String,
    pub receive_uln_302_view: String,
    pub read_lib_1002: Option<String>,
    pub read_lib_1002_view: Option<String>,
    pub send_uln_301: String,
    pub send_uln_302: String,
}

fn canonical_lz_environment(environment: &str) -> Result<&str, ConfigError> {
    match environment {
        "mainnet" => Ok("mainnet"),
        "testnet" => Ok("testnet"),
        "sandbox" | "localnet" => Ok("sandbox"),
        other => Err(ConfigError::UnknownLayerZeroEnvironment(other.to_string())),
    }
}

pub fn layerzero_evm_endpoint_id(chain_name: &str, environment: &str) -> Result<u32, ConfigError> {
    layerzero_evm_endpoint_id_for_version(chain_name, environment, "V2")
}

pub fn layerzero_evm_endpoint_id_for_version(
    chain_name: &str,
    environment: &str,
    endpoint_version: &str,
) -> Result<u32, ConfigError> {
    let environment = canonical_lz_environment(environment)?;
    generated_layerzero_evm::LZ_EVM_ENDPOINT_IDS
        .iter()
        .find(|(env, chain, version, _)| {
            *env == environment && *chain == chain_name && *version == endpoint_version
        })
        .map(|(_, _, _, eid)| *eid)
        .ok_or_else(|| ConfigError::MissingLayerZeroEndpointId {
            environment: environment.to_string(),
            chain_name: chain_name.to_string(),
        })
}

pub fn layerzero_chain_name_by_evm_endpoint_id(
    environment: &str,
    chain_names: &[String],
) -> Result<HashMap<u32, String>, ConfigError> {
    let environment = canonical_lz_environment(environment)?;
    let mut out = HashMap::new();
    for chain_name in chain_names {
        for endpoint_version in ["V1", "V2"] {
            let endpoint_id =
                layerzero_evm_endpoint_id_for_version(chain_name, environment, endpoint_version)?;
            out.insert(endpoint_id, chain_name.clone());
        }
    }
    Ok(out)
}

pub fn layerzero_contract_address(
    chain_name: &str,
    environment: &str,
    contract_name: &str,
) -> Result<&'static str, ConfigError> {
    let environment = canonical_lz_environment(environment)?;
    generated_layerzero_evm::LZ_EVM_DEPLOYMENT_ADDRESSES
        .iter()
        .find(|(env, chain, contract, _)| {
            *env == environment && *chain == chain_name && *contract == contract_name
        })
        .map(|(_, _, _, address)| *address)
        .ok_or_else(|| ConfigError::MissingLayerZeroContractAddress {
            environment: environment.to_string(),
            chain_name: chain_name.to_string(),
            contract_name: contract_name.to_string(),
        })
}

pub fn ton_code_cell(contract: &str) -> Option<&'static str> {
    generated_ton_layerzero::TON_CODE_CELLS
        .iter()
        .find(|(name, _)| *name == contract)
        .map(|(_, hex)| *hex)
}

pub fn ton_deployment_address(environment: &str, contract: &str) -> Option<&'static str> {
    generated_ton_layerzero::TON_DEPLOYMENTS
        .iter()
        .find(|(env, name, _)| *env == environment && *name == contract)
        .map(|(_, _, address)| *address)
}

pub fn layerzero_evm_contracts(
    chain_name: &str,
    environment: &str,
) -> Result<LayerZeroEvmContracts, ConfigError> {
    Ok(LayerZeroEvmContracts {
        endpoint_v1: layerzero_contract_address(chain_name, environment, "Endpoint")
            .ok()
            .map(ToOwned::to_owned),
        endpoint_v2: layerzero_contract_address(chain_name, environment, "EndpointV2")?.to_string(),
        endpoint_v2_view: layerzero_contract_address(chain_name, environment, "EndpointV2View")?
            .to_string(),
        uln_v2: layerzero_contract_address(chain_name, environment, "UltraLightNodeV2")?
            .to_string(),
        receive_uln_301: layerzero_contract_address(chain_name, environment, "ReceiveUln301")?
            .to_string(),
        receive_uln_301_view: layerzero_contract_address(
            chain_name,
            environment,
            "ReceiveUln301View",
        )?
        .to_string(),
        receive_uln_302: layerzero_contract_address(chain_name, environment, "ReceiveUln302")?
            .to_string(),
        receive_uln_302_view: layerzero_contract_address(
            chain_name,
            environment,
            "ReceiveUln302View",
        )?
        .to_string(),
        read_lib_1002: layerzero_contract_address(chain_name, environment, "ReadLib1002")
            .ok()
            .map(ToOwned::to_owned),
        read_lib_1002_view: layerzero_contract_address(chain_name, environment, "ReadLib1002View")
            .ok()
            .map(ToOwned::to_owned),
        send_uln_301: layerzero_contract_address(chain_name, environment, "SendUln301")?
            .to_string(),
        send_uln_302: layerzero_contract_address(chain_name, environment, "SendUln302")?
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ProviderUri {
    Uri(String),
    UriWithHeaders {
        uri: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderConfig {
    pub uris: Vec<ProviderUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum: Option<u64>,
}

pub type ProviderConfigs = IndexMap<String, ProviderConfig>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactedUrl<'a>(pub &'a str);

impl fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&redact_url(self.0))
    }
}

pub fn redact_url(raw: &str) -> String {
    let (prefix, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => return "<redacted>".to_string(),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => format!("<redacted>@{host}"),
        None => authority.to_string(),
    };
    format!("{prefix}{authority}{}", redact_path_and_query(suffix))
}

pub fn redact_header_value(name: &str, value: &str) -> String {
    if is_secret_name(name) {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

pub fn redact_secret_value(name: &str, value: &str) -> String {
    if is_secret_name(name) {
        "<redacted>".to_string()
    } else {
        value.to_string()
    }
}

pub fn redact_kms_key_id(provider: &str, key_id: &str) -> String {
    let suffix = last_chars(key_id, 4);
    format!("{provider}:...{suffix}")
}

fn is_secret_name(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    normalized == "authorization"
        || normalized == "x-api-key"
        || normalized.contains("api-key")
        || normalized.contains("auth-token")
        || normalized.contains("token")
        || normalized.contains("mnemonic")
        || normalized.contains("private-key")
        || normalized.contains("secret")
}

fn redact_path_and_query(raw: &str) -> String {
    let (without_fragment, fragment) = match raw.split_once('#') {
        Some((before, _)) => (before, "#<redacted>"),
        None => (raw, ""),
    };
    let (path, query) = match without_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (without_fragment, None),
    };
    let redacted_path = if path.is_empty() || path == "/" {
        path.to_string()
    } else {
        "/<redacted>".to_string()
    };
    let redacted_query = query.map(|_| "?<redacted>".to_string()).unwrap_or_default();
    format!("{redacted_path}{redacted_query}{fragment}")
}

fn last_chars(value: &str, count: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let start = chars.len().saturating_sub(count);
    chars[start..].iter().collect()
}

pub trait ProviderConfigGetter {
    fn get_provider_config(&self, chain_name: &str) -> Option<&ProviderConfig>;
    fn get_provider_configs(&self) -> &ProviderConfigs;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteProviderConfigRequest {
    S3 {
        bucket: String,
        key: String,
        region: Option<String>,
    },
    GCS {
        bucket: String,
        key: String,
        project_id: String,
        region: String,
    },
}

#[async_trait]
pub trait RemoteProviderConfigLoader: Send + Sync {
    async fn load_provider_config(
        &self,
        request: RemoteProviderConfigRequest,
    ) -> Result<String, ConfigError>;
}

pub fn provider_config_from_env_map(
    vars: &HashMap<String, String>,
    provider_config_type: &ProviderConfigType,
    required_chain_names: Option<&[String]>,
) -> Result<StaticProviderConfig, ConfigError> {
    match provider_config_type {
        ProviderConfigType::LOCAL => {
            if let Some(file_path) = optional(vars, LZ_PROVIDER_CONFIG_FILE_PATH) {
                let raw = fs::read_to_string(file_path)
                    .map_err(|error| ConfigError::Io(error.to_string()))?;
                let provider_config = serde_json::from_str::<ProviderConfigs>(&raw)
                    .map_err(|error| ConfigError::Json(error.to_string()))?;
                StaticProviderConfig::new(provider_config, required_chain_names)
            } else if let Some(raw) = optional(vars, LZ_PROVIDER_CONFIG) {
                let provider_config = serde_json::from_str::<ProviderConfigs>(&raw)
                    .map_err(|error| ConfigError::Json(error.to_string()))?;
                StaticProviderConfig::new(provider_config, required_chain_names)
            } else {
                Err(ConfigError::MissingLocalProviderConfig)
            }
        }
        ProviderConfigType::S3 => Err(ConfigError::UnsupportedProviderConfigType("S3".to_string())),
        ProviderConfigType::GCS => Err(ConfigError::UnsupportedProviderConfigType(
            "GCS".to_string(),
        )),
    }
}

pub async fn provider_config_from_env_map_async(
    vars: &HashMap<String, String>,
    provider_config_type: &ProviderConfigType,
    required_chain_names: Option<&[String]>,
    remote_loader: &impl RemoteProviderConfigLoader,
) -> Result<StaticProviderConfig, ConfigError> {
    match provider_config_type {
        ProviderConfigType::LOCAL => {
            provider_config_from_env_map(vars, provider_config_type, required_chain_names)
        }
        ProviderConfigType::S3 => {
            let raw = remote_loader
                .load_provider_config(RemoteProviderConfigRequest::S3 {
                    bucket: required(vars, LZ_PROVIDER_BUCKET)?.to_string(),
                    key: LZ_PROVIDER_CONFIG_REMOTE_KEY.to_string(),
                    region: Some(
                        optional(vars, LZ_CDK_DEPLOY_REGION)
                            .unwrap_or_else(|| "us-east-1".to_string()),
                    ),
                })
                .await?;
            let provider_config = serde_json::from_str::<ProviderConfigs>(&raw)
                .map_err(|error| ConfigError::Json(error.to_string()))?;
            StaticProviderConfig::new(provider_config, required_chain_names)
        }
        ProviderConfigType::GCS => {
            let raw = remote_loader
                .load_provider_config(RemoteProviderConfigRequest::GCS {
                    bucket: required(vars, LZ_PROVIDER_BUCKET)?.to_string(),
                    key: LZ_PROVIDER_CONFIG_REMOTE_KEY.to_string(),
                    project_id: required(vars, GCP_PROJECT_ID)?.to_string(),
                    region: "us-east1".to_string(),
                })
                .await?;
            let provider_config = serde_json::from_str::<ProviderConfigs>(&raw)
                .map_err(|error| ConfigError::Json(error.to_string()))?;
            StaticProviderConfig::new(provider_config, required_chain_names)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticProviderConfig {
    provider_config: ProviderConfigs,
}

impl StaticProviderConfig {
    pub fn new(
        mut provider_config: ProviderConfigs,
        required_chain_names: Option<&[String]>,
    ) -> Result<Self, ConfigError> {
        check_for_missing_chain_names(&provider_config, required_chain_names)?;
        if let Some(required_chain_names) = required_chain_names {
            provider_config.retain(|chain_name, _| {
                required_chain_names
                    .iter()
                    .any(|required| required == chain_name)
            });
        }
        Ok(Self { provider_config })
    }
}

impl ProviderConfigGetter for StaticProviderConfig {
    fn get_provider_config(&self, chain_name: &str) -> Option<&ProviderConfig> {
        self.provider_config.get(chain_name)
    }

    fn get_provider_configs(&self) -> &ProviderConfigs {
        &self.provider_config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProviderConfig {
    inner: StaticProviderConfig,
}

impl FileProviderConfig {
    pub fn create(
        file_path: impl AsRef<Path>,
        required_chain_names: Option<&[String]>,
    ) -> Result<Self, ConfigError> {
        let raw =
            fs::read_to_string(file_path).map_err(|error| ConfigError::Io(error.to_string()))?;
        let provider_config = serde_json::from_str::<ProviderConfigs>(&raw)
            .map_err(|error| ConfigError::Json(error.to_string()))?;
        Ok(Self {
            inner: StaticProviderConfig::new(provider_config, required_chain_names)?,
        })
    }
}

impl ProviderConfigGetter for FileProviderConfig {
    fn get_provider_config(&self, chain_name: &str) -> Option<&ProviderConfig> {
        self.inner.get_provider_config(chain_name)
    }

    fn get_provider_configs(&self) -> &ProviderConfigs {
        self.inner.get_provider_configs()
    }
}

fn check_for_missing_chain_names(
    config: &ProviderConfigs,
    required_chain_names: Option<&[String]>,
) -> Result<(), ConfigError> {
    let missing_chain_names = required_chain_names
        .unwrap_or_default()
        .iter()
        .filter(|chain_name| !config.contains_key(*chain_name))
        .cloned()
        .collect::<Vec<_>>();
    if missing_chain_names.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::MissingChainNames(
            missing_chain_names.join(","),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;

    #[derive(Clone)]
    struct RecordingRemoteProviderConfigLoader {
        raw: String,
        calls: Arc<Mutex<Vec<RemoteProviderConfigRequest>>>,
    }

    #[async_trait]
    impl RemoteProviderConfigLoader for RecordingRemoteProviderConfigLoader {
        async fn load_provider_config(
            &self,
            request: RemoteProviderConfigRequest,
        ) -> Result<String, ConfigError> {
            self.calls.lock().unwrap().push(request);
            Ok(self.raw.clone())
        }
    }

    #[test]
    fn preserves_env_var_names() {
        assert_eq!(LZ_WALLETS, "LAYERZERO_WALLETS");
        assert_eq!(LZ_AVAILABLE_CHAIN_NAMES, "LAYERZERO_AVAILABLE_CHAIN_NAMES");
        assert_eq!(
            LZ_SUPPORTED_ULN_VERSIONS,
            "LAYERZERO_SUPPORTED_ULN_VERSIONS"
        );
        assert_eq!(LZ_PROVIDER_CONFIG_TYPE, "PROVIDER_CONFIG_TYPE");
        assert_eq!(LZ_PROVIDER_BUCKET, "CONFIG_BUCKET_NAME");
        assert_eq!(LZ_KMS_CLOUD_TYPE, "KMS_CLOUD_TYPE");
        assert_eq!(LZ_KMS_IDS, "LAYERZERO_KMS_IDS");
    }

    #[test]
    fn generated_ton_static_config_spot_check() {
        assert!(generated_ton_layerzero::TON_DEPLOYMENTS.contains(&(
            "mainnet",
            "UlnManager",
            "EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH",
        )));
        for contract in ["Uln", "UlnConnection", "Proxy"] {
            assert!(
                generated_ton_layerzero::TON_CODE_CELLS
                    .iter()
                    .any(|(name, _)| *name == contract),
                "missing TON code cell for {contract}",
            );
        }
        assert!(ton_code_cell("Uln").is_some());
        assert_eq!(
            ton_deployment_address("mainnet", "UlnManager"),
            Some("EQAGtSsRq69lvx_0fFfokLpK1qdaaIWbvlpRwfxFGVTFTLrH"),
        );
    }

    #[test]
    fn environment_capability_uses_v2_v302_available_union() {
        let mainnet = layerzero_available_chain_names("mainnet").unwrap();
        assert!(mainnet.iter().any(|chain_name| chain_name == "movement"));
        assert!(mainnet.iter().any(|chain_name| chain_name == "iotal1"));
        assert!(!mainnet.iter().any(|chain_name| chain_name == "bb1"));
        assert_eq!(
            mainnet
                .iter()
                .filter(|chain_name| chain_name.as_str() == "ethereum")
                .count(),
            1
        );

        let sandbox = layerzero_available_chain_names("sandbox").unwrap();
        assert_eq!(
            layerzero_available_chain_names("localnet").unwrap(),
            sandbox
        );
        assert_eq!(
            layerzero_available_chain_names("unknown").unwrap_err(),
            ConfigError::UnknownLayerZeroEnvironment("unknown".to_string())
        );
    }

    #[test]
    fn operational_chain_names_exclude_unresolved_gate_zero_deployments() {
        let mainnet = layerzero_operational_chain_names(
            "mainnet",
            Some(&[
                "ethereum".to_string(),
                "stellar".to_string(),
                "sui".to_string(),
                "iotal1".to_string(),
                "ton".to_string(),
            ]),
        )
        .unwrap();
        // Sui and IOTA read a real verdict in both environments. TON only has a
        // mainnet deployment carrying traffic, so its testnet stays blocked.
        assert_eq!(mainnet, vec!["ethereum", "ton", "sui", "iotal1"]);
        for chain_name in ["ton", "sui", "iotal1"] {
            assert!(layerzero_rollout_block_reason("mainnet", chain_name).is_none());
        }
        for chain_name in ["sui", "iotal1"] {
            assert!(layerzero_rollout_block_reason("testnet", chain_name).is_none());
        }
        assert!(layerzero_rollout_block_reason("testnet", "ton").is_some());
        assert!(layerzero_rollout_block_reason("mainnet", "stellar").is_some());
        assert!(layerzero_rollout_block_reason("testnet", "stellar").is_some());

        let testnet = layerzero_operational_chain_names(
            "testnet",
            Some(&[
                "bsc".to_string(),
                "moninet".to_string(),
                "stellar".to_string(),
            ]),
        )
        .unwrap();
        assert_eq!(testnet, vec!["bsc"]);
        assert!(layerzero_rollout_block_reason("testnet", "moninet").is_some());
        assert!(layerzero_rollout_block_reason("mainnet", "stellar").is_some());
    }

    #[test]
    fn environment_capability_preserves_raw_status_and_source_line() {
        let movement = layerzero_chain_capabilities("testnet")
            .unwrap()
            .into_iter()
            .find(|capability| {
                capability.uln_version == "V302" && capability.chain_name == "movement"
            })
            .unwrap();
        assert_eq!(movement.status, "ACTIVE");
        assert_eq!(movement.source_line, 662);
    }

    #[test]
    fn static_provider_config_projects_to_required_chain_names() {
        let provider_config = StaticProviderConfig::new(
            IndexMap::from([
                (
                    "extra".to_string(),
                    ProviderConfig {
                        uris: vec![ProviderUri::Uri("https://extra.example".to_string())],
                        quorum: Some(1),
                    },
                ),
                (
                    "ethereum".to_string(),
                    ProviderConfig {
                        uris: vec![ProviderUri::Uri("https://eth.example".to_string())],
                        quorum: Some(1),
                    },
                ),
            ]),
            Some(&["ethereum".to_string()]),
        )
        .unwrap();
        assert_eq!(
            provider_config
                .get_provider_configs()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["ethereum"]
        );
    }

    #[test]
    fn parses_runtime_config_like_ts_bootstrap() {
        let cfg = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (LZ_SUPPORTED_ULN_VERSIONS, r#"["V2","V301"]"#),
            (LZ_AVAILABLE_CHAIN_NAMES, "ethereum,bsc,avalanche"),
            (LZ_DEBUG_MODE, "true"),
            (EXTRA_CONTEXT_REQUEST_URL, "https://example.test"),
            (EXTRA_CONTEXT_REQUEST_AUTH_TOKEN, "token"),
        ])
        .unwrap();
        assert_eq!(cfg.server_port, 3000);
        assert_eq!(cfg.provider_config_type, ProviderConfigType::LOCAL);
        assert_eq!(cfg.environment.as_deref(), Some("mainnet"));
        assert_eq!(cfg.supported_uln_versions, vec!["V2", "V301"]);
        assert_eq!(
            cfg.available_chain_names.unwrap(),
            vec!["avalanche", "bsc", "ethereum"]
        );
        assert!(cfg.debug_mode);
    }

    #[test]
    fn runtime_config_rejects_invalid_extra_context_combinations() {
        let auth_without_url = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (LZ_SUPPORTED_ULN_VERSIONS, r#"["V2","V301"]"#),
            (EXTRA_CONTEXT_REQUEST_AUTH_TOKEN, "token"),
        ])
        .unwrap_err();
        assert_eq!(auth_without_url, ConfigError::ExtraContextAuthWithoutUrl);

        let http_and_lambda = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (LZ_SUPPORTED_ULN_VERSIONS, r#"["V2","V301"]"#),
            (EXTRA_CONTEXT_REQUEST_URL, "https://example.test"),
            (EXTRA_CONTEXT_AWS_LAMBDA_NAME, "extra-context"),
        ])
        .unwrap_err();
        assert_eq!(http_and_lambda, ConfigError::ConflictingExtraContext);
    }
    #[test]
    fn runtime_config_requires_supported_uln_versions() {
        let error = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
        ])
        .unwrap_err();
        assert_eq!(
            error,
            ConfigError::MissingEnv("LAYERZERO_SUPPORTED_ULN_VERSIONS")
        );
    }

    #[test]
    fn runtime_config_rejects_empty_supported_uln_versions() {
        let error = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            ("LAYERZERO_SUPPORTED_ULN_VERSIONS", "[]"),
        ])
        .unwrap_err();
        assert_eq!(error.to_string(), "No ULN versions provided");
    }

    #[test]
    fn runtime_config_parity_requires_lz_env() {
        let error = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
        ])
        .unwrap_err();
        assert_eq!(error, ConfigError::MissingEnv(LZ_ENV));
    }

    #[test]
    fn runtime_config_parity_uses_image_version_and_split_only_chain_csv() {
        let config = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (LZ_SUPPORTED_ULN_VERSIONS, r#"["V2","V301"]"#),
            ("PILLAR_IMAGE_VERSION", "pillar-test-version"),
            (LZ_AVAILABLE_CHAIN_NAMES, " ethereum ,,bsc "),
        ])
        .unwrap();

        assert_eq!(config.image_version.as_deref(), Some("pillar-test-version"));
        assert!(config.available_chain_names.unwrap().is_empty());
    }

    #[test]
    fn runtime_config_filters_available_chain_csv_against_environment_union() {
        let config = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (LZ_SUPPORTED_ULN_VERSIONS, r#"["V2","V301"]"#),
            (LZ_AVAILABLE_CHAIN_NAMES, " ethereum ,,bsc "),
        ])
        .unwrap();

        assert!(config.available_chain_names.unwrap().is_empty());
    }

    #[tokio::test]
    async fn runtime_config_parity_supports_local_s3_and_gcs_sources() {
        let local = provider_config_from_env_map(
            &HashMap::from([(
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#.to_string(),
            )]),
            &ProviderConfigType::LOCAL,
            Some(&["ethereum".to_string()]),
        )
        .unwrap();
        assert_eq!(
            local.get_provider_config("ethereum").unwrap().quorum,
            Some(1)
        );

        let file = NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#,
        )
        .unwrap();
        let local_file = provider_config_from_env_map(
            &HashMap::from([(
                LZ_PROVIDER_CONFIG_FILE_PATH.to_string(),
                file.path().to_string_lossy().to_string(),
            )]),
            &ProviderConfigType::LOCAL,
            Some(&["bsc".to_string()]),
        )
        .unwrap();
        assert_eq!(
            local_file.get_provider_config("bsc").unwrap().quorum,
            Some(1)
        );

        for (provider_config_type, vars, expected_request) in [
            (
                ProviderConfigType::S3,
                HashMap::from([(
                    LZ_PROVIDER_BUCKET.to_string(),
                    "provider-bucket".to_string(),
                )]),
                RemoteProviderConfigRequest::S3 {
                    bucket: "provider-bucket".to_string(),
                    key: "providers.json".to_string(),
                    region: Some("us-east-1".to_string()),
                },
            ),
            (
                ProviderConfigType::GCS,
                HashMap::from([
                    (
                        LZ_PROVIDER_BUCKET.to_string(),
                        "provider-bucket".to_string(),
                    ),
                    (GCP_PROJECT_ID.to_string(), "gcp-project".to_string()),
                ]),
                RemoteProviderConfigRequest::GCS {
                    bucket: "provider-bucket".to_string(),
                    key: "providers.json".to_string(),
                    project_id: "gcp-project".to_string(),
                    region: "us-east1".to_string(),
                },
            ),
        ] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let loader = RecordingRemoteProviderConfigLoader {
                raw: r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#.to_string(),
                calls: calls.clone(),
            };
            let remote = provider_config_from_env_map_async(
                &vars,
                &provider_config_type,
                Some(&["ethereum".to_string()]),
                &loader,
            )
            .await
            .unwrap();
            assert_eq!(
                remote.get_provider_config("ethereum").unwrap().quorum,
                Some(1)
            );
            assert_eq!(calls.lock().unwrap().as_slice(), &[expected_request]);
        }
    }

    fn provider_configs() -> ProviderConfigs {
        ProviderConfigs::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://rpc.example".to_string()),
                    ProviderUri::UriWithHeaders {
                        uri: "https://rpc-with-headers.example".to_string(),
                        headers: HashMap::from([(
                            "authorization".to_string(),
                            "token".to_string(),
                        )]),
                    },
                ],
                quorum: Some(1),
            },
        )])
    }

    #[test]
    fn redaction_preserves_url_origin_and_masks_secret_material() {
        let raw = "https://user:pass@eth-mainnet.g.alchemy.com/v2/redaction-test-key-0123456789abcdef?apiKey=redaction-test-key-0123456789abcdef&debug=true";
        let redacted = redact_url(raw);

        assert!(redacted.starts_with("https://<redacted>@eth-mainnet.g.alchemy.com/"));
        assert!(redacted.contains("/<redacted>"));
        assert!(redacted.contains("?<redacted>"));
        assert!(!redacted.contains("redaction-test-key-0123456789abcdef"));
        assert!(!redacted.contains("user:pass"));
    }

    #[test]
    fn redaction_masks_headers_mnemonics_private_keys_and_kms_ids() {
        assert_eq!(
            redact_header_value("Authorization", "Bearer raw-token"),
            "<redacted>"
        );
        assert_eq!(redact_header_value("X-API-Key", "raw-key"), "<redacted>");
        assert_eq!(
            redact_secret_value(
                "mnemonic",
                "test test test test test test test test test test test junk"
            ),
            "<redacted>"
        );
        assert_eq!(
            redact_secret_value("PRIVATE_KEY", "0xabc123abc123abc123"),
            "<redacted>"
        );
        assert_eq!(
            redact_kms_key_id(
                "AWS",
                "arn:aws:kms:ap-northeast-2:123456789012:key/abcdef123456"
            ),
            "AWS:...3456"
        );
    }

    #[test]
    fn redaction_handles_malformed_and_api_key_like_path_segments() {
        let malformed = "localhost/v2/redaction-test-key-0123456789abcdef";
        let redacted = format!("{}", RedactedUrl(malformed));

        assert_eq!(redacted, "<redacted>");
        assert!(!redacted.contains("redaction-test-key-0123456789abcdef"));
    }

    #[test]
    fn redaction_hides_short_and_percent_encoded_path_credentials() {
        for raw in [
            "https://rpc.example/secret",
            "https://rpc.example/%73%65%63%72%65%74",
            "https://rpc.example/public/path#short-secret",
        ] {
            let redacted = redact_url(raw);
            assert!(!redacted.contains("secret"), "{redacted}");
            assert!(!redacted.contains("%73%65"), "{redacted}");
        }
    }

    #[test]
    fn static_provider_config_rejects_missing_required_chains_like_ts() {
        let err = StaticProviderConfig::new(
            provider_configs(),
            Some(&["ethereum".to_string(), "bsc".to_string()]),
        )
        .unwrap_err();
        assert_eq!(err, ConfigError::MissingChainNames("bsc".to_string()));
        assert_eq!(
            err.to_string(),
            "missing config for required chainNames: [bsc]"
        );
    }

    #[test]
    fn static_provider_config_returns_full_config() {
        let getter =
            StaticProviderConfig::new(provider_configs(), Some(&["ethereum".to_string()])).unwrap();
        assert_eq!(
            getter.get_provider_config("ethereum").unwrap().quorum,
            Some(1)
        );
        assert!(getter.get_provider_config("bsc").is_none());
        assert_eq!(getter.get_provider_configs().len(), 1);
    }

    #[test]
    fn static_chain_type_name_matches_typescript_core_chain_families() {
        assert_eq!(STATIC_CHAIN_TYPE_NAMES.len(), 265);
        assert_eq!(static_chain_type_name("ethereum").unwrap(), "EVM");
        assert_eq!(static_chain_type_name("bsc").unwrap(), "EVM");
        assert_eq!(static_chain_type_name("aptos").unwrap(), "APTOS");
        assert_eq!(static_chain_type_name("movement").unwrap(), "APTOS");
        assert_eq!(static_chain_type_name("initia").unwrap(), "INITIA");
        assert_eq!(static_chain_type_name("iotal1").unwrap(), "IOTAMOVE");
        assert_eq!(static_chain_type_name("monad").unwrap(), "EVM");
        assert_eq!(static_chain_type_name("plasma3").unwrap(), "EVM");
        assert_eq!(static_chain_type_name("solana").unwrap(), "SOLANA");
        assert_eq!(static_chain_type_name("starknet").unwrap(), "STARKNET");
        assert_eq!(static_chain_type_name("stellar").unwrap(), "STELLAR");
        assert_eq!(static_chain_type_name("sui").unwrap(), "SUI");
        assert_eq!(static_chain_type_name("ton").unwrap(), "TON");
        assert_eq!(static_chain_type_name("tron").unwrap(), "TRON");
        assert_eq!(static_chain_type_name("zkverify").unwrap(), "EVM");
        assert_eq!(
            static_chain_type_name("unknown").unwrap_err(),
            ConfigError::UnknownStaticChainName("unknown".to_string())
        );
    }

    #[test]
    fn static_chain_type_by_chain_name_builds_runtime_mapping() {
        let mapping =
            static_chain_type_by_chain_name(&["ethereum".to_string(), "solana".to_string()])
                .unwrap();

        assert_eq!(mapping["ethereum"], "EVM");
        assert_eq!(mapping["solana"], "SOLANA");
    }

    #[test]
    fn layerzero_evm_endpoint_ids_match_common_v2_networks() {
        assert_eq!(generated_layerzero_evm::LZ_EVM_ENDPOINT_IDS.len(), 853);
        assert_eq!(
            layerzero_evm_endpoint_id("ethereum", "mainnet").unwrap(),
            30_101
        );
        assert_eq!(layerzero_evm_endpoint_id("bsc", "mainnet").unwrap(), 30_102);
        assert_eq!(
            layerzero_evm_endpoint_id("base", "mainnet").unwrap(),
            30_184
        );
        assert_eq!(
            layerzero_evm_endpoint_id("sepolia", "testnet").unwrap(),
            40_161
        );
        assert_eq!(
            layerzero_evm_endpoint_id("ethereum", "localnet").unwrap(),
            50_121
        );
        assert_eq!(
            layerzero_evm_endpoint_id_for_version("ethereum", "mainnet", "V1").unwrap(),
            101
        );
        let mapping = layerzero_chain_name_by_evm_endpoint_id(
            "mainnet",
            &["ethereum".to_string(), "bsc".to_string()],
        )
        .unwrap();
        assert_eq!(mapping[&101], "ethereum");
        assert_eq!(mapping[&30_101], "ethereum");
        assert_eq!(mapping[&102], "bsc");
        assert_eq!(mapping[&30_102], "bsc");
        assert_eq!(
            layerzero_evm_endpoint_id("unknown", "mainnet").unwrap_err(),
            ConfigError::MissingLayerZeroEndpointId {
                environment: "mainnet".to_string(),
                chain_name: "unknown".to_string()
            }
        );
    }

    #[test]
    fn layerzero_evm_contracts_match_static_deployment_config() {
        assert_eq!(
            generated_layerzero_evm::LZ_EVM_DEPLOYMENT_ADDRESSES.len(),
            3911
        );
        let ethereum = layerzero_evm_contracts("ethereum", "mainnet").unwrap();
        // The V1 endpoint, needed for pathways whose `dstEid` is a V1 endpoint
        // id. Not every chain has one, so the field is optional.
        assert_eq!(
            ethereum.endpoint_v1.as_deref(),
            Some("0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675")
        );
        assert_eq!(
            ethereum.endpoint_v2,
            "0x1a44076050125825900e736c501f859c50fE728c"
        );
        assert_eq!(
            ethereum.endpoint_v2_view,
            "0x8FAFC84cAeA1Cef8475cb5CB344658D160c9CE0b"
        );
        assert_eq!(
            ethereum.uln_v2,
            "0x4D73AdB72bC3DD368966edD0f0b2148401A178E2"
        );
        assert_eq!(
            ethereum.receive_uln_301,
            "0x245B6e8FFE9ea5Fc301e32d16F66bD4C2123eEfC"
        );
        assert_eq!(
            ethereum.receive_uln_301_view,
            "0x0330f95a5110E9F72fe0776A1291834FfEACB1e0"
        );
        assert_eq!(
            ethereum.receive_uln_302,
            "0xc02Ab410f0734EFa3F14628780e6e695156024C2"
        );
        assert_eq!(
            ethereum.receive_uln_302_view,
            "0xcc0de82D7d520d8d5897d23cf961867Bc16Fd346"
        );
        assert_eq!(
            ethereum.read_lib_1002,
            Some("0x74F55Bc2a79A27A0bF1D1A35dB5d0Fc36b9FDB9D".to_string())
        );
        assert_eq!(
            ethereum.read_lib_1002_view,
            Some("0x60adfF2ADb728f7D3029e43dEA8c212f31c2962c".to_string())
        );
        assert_eq!(
            ethereum.send_uln_302,
            "0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1"
        );

        let sandbox = layerzero_evm_contracts("bsc", "localnet").unwrap();
        assert_eq!(
            sandbox.receive_uln_302,
            "0x5C7c905B505f0Cf40Ab6600d05e677F717916F6B"
        );
        assert_eq!(
            sandbox.receive_uln_302_view,
            "0x544eAe853EA3774A8857573C6423E6Db95b79258"
        );
        assert_eq!(
            layerzero_contract_address("abstract", "mainnet", "SendUln302").unwrap(),
            "0x166CAb679EBDB0853055522D3B523621b94029a1"
        );
        assert_eq!(
            layerzero_contract_address("amoy", "testnet", "ReceiveUln302").unwrap(),
            "0x53fd4C4fBBd53F6bC58CaE6704b92dB1f360A648"
        );
    }

    #[test]
    fn file_provider_config_reads_json_from_disk() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#,
        )
        .unwrap();
        let getter =
            FileProviderConfig::create(file.path(), Some(&["ethereum".to_string()])).unwrap();
        assert_eq!(
            getter.get_provider_config("ethereum").unwrap().uris.len(),
            1
        );
    }

    #[test]
    fn local_provider_config_from_env_matches_ts_bootstrap_order() {
        let getter = provider_config_from_env_map(
            &HashMap::from([(
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#.to_string(),
            )]),
            &ProviderConfigType::LOCAL,
            Some(&["ethereum".to_string()]),
        )
        .unwrap();
        assert_eq!(
            getter.get_provider_config("ethereum").unwrap().quorum,
            Some(1)
        );

        let file = NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"{"bsc":{"uris":["https://bsc-rpc-a.example","https://bsc-rpc-b.example"],"quorum":2}}"#,
        )
        .unwrap();
        let getter = provider_config_from_env_map(
            &HashMap::from([
                (
                    LZ_PROVIDER_CONFIG.to_string(),
                    r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#.to_string(),
                ),
                (
                    LZ_PROVIDER_CONFIG_FILE_PATH.to_string(),
                    file.path().to_string_lossy().to_string(),
                ),
            ]),
            &ProviderConfigType::LOCAL,
            Some(&["bsc".to_string()]),
        )
        .unwrap();
        assert!(getter.get_provider_config("ethereum").is_none());
        assert_eq!(getter.get_provider_config("bsc").unwrap().quorum, Some(2));
    }

    #[test]
    fn local_provider_config_requires_inline_json_or_file_path() {
        let err = provider_config_from_env_map(&HashMap::new(), &ProviderConfigType::LOCAL, None)
            .unwrap_err();
        assert_eq!(err, ConfigError::MissingLocalProviderConfig);
    }

    #[test]
    fn remote_provider_config_types_are_explicitly_not_wired_yet() {
        let err = provider_config_from_env_map(&HashMap::new(), &ProviderConfigType::S3, None)
            .unwrap_err();
        assert_eq!(
            err,
            ConfigError::UnsupportedProviderConfigType("S3".to_string())
        );
    }

    #[tokio::test]
    async fn s3_provider_config_loads_providers_json_like_typescript() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let loader = RecordingRemoteProviderConfigLoader {
            raw: r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#.to_string(),
            calls: calls.clone(),
        };
        let getter = provider_config_from_env_map_async(
            &HashMap::from([
                (
                    LZ_PROVIDER_BUCKET.to_string(),
                    "provider-bucket".to_string(),
                ),
                (
                    LZ_CDK_DEPLOY_REGION.to_string(),
                    "ap-northeast-2".to_string(),
                ),
            ]),
            &ProviderConfigType::S3,
            Some(&["ethereum".to_string()]),
            &loader,
        )
        .await
        .unwrap();

        assert_eq!(
            getter.get_provider_config("ethereum").unwrap().uris,
            vec![ProviderUri::Uri("https://rpc.example".to_string())]
        );
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[RemoteProviderConfigRequest::S3 {
                bucket: "provider-bucket".to_string(),
                key: "providers.json".to_string(),
                region: Some("ap-northeast-2".to_string()),
            }]
        );
    }

    #[tokio::test]
    async fn gcs_provider_config_uses_bucket_project_and_default_key() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let loader = RecordingRemoteProviderConfigLoader {
            raw: r#"{"bsc":{"uris":["https://bsc-a.example","https://bsc-b.example"],"quorum":2}}"#
                .to_string(),
            calls: calls.clone(),
        };
        let getter = provider_config_from_env_map_async(
            &HashMap::from([
                (
                    LZ_PROVIDER_BUCKET.to_string(),
                    "provider-bucket".to_string(),
                ),
                (GCP_PROJECT_ID.to_string(), "gcp-project".to_string()),
            ]),
            &ProviderConfigType::GCS,
            Some(&["bsc".to_string()]),
            &loader,
        )
        .await
        .unwrap();

        assert_eq!(getter.get_provider_config("bsc").unwrap().quorum, Some(2));
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[RemoteProviderConfigRequest::GCS {
                bucket: "provider-bucket".to_string(),
                key: "providers.json".to_string(),
                project_id: "gcp-project".to_string(),
                region: "us-east1".to_string(),
            }]
        );
    }

    fn wallet_json() -> &'static str {
        r#"[{
            "name": "wallet-a",
            "walletSetName": "set-a",
            "supportedChainNames": ["ethereum"],
            "byChainType": {
                "EVM": {
                    "secretName": "secret-a",
                    "signerType": "Mnemonic",
                    "address": "0xaaa"
                }
            }
        },{
            "name": "wallet-b",
            "walletSetName": "set-b",
            "byChainType": {
                "EVM": {
                    "secretName": "secret-b",
                    "signerType": "KMS",
                    "kmsProvider": "AWS"
                }
            }
        }]"#
    }

    #[test]
    fn wallet_definitions_from_env_matches_ts_empty_guard() {
        let wallets = wallet_definitions_from_env_map(&HashMap::from([(
            LZ_WALLETS.to_string(),
            wallet_json().to_string(),
        )]))
        .unwrap();
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].name, "wallet-a");
        assert_eq!(
            wallets[1].by_chain_type["EVM"].kms_provider,
            Some(KmsProvider::AWS)
        );

        let err = wallet_definitions_from_env_map(&HashMap::from([(
            LZ_WALLETS.to_string(),
            "[]".to_string(),
        )]))
        .unwrap_err();
        assert_eq!(err, ConfigError::NoWalletDefinition(LZ_WALLETS));
        assert_eq!(
            err.to_string(),
            "No walletDefinition found in LAYERZERO_WALLETS"
        );
    }

    #[test]
    fn mnemonic_map_from_env_matches_ts_empty_guard() {
        let map = wallet_to_mnemonic_map_from_env_map(&HashMap::from([(
            LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            r#"{"wallet-a-EVM":{"mnemonic":"test","path":"m/44'/60'/0'/0/0"}}"#.to_string(),
        )]))
        .unwrap();
        assert_eq!(map["wallet-a-EVM"].mnemonic, "test");
        assert_eq!(map["wallet-a-EVM"].path, "m/44'/60'/0'/0/0");

        let err = wallet_to_mnemonic_map_from_env_map(&HashMap::from([(
            LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            "{}".to_string(),
        )]))
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::NoMnemonicDefinition(LZ_WALLET_MNEMONIC_MAPPING)
        );
        assert_eq!(
            err.to_string(),
            "No mnemonic definition found in LAYERZERO_WALLET_MNEMONIC_MAPPING"
        );
    }

    #[test]
    fn build_wallets_by_chain_name_filters_supported_chains_like_ts() {
        let wallets = wallet_definitions_from_env_map(&HashMap::from([(
            LZ_WALLETS.to_string(),
            wallet_json().to_string(),
        )]))
        .unwrap();
        let by_chain =
            build_wallets_by_chain_name(&wallets, &["ethereum".to_string(), "bsc".to_string()]);
        assert_eq!(by_chain["ethereum"], vec!["wallet-a", "wallet-b"]);
        assert_eq!(by_chain["bsc"], vec!["wallet-b"]);
    }

    #[test]
    fn wallet_definitions_from_file_path_env_reads_json() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), wallet_json()).unwrap();
        let wallets = wallet_definitions_from_file_path_env_map(&HashMap::from([(
            LZ_WALLETS_FILE_PATH.to_string(),
            file.path().to_string_lossy().to_string(),
        )]))
        .unwrap();
        assert_eq!(wallets.len(), 2);
    }

    #[test]
    fn signer_factory_type_parses_backward_compatible_values() {
        assert_eq!(
            SignerSdkFactoryType::parse("MNEMONIC").unwrap(),
            SignerSdkFactoryType::AwsMnemonic
        );
        assert_eq!(
            SignerSdkFactoryType::parse("LOCAL_MNEMONIC").unwrap(),
            SignerSdkFactoryType::LocalMnemonic
        );
        assert_eq!(
            SignerSdkFactoryType::parse("KMS").unwrap(),
            SignerSdkFactoryType::Kms
        );
        assert_eq!(
            SignerSdkFactoryType::parse("BAD").unwrap_err(),
            ConfigError::UnknownSignerType("BAD".to_string())
        );
    }

    #[test]
    fn kms_options_from_env_match_provider_branches() {
        assert_eq!(
            kms_signer_adapter_factory_options_from_env_map(&HashMap::from([
                (LZ_KMS_CLOUD_TYPE.to_string(), "AWS".to_string()),
                (
                    LZ_CDK_DEPLOY_REGION.to_string(),
                    "ap-northeast-2".to_string()
                ),
            ]))
            .unwrap(),
            KmsSignerAdapterFactoryOptions::Aws {
                region: Some("ap-northeast-2".to_string())
            }
        );
        assert_eq!(
            kms_signer_adapter_factory_options_from_env_map(&HashMap::from([
                (LZ_KMS_CLOUD_TYPE.to_string(), "GCP".to_string()),
                (GCP_PROJECT_ID.to_string(), "project".to_string()),
                (GCP_KEY_RING_ID.to_string(), "ring".to_string()),
            ]))
            .unwrap(),
            KmsSignerAdapterFactoryOptions::Gcp {
                project_id: "project".to_string(),
                location_id: "global".to_string(),
                key_ring_id: "ring".to_string(),
                key_version: "1".to_string(),
            }
        );
        assert_eq!(
            kms_signer_adapter_factory_options_from_env_map(&HashMap::from([
                (LZ_KMS_CLOUD_TYPE.to_string(), "AZURE".to_string()),
                (AZURE_KEY_VAULT_URL.to_string(), "https://vault".to_string()),
            ]))
            .unwrap(),
            KmsSignerAdapterFactoryOptions::Azure {
                vault_url: "https://vault".to_string()
            }
        );
        assert_eq!(
            kms_signer_adapter_factory_options_from_env_map(&HashMap::from([(
                LZ_KMS_CLOUD_TYPE.to_string(),
                "UNKNOWN".to_string()
            )]))
            .unwrap_err(),
            ConfigError::UnknownKmsCloudType("UNKNOWN".to_string())
        );

        assert_eq!(
            kms_signer_adapter_factory_options_from_env_map(&HashMap::from([
                (LZ_KMS_CLOUD_TYPE.to_string(), "AZURE".to_string()),
                (
                    AZURE_KEY_VAULT_URL.to_string(),
                    "http://vault.example".to_string(),
                ),
            ]))
            .unwrap(),
            KmsSignerAdapterFactoryOptions::Azure {
                vault_url: "http://vault.example".to_string()
            }
        );
    }

    #[test]
    fn kms_wallet_definitions_match_ts_generated_names_and_chain_types() {
        let wallets = kms_wallet_definitions_from_env_map(
            &HashMap::from([
                (LZ_KMS_IDS.to_string(), "key-a,key-b".to_string()),
                (LZ_KMS_CLOUD_TYPE.to_string(), "AWS".to_string()),
            ]),
            &["ethereum".to_string(), "solana".to_string()],
            &HashMap::from([
                ("ethereum".to_string(), "EVM".to_string()),
                ("solana".to_string(), "SOLANA".to_string()),
            ]),
        )
        .unwrap();
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].name, "KmsWallet0");
        assert_eq!(wallets[0].wallet_set_name, "KmsWalletSetName0");
        assert_eq!(wallets[1].name, "KmsWallet1");
        assert_eq!(wallets[0].by_chain_type["EVM"].secret_name, "key-a");
        assert_eq!(
            wallets[0].by_chain_type["SOLANA"].signer_type,
            Some(SignerType::KMS)
        );
        assert_eq!(
            wallets[0].by_chain_type["SOLANA"].kms_provider,
            Some(KmsProvider::AWS)
        );
    }

    #[test]
    fn kms_wallet_definitions_reject_empty_kms_ids() {
        let err = kms_wallet_definitions_from_env_map(
            &HashMap::from([
                (LZ_KMS_IDS.to_string(), " , ".to_string()),
                (LZ_KMS_CLOUD_TYPE.to_string(), "AWS".to_string()),
            ]),
            &["ethereum".to_string()],
            &HashMap::from([("ethereum".to_string(), "EVM".to_string())]),
        )
        .unwrap_err();
        assert_eq!(err, ConfigError::NoKmsIds);
        assert_eq!(err.to_string(), "No kms ids found in LAYERZERO_KMS_IDS");
    }
}

#[cfg(test)]
mod auth_config_tests {
    use super::*;

    fn base(extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut vars = HashMap::from([
            (SERVER_PORT.to_string(), "3000".to_string()),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                r#"["V2","V301"]"#.to_string(),
            ),
            (
                PILLAR_API_AUTH_TOKENS.to_string(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            ),
        ]);
        vars.extend(
            extra
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string())),
        );
        vars
    }

    #[test]
    fn auth_tokens_are_required_and_minimum_length() {
        assert_eq!(
            load_from_map(base(&[(PILLAR_API_AUTH_TOKENS, "")])).unwrap_err(),
            ConfigError::MissingEnv(PILLAR_API_AUTH_TOKENS)
        );
        assert_eq!(
            load_from_map(base(&[(PILLAR_API_AUTH_TOKENS, "short")])).unwrap_err(),
            ConfigError::InvalidAuthToken
        );
    }

    #[test]
    fn auth_tokens_trim_empty_entries_and_accept_multiple() {
        let config = load_from_map(base(&[(
            PILLAR_API_AUTH_TOKENS,
            " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, , bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ",
        )]))
        .unwrap();
        assert_eq!(
            config.api_auth_tokens,
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()
            ]
        );
    }

    #[test]
    fn connection_and_shutdown_values_validate_and_default() {
        let defaults = load_from_map(base(&[])).unwrap();
        assert_eq!(defaults.max_connections, 1024);
        assert_eq!(defaults.shutdown_grace_seconds, 25);
        assert!(matches!(
            load_from_map(base(&[(PILLAR_MAX_CONNECTIONS, "0")])),
            Err(ConfigError::InvalidMaxConnections(_))
        ));
        assert!(matches!(
            load_from_map(base(&[(PILLAR_SHUTDOWN_GRACE_SECONDS, "bad")])),
            Err(ConfigError::InvalidShutdownGraceSeconds(_))
        ));
    }
}
