use async_trait::async_trait;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs};
use url::{Host, Url};
use zeroize::Zeroizing;

mod execution;
mod generated_chain_metadata;
mod generated_layerzero_environment;
mod generated_layerzero_evm;
mod generated_layerzero_legacy_chain_ids;
mod generated_ton_layerzero;
pub mod provider_validation;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub use execution::{AuditConfig, ExecutionLimits};

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
pub const LZ_PROVIDER_CONFIG_TYPE: &str = "PROVIDER_CONFIG_TYPE";
pub const LZ_PROVIDER_CONFIG: &str = "LAYERZERO_PROVIDER_CONFIG";
pub const LZ_PROVIDER_CONFIG_FILE_PATH: &str = "LAYERZERO_PROVIDER_CONFIG_FILE_PATH";
pub const LZ_QUORUM_STRATEGY_CONFIG: &str = "LAYERZERO_QUORUM_STRATEGY_CONFIG";
pub const LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH: &str = "LAYERZERO_QUORUM_STRATEGY_CONFIG_FILE_PATH";
pub const LZ_PROVIDER_BUCKET: &str = "CONFIG_BUCKET_NAME";
pub const LZ_PROVIDER_CONFIG_REMOTE_KEY: &str = "providers-v2.json";
pub const LZ_QUORUM_STRATEGY_REMOTE_KEY: &str = "quorum-strategy.json";
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
/// Serve the two signing routes without a bearer token.
///
/// LayerZero calls a registered DVN endpoint with no credential of ours, so a
/// deployment that is meant to receive that traffic cannot require one. This is
/// opt-in and narrow: it drops the requirement from `POST /` and
/// `POST /v2/resolve-and-sign` only. `/signer-info`, `/provider-health/report`
/// and `/metrics` keep it, and `PILLAR_API_AUTH_TOKENS` stays required, so an
/// operator cannot reach this state by forgetting to configure tokens.
pub const PILLAR_PUBLIC_SIGN_ROUTES: &str = "PILLAR_PUBLIC_SIGN_ROUTES";
/// Serve every route without a bearer token.
///
/// Only the exact string `false` disables authentication, and the default is
/// enabled, so a missing or misspelled value keeps the tokens required. Use it
/// where the endpoint is already restricted at the network edge — the mainnet
/// deployment gates callers with an ingress source-IP allowlist, so a second
/// shared secret buys nothing there. Deployments without that edge restriction
/// must leave this unset: it opens `/signer-info`, `/provider-health/report`
/// and `/metrics` too, which `PILLAR_PUBLIC_SIGN_ROUTES` deliberately does not.
///
/// `PILLAR_API_AUTH_TOKENS` becomes optional in this mode and is ignored.
pub const PILLAR_API_AUTH_ENABLED: &str = "PILLAR_API_AUTH_ENABLED";
pub const PILLAR_MAX_CONNECTIONS: &str = "PILLAR_MAX_CONNECTIONS";
pub const PILLAR_SHUTDOWN_GRACE_SECONDS: &str = "PILLAR_SHUTDOWN_GRACE_SECONDS";
pub const PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS: &str = "PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS";

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
    ("LZ_PROVIDER_CONFIG_TYPE", LZ_PROVIDER_CONFIG_TYPE),
    ("LZ_PROVIDER_CONFIG", LZ_PROVIDER_CONFIG),
    ("LZ_PROVIDER_CONFIG_FILE_PATH", LZ_PROVIDER_CONFIG_FILE_PATH),
    ("LZ_QUORUM_STRATEGY_CONFIG", LZ_QUORUM_STRATEGY_CONFIG),
    (
        "LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH",
        LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH,
    ),
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
    ("PILLAR_PUBLIC_SIGN_ROUTES", PILLAR_PUBLIC_SIGN_ROUTES),
    ("PILLAR_API_AUTH_ENABLED", PILLAR_API_AUTH_ENABLED),
    ("PILLAR_MAX_CONNECTIONS", PILLAR_MAX_CONNECTIONS),
    (
        "PILLAR_SHUTDOWN_GRACE_SECONDS",
        PILLAR_SHUTDOWN_GRACE_SECONDS,
    ),
    (
        "PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS",
        PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS,
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

/// `Debug` by hand, for the same reason as [`Mnemonic`]: this type carries two
/// bearer credentials - `EXTRA_CONTEXT_REQUEST_AUTH_TOKEN`, which authenticates
/// this service to the operator's policy endpoint, and `PILLAR_API_AUTH_TOKENS`,
/// which authenticates callers to it. The derived `Debug` printed both, so one
/// `{:?}` on a startup error path would have written them to the log. Presence
/// and count are kept, because "is a token configured" is the question an
/// operator actually debugs.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub server_port: u16,
    pub provider_config_type: ProviderConfigType,
    pub environment: Option<String>,
    pub available_chain_names: Option<Vec<String>>,
    pub debug_mode: bool,
    pub extra_context_request_url: Option<String>,
    pub extra_context_request_auth_token: Option<String>,
    pub extra_context_aws_lambda_name: Option<String>,
    pub image_version: Option<String>,
    pub api_auth_tokens: Vec<String>,
    pub api_auth_enabled: bool,
    pub public_sign_routes: bool,
    pub max_connections: usize,
    pub shutdown_grace_seconds: u64,
    pub shutdown_withdrawal: std::time::Duration,
    pub execution_limits: ExecutionLimits,
    pub audit: Option<AuditConfig>,
}

/// Rendered in place of a secret. Shared so a reader can grep one spelling.
pub(crate) const REDACTED: &str = "<redacted>";

fn redacted_option(value: Option<&String>) -> &'static str {
    if value.is_some() {
        REDACTED
    } else {
        "None"
    }
}

impl std::fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeConfig")
            .field("server_port", &self.server_port)
            .field("provider_config_type", &self.provider_config_type)
            .field("environment", &self.environment)
            .field("available_chain_names", &self.available_chain_names)
            .field("debug_mode", &self.debug_mode)
            .field("extra_context_request_url", &self.extra_context_request_url)
            .field(
                "extra_context_request_auth_token",
                &redacted_option(self.extra_context_request_auth_token.as_ref()),
            )
            .field(
                "extra_context_aws_lambda_name",
                &self.extra_context_aws_lambda_name,
            )
            .field("image_version", &self.image_version)
            .field(
                "api_auth_tokens",
                &format_args!("{REDACTED} x{}", self.api_auth_tokens.len()),
            )
            .field("api_auth_enabled", &self.api_auth_enabled)
            .field("public_sign_routes", &self.public_sign_routes)
            .field("max_connections", &self.max_connections)
            .field("shutdown_grace_seconds", &self.shutdown_grace_seconds)
            .field("shutdown_withdrawal", &self.shutdown_withdrawal)
            .field("execution_limits", &self.execution_limits)
            .field("audit_enabled", &self.audit.is_some())
            .finish()
    }
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
    #[error("Invalid PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS: {0}")]
    InvalidShutdownWithdrawalSeconds(String),
    #[error("{0}")]
    Execution(String),
    #[error("Unknown provider config type: {0}")]
    InvalidProviderConfigType(String),
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
    #[error("{0} must use HTTPS; plain HTTP is accepted only for a literal loopback address outside mainnet")]
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
    /// The destination's pinned deployment was confirmed on chain to be a
    /// superseded generation. The ULN address is hashed into the attestation,
    /// so signing anyway would emit a signature aimed at a contract no live
    /// verifier reads - a silently useless attestation rather than a loud
    /// failure. Refuse instead, and name both generations so the operator can
    /// re-pin from a source they trust.
    #[error(
        "LayerZero {chain_name} deployment for {environment} is unconfirmed: this build pins \
         {pinned}, but LayerZero's metadata service publishes {published}. Confirmed on chain \
         {confirmed_on}: separate generations by the same deployer, with disjoint code. The \
         address is signed over, so {chain_name} destinations are refused until the pinned \
         table is re-derived from a confirmed deployment."
    )]
    UnconfirmedDeploymentGeneration {
        environment: String,
        chain_name: String,
        pinned: String,
        published: String,
        confirmed_on: String,
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
        ("testnet", "moninet") => {
            Some("moninet-testnet deployment addresses require operator and on-chain confirmation")
        }
        // Every chain-native payload-signed observer has read a real verdict for
        // a genuinely delivered packet, using that message's own on-chain
        // arguments, first on **mainnet**:
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
        // TON testnet now has the same kind of evidence: an Arbitrum Sepolia ->
        // TON testnet packet (nonce 11) delivered to the deployed `UlnConnection`
        // `0:6E3B…14EC`, whose `committableView` answered `VERIFIED`. The tests
        // `derives_the_testnet_uln_connection_from_the_configured_uln_manager`,
        // `rebuilds_the_testnet_delivered_packet_cell` and
        // `runtime_rpc_validation_checks_send_the_testnet_packet_and_reject_its_verified_state`
        // replay it offline. The gate stays until the owner decides the rollout.
        ("testnet", "ton") => Some(
            "TON testnet payload-signed checks are proven by offline fixtures only; rollout awaits an operator decision",
        ),
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
    // Only the exact string turns authentication off, so a typo leaves the
    // tokens required rather than silently opening every route.
    let api_auth_enabled = optional(&map, PILLAR_API_AUTH_ENABLED).as_deref() != Some("false");
    let api_auth_tokens = if api_auth_enabled {
        let auth_raw = required(&map, PILLAR_API_AUTH_TOKENS)?;
        let tokens = auth_raw
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            return Err(ConfigError::MissingAuthTokens);
        }
        if tokens.iter().any(|token| token.chars().count() < 32) {
            return Err(ConfigError::InvalidAuthToken);
        }
        tokens
    } else {
        // Nothing consults the tokens in this mode; keeping a copy would only
        // hand the process a secret it cannot use.
        Vec::new()
    };
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
    let shutdown_grace = std::time::Duration::from_secs(shutdown_grace_seconds);
    let shutdown_withdrawal = match optional(&map, PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS) {
        None => std::time::Duration::from_secs(5).min(shutdown_grace / 5),
        Some(value) => value
            .parse::<u64>()
            .ok()
            .map(std::time::Duration::from_secs)
            .filter(|withdrawal| *withdrawal < shutdown_grace)
            .ok_or(ConfigError::InvalidShutdownWithdrawalSeconds(value))?,
    };
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
    if let Some(url) = extra_context_request_url.as_deref() {
        validate_service_url(EXTRA_CONTEXT_REQUEST_URL, url, &environment)?;
    }
    let requested_chain_names = optional(&map, LZ_AVAILABLE_CHAIN_NAMES)
        .map(|value| value.split(',').map(str::to_string).collect::<Vec<_>>());
    let available_chain_names =
        layerzero_operational_chain_names(&environment, requested_chain_names.as_deref())?;
    Ok(RuntimeConfig {
        server_port,
        provider_config_type,
        environment: Some(environment),
        available_chain_names: Some(available_chain_names),
        debug_mode: optional(&map, LZ_DEBUG_MODE).as_deref() == Some("true"),
        extra_context_request_url,
        extra_context_request_auth_token,
        extra_context_aws_lambda_name,
        image_version: optional(&map, PILLAR_IMAGE_VERSION),
        api_auth_tokens,
        api_auth_enabled,
        public_sign_routes: optional(&map, PILLAR_PUBLIC_SIGN_ROUTES).as_deref() == Some("true"),
        max_connections,
        shutdown_grace_seconds,
        shutdown_withdrawal,
        execution_limits: ExecutionLimits::from_map(&map).map_err(ConfigError::Execution)?,
        audit: AuditConfig::from_map(&map).map_err(ConfigError::Execution)?,
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

/// Refuse an outbound service URL that would ship a bearer token in cleartext.
///
/// `EXTRA_CONTEXT_REQUEST_URL` receives the sent-event payload this service is
/// about to attest to, plus `EXTRA_CONTEXT_REQUEST_AUTH_TOKEN` as a bearer
/// header. `InvalidServiceUrl`, `InsecureServiceUrl` and `ServiceUrlUserinfo`
/// were declared with `ConfigError` and never constructed, so a plain `http://`
/// value used to be accepted and sent both in the clear.
///
/// Loopback is admitted by literal address only, and only outside `mainnet`.
/// `localhost` is rejected on purpose: it resolves through the host's name
/// service, so it is not the literal loopback the error text promises. A
/// mainnet deployment pointing this at its own host is a misconfiguration
/// rather than a development convenience, so it is refused too.
fn validate_service_url(
    name: &'static str,
    raw: &str,
    environment: &str,
) -> Result<(), ConfigError> {
    let parsed = Url::parse(raw).map_err(|_| ConfigError::InvalidServiceUrl(name))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::ServiceUrlUserinfo(name));
    }
    let literal_loopback = match parsed.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if literal_loopback && environment != "mainnet" => Ok(()),
        _ => Err(ConfigError::InsecureServiceUrl(name)),
    }
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

/// `Deserialize` only, `Debug` by hand, and the phrase held in `Zeroizing`.
///
/// This used to derive both `Debug` and `Serialize` over a plaintext BIP-39
/// phrase, so a single `{:?}` or `tracing::debug!(?wallet)` added anywhere -
/// including inside an error context - would have printed the signing key's
/// seed phrase into the operational log. Nothing serialized it; the JSON in
/// `LZ_WALLET_MNEMONIC_MAPPING` only ever needs to be read.
///
/// `Zeroizing` wipes this copy on drop, so the phrase stops being resident for
/// the process lifetime. It is a partial mitigation and worth stating as one:
/// `serde_json` allocates its own intermediate while parsing, and the process
/// environment block that carried the JSON is outside this type's control.
/// Note also that `Zeroizing`'s own `Debug` is derived and prints the inner
/// value, so the hand-written `Debug` below is still what redacts.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Mnemonic {
    pub mnemonic: Zeroizing<String>,
    pub path: String,
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mnemonic")
            .field("mnemonic", &REDACTED)
            .field("path", &self.path)
            .finish()
    }
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
    ("alpen", "EVM"),
    ("amoy", "EVM"),
    ("animechain", "EVM"),
    ("anubis", "EVM"),
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
    ("canton", "CANTON"),
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
    ("hashkey", "EVM"),
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
    ("memecore", "EVM"),
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
    ("opn", "EVM"),
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

/// lz-definitions' `getNetworkForChainId(id).chainName` for every id it accepts:
/// a ULN v1 chain id (endpoint id minus 100) or any endpoint id, on any stage.
pub fn layerzero_legacy_chain_name(id: u32) -> Option<&'static str> {
    let table = generated_layerzero_legacy_chain_ids::LZ_LEGACY_CHAIN_NAME_BY_ID;
    table
        .binary_search_by_key(&id, |(candidate, _)| *candidate)
        .ok()
        .map(|index| table[index].1)
}

/// Upstream's `chainMetadataConfigGetter.getMaxEthGetLogsBlockRange(chain)` on an
/// environment; `None` where its chain metadata has no entry.
pub fn max_eth_get_logs_block_range(environment: &str, chain_name: &str) -> Option<u32> {
    generated_chain_metadata::CHAIN_MAX_ETH_GET_LOGS_BLOCK_RANGE
        .iter()
        .find(|(env, chain, _)| *env == environment && *chain == chain_name)
        .map(|(_, _, range)| *range)
}

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
        out.insert(
            layerzero_evm_endpoint_id_for_version(chain_name, environment, "V2")?,
            chain_name.clone(),
        );
        // Chains launched after ULN v1 (e.g. testnet `alpen`, lz-definitions 3.1.15) have no
        // EndpointV1 id at all.
        if let Ok(endpoint_id) =
            layerzero_evm_endpoint_id_for_version(chain_name, environment, "V1")
        {
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

/// One chain's `rpc` provider pool: each URI with the `(category, entity)` it votes as, and
/// the resolved strategy a response's voters must satisfy. Built only from a validated
/// providers-v2 / quorum-strategy pair (or the `test-support` constructor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConfig {
    pub uris: Vec<ProviderUri>,
    pub voters: Vec<provider_validation::ProviderVoter>,
    pub strategy: provider_validation::QuorumStrategy,
    /// The chain's `sequencer` entries, which only Canton reads (upstream takes the first).
    pub sequencer: Vec<ProviderUri>,
}

impl ProviderConfig {
    pub fn new(
        uris: Vec<ProviderUri>,
        voters: Vec<provider_validation::ProviderVoter>,
        strategy: provider_validation::QuorumStrategy,
    ) -> Result<Self, String> {
        let config = Self {
            uris,
            voters,
            strategy,
            sequencer: Vec::new(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_sequencer(mut self, sequencer: Vec<ProviderUri>) -> Self {
        self.sequencer = sequencer;
        self
    }

    /// The invariants every request-time quorum relies on. Rechecked at dispatch so a
    /// hand-built value cannot weaken them.
    pub fn validate(&self) -> Result<(), String> {
        if self.uris.is_empty() {
            return Err("no provider URI".to_string());
        }
        if self.voters.len() != self.uris.len() {
            return Err(format!(
                "{} voters for {} provider URIs",
                self.voters.len(),
                self.uris.len()
            ));
        }
        let resolved = self
            .strategy
            .all_of
            .iter()
            .chain(&self.strategy.one_of)
            .flat_map(|requirement| requirement.values())
            .all(|quorum| matches!(quorum, provider_validation::Quorum::Count(_)));
        if !resolved {
            return Err("strategy still contains an unresolved \"max\"".to_string());
        }
        // A strategy met by no voters at all asks for a signature without provider agreement.
        if provider_validation::is_strategy_satisfiable(
            &std::collections::BTreeMap::new(),
            &self.strategy,
        ) {
            return Err(format!(
                "strategy {} requires no provider agreement",
                provider_validation::canonical_strategy_key(&self.strategy)
            ));
        }
        if !provider_validation::is_strategy_satisfiable(
            &provider_validation::voter_entities(&self.voters),
            &self.strategy,
        ) {
            return Err(format!(
                "strategy {} is not satisfiable by the configured entities",
                provider_validation::canonical_strategy_key(&self.strategy)
            ));
        }
        Ok(())
    }

    /// Whether one entity alone can satisfy the strategy, i.e. a single trust root.
    pub fn single_entity_trust_root(&self) -> bool {
        self.voters.iter().any(|voter| {
            provider_validation::is_strategy_satisfiable(
                &provider_validation::voter_entities([voter]),
                &self.strategy,
            )
        })
    }

    /// Every URI its own entity under `{ allOf: [{ any: quorum }] }`: `quorum` agreeing
    /// URIs, the semantics test fixtures are written against.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_distinct_entities(uris: Vec<ProviderUri>, quorum: u64) -> Self {
        let voters = (0..uris.len())
            .map(|index| provider_validation::ProviderVoter {
                category: provider_validation::PROVIDER_CATEGORY_INTERNAL.to_string(),
                entity: format!("entity-{index}"),
            })
            .collect();
        let strategy = provider_validation::QuorumStrategy {
            all_of: vec![std::collections::BTreeMap::from([(
                provider_validation::PROVIDER_CATEGORY_ANY.to_string(),
                provider_validation::Quorum::Count(quorum),
            )])],
            one_of: Vec::new(),
        };
        Self {
            uris,
            voters,
            strategy,
            sequencer: Vec::new(),
        }
    }
}

pub type ProviderConfigs = IndexMap<String, ProviderConfig>;

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

/// Redact a name/value pair whose name suggests it carries a secret.
///
/// This used to exist twice, as `redact_header_value` and `redact_secret_value`
/// with byte-identical bodies and no production caller between them. The one
/// place that actually redacts headers - `redact_provider_uri` in the startup
/// report - maps over header *keys* and prints `<redacted>` for every value
/// unconditionally, which is strictly stronger than this allow-list. Keep that
/// in mind before reaching for this: it passes through any name that is not on
/// the known-secret list.
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

/// The two bucket objects one remote generation is built from. Both are fetched for every
/// load and validated together, so a generation never pairs one poll's providers with
/// another's strategy (upstream `S3ProviderConfig`, `providerConfig/index.ts:131-152`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteProviderSource {
    pub providers: RemoteProviderConfigRequest,
    pub strategy: RemoteProviderConfigRequest,
}

impl RemoteProviderSource {
    pub fn from_env_map(
        vars: &HashMap<String, String>,
        provider_config_type: &ProviderConfigType,
    ) -> Result<Option<Self>, ConfigError> {
        let request = |key: &str| -> Result<Option<RemoteProviderConfigRequest>, ConfigError> {
            Ok(match provider_config_type {
                ProviderConfigType::LOCAL => None,
                ProviderConfigType::S3 => Some(RemoteProviderConfigRequest::S3 {
                    bucket: required(vars, LZ_PROVIDER_BUCKET)?.to_string(),
                    key: key.to_string(),
                    region: Some(
                        optional(vars, LZ_CDK_DEPLOY_REGION)
                            .unwrap_or_else(|| "us-east-1".to_string()),
                    ),
                }),
                ProviderConfigType::GCS => Some(RemoteProviderConfigRequest::GCS {
                    bucket: required(vars, LZ_PROVIDER_BUCKET)?.to_string(),
                    key: key.to_string(),
                    project_id: required(vars, GCP_PROJECT_ID)?.to_string(),
                    region: "us-east1".to_string(),
                }),
            })
        };
        let (Some(providers), Some(strategy)) = (
            request(LZ_PROVIDER_CONFIG_REMOTE_KEY)?,
            request(LZ_QUORUM_STRATEGY_REMOTE_KEY)?,
        ) else {
            return Ok(None);
        };
        Ok(Some(Self {
            providers,
            strategy,
        }))
    }

    pub async fn load(
        &self,
        loader: &(impl RemoteProviderConfigLoader + ?Sized),
        required_chain_names: Option<&[String]>,
    ) -> Result<StaticProviderConfig, ConfigError> {
        let (providers, strategy) = futures::join!(
            loader.load_provider_config(self.providers.clone()),
            loader.load_provider_config(self.strategy.clone()),
        );
        StaticProviderConfig::from_v2(&providers?, &strategy?, required_chain_names)
    }
}

/// LOCAL pairs a providers file with a strategy file and inline JSON with inline JSON, as
/// upstream's bootstrap does (`boostrapConfig/index.ts:286-305`); either half missing is a
/// startup error.
pub fn provider_config_from_env_map(
    vars: &HashMap<String, String>,
    provider_config_type: &ProviderConfigType,
    required_chain_names: Option<&[String]>,
) -> Result<StaticProviderConfig, ConfigError> {
    match provider_config_type {
        ProviderConfigType::LOCAL => {
            let read = |path: &str| {
                fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))
            };
            if let Some(file_path) = optional(vars, LZ_PROVIDER_CONFIG_FILE_PATH) {
                let providers = read(&file_path)?;
                provider_validation::reject_legacy_provider_config(&providers)?;
                let strategy_path = required(vars, LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH)?;
                StaticProviderConfig::from_v2(
                    &providers,
                    &read(strategy_path)?,
                    required_chain_names,
                )
            } else if let Some(raw) = optional(vars, LZ_PROVIDER_CONFIG) {
                provider_validation::reject_legacy_provider_config(&raw)?;
                StaticProviderConfig::from_v2(
                    &raw,
                    required(vars, LZ_QUORUM_STRATEGY_CONFIG)?,
                    required_chain_names,
                )
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
    match RemoteProviderSource::from_env_map(vars, provider_config_type)? {
        Some(source) => source.load(remote_loader, required_chain_names).await,
        None => provider_config_from_env_map(vars, provider_config_type, required_chain_names),
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

    /// Validates a providers-v2 / quorum-strategy pair and restricts it to the roster.
    pub fn from_v2(
        providers_raw: &str,
        strategy_raw: &str,
        required_chain_names: Option<&[String]>,
    ) -> Result<Self, ConfigError> {
        Self::new(
            provider_validation::provider_configs_from_v2(providers_raw, strategy_raw)?,
            required_chain_names,
        )
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

    /// Answers each bucket key with its own body, as a bucket holding both objects would.
    #[derive(Clone)]
    struct RecordingRemoteProviderConfigLoader {
        providers: String,
        strategy: String,
        calls: Arc<Mutex<Vec<RemoteProviderConfigRequest>>>,
    }

    impl RecordingRemoteProviderConfigLoader {
        fn from_uris_json(
            fixture: &str,
            calls: Arc<Mutex<Vec<RemoteProviderConfigRequest>>>,
        ) -> Self {
            let (providers, strategy) = test_support::providers_v2_from_uris_json(fixture);
            Self {
                providers,
                strategy,
                calls,
            }
        }
    }

    #[async_trait]
    impl RemoteProviderConfigLoader for RecordingRemoteProviderConfigLoader {
        async fn load_provider_config(
            &self,
            request: RemoteProviderConfigRequest,
        ) -> Result<String, ConfigError> {
            let key = match &request {
                RemoteProviderConfigRequest::S3 { key, .. }
                | RemoteProviderConfigRequest::GCS { key, .. } => key.clone(),
            };
            self.calls.lock().unwrap().push(request);
            match key.as_str() {
                LZ_PROVIDER_CONFIG_REMOTE_KEY => Ok(self.providers.clone()),
                LZ_QUORUM_STRATEGY_REMOTE_KEY => Ok(self.strategy.clone()),
                other => Err(ConfigError::RemoteProviderConfig(format!(
                    "no object {other}"
                ))),
            }
        }
    }

    fn inline_v2_env(fixture: &str) -> HashMap<String, String> {
        let (providers, strategy) = test_support::providers_v2_from_uris_json(fixture);
        HashMap::from([
            (LZ_PROVIDER_CONFIG.to_string(), providers),
            (LZ_QUORUM_STRATEGY_CONFIG.to_string(), strategy),
        ])
    }

    fn sorted_requests(calls: &Arc<Mutex<Vec<RemoteProviderConfigRequest>>>) -> Vec<String> {
        let mut keys = calls
            .lock()
            .unwrap()
            .iter()
            .map(|request| format!("{request:?}"))
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    #[test]
    fn preserves_env_var_names() {
        assert_eq!(LZ_WALLETS, "LAYERZERO_WALLETS");
        assert_eq!(LZ_AVAILABLE_CHAIN_NAMES, "LAYERZERO_AVAILABLE_CHAIN_NAMES");
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
        assert!(layerzero_chain_capabilities("mainnet")
            .unwrap()
            .iter()
            .any(|capability| capability.chain_name == "canton" && capability.status == "ACTIVE"));
        assert!(mainnet.iter().any(|chain_name| chain_name == "canton"));
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
        // Sui and IOTA read a real verdict in both environments. TON testnet has
        // one too, but stays blocked until the operator decides its rollout.
        assert_eq!(mainnet, vec!["ethereum", "ton", "sui", "iotal1", "stellar"]);
        for chain_name in ["ton", "sui", "iotal1"] {
            assert!(layerzero_rollout_block_reason("mainnet", chain_name).is_none());
        }
        for chain_name in ["sui", "iotal1"] {
            assert!(layerzero_rollout_block_reason("testnet", chain_name).is_none());
        }
        assert!(layerzero_rollout_block_reason("testnet", "ton").is_some());
        assert!(layerzero_rollout_block_reason("mainnet", "stellar").is_none());
        assert!(layerzero_rollout_block_reason("testnet", "stellar").is_none());

        let testnet = layerzero_operational_chain_names(
            "testnet",
            Some(&[
                "bsc".to_string(),
                "moninet".to_string(),
                "stellar".to_string(),
            ]),
        )
        .unwrap();
        assert_eq!(testnet, vec!["bsc", "stellar"]);
        assert!(layerzero_rollout_block_reason("testnet", "moninet").is_some());
    }

    #[test]
    fn environment_capability_preserves_raw_status() {
        let movement = layerzero_chain_capabilities("testnet")
            .unwrap()
            .into_iter()
            .find(|capability| {
                capability.uln_version == "V302" && capability.chain_name == "movement"
            })
            .unwrap();
        assert_eq!(movement.status, "ACTIVE");
    }

    #[test]
    fn static_provider_config_projects_to_required_chain_names() {
        let provider_config = StaticProviderConfig::new(
            IndexMap::from([
                (
                    "extra".to_string(),
                    ProviderConfig::with_distinct_entities(
                        vec![ProviderUri::Uri("https://extra.example".to_string())],
                        1,
                    ),
                ),
                (
                    "ethereum".to_string(),
                    ProviderConfig::with_distinct_entities(
                        vec![ProviderUri::Uri("https://eth.example".to_string())],
                        1,
                    ),
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
            (LZ_AVAILABLE_CHAIN_NAMES, "ethereum,bsc,avalanche"),
            (LZ_DEBUG_MODE, "true"),
            (EXTRA_CONTEXT_REQUEST_URL, "https://example.test"),
            (EXTRA_CONTEXT_REQUEST_AUTH_TOKEN, "token"),
        ])
        .unwrap();
        assert_eq!(cfg.server_port, 3000);
        assert_eq!(cfg.provider_config_type, ProviderConfigType::LOCAL);
        assert_eq!(cfg.environment.as_deref(), Some("mainnet"));
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
            (EXTRA_CONTEXT_REQUEST_AUTH_TOKEN, "token"),
        ])
        .unwrap_err();
        assert_eq!(auth_without_url, ConfigError::ExtraContextAuthWithoutUrl);

        let http_and_lambda = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (EXTRA_CONTEXT_REQUEST_URL, "https://example.test"),
            (EXTRA_CONTEXT_AWS_LAMBDA_NAME, "extra-context"),
        ])
        .unwrap_err();
        assert_eq!(http_and_lambda, ConfigError::ConflictingExtraContext);
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
            ("PILLAR_IMAGE_VERSION", "pillar-test-version"),
            (LZ_AVAILABLE_CHAIN_NAMES, " ethereum ,,bsc "),
        ])
        .unwrap();

        assert_eq!(config.image_version.as_deref(), Some("pillar-test-version"));
        assert!(config.available_chain_names.unwrap().is_empty());
    }

    fn extra_context_env(
        url: &'static str,
        environment: &'static str,
    ) -> Vec<(&'static str, &'static str)> {
        vec![
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, environment),
            (EXTRA_CONTEXT_REQUEST_URL, url),
            (EXTRA_CONTEXT_REQUEST_AUTH_TOKEN, "extra-context-token"),
        ]
    }

    #[test]
    fn rejects_an_extra_context_url_that_would_send_the_bearer_token_in_cleartext() {
        // `localhost` resolves through the host's name service, so it is not a
        // literal loopback address; the third case is a hostname that merely
        // starts with one.
        for environment in ["mainnet", "testnet", "sandbox"] {
            for url in [
                "http://extra-context.example/verify",
                "http://localhost:3000/verify",
                "http://127.0.0.1.attacker.example/verify",
                "ftp://extra-context.example/verify",
            ] {
                assert_eq!(
                    load_from_map(extra_context_env(url, environment)).unwrap_err(),
                    ConfigError::InsecureServiceUrl(EXTRA_CONTEXT_REQUEST_URL),
                    "{url} must not be accepted on {environment}"
                );
            }
        }
    }

    #[test]
    fn rejects_loopback_http_extra_context_urls_on_mainnet() {
        for url in ["http://127.0.0.1:3000/verify", "http://[::1]:3000/verify"] {
            assert_eq!(
                load_from_map(extra_context_env(url, "mainnet")).unwrap_err(),
                ConfigError::InsecureServiceUrl(EXTRA_CONTEXT_REQUEST_URL),
                "{url} must not be accepted on mainnet"
            );
        }
    }

    #[test]
    fn rejects_an_extra_context_url_carrying_userinfo() {
        for url in [
            "https://user@extra-context.example/verify",
            "https://user:pass@extra-context.example/verify",
            "https://:pass@extra-context.example/verify",
        ] {
            assert_eq!(
                load_from_map(extra_context_env(url, "mainnet")).unwrap_err(),
                ConfigError::ServiceUrlUserinfo(EXTRA_CONTEXT_REQUEST_URL),
                "{url} must not be accepted"
            );
        }
    }

    #[test]
    fn rejects_an_extra_context_url_that_is_not_absolute() {
        for url in ["/verify", "extra-context.example/verify", "", "not a url"] {
            let error = load_from_map(extra_context_env(url, "mainnet")).unwrap_err();
            assert!(
                matches!(
                    error,
                    ConfigError::InvalidServiceUrl(EXTRA_CONTEXT_REQUEST_URL)
                        | ConfigError::ExtraContextAuthWithoutUrl
                ),
                "{url} must not be accepted, got {error:?}"
            );
        }
    }

    #[test]
    fn accepts_https_extra_context_urls_in_every_environment() {
        for environment in ["mainnet", "testnet", "sandbox"] {
            let url = "https://extra-context.example/verify";
            let config = load_from_map(extra_context_env(url, environment))
                .unwrap_or_else(|error| panic!("{url} must be accepted, got {error:?}"));
            assert_eq!(config.extra_context_request_url.as_deref(), Some(url));
        }
    }

    #[test]
    fn accepts_literal_loopback_http_extra_context_urls_outside_mainnet() {
        for environment in ["testnet", "sandbox"] {
            for url in ["http://127.0.0.1:3000/verify", "http://[::1]:3000/verify"] {
                let config =
                    load_from_map(extra_context_env(url, environment)).unwrap_or_else(|error| {
                        panic!("{url} must be accepted on {environment}, got {error:?}")
                    });
                assert_eq!(config.extra_context_request_url.as_deref(), Some(url));
            }
        }
    }

    #[test]
    fn runtime_config_filters_available_chain_csv_against_environment_union() {
        let config = load_from_map([
            (SERVER_PORT, "3000"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (LZ_PROVIDER_CONFIG_TYPE, "LOCAL"),
            (LZ_ENV, "mainnet"),
            (LZ_AVAILABLE_CHAIN_NAMES, " ethereum ,,bsc "),
        ])
        .unwrap();

        assert!(config.available_chain_names.unwrap().is_empty());
    }

    #[tokio::test]
    async fn runtime_config_parity_supports_local_s3_and_gcs_sources() {
        let local = provider_config_from_env_map(
            &inline_v2_env(r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#),
            &ProviderConfigType::LOCAL,
            Some(&["ethereum".to_string()]),
        )
        .unwrap();
        assert_eq!(local.get_provider_config("ethereum").unwrap().uris.len(), 1);

        let (providers, strategy) = test_support::providers_v2_from_uris_json(
            r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#,
        );
        let providers_file = NamedTempFile::new().unwrap();
        let strategy_file = NamedTempFile::new().unwrap();
        std::fs::write(providers_file.path(), providers).unwrap();
        std::fs::write(strategy_file.path(), strategy).unwrap();
        let local_file = provider_config_from_env_map(
            &HashMap::from([
                (
                    LZ_PROVIDER_CONFIG_FILE_PATH.to_string(),
                    providers_file.path().to_string_lossy().to_string(),
                ),
                (
                    LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH.to_string(),
                    strategy_file.path().to_string_lossy().to_string(),
                ),
            ]),
            &ProviderConfigType::LOCAL,
            Some(&["bsc".to_string()]),
        )
        .unwrap();
        assert_eq!(local_file.get_provider_config("bsc").unwrap().uris.len(), 1);

        for (provider_config_type, vars, request) in [
            (
                ProviderConfigType::S3,
                HashMap::from([(
                    LZ_PROVIDER_BUCKET.to_string(),
                    "provider-bucket".to_string(),
                )]),
                (|key: &str| RemoteProviderConfigRequest::S3 {
                    bucket: "provider-bucket".to_string(),
                    key: key.to_string(),
                    region: Some("us-east-1".to_string()),
                }) as fn(&str) -> RemoteProviderConfigRequest,
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
                |key: &str| RemoteProviderConfigRequest::GCS {
                    bucket: "provider-bucket".to_string(),
                    key: key.to_string(),
                    project_id: "gcp-project".to_string(),
                    region: "us-east1".to_string(),
                },
            ),
        ] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let loader = RecordingRemoteProviderConfigLoader::from_uris_json(
                r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#,
                calls.clone(),
            );
            let remote = provider_config_from_env_map_async(
                &vars,
                &provider_config_type,
                Some(&["ethereum".to_string()]),
                &loader,
            )
            .await
            .unwrap();
            assert_eq!(
                remote.get_provider_config("ethereum").unwrap().uris.len(),
                1
            );
            let mut expected = vec![
                format!("{:?}", request(LZ_PROVIDER_CONFIG_REMOTE_KEY)),
                format!("{:?}", request(LZ_QUORUM_STRATEGY_REMOTE_KEY)),
            ];
            expected.sort();
            assert_eq!(sorted_requests(&calls), expected);
        }
    }

    fn provider_configs() -> ProviderConfigs {
        ProviderConfigs::from([(
            "ethereum".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![
                    ProviderUri::Uri("https://rpc.example".to_string()),
                    ProviderUri::UriWithHeaders {
                        uri: "https://rpc-with-headers.example".to_string(),
                        headers: HashMap::from([(
                            "authorization".to_string(),
                            "token".to_string(),
                        )]),
                    },
                ],
                1,
            ),
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
            redact_secret_value("Authorization", "Bearer raw-token"),
            "<redacted>"
        );
        assert_eq!(redact_secret_value("X-API-Key", "raw-key"), "<redacted>");
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
        let redacted = redact_url(malformed);

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
            getter.get_provider_config("ethereum").unwrap().uris.len(),
            2
        );
        assert!(getter.get_provider_config("bsc").is_none());
        assert_eq!(getter.get_provider_configs().len(), 1);
    }

    #[test]
    fn static_chain_type_name_matches_typescript_core_chain_families() {
        assert!(
            STATIC_CHAIN_TYPE_NAMES
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0),
            "static_chain_type_name binary-searches this table"
        );
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
    fn local_provider_config_from_env_matches_ts_bootstrap_order() {
        let getter = provider_config_from_env_map(
            &inline_v2_env(r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#),
            &ProviderConfigType::LOCAL,
            Some(&["ethereum".to_string()]),
        )
        .unwrap();
        assert_eq!(
            getter.get_provider_config("ethereum").unwrap().uris.len(),
            1
        );

        let (providers, strategy) = test_support::providers_v2_from_uris_json(
            r#"{"bsc":{"uris":["https://bsc-rpc-a.example","https://bsc-rpc-b.example"],"quorum":2}}"#,
        );
        let providers_file = NamedTempFile::new().unwrap();
        let strategy_file = NamedTempFile::new().unwrap();
        std::fs::write(providers_file.path(), providers).unwrap();
        std::fs::write(strategy_file.path(), strategy).unwrap();
        let mut vars = inline_v2_env(r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#);
        vars.insert(
            LZ_PROVIDER_CONFIG_FILE_PATH.to_string(),
            providers_file.path().to_string_lossy().to_string(),
        );
        // The file path wins, and it pairs only with the strategy *file*.
        assert_eq!(
            provider_config_from_env_map(
                &vars,
                &ProviderConfigType::LOCAL,
                Some(&["bsc".to_string()])
            )
            .unwrap_err(),
            ConfigError::MissingEnv(LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH)
        );
        vars.insert(
            LZ_QUORUM_STRATEGY_CONFIG_FILE_PATH.to_string(),
            strategy_file.path().to_string_lossy().to_string(),
        );
        let getter = provider_config_from_env_map(
            &vars,
            &ProviderConfigType::LOCAL,
            Some(&["bsc".to_string()]),
        )
        .unwrap();
        assert!(getter.get_provider_config("ethereum").is_none());
        let bsc = getter.get_provider_config("bsc").unwrap();
        assert_eq!(bsc.uris.len(), 2);
        assert_eq!(
            provider_validation::canonical_strategy_key(&bsc.strategy),
            r#"{"allOf":[{"any":2}],"oneOf":[]}"#
        );
    }

    #[test]
    fn local_provider_config_requires_inline_json_or_file_path() {
        let err = provider_config_from_env_map(&HashMap::new(), &ProviderConfigType::LOCAL, None)
            .unwrap_err();
        assert_eq!(err, ConfigError::MissingLocalProviderConfig);

        let mut vars = inline_v2_env(r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#);
        vars.remove(LZ_QUORUM_STRATEGY_CONFIG);
        assert_eq!(
            provider_config_from_env_map(&vars, &ProviderConfigType::LOCAL, None).unwrap_err(),
            ConfigError::MissingEnv(LZ_QUORUM_STRATEGY_CONFIG),
            "a providers file without its strategy must not load"
        );

        // An unmigrated deployment carries only the old inline map: it is told why.
        let legacy_only = HashMap::from([(
            LZ_PROVIDER_CONFIG.to_string(),
            r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#.to_string(),
        )]);
        assert_eq!(
            provider_config_from_env_map(&legacy_only, &ProviderConfigType::LOCAL, None)
                .unwrap_err(),
            ConfigError::ProviderValidation(
                provider_validation::LEGACY_PROVIDER_CONFIG_ERROR.to_string()
            )
        );
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
    async fn s3_provider_config_loads_providers_and_strategy_like_typescript() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let loader = RecordingRemoteProviderConfigLoader::from_uris_json(
            r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#,
            calls.clone(),
        );
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
        let request = |key: &str| {
            format!(
                "{:?}",
                RemoteProviderConfigRequest::S3 {
                    bucket: "provider-bucket".to_string(),
                    key: key.to_string(),
                    region: Some("ap-northeast-2".to_string()),
                }
            )
        };
        assert_eq!(
            sorted_requests(&calls),
            vec![
                request("providers-v2.json"),
                request("quorum-strategy.json")
            ]
        );
    }

    #[tokio::test]
    async fn remote_provider_config_rejects_a_load_missing_either_object() {
        struct OneObject(&'static str, String);
        #[async_trait]
        impl RemoteProviderConfigLoader for OneObject {
            async fn load_provider_config(
                &self,
                request: RemoteProviderConfigRequest,
            ) -> Result<String, ConfigError> {
                match request {
                    RemoteProviderConfigRequest::S3 { key, .. } if key == self.0 => {
                        Ok(self.1.clone())
                    }
                    _ => Err(ConfigError::RemoteProviderConfig("NoSuchKey".to_string())),
                }
            }
        }
        let (providers, strategy) = test_support::providers_v2_from_uris_json(
            r#"{"ethereum":{"uris":["https://rpc.example"],"quorum":1}}"#,
        );
        let vars = HashMap::from([(
            LZ_PROVIDER_BUCKET.to_string(),
            "provider-bucket".to_string(),
        )]);
        for loader in [
            OneObject(LZ_PROVIDER_CONFIG_REMOTE_KEY, providers),
            OneObject(LZ_QUORUM_STRATEGY_REMOTE_KEY, strategy),
        ] {
            let error = provider_config_from_env_map_async(
                &vars,
                &ProviderConfigType::S3,
                Some(&["ethereum".to_string()]),
                &loader,
            )
            .await
            .unwrap_err();
            assert_eq!(
                error,
                ConfigError::RemoteProviderConfig("NoSuchKey".to_string())
            );
        }
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
        assert_eq!(map["wallet-a-EVM"].mnemonic.as_str(), "test");
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
    fn public_sign_routes_defaults_off_and_needs_the_exact_string() {
        // Opening a signer's write path must take a deliberate value. Anything
        // other than "true" - unset, empty, "1", "TRUE", "yes" - leaves the
        // bearer requirement in place, so a typo cannot silently expose it.
        assert!(!load_from_map(base(&[])).unwrap().public_sign_routes);
        for value in ["", "1", "TRUE", "yes", "false"] {
            assert!(
                !load_from_map(base(&[(PILLAR_PUBLIC_SIGN_ROUTES, value)]))
                    .unwrap()
                    .public_sign_routes,
                "{value:?} must not open the sign routes"
            );
        }
        assert!(
            load_from_map(base(&[(PILLAR_PUBLIC_SIGN_ROUTES, "true")]))
                .unwrap()
                .public_sign_routes
        );
    }

    #[test]
    fn api_auth_defaults_on_and_only_the_exact_string_disables_it() {
        // Same shape as the sign-route switch, and stricter in consequence:
        // this one opens identity, the health report and metrics too. Anything
        // other than "false" must leave authentication in place.
        assert!(load_from_map(base(&[])).unwrap().api_auth_enabled);
        for value in ["", "0", "FALSE", "no", "true"] {
            assert!(
                load_from_map(base(&[(PILLAR_API_AUTH_ENABLED, value)]))
                    .unwrap()
                    .api_auth_enabled,
                "{value:?} must not disable api auth"
            );
        }
        assert!(
            !load_from_map(base(&[(PILLAR_API_AUTH_ENABLED, "false")]))
                .unwrap()
                .api_auth_enabled
        );
    }

    #[test]
    fn disabling_api_auth_makes_tokens_optional_and_drops_them() {
        // A deployment that authenticates nobody should not have to carry a
        // shared secret, and must not keep one in memory if it is supplied.
        let mut without_tokens = base(&[(PILLAR_API_AUTH_ENABLED, "false")]);
        without_tokens.remove(PILLAR_API_AUTH_TOKENS);
        let config = load_from_map(without_tokens).unwrap();
        assert!(!config.api_auth_enabled);
        assert!(config.api_auth_tokens.is_empty());

        let with_tokens = load_from_map(base(&[
            (PILLAR_API_AUTH_ENABLED, "false"),
            (PILLAR_API_AUTH_TOKENS, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ]))
        .unwrap();
        assert!(with_tokens.api_auth_tokens.is_empty());

        // Removing the token while auth stays on is still a boot failure.
        let mut enabled_without_tokens = base(&[]);
        enabled_without_tokens.remove(PILLAR_API_AUTH_TOKENS);
        assert_eq!(
            load_from_map(enabled_without_tokens).unwrap_err(),
            ConfigError::MissingEnv(PILLAR_API_AUTH_TOKENS)
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

    #[test]
    fn shutdown_withdrawal_defaults_to_a_fifth_of_grace_capped_at_five_seconds() {
        use std::time::Duration;
        let withdrawal = |vars: &[(&str, &str)]| {
            load_from_map(base(vars)).map(|config| config.shutdown_withdrawal)
        };
        assert_eq!(withdrawal(&[]).unwrap(), Duration::from_secs(5));
        for (grace, expected) in [
            ("1", Duration::from_millis(200)),
            ("10", Duration::from_secs(2)),
            ("25", Duration::from_secs(5)),
            ("100", Duration::from_secs(5)),
        ] {
            assert_eq!(
                withdrawal(&[(PILLAR_SHUTDOWN_GRACE_SECONDS, grace)]).unwrap(),
                expected,
                "grace {grace}"
            );
        }
        assert_eq!(
            withdrawal(&[(PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS, "0")]).unwrap(),
            Duration::ZERO
        );
        assert_eq!(
            withdrawal(&[(PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS, "24")]).unwrap(),
            Duration::from_secs(24)
        );
        for (grace, bad) in [
            ("25", "25"),
            ("25", "26"),
            ("25", "-1"),
            ("25", "1.5"),
            ("25", "x"),
            ("1", "1"),
        ] {
            assert!(
                matches!(
                    withdrawal(&[
                        (PILLAR_SHUTDOWN_GRACE_SECONDS, grace),
                        (PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS, bad),
                    ]),
                    Err(ConfigError::InvalidShutdownWithdrawalSeconds(_))
                ),
                "grace {grace} withdrawal {bad}"
            );
        }
        assert_eq!(
            withdrawal(&[
                (PILLAR_SHUTDOWN_GRACE_SECONDS, "1"),
                (PILLAR_SHUTDOWN_WITHDRAWAL_SECONDS, "0"),
            ])
            .unwrap(),
            Duration::ZERO
        );
    }

    #[test]
    fn runtime_config_debug_redacts_both_bearer_credentials() {
        const API_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const EXTRA_TOKEN: &str = "extra-context-bearer-secret";
        let config = load_from_map(base(&[
            (PILLAR_API_AUTH_TOKENS, API_TOKEN),
            (EXTRA_CONTEXT_REQUEST_URL, "https://policy.example.com"),
            (EXTRA_CONTEXT_REQUEST_AUTH_TOKEN, EXTRA_TOKEN),
        ]))
        .unwrap();
        // Sanity: the values really are in the struct, so the assertions below
        // are about the rendering and not about a config that never loaded.
        assert_eq!(config.api_auth_tokens, vec![API_TOKEN.to_string()]);
        assert_eq!(
            config.extra_context_request_auth_token.as_deref(),
            Some(EXTRA_TOKEN)
        );

        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains(API_TOKEN),
            "RuntimeConfig Debug leaked a caller bearer token: {rendered}"
        );
        assert!(
            !rendered.contains(EXTRA_TOKEN),
            "RuntimeConfig Debug leaked the extra-context bearer token: {rendered}"
        );
        // Still usable for the question an operator debugs.
        assert!(
            rendered.contains("api_auth_tokens: <redacted> x1")
                && rendered.contains("https://policy.example.com"),
            "Debug must still report token presence and the endpoint: {rendered}"
        );
    }
}
