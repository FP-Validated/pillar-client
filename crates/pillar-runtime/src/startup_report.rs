use pillar_config::{
    load_from_map, provider_config_from_env_map, redact_kms_key_id, redact_url, KmsProvider,
    ProviderConfigGetter, ProviderConfigType, ProviderUri, RuntimeConfig, SignerSdkFactoryType,
    LZ_KMS_CLOUD_TYPE, LZ_KMS_IDS, SIGNER_TYPE,
};
use std::{collections::HashMap, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Production,
    Development,
}

impl fmt::Display for RuntimeMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => formatter.write_str("production"),
            Self::Development => formatter.write_str("development"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupChainReport {
    pub chain_name: String,
    pub provider_count: usize,
    /// The resolved `rpc` strategy, as upstream's `canonicalStrategyKey` renders it.
    pub quorum: String,
    /// `category/entity` per provider, in configuration order.
    pub entities: Vec<String>,
    pub providers: Vec<String>,
    /// One entity alone can satisfy the strategy.
    pub single_provider_trust_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupReport {
    pub environment: String,
    pub image_version: String,
    pub configured_chains: Vec<StartupChainReport>,
    pub total_provider_count: usize,
    pub signer_provider_type: String,
    pub kms_key_ids: Vec<String>,
    pub auth_token_count: usize,
    /// Whether `POST /` and `POST /v2/resolve-and-sign` serve unauthenticated
    /// callers. Printed on every boot: a signer that stopped requiring a
    /// credential must not be able to do so silently.
    pub public_sign_routes: bool,
    /// Whether any route still requires a bearer token. Printed on every boot
    /// for the same reason as `public_sign_routes`, and it subsumes it: with
    /// authentication off, identity, the health report and metrics are open
    /// too, so an operator must be able to see that from the log alone.
    pub api_auth_enabled: bool,
    pub metrics_state: String,
    pub audit_enabled: bool,
    pub mode: RuntimeMode,
}

impl StartupReport {
    pub(crate) fn from_parts(
        vars: &HashMap<String, String>,
        runtime_config: &RuntimeConfig,
        provider_config: &impl ProviderConfigGetter,
        available_chain_names: &[String],
        mode: RuntimeMode,
    ) -> Result<Self, String> {
        let configured_chains =
            available_chain_names
                .iter()
                .map(|chain_name| {
                    let config = provider_config
                        .get_provider_config(chain_name)
                        .ok_or_else(|| format!("missing provider config for {chain_name}"))?;
                    Ok(StartupChainReport {
                        chain_name: chain_name.clone(),
                        provider_count: config.uris.len(),
                        quorum: pillar_config::provider_validation::canonical_strategy_key(
                            &config.strategy,
                        ),
                        entities: config
                            .voters
                            .iter()
                            .map(|voter| {
                                format!(
                                    "{}/{}",
                                    voter.category,
                                    if voter.entity.bytes().all(|byte| byte.is_ascii_alphanumeric()
                                        || b"._-".contains(&byte))
                                    {
                                        voter.entity.as_str()
                                    } else {
                                        "<unlisted entity>"
                                    }
                                )
                            })
                            .collect(),
                        single_provider_trust_root: config.single_entity_trust_root(),
                        providers: config.uris.iter().map(redact_provider_uri).collect(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
        let total_provider_count = configured_chains
            .iter()
            .map(|chain| chain.provider_count)
            .sum();
        let kms_provider = vars
            .get(LZ_KMS_CLOUD_TYPE)
            .filter(|value| !value.is_empty())
            .cloned();
        let signer_provider_type = signer_provider_type(vars, kms_provider.as_deref())?;
        let kms_key_ids = redacted_kms_key_ids(vars, kms_provider.as_deref());

        Ok(Self {
            environment: runtime_config
                .environment
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            image_version: runtime_config
                .image_version
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            configured_chains,
            total_provider_count,
            signer_provider_type,
            kms_key_ids,
            auth_token_count: runtime_config.api_auth_tokens.len(),
            public_sign_routes: runtime_config.public_sign_routes,
            api_auth_enabled: runtime_config.api_auth_enabled,
            metrics_state: "enabled".to_string(),
            audit_enabled: runtime_config.audit.is_some(),
            mode,
        })
    }
}

impl fmt::Display for StartupReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Pillar startup report")?;
        writeln!(formatter, "environment: {}", self.environment)?;
        writeln!(formatter, "image_version: {}", self.image_version)?;
        writeln!(formatter, "mode: {}", self.mode)?;
        writeln!(formatter, "metrics: {}", self.metrics_state)?;
        writeln!(
            formatter,
            "signing_audit: {}",
            if self.audit_enabled {
                "enabled (fail-closed)"
            } else {
                "disabled"
            }
        )?;
        writeln!(formatter, "auth_tokens: {}", self.auth_token_count)?;
        writeln!(
            formatter,
            "api_auth: {}",
            if self.api_auth_enabled {
                "required"
            } else {
                "disabled (every route public)"
            }
        )?;
        writeln!(
            formatter,
            "sign_routes: {}",
            if !self.api_auth_enabled || self.public_sign_routes {
                "public (no bearer required)"
            } else {
                "authenticated"
            }
        )?;
        writeln!(formatter, "signer: {}", self.signer_provider_type)?;
        if !self.kms_key_ids.is_empty() {
            writeln!(formatter, "kms_keys: [{}]", self.kms_key_ids.join(", "))?;
        }
        writeln!(
            formatter,
            "configured_chains: {} total_providers={}",
            self.configured_chains.len(),
            self.total_provider_count
        )?;
        for chain in &self.configured_chains {
            writeln!(
                formatter,
                "- {} providers={} quorum={}{} entities=[{}] [{}]",
                chain.chain_name,
                chain.provider_count,
                chain.quorum,
                if chain.single_provider_trust_root {
                    " single-provider-trust-root"
                } else {
                    ""
                },
                chain.entities.join(", "),
                chain.providers.join(", ")
            )?;
        }
        Ok(())
    }
}

pub fn startup_report_from_env_map(
    vars: &HashMap<String, String>,
) -> Result<StartupReport, String> {
    let runtime_config = load_from_map(vars.clone()).map_err(|error| error.to_string())?;
    let provider_config = provider_config_from_env_map(
        vars,
        &runtime_config.provider_config_type,
        runtime_config.available_chain_names.as_deref(),
    )
    .map_err(|error| error.to_string())?;
    let available_chain_names = runtime_config
        .available_chain_names
        .clone()
        .unwrap_or_else(|| {
            provider_config
                .get_provider_configs()
                .keys()
                .cloned()
                .collect()
        });
    let mode = startup_mode(vars, &runtime_config);
    StartupReport::from_parts(
        vars,
        &runtime_config,
        &provider_config,
        &available_chain_names,
        mode,
    )
}

fn startup_mode(vars: &HashMap<String, String>, runtime_config: &RuntimeConfig) -> RuntimeMode {
    let signer_is_kms = vars
        .get(SIGNER_TYPE)
        .filter(|value| !value.is_empty())
        .and_then(|value| SignerSdkFactoryType::parse(value).ok())
        == Some(SignerSdkFactoryType::Kms);
    if signer_is_kms || runtime_config.provider_config_type != ProviderConfigType::LOCAL {
        RuntimeMode::Production
    } else {
        RuntimeMode::Development
    }
}

fn redact_provider_uri(provider_uri: &ProviderUri) -> String {
    match provider_uri {
        ProviderUri::Uri(uri) => redact_url(uri),
        ProviderUri::UriWithHeaders { uri, headers } => {
            let mut header_pairs = headers
                .keys()
                .map(|name| format!("{name}=<redacted>"))
                .collect::<Vec<_>>();
            header_pairs.sort();
            format!("{} headers=[{}]", redact_url(uri), header_pairs.join(", "))
        }
    }
}

fn signer_provider_type(
    vars: &HashMap<String, String>,
    kms_provider: Option<&str>,
) -> Result<String, String> {
    let raw = vars
        .get(SIGNER_TYPE)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or("unwired");
    match SignerSdkFactoryType::parse(raw) {
        Ok(SignerSdkFactoryType::Kms) => Ok(format!("KMS({})", kms_provider.unwrap_or("unknown"))),
        Ok(SignerSdkFactoryType::AwsMnemonic) => Ok("MNEMONIC".to_string()),
        Ok(SignerSdkFactoryType::LocalMnemonic) => Ok("LOCAL_MNEMONIC".to_string()),
        Err(_) if raw == "unwired" => Ok("unwired".to_string()),
        Err(error) => Err(error.to_string()),
    }
}

fn redacted_kms_key_ids(vars: &HashMap<String, String>, kms_provider: Option<&str>) -> Vec<String> {
    let Some(provider) = kms_provider else {
        return Vec::new();
    };
    if KmsProvider::parse(provider).is_err() {
        return Vec::new();
    }
    vars.get(LZ_KMS_IDS)
        .into_iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|key_id| redact_kms_key_id(provider, key_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_report_hides_undeclared_entity_labels() {
        let vars = HashMap::from([
            (pillar_config::SERVER_PORT.to_string(), "3000".to_string()),
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (
                pillar_config::LZ_PROVIDER_CONFIG_TYPE.to_string(),
                "LOCAL".to_string(),
            ),
            (pillar_config::LZ_ENV.to_string(), "testnet".to_string()),
        ]);
        let runtime = load_from_map(vars.clone()).unwrap();
        let providers = pillar_config::StaticProviderConfig::from_v2(
            r#"{"entities":["unsafe entity label"],"chains":{"ethereum":{"rpc":[{"uri":"https://rpc.example","category":"internal","entity":"unsafe entity label"}]}}}"#,
            r#"{"default":{"allOf":[{"any":1}]}}"#,
            None,
        ).unwrap();
        let report = StartupReport::from_parts(
            &vars,
            &runtime,
            &providers,
            &["ethereum".to_string()],
            RuntimeMode::Development,
        )
        .unwrap();
        let output = report.to_string();
        assert!(!output.contains("unsafe entity label"), "{output}");
        assert!(output.contains("<unlisted entity>"), "{output}");
    }
}
