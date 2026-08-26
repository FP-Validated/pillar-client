use super::*;

pub fn signer_chain_type_from_config(value: &str) -> Result<ChainType, String> {
    match value {
        "APTOS" => Ok(ChainType::Aptos),
        "EVM" => Ok(ChainType::Evm),
        "TRON" => Ok(ChainType::Tron),
        "INITIA" => Ok(ChainType::Initia),
        "SOLANA" => Ok(ChainType::Solana),
        "IOTAMOVE" => Ok(ChainType::IotaMove),
        "SUI" => Ok(ChainType::Sui),
        "TON" => Ok(ChainType::Ton),
        "STARKNET" => Ok(ChainType::Starknet),
        "STELLAR" => Ok(ChainType::Stellar),
        other => Err(format!("Unsupported signer chain type: {other}")),
    }
}

pub(crate) fn signer_chain_type_ts_name(chain_type: ChainType) -> &'static str {
    match chain_type {
        ChainType::Aptos => "APTOS",
        ChainType::Evm => "EVM",
        ChainType::Tron => "TRON",
        ChainType::Initia => "INITIA",
        ChainType::Solana => "SOLANA",
        ChainType::IotaMove => "IOTAMOVE",
        ChainType::Sui => "SUI",
        ChainType::Ton => "TON",
        ChainType::Starknet => "STARKNET",
        ChainType::Stellar => "STELLAR",
    }
}

pub(crate) fn signer_kind_from_config(
    definition: &pillar_config::WalletSignerConfig,
) -> Result<Option<WalletSignerKind>, String> {
    match definition.signer_type {
        None | Some(pillar_config::SignerType::Mnemonic) => Ok(Some(WalletSignerKind::Mnemonic)),
        Some(pillar_config::SignerType::KMS) => {
            let provider = definition
                .kms_provider
                .as_ref()
                .ok_or_else(|| "KMS signer requires kmsProvider".to_string())?;
            Ok(Some(WalletSignerKind::Kms {
                provider: signer_kms_provider_from_config(provider),
            }))
        }
    }
}

pub(crate) fn signer_kms_provider_from_config(
    provider: &pillar_config::KmsProvider,
) -> KmsProvider {
    match provider {
        pillar_config::KmsProvider::AWS => KmsProvider::Aws,
        pillar_config::KmsProvider::GCP => KmsProvider::Gcp,
        pillar_config::KmsProvider::AZURE => KmsProvider::Azure,
    }
}

pub(crate) fn typed_chain_type_by_chain_name(
    chain_type_by_chain_name: &HashMap<String, String>,
) -> Result<HashMap<String, ChainType>, String> {
    chain_type_by_chain_name
        .iter()
        .map(|(chain_name, chain_type)| {
            Ok((
                chain_name.clone(),
                signer_chain_type_from_config(chain_type)?,
            ))
        })
        .collect()
}

pub(crate) fn has_env(vars: &HashMap<String, String>, key: &str) -> bool {
    vars.get(key).is_some_and(|value| !value.is_empty())
}
