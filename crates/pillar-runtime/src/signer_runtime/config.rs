use super::*;

pub struct RuntimeSignerConfig {
    pub wallet_definitions: Vec<WalletDefinition>,
    pub wallets_by_chain_name: HashMap<String, Vec<WalletRef>>,
    pub material: RuntimeSignerMaterial,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeSignerMaterial {
    AwsMnemonic {
        region: Option<String>,
    },
    LocalMnemonic {
        wallet_to_mnemonic_map: WalletToMnemonicMap,
    },
    Kms {
        options: KmsSignerAdapterFactoryOptions,
    },
}

pub fn runtime_signer_config_from_env_map(
    vars: &HashMap<String, String>,
    chain_names: &[String],
    chain_type_by_chain_name: &HashMap<String, String>,
) -> Result<RuntimeSignerConfig, String> {
    let signer_type = vars
        .get(SIGNER_TYPE)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Missing required environment variable {SIGNER_TYPE}"))
        .and_then(|value| SignerSdkFactoryType::parse(value).map_err(|error| error.to_string()))?;

    let (config_wallet_definitions, material) = match signer_type {
        SignerSdkFactoryType::AwsMnemonic => {
            let wallet_definitions =
                wallet_definitions_from_env_map(vars).map_err(|error| error.to_string())?;
            (
                wallet_definitions,
                RuntimeSignerMaterial::AwsMnemonic {
                    region: vars
                        .get(LZ_CDK_DEPLOY_REGION)
                        .filter(|value| !value.is_empty())
                        .cloned(),
                },
            )
        }
        SignerSdkFactoryType::LocalMnemonic => {
            let wallet_definitions = if has_env(vars, LZ_WALLETS_FILE_PATH) {
                wallet_definitions_from_file_path_env_map(vars)
                    .map_err(|error| error.to_string())?
            } else {
                wallet_definitions_from_env_map(vars).map_err(|error| error.to_string())?
            };
            let wallet_to_mnemonic_map = if has_env(vars, LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH) {
                wallet_to_mnemonic_map_from_file_path_env_map(vars)
                    .map_err(|error| error.to_string())?
            } else {
                wallet_to_mnemonic_map_from_env_map(vars).map_err(|error| error.to_string())?
            };
            (
                wallet_definitions,
                RuntimeSignerMaterial::LocalMnemonic {
                    wallet_to_mnemonic_map,
                },
            )
        }
        SignerSdkFactoryType::Kms => {
            let wallet_definitions =
                kms_wallet_definitions_from_env_map(vars, chain_names, chain_type_by_chain_name)
                    .map_err(|error| error.to_string())?;
            let options = kms_signer_adapter_factory_options_from_env_map(vars)
                .map_err(|error| error.to_string())?;
            (wallet_definitions, RuntimeSignerMaterial::Kms { options })
        }
    };

    let wallets_by_chain_name =
        build_wallets_by_chain_name(&config_wallet_definitions, chain_names)
            .into_iter()
            .map(|(chain_name, wallets)| {
                (
                    chain_name,
                    wallets
                        .into_iter()
                        .map(|wallet_name| WalletRef { wallet_name })
                        .collect(),
                )
            })
            .collect();
    let wallet_definitions = signer_wallet_definitions_from_config(&config_wallet_definitions)?;

    Ok(RuntimeSignerConfig {
        wallet_definitions,
        wallets_by_chain_name,
        material,
    })
}

pub fn infer_chain_type_by_chain_name_from_signer_env_map(
    vars: &HashMap<String, String>,
    chain_names: &[String],
) -> Result<HashMap<String, String>, String> {
    let signer_type = vars
        .get(SIGNER_TYPE)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Missing required environment variable {SIGNER_TYPE}"))
        .and_then(|value| SignerSdkFactoryType::parse(value).map_err(|error| error.to_string()))?;

    let wallet_definitions = match signer_type {
        SignerSdkFactoryType::AwsMnemonic => {
            wallet_definitions_from_env_map(vars).map_err(|error| error.to_string())?
        }
        SignerSdkFactoryType::LocalMnemonic => {
            if has_env(vars, LZ_WALLETS_FILE_PATH) {
                wallet_definitions_from_file_path_env_map(vars)
                    .map_err(|error| error.to_string())?
            } else {
                wallet_definitions_from_env_map(vars).map_err(|error| error.to_string())?
            }
        }
        SignerSdkFactoryType::Kms => {
            return static_chain_type_by_chain_name(chain_names).map_err(|error| error.to_string())
        }
    };
    infer_chain_type_by_chain_name_from_wallet_definitions(&wallet_definitions, chain_names)
}

pub(crate) fn infer_chain_type_by_chain_name_from_wallet_definitions(
    wallet_definitions: &[pillar_config::WalletDefinition],
    chain_names: &[String],
) -> Result<HashMap<String, String>, String> {
    chain_names
        .iter()
        .map(|chain_name| {
            let mut chain_types = wallet_definitions
                .iter()
                .filter(|wallet| {
                    wallet.supported_chain_names.as_ref().is_none_or(|supported| {
                        supported.iter().any(|supported| supported == chain_name)
                    })
                })
                .flat_map(|wallet| wallet.by_chain_type.keys().cloned())
                .collect::<Vec<_>>();
            chain_types.sort();
            chain_types.dedup();
            match chain_types.as_slice() {
                // The wallet declares the chain type; the chain's actual family
                // is what decides the curve, the seed derivation, the message
                // prefix and the address. A wallet that declares only EVM and
                // does not restrict `supportedChainNames` used to hand EVM
                // semantics to every configured chain, so a Solana or TON
                // destination got EIP-191 prefixing, a secp256k1 key over the
                // BIP-39 seed and a +27 recovery id. Refuse the disagreement at
                // assembly instead of signing with the wrong shape.
                [chain_type] => {
                    let expected = pillar_config::static_chain_type_name(chain_name)
                        .map_err(|error| error.to_string())?;
                    if chain_type != expected {
                        return Err(format!(
                            "Signer chain type for {chain_name} inferred as {chain_type} from the wallet definitions, but the static chain table says {expected}"
                        ));
                    }
                    Ok((chain_name.clone(), chain_type.clone()))
                }
                [] => Err(format!(
                    "Cannot infer signer chain type for {chain_name}: no wallet definitions match"
                )),
                many => Err(format!(
                    "Cannot infer signer chain type for {chain_name}: ambiguous wallet chain types {}",
                    many.join(",")
                )),
            }
        })
        .collect()
}

pub fn signer_wallet_definitions_from_config(
    wallet_definitions: &[pillar_config::WalletDefinition],
) -> Result<Vec<WalletDefinition>, String> {
    wallet_definitions
        .iter()
        .map(|wallet| {
            let by_chain_type = wallet
                .by_chain_type
                .iter()
                .map(|(chain_type, definition)| {
                    let chain_type = signer_chain_type_from_config(chain_type)?;
                    let signer_kind = signer_kind_from_config(definition).map_err(|error| {
                        format!("wallet {} chain {:?}: {error}", wallet.name, chain_type)
                    })?;
                    Ok((
                        chain_type,
                        ChainTypeWalletDefinition {
                            secret_name: definition.secret_name.clone(),
                            signer_kind,
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>, String>>()?;
            Ok(WalletDefinition {
                name: wallet.name.clone(),
                by_chain_type,
            })
        })
        .collect()
}

pub fn signer_local_mnemonic_map_from_config(
    wallet_to_mnemonic_map: &WalletToMnemonicMap,
) -> HashMap<String, SignerLocalMnemonic> {
    wallet_to_mnemonic_map
        .iter()
        .map(|(key, mnemonic)| {
            (
                key.clone(),
                SignerLocalMnemonic {
                    mnemonic: mnemonic.mnemonic.clone(),
                    path: mnemonic.path.clone(),
                },
            )
        })
        .collect()
}
