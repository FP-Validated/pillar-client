use super::*;

pub async fn runtime_signer_assembly_from_config(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
) -> Result<RuntimeSignerAssembly, String> {
    runtime_signer_assembly_from_config_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        Arc::new(Mutex::new(PillarMetrics::new())),
    )
    .await
}

pub async fn runtime_signer_assembly_from_config_with_metrics(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<RuntimeSignerAssembly, String> {
    match signer_config.material.clone() {
        RuntimeSignerMaterial::LocalMnemonic { .. } => {
            let assembly = local_mnemonic_signer_assembly_from_config_with_metrics(
                signer_config,
                chain_type_by_chain_name,
                metrics,
            )
            .await?;
            Ok(RuntimeSignerAssembly {
                signer_getter: assembly.signer_getter,
                signer_info: assembly.signer_info,
            })
        }
        RuntimeSignerMaterial::Kms { .. } => {
            let assembly = kms_signer_assembly_from_config_with_metrics(
                signer_config,
                chain_type_by_chain_name,
                metrics,
            )
            .await?;
            Ok(RuntimeSignerAssembly {
                signer_getter: assembly.signer_getter,
                signer_info: assembly.signer_info,
            })
        }
        RuntimeSignerMaterial::AwsMnemonic { region } => {
            let assembly = aws_mnemonic_signer_assembly_from_config_with_metrics(
                signer_config,
                chain_type_by_chain_name,
                region,
                metrics,
            )
            .await?;
            Ok(RuntimeSignerAssembly {
                signer_getter: assembly.signer_getter,
                signer_info: assembly.signer_info,
            })
        }
    }
}

pub async fn aws_mnemonic_signer_assembly_from_config(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    region: Option<String>,
) -> Result<LocalMnemonicSignerAssembly, String> {
    aws_mnemonic_signer_assembly_from_config_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        region,
        Arc::new(Mutex::new(PillarMetrics::new())),
    )
    .await
}

pub async fn aws_mnemonic_signer_assembly_from_config_with_metrics(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    region: Option<String>,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<LocalMnemonicSignerAssembly, String> {
    let client = production_aws_mnemonic_secret_client(region.as_ref()).await?;
    aws_mnemonic_signer_assembly_from_secret_client_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        client,
        metrics,
    )
    .await
}

pub async fn production_aws_mnemonic_secret_client(
    region: Option<&String>,
) -> Result<AwsSecretsManagerMnemonicClient, String> {
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(region) = region {
        config_loader =
            config_loader.region(aws_sdk_secretsmanager::config::Region::new(region.clone()));
    }
    let config = config_loader.load().await;
    Ok(AwsSecretsManagerMnemonicClient::new(
        aws_sdk_secretsmanager::Client::new(&config),
    ))
}

pub async fn aws_mnemonic_signer_assembly_from_secret_client<C>(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    secret_client: C,
) -> Result<LocalMnemonicSignerAssembly, String>
where
    C: AwsMnemonicSecretClient,
{
    aws_mnemonic_signer_assembly_from_secret_client_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        secret_client,
        Arc::new(Mutex::new(PillarMetrics::new())),
    )
    .await
}

pub async fn aws_mnemonic_signer_assembly_from_secret_client_with_metrics<C>(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    secret_client: C,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<LocalMnemonicSignerAssembly, String>
where
    C: AwsMnemonicSecretClient,
{
    if !matches!(
        signer_config.material,
        RuntimeSignerMaterial::AwsMnemonic { .. }
    ) {
        return Err("runtime signer config is not MNEMONIC".to_string());
    }
    let wallet_to_mnemonic_map =
        aws_mnemonic_map_from_secret_client(&signer_config.wallet_definitions, &secret_client)
            .await?;
    let signer_getter = LocalMnemonicSignerGetter::with_metrics(
        chain_type_by_chain_name,
        signer_config.wallet_definitions,
        wallet_to_mnemonic_map,
        metrics,
    )?;
    let signer_info = signer_getter
        .signer_info_map(&signer_config.wallets_by_chain_name)
        .await?;
    Ok(LocalMnemonicSignerAssembly {
        signer_getter: Arc::new(signer_getter),
        signer_info,
    })
}

pub(crate) async fn aws_mnemonic_map_from_secret_client<C>(
    wallet_definitions: &[WalletDefinition],
    secret_client: &C,
) -> Result<HashMap<String, SignerLocalMnemonic>, String>
where
    C: AwsMnemonicSecretClient,
{
    let mut wallet_to_mnemonic_map = HashMap::new();
    for wallet in wallet_definitions {
        for (chain_type, definition) in &wallet.by_chain_type {
            let mnemonic = secret_client.get_mnemonic(&definition.secret_name).await?;
            wallet_to_mnemonic_map.insert(
                format!("{}-{}", wallet.name, signer_chain_type_ts_name(*chain_type)),
                mnemonic,
            );
        }
    }
    Ok(wallet_to_mnemonic_map)
}

pub async fn local_mnemonic_signer_assembly_from_config(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
) -> Result<LocalMnemonicSignerAssembly, String> {
    local_mnemonic_signer_assembly_from_config_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        Arc::new(Mutex::new(PillarMetrics::new())),
    )
    .await
}
pub async fn local_mnemonic_signer_assembly_from_config_with_metrics(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<LocalMnemonicSignerAssembly, String> {
    let RuntimeSignerMaterial::LocalMnemonic {
        wallet_to_mnemonic_map,
    } = signer_config.material
    else {
        return Err("runtime signer config is not LOCAL_MNEMONIC".to_string());
    };
    let signer_getter = LocalMnemonicSignerGetter::with_metrics(
        chain_type_by_chain_name,
        signer_config.wallet_definitions,
        signer_local_mnemonic_map_from_config(&wallet_to_mnemonic_map),
        metrics,
    )?;
    let signer_info = signer_getter
        .signer_info_map(&signer_config.wallets_by_chain_name)
        .await?;
    Ok(LocalMnemonicSignerAssembly {
        signer_getter: Arc::new(signer_getter),
        signer_info,
    })
}

pub async fn kms_signer_assembly_from_config(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
) -> Result<KmsSignerAssembly, String> {
    kms_signer_assembly_from_config_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        Arc::new(Mutex::new(PillarMetrics::new())),
    )
    .await
}
pub async fn kms_signer_assembly_from_config_with_metrics(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<KmsSignerAssembly, String> {
    let RuntimeSignerMaterial::Kms { options } = signer_config.material.clone() else {
        return Err("runtime signer config is not KMS".to_string());
    };
    let raw_factory = production_kms_raw_signer_factory_from_options(&options).await?;
    kms_signer_assembly_from_raw_factory_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        raw_factory,
        kms_credentials_flags(&options),
        metrics,
    )
    .await
}
pub async fn kms_signer_assembly_from_raw_factory(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    raw_factory: Arc<dyn RawSignerAdapterFactory>,
    credentials: KmsCredentialFlags,
) -> Result<KmsSignerAssembly, String> {
    kms_signer_assembly_from_raw_factory_with_metrics(
        signer_config,
        chain_type_by_chain_name,
        raw_factory,
        credentials,
        Arc::new(Mutex::new(PillarMetrics::new())),
    )
    .await
}
pub async fn kms_signer_assembly_from_raw_factory_with_metrics(
    signer_config: RuntimeSignerConfig,
    chain_type_by_chain_name: HashMap<String, ChainType>,
    raw_factory: Arc<dyn RawSignerAdapterFactory>,
    credentials: KmsCredentialFlags,
    metrics: Arc<Mutex<PillarMetrics>>,
) -> Result<KmsSignerAssembly, String> {
    if !matches!(signer_config.material, RuntimeSignerMaterial::Kms { .. }) {
        return Err("runtime signer config is not KMS".to_string());
    }
    let signer_getter = KmsSignerGetter::with_metrics(
        chain_type_by_chain_name,
        signer_config.wallet_definitions,
        raw_factory,
        credentials,
        metrics,
    )?;
    let signer_info = signer_getter
        .signer_info_map(&signer_config.wallets_by_chain_name)
        .await?;
    Ok(KmsSignerAssembly {
        signer_getter: Arc::new(signer_getter),
        signer_info,
    })
}

pub async fn production_kms_raw_signer_factory_from_options(
    options: &KmsSignerAdapterFactoryOptions,
) -> Result<Arc<dyn RawSignerAdapterFactory>, String> {
    match options {
        KmsSignerAdapterFactoryOptions::Aws { region } => {
            let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
            if let Some(region) = region {
                config_loader =
                    config_loader.region(aws_sdk_kms::config::Region::new(region.clone()));
            }
            let config = config_loader.load().await;
            let client = aws_sdk_kms::Client::new(&config);
            Ok(Arc::new(AwsKmsRawSignerAdapterFactory::new(Arc::new(
                AwsSdkKmsClient::new(client),
            ))) as Arc<dyn RawSignerAdapterFactory>)
        }
        KmsSignerAdapterFactoryOptions::Gcp {
            project_id,
            location_id,
            key_ring_id,
            key_version,
        } => Ok(Arc::new(GcpKmsRawSignerAdapterFactory::new(
            GcpKmsOptions {
                project_id: project_id.clone(),
                location_id: location_id.clone(),
                key_ring_id: key_ring_id.clone(),
                key_version: key_version.clone(),
            },
            Arc::new(
                GoogleCloudKmsClient::from_default_credentials()
                    .await
                    .map_err(|error| error.to_string())?,
            ),
        )) as Arc<dyn RawSignerAdapterFactory>),
        KmsSignerAdapterFactoryOptions::Azure { vault_url } => {
            let tenant_id = std::env::var("AZURE_TENANT_ID")
                .map_err(|_| "AZURE_TENANT_ID is required for Azure KMS".to_string())?;
            let client_id = std::env::var("AZURE_CLIENT_ID")
                .map_err(|_| "AZURE_CLIENT_ID is required for Azure KMS".to_string())?;
            let client_secret = std::env::var("AZURE_CLIENT_SECRET")
                .map_err(|_| "AZURE_CLIENT_SECRET is required for Azure KMS".to_string())?;
            let credential: Arc<dyn azure_core::credentials::TokenCredential> =
                azure_identity::ClientSecretCredential::new(
                    &tenant_id,
                    client_id,
                    azure_core::credentials::Secret::new(client_secret),
                    None,
                )
                .map_err(|error| error.to_string())?;
            let client = azure_security_keyvault_keys::KeyClient::new(vault_url, credential, None)
                .map_err(|error| error.to_string())?;
            Ok(Arc::new(AzureKmsRawSignerAdapterFactory::new(Arc::new(
                AzureKeyVaultKmsClient::new(client),
            ))) as Arc<dyn RawSignerAdapterFactory>)
        }
    }
}
