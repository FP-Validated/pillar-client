use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KmsCredentialFlags {
    pub gcp_credentials_set: bool,
    pub azure_credentials_set: bool,
}

pub(crate) fn kms_credentials_flags(
    options: &KmsSignerAdapterFactoryOptions,
) -> KmsCredentialFlags {
    KmsCredentialFlags {
        gcp_credentials_set: matches!(options, KmsSignerAdapterFactoryOptions::Gcp { .. }),
        azure_credentials_set: matches!(options, KmsSignerAdapterFactoryOptions::Azure { .. }),
    }
}

impl LocalMnemonicSignerGetter {
    pub fn new(
        chain_type_by_chain_name: HashMap<String, ChainType>,
        wallet_definitions: Vec<WalletDefinition>,
        wallet_to_mnemonic_map: HashMap<String, SignerLocalMnemonic>,
    ) -> Result<Self, String> {
        Self::with_metrics(
            chain_type_by_chain_name,
            wallet_definitions,
            wallet_to_mnemonic_map,
            Arc::new(Mutex::new(PillarMetrics::new())),
        )
    }

    pub fn with_metrics(
        chain_type_by_chain_name: HashMap<String, ChainType>,
        wallet_definitions: Vec<WalletDefinition>,
        wallet_to_mnemonic_map: HashMap<String, SignerLocalMnemonic>,
        metrics: Arc<Mutex<PillarMetrics>>,
    ) -> Result<Self, String> {
        Ok(Self {
            chain_type_by_chain_name,
            signer_factory: SignerAdapterFactory::new(
                wallet_definitions,
                LocalMnemonicRawSignerAdapterFactory::new(wallet_to_mnemonic_map),
                false,
                false,
            )
            .map_err(|error| error.to_string())?,
            metrics,
        })
    }

    async fn observe<T>(
        &self,
        result: Result<T, pillar_signer::SignerError>,
        operation: &'static str,
    ) -> Result<T, pillar_signer::SignerError> {
        if let Err(error) = &result {
            if !matches!(
                error,
                pillar_signer::SignerError::Admission(_) | pillar_signer::SignerError::Audit(_)
            ) {
                self.metrics
                    .lock()
                    .await
                    .record_signer_error("local_mnemonic");
                tracing::error!(target: "pillar_runtime", backend = "local_mnemonic", operation, "signer operation failed");
            }
        }
        result
    }

    pub async fn get_signer_info(
        &self,
        chain_name: &str,
        wallet_name: &str,
    ) -> Result<pillar_signer::SignerInfo, String> {
        let chain_type = *self
            .chain_type_by_chain_name
            .get(chain_name)
            .ok_or_else(|| format!("No chain type for {chain_name}"))?;
        let result = self
            .signer_factory
            .get_adapter(chain_type, wallet_name)
            .await;
        let raw_signer = self
            .observe(result, "public_key")
            .await
            .map_err(|error| error.to_string())?;
        let result = PillarSignerAdapterKind::for_chain_type(chain_type, raw_signer, false);
        let signer = self
            .observe(result, "public_key")
            .await
            .map_err(|error| error.to_string())?;
        self.observe(signer.get_signer_info().await, "public_key")
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn signer_info_map(
        &self,
        wallets_by_chain_name: &HashMap<String, Vec<WalletRef>>,
    ) -> Result<BTreeMap<String, Vec<SignerInfo>>, String> {
        let mut signer_info = BTreeMap::new();
        for (chain_name, wallets) in wallets_by_chain_name {
            let mut chain_signers = Vec::with_capacity(wallets.len());
            for wallet in wallets {
                let info = self
                    .get_signer_info(chain_name, &wallet.wallet_name)
                    .await?;
                chain_signers.push(SignerInfo {
                    address: Some(info.address),
                    public_key: Some(info.public_key),
                });
            }
            signer_info.insert(chain_name.clone(), chain_signers);
        }
        Ok(signer_info)
    }
}

pub struct KmsSignerGetter {
    chain_type_by_chain_name: HashMap<String, ChainType>,
    signer_factory: SignerAdapterFactory<Arc<dyn RawSignerAdapterFactory>>,
    metrics: Arc<Mutex<PillarMetrics>>,
    backend: &'static str,
}

impl KmsSignerGetter {
    pub fn new(
        chain_type_by_chain_name: HashMap<String, ChainType>,
        wallet_definitions: Vec<WalletDefinition>,
        raw_factory: Arc<dyn RawSignerAdapterFactory>,
        credentials: KmsCredentialFlags,
    ) -> Result<Self, String> {
        Self::with_metrics(
            chain_type_by_chain_name,
            wallet_definitions,
            raw_factory,
            credentials,
            Arc::new(Mutex::new(PillarMetrics::new())),
        )
    }

    pub fn with_metrics(
        chain_type_by_chain_name: HashMap<String, ChainType>,
        wallet_definitions: Vec<WalletDefinition>,
        raw_factory: Arc<dyn RawSignerAdapterFactory>,
        credentials: KmsCredentialFlags,
        metrics: Arc<Mutex<PillarMetrics>>,
    ) -> Result<Self, String> {
        let backend = if credentials.azure_credentials_set {
            "kms_azure"
        } else if credentials.gcp_credentials_set {
            "kms_gcp"
        } else {
            "kms_aws"
        };
        Ok(Self {
            chain_type_by_chain_name,
            signer_factory: SignerAdapterFactory::new(
                wallet_definitions,
                raw_factory,
                credentials.gcp_credentials_set,
                credentials.azure_credentials_set,
            )
            .map_err(|error| error.to_string())?,
            metrics,
            backend,
        })
    }

    async fn observe<T>(
        &self,
        result: Result<T, pillar_signer::SignerError>,
        operation: &'static str,
    ) -> Result<T, pillar_signer::SignerError> {
        if let Err(error) = &result {
            if !matches!(
                error,
                pillar_signer::SignerError::Admission(_) | pillar_signer::SignerError::Audit(_)
            ) {
                self.metrics.lock().await.record_signer_error(self.backend);
                tracing::error!(target: "pillar_runtime", backend = self.backend, operation, "signer operation failed");
            }
        }
        result
    }

    pub async fn get_signer_info(
        &self,
        chain_name: &str,
        wallet_name: &str,
    ) -> Result<pillar_signer::SignerInfo, String> {
        let chain_type = *self
            .chain_type_by_chain_name
            .get(chain_name)
            .ok_or_else(|| format!("No chain type for {chain_name}"))?;
        let result = self
            .signer_factory
            .get_adapter(chain_type, wallet_name)
            .await;
        let raw_signer = self
            .observe(result, "public_key")
            .await
            .map_err(|error| error.to_string())?;
        let result = PillarSignerAdapterKind::for_chain_type(chain_type, raw_signer, true);
        let signer = self
            .observe(result, "public_key")
            .await
            .map_err(|error| error.to_string())?;
        self.observe(signer.get_signer_info().await, "public_key")
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn signer_info_map(
        &self,
        wallets_by_chain_name: &HashMap<String, Vec<WalletRef>>,
    ) -> Result<BTreeMap<String, Vec<SignerInfo>>, String> {
        let mut signer_info = BTreeMap::new();
        for (chain_name, wallets) in wallets_by_chain_name {
            let mut chain_signers = Vec::with_capacity(wallets.len());
            for wallet in wallets {
                let info = self
                    .get_signer_info(chain_name, &wallet.wallet_name)
                    .await?;
                chain_signers.push(SignerInfo {
                    address: Some(info.address),
                    public_key: Some(info.public_key),
                });
            }
            signer_info.insert(chain_name.clone(), chain_signers);
        }
        Ok(signer_info)
    }
}

#[async_trait]
impl SignerGetter for KmsSignerGetter {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<Signature, AppCoreError> {
        let chain_type = *self
            .chain_type_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| AppCoreError::Internal(format!("No chain type for {dst_chain_name}")))?;
        let raw_signer = self
            .signer_factory
            .get_adapter(chain_type, wallet_name)
            .await
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let signer = PillarSignerAdapterKind::for_chain_type(chain_type, raw_signer, true)
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let data = decode_hex_data(data_hex)?;
        self.observe(signer.pillar_sign(&data).await, "sign")
            .await
            .map_err(|error| match error {
                pillar_signer::SignerError::Admission(error) => AppCoreError::Admission(error),
                other => AppCoreError::Internal(other.to_string()),
            })
    }
}

#[async_trait]
impl SignerGetter for LocalMnemonicSignerGetter {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<Signature, AppCoreError> {
        let chain_type = *self
            .chain_type_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| AppCoreError::Internal(format!("No chain type for {dst_chain_name}")))?;
        let raw_signer = self
            .signer_factory
            .get_adapter(chain_type, wallet_name)
            .await
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let signer = PillarSignerAdapterKind::for_chain_type(chain_type, raw_signer, false)
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let data = decode_hex_data(data_hex)?;
        self.observe(signer.pillar_sign(&data).await, "sign")
            .await
            .map_err(|error| match error {
                pillar_signer::SignerError::Admission(error) => AppCoreError::Admission(error),
                other => AppCoreError::Internal(other.to_string()),
            })
    }
}

pub(crate) fn decode_hex_data(value: &str) -> Result<Vec<u8>, AppCoreError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|error| AppCoreError::Internal(error.to_string()))
}
