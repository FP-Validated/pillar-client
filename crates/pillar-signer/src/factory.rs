use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};

use crate::types::{
    ChainType, ChainTypeWalletDefinition, KmsProvider, RawSignerAdapter, SignerError,
    WalletDefinition, WalletSignerKind,
};

#[async_trait]
pub trait RawSignerAdapterFactory: Send + Sync + 'static {
    async fn mnemonic(
        &self,
        wallet_name: &str,
        chain_type: ChainType,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError>;

    async fn kms(
        &self,
        provider: KmsProvider,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError>;
}

#[async_trait]
impl<T> RawSignerAdapterFactory for Arc<T>
where
    T: RawSignerAdapterFactory + ?Sized,
{
    async fn mnemonic(
        &self,
        wallet_name: &str,
        chain_type: ChainType,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        (**self).mnemonic(wallet_name, chain_type, definition).await
    }

    async fn kms(
        &self,
        provider: KmsProvider,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        (**self).kms(provider, definition).await
    }
}

type SignerAdapterCache =
    tokio::sync::Mutex<HashMap<ChainType, HashMap<String, Arc<dyn RawSignerAdapter>>>>;

pub struct SignerAdapterFactory<F> {
    wallet_definition_by_wallet_name: HashMap<String, WalletDefinition>,
    wallet_name_to_signer_adapter_by_chain_type: SignerAdapterCache,
    raw_factory: F,
    pub gcp_credentials_set: bool,
    pub azure_credentials_set: bool,
}

impl<F> SignerAdapterFactory<F>
where
    F: RawSignerAdapterFactory,
{
    pub fn new(
        wallet_definitions: Vec<WalletDefinition>,
        raw_factory: F,
        gcp_credentials_set: bool,
        azure_credentials_set: bool,
    ) -> Result<Self, SignerError> {
        let mut wallet_definition_by_wallet_name = HashMap::new();
        for wallet_definition in wallet_definitions {
            if wallet_definition_by_wallet_name.contains_key(&wallet_definition.name) {
                return Err(SignerError::DuplicateWalletDefinition(
                    wallet_definition.name,
                ));
            }
            wallet_definition_by_wallet_name
                .insert(wallet_definition.name.clone(), wallet_definition);
        }
        Ok(Self {
            wallet_definition_by_wallet_name,
            wallet_name_to_signer_adapter_by_chain_type: tokio::sync::Mutex::new(HashMap::new()),
            raw_factory,
            gcp_credentials_set,
            azure_credentials_set,
        })
    }

    pub async fn get_adapter(
        &self,
        chain_type: ChainType,
        wallet_name: &str,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        let wallet_definition = self
            .wallet_definition_by_wallet_name
            .get(wallet_name)
            .ok_or_else(|| SignerError::WalletDefinitionNotFound(wallet_name.to_string()))?;

        if let Some(adapter) = self
            .wallet_name_to_signer_adapter_by_chain_type
            .lock()
            .await
            .get(&chain_type)
            .and_then(|by_wallet| by_wallet.get(wallet_name))
            .cloned()
        {
            return Ok(adapter);
        }

        let adapter = self
            .create_signer_adapter(chain_type, wallet_name, wallet_definition)
            .await?;
        self.wallet_name_to_signer_adapter_by_chain_type
            .lock()
            .await
            .entry(chain_type)
            .or_default()
            .insert(wallet_name.to_string(), adapter.clone());
        Ok(adapter)
    }

    async fn create_signer_adapter(
        &self,
        chain_type: ChainType,
        wallet_name: &str,
        wallet_definition: &WalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        let chain_type_wallet_definition = wallet_definition
            .by_chain_type
            .get(&chain_type)
            .ok_or(SignerError::ChainTypeWalletDefinitionNotFound(chain_type))?;
        match &chain_type_wallet_definition.signer_kind {
            None | Some(WalletSignerKind::Mnemonic) => {
                self.raw_factory
                    .mnemonic(wallet_name, chain_type, chain_type_wallet_definition)
                    .await
            }
            Some(WalletSignerKind::Kms { provider }) => match provider {
                KmsProvider::Aws => {
                    self.raw_factory
                        .kms(*provider, chain_type_wallet_definition)
                        .await
                }
                KmsProvider::Gcp => {
                    if !self.gcp_credentials_set {
                        return Err(SignerError::GcpCredentialsNotSet);
                    }
                    self.raw_factory
                        .kms(*provider, chain_type_wallet_definition)
                        .await
                }
                KmsProvider::Azure => {
                    if !self.azure_credentials_set {
                        return Err(SignerError::AzureCredentialsNotSet);
                    }
                    self.raw_factory
                        .kms(*provider, chain_type_wallet_definition)
                        .await
                }
            },
            Some(WalletSignerKind::Unsupported(value)) => {
                Err(SignerError::UnsupportedSignerType(value.clone()))
            }
        }
    }
}
