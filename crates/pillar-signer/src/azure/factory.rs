use async_trait::async_trait;
use std::sync::Arc;

use crate::azure::{AzureKmsClient, AzureKmsRawSignerAdapter};
use crate::factory::RawSignerAdapterFactory;
use crate::types::{
    ChainType, ChainTypeWalletDefinition, KmsProvider, RawSignerAdapter, SignerError,
};

pub struct AzureKmsRawSignerAdapterFactory<C> {
    client: Arc<C>,
}

impl<C> AzureKmsRawSignerAdapterFactory<C>
where
    C: AzureKmsClient,
{
    pub fn new(client: Arc<C>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<C> RawSignerAdapterFactory for AzureKmsRawSignerAdapterFactory<C>
where
    C: AzureKmsClient,
{
    async fn mnemonic(
        &self,
        _wallet_name: &str,
        _chain_type: ChainType,
        _definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        Err(SignerError::UnsupportedSignerType("MNEMONIC".to_string()))
    }

    async fn kms(
        &self,
        provider: KmsProvider,
        definition: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        if provider != KmsProvider::Azure {
            return Err(SignerError::UnsupportedKmsProvider(provider));
        }
        Ok(Arc::new(AzureKmsRawSignerAdapter::new(
            definition.secret_name.clone(),
            self.client.clone(),
        )?))
    }
}
