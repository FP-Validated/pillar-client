use std::sync::Arc;

use crate::chain_address::{
    AptosChain, EvmAddressChain, EvmChain, InitiaChain, PillarSignerAdapter, SignerInfo,
    SolanaChain, SuiChain, TonChain,
};
use crate::types::{ChainType, RawSignerAdapter, SignerError};

pub enum PillarSignerAdapterKind {
    Aptos(PillarSignerAdapter<AptosChain>),
    Evm(PillarSignerAdapter<EvmChain>),
    Initia(PillarSignerAdapter<InitiaChain>),
    Solana(PillarSignerAdapter<SolanaChain>),
    Sui(PillarSignerAdapter<SuiChain>),
    Ton(PillarSignerAdapter<TonChain>),
    Starknet(PillarSignerAdapter<EvmAddressChain>),
    Stellar(PillarSignerAdapter<EvmAddressChain>),
}

impl PillarSignerAdapterKind {
    pub fn for_chain_type(
        chain_type: ChainType,
        signer_adapter: Arc<dyn RawSignerAdapter>,
        is_kms: bool,
    ) -> Result<Self, SignerError> {
        Ok(match chain_type {
            ChainType::Aptos => {
                Self::Aptos(PillarSignerAdapter::new(signer_adapter, AptosChain, is_kms))
            }
            ChainType::Evm | ChainType::Tron => {
                Self::Evm(PillarSignerAdapter::new(signer_adapter, EvmChain, is_kms))
            }
            ChainType::Initia => Self::Initia(PillarSignerAdapter::new(
                signer_adapter,
                InitiaChain,
                is_kms,
            )),
            ChainType::Solana => Self::Solana(PillarSignerAdapter::new(
                signer_adapter,
                SolanaChain,
                is_kms,
            )),
            ChainType::IotaMove | ChainType::Sui => {
                Self::Sui(PillarSignerAdapter::new(signer_adapter, SuiChain, is_kms))
            }
            ChainType::Ton => Self::Ton(PillarSignerAdapter::new(signer_adapter, TonChain, is_kms)),
            ChainType::Starknet => Self::Starknet(PillarSignerAdapter::new(
                signer_adapter,
                EvmAddressChain,
                is_kms,
            )),
            ChainType::Stellar => Self::Stellar(PillarSignerAdapter::new(
                signer_adapter,
                EvmAddressChain,
                is_kms,
            )),
        })
    }

    pub async fn pillar_sign(&self, data: &[u8]) -> Result<pillar_core::Signature, SignerError> {
        match self {
            Self::Aptos(adapter) => adapter.pillar_sign(data).await,
            Self::Evm(adapter) => adapter.pillar_sign(data).await,
            Self::Initia(adapter) => adapter.pillar_sign(data).await,
            Self::Solana(adapter) => adapter.pillar_sign(data).await,
            Self::Sui(adapter) => adapter.pillar_sign(data).await,
            Self::Ton(adapter) => adapter.pillar_sign(data).await,
            Self::Starknet(adapter) => adapter.pillar_sign(data).await,
            Self::Stellar(adapter) => adapter.pillar_sign(data).await,
        }
    }

    pub async fn get_signer_info(&self) -> Result<SignerInfo, SignerError> {
        match self {
            Self::Aptos(adapter) => adapter.get_signer_info().await,
            Self::Evm(adapter) => adapter.get_signer_info().await,
            Self::Initia(adapter) => adapter.get_signer_info().await,
            Self::Solana(adapter) => adapter.get_signer_info().await,
            Self::Sui(adapter) => adapter.get_signer_info().await,
            Self::Ton(adapter) => adapter.get_signer_info().await,
            Self::Starknet(adapter) => adapter.get_signer_info().await,
            Self::Stellar(adapter) => adapter.get_signer_info().await,
        }
    }
}

#[cfg(test)]
mod tests;
