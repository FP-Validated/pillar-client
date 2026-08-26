use async_trait::async_trait;
use std::sync::Arc;

use super::*;
use crate::types::{ChainType, PublicKeyRequest, RawSignerAdapter, SignRequest, SignerError};

#[derive(Default)]
struct MockRawSigner;

#[async_trait]
impl RawSignerAdapter for MockRawSigner {
    async fn sign(&self, _request: SignRequest) -> Result<Vec<u8>, SignerError> {
        Ok(vec![0xab, 0xcd])
    }

    async fn get_public_key(&self, _request: PublicKeyRequest) -> Result<Vec<u8>, SignerError> {
        Ok((1u8..=33).collect())
    }
}

#[test]
fn signer_getter_mapping_matches_typescript_switch() {
    assert!(matches!(
        PillarSignerAdapterKind::for_chain_type(ChainType::Evm, Arc::new(MockRawSigner), true)
            .unwrap(),
        PillarSignerAdapterKind::Evm(_)
    ));
    assert!(matches!(
        PillarSignerAdapterKind::for_chain_type(ChainType::Solana, Arc::new(MockRawSigner), true)
            .unwrap(),
        PillarSignerAdapterKind::Solana(_)
    ));
    assert!(matches!(
        PillarSignerAdapterKind::for_chain_type(ChainType::Initia, Arc::new(MockRawSigner), true)
            .unwrap(),
        PillarSignerAdapterKind::Initia(_)
    ));
    assert!(matches!(
        PillarSignerAdapterKind::for_chain_type(ChainType::IotaMove, Arc::new(MockRawSigner), true)
            .unwrap(),
        PillarSignerAdapterKind::Sui(_)
    ));
    assert!(matches!(
        PillarSignerAdapterKind::for_chain_type(ChainType::Starknet, Arc::new(MockRawSigner), true)
            .unwrap(),
        PillarSignerAdapterKind::Starknet(_)
    ));
    assert!(matches!(
        PillarSignerAdapterKind::for_chain_type(ChainType::Stellar, Arc::new(MockRawSigner), true)
            .unwrap(),
        PillarSignerAdapterKind::Stellar(_)
    ));
}
