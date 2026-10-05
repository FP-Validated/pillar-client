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

/// Upstream 1.2.66's `GasolinaCantonSignerAdapter` over the test mnemonic: a raw
/// signature with an untransformed recovery id over the raw digest, and the key
/// with its prefix byte dropped as both address and signer-info key
/// (`scripts/gasolina-parity/emit-ve3-sign.ts`).
#[tokio::test]
async fn canton_signature_and_identity_match_gasolina() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/gasolina_parity/canton_sign.json"
    ))
    .unwrap();
    let signer = crate::LocalMnemonicRawSignerAdapter::new(crate::LocalMnemonic {
        mnemonic: zeroize::Zeroizing::new(fixture["mnemonic"].as_str().unwrap().to_string()),
        path: fixture["derivationPath"].as_str().unwrap().to_string(),
    });
    let adapter =
        PillarSignerAdapterKind::for_chain_type(ChainType::Canton, Arc::new(signer), false)
            .unwrap();
    let digest = hex::decode(fixture["digest"].as_str().unwrap().trim_start_matches("0x")).unwrap();

    let signature = adapter.pillar_sign(&digest).await.unwrap();
    assert_eq!(signature.signature, fixture["signature"].as_str().unwrap());
    assert_eq!(signature.address, fixture["address"].as_str().unwrap());

    let info = adapter.get_signer_info().await.unwrap();
    assert_eq!(
        info.address,
        fixture["signerInfo"]["address"].as_str().unwrap()
    );
    assert_eq!(
        info.public_key,
        fixture["signerInfo"]["publicKey"].as_str().unwrap()
    );
}
