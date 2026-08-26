use std::collections::HashMap;

use super::*;
use crate::chain_address::bytes_to_hex;
use crate::{
    ChainType, ChainTypeWalletDefinition, PublicKeyRequest, RawSignerAdapter, SeedKind,
    SignatureType, SignerAdapterFactory, WalletDefinition, WalletSignerKind,
};

#[tokio::test]
async fn local_mnemonic_factory_uses_typescript_wallet_chain_key() {
    let factory = LocalMnemonicRawSignerAdapterFactory::new(HashMap::from([(
        "wallet-a-EVM".to_string(),
        LocalMnemonic {
            mnemonic: "test test test test test test test test test test test junk".to_string(),
            path: "m/44'/60'/0'/0/0".to_string(),
        },
    )]));
    let signer_factory = SignerAdapterFactory::new(
        vec![WalletDefinition {
            name: "wallet-a".to_string(),
            by_chain_type: HashMap::from([(
                ChainType::Evm,
                ChainTypeWalletDefinition {
                    secret_name: "unused-local-secret-name".to_string(),
                    signer_kind: Some(WalletSignerKind::Mnemonic),
                },
            )]),
        }],
        factory,
        false,
        false,
    )
    .unwrap();

    let adapter = signer_factory
        .get_adapter(ChainType::Evm, "wallet-a")
        .await
        .unwrap();
    let public_key = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(
        bytes_to_hex(&public_key),
        concat!(
            "04",
            "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
        )
    );
}
