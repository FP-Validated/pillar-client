use async_trait::async_trait;
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::*;
use crate::factory::RawSignerAdapterFactory;
use crate::types::{
    ChainTypeWalletDefinition, KmsProvider, PublicKeyRequest, RawSignerAdapter, SeedKind,
    SignRequest, SignatureType, SignerError, WalletSignerKind,
};
include!("phase1_tests.rs");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MockAzureSignatureEncoding {
    Der,
    Raw,
}

struct MockAzureKmsClient {
    key_id: AzureKmsKeyId,
    ecdsa_signing_key: EcdsaSigningKey,
    signature_encoding: MockAzureSignatureEncoding,
    sign_digests: Mutex<Vec<Vec<u8>>>,
    public_key_calls: Mutex<usize>,
    coordinates: Option<(Vec<u8>, Vec<u8>)>,
}

#[async_trait]
impl AzureKmsClient for MockAzureKmsClient {
    async fn sign_es256k_digest(
        &self,
        key_id: &AzureKmsKeyId,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let mut expected = self.key_id.clone();
        expected.version.get_or_insert_with(|| "version-one".into());
        assert_eq!(key_id, &expected);
        self.sign_digests.lock().await.push(digest.to_vec());
        let (signature, _) = self
            .ecdsa_signing_key
            .sign_prehash_recoverable(digest)
            .unwrap();
        Ok(match self.signature_encoding {
            MockAzureSignatureEncoding::Der => signature.to_der().as_bytes().to_vec(),
            MockAzureSignatureEncoding::Raw => signature.to_bytes().to_vec(),
        })
    }

    async fn get_ec_public_key_coordinates(
        &self,
        key_id: &AzureKmsKeyId,
    ) -> Result<AzureEcPublicKey, SignerError> {
        assert_eq!(key_id, &self.key_id);
        *self.public_key_calls.lock().await += 1;
        let mut resolved = key_id.clone();
        resolved.version.get_or_insert_with(|| "version-one".into());
        let reference = format!(
            "https://test.invalid/keys/{}/{}",
            resolved.name,
            resolved.version.as_deref().unwrap()
        );
        if let Some(coordinates) = &self.coordinates {
            let (x, y) = coordinates.clone();
            return Ok(AzureEcPublicKey {
                key_id: resolved,
                reference,
                x,
                y,
            });
        }
        let public_key = self
            .ecdsa_signing_key
            .verifying_key()
            .to_encoded_point(false);
        let x = public_key.x().unwrap().to_vec();
        let y = public_key.y().unwrap().to_vec();
        Ok(AzureEcPublicKey {
            key_id: resolved,
            reference,
            x,
            y,
        })
    }
}

#[tokio::test]
async fn azure_kms_adapter_signs_raw_signature_and_decodes_coordinates() {
    let signing_key = EcdsaSigningKey::from_slice(&[16u8; 32]).unwrap();
    let key_id = AzureKmsKeyId {
        name: "key-a".to_string(),
        version: Some("ver-1".to_string()),
    };
    let client = Arc::new(MockAzureKmsClient {
        key_id,
        ecdsa_signing_key: signing_key.clone(),
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: None,
    });
    let adapter = AzureKmsRawSignerAdapter::new(
        "https://vault.vault.azure.net/keys/key-a/ver-1".to_string(),
        client.clone(),
    )
    .unwrap();
    let digest = [0x66u8; 32];
    let (expected_signature, expected_recovery_id) =
        signing_key.sign_prehash_recoverable(&digest).unwrap();

    let signature = adapter
        .sign(SignRequest {
            data: digest.to_vec(),
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            transform_recovery_id: true,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    let expected_signature_bytes = expected_signature.to_bytes();
    assert_eq!(&signature[..64], &expected_signature_bytes[..]);
    assert_eq!(signature[64], expected_recovery_id.to_byte() + 27);
    assert_eq!(client.sign_digests.lock().await.as_slice(), &[digest]);
    assert_eq!(*client.public_key_calls.lock().await, 1);

    let public_key = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();
    assert_eq!(
        public_key,
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    );
    assert_eq!(*client.public_key_calls.lock().await, 1);
}

#[tokio::test]
async fn azure_kms_adapter_signs_der_signature_like_typescript_fallback() {
    let signing_key = EcdsaSigningKey::from_slice(&[17u8; 32]).unwrap();
    let key_id = AzureKmsKeyId {
        name: "key-der".to_string(),
        version: None,
    };
    let client = Arc::new(MockAzureKmsClient {
        key_id,
        ecdsa_signing_key: signing_key.clone(),
        signature_encoding: MockAzureSignatureEncoding::Der,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: None,
    });
    let adapter = AzureKmsRawSignerAdapter::new("key-der".to_string(), client.clone()).unwrap();
    let digest = [0x77u8; 32];
    let (expected_signature, expected_recovery_id) =
        signing_key.sign_prehash_recoverable(&digest).unwrap();

    let signature = adapter
        .sign(SignRequest {
            data: digest.to_vec(),
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            transform_recovery_id: false,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    let expected_signature_bytes = expected_signature.to_bytes();
    assert_eq!(&signature[..64], &expected_signature_bytes[..]);
    assert_eq!(signature[64], expected_recovery_id.to_byte());
    assert_eq!(client.sign_digests.lock().await.as_slice(), &[digest]);
}

#[tokio::test]
async fn azure_kms_factory_accepts_key_url_and_rejects_other_providers() {
    let signing_key = EcdsaSigningKey::from_slice(&[18u8; 32]).unwrap();
    let client = Arc::new(MockAzureKmsClient {
        key_id: AzureKmsKeyId {
            name: "factory-key".to_string(),
            version: Some("42".to_string()),
        },
        ecdsa_signing_key: signing_key,
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: None,
    });
    let factory = AzureKmsRawSignerAdapterFactory::new(client.clone());
    let definition = ChainTypeWalletDefinition {
        secret_name: "https://vault.vault.azure.net/keys/factory-key/42".to_string(),
        signer_kind: Some(WalletSignerKind::Kms {
            provider: KmsProvider::Azure,
        }),
    };

    let adapter = factory.kms(KmsProvider::Azure, &definition).await.unwrap();
    adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();
    assert_eq!(*client.public_key_calls.lock().await, 1);

    let err = match factory.kms(KmsProvider::Aws, &definition).await {
        Ok(_) => panic!("expected unsupported KMS provider"),
        Err(err) => err,
    };
    assert_eq!(err, SignerError::UnsupportedKmsProvider(KmsProvider::Aws));
}

#[tokio::test]
async fn azure_kms_adapter_left_pads_short_ec_coordinates_to_32_bytes() {
    let key_id = AzureKmsKeyId {
        name: "padded-key".to_string(),
        version: None,
    };
    let client = Arc::new(MockAzureKmsClient {
        key_id,
        ecdsa_signing_key: EcdsaSigningKey::from_slice(&[19u8; 32]).unwrap(),
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: Some((vec![0xca; 31], vec![0x11; 30])),
    });
    let adapter = AzureKmsRawSignerAdapter::new("padded-key".to_string(), client).unwrap();

    let public_key = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();

    assert_eq!(public_key.len(), 65);
    assert_eq!(public_key[0], 0x04);
    assert_eq!(public_key[1], 0);
    assert_eq!(public_key[2], 0xca);
    assert_eq!(public_key[33], 0);
    assert_eq!(public_key[34], 0);
    assert_eq!(public_key[35], 0x11);
}

#[tokio::test]
async fn azure_kms_adapter_rejects_ec_coordinate_longer_than_32_bytes() {
    let key_id = AzureKmsKeyId {
        name: "oversized-key".to_string(),
        version: None,
    };
    let client = Arc::new(MockAzureKmsClient {
        key_id,
        ecdsa_signing_key: EcdsaSigningKey::from_slice(&[20u8; 32]).unwrap(),
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: Some((vec![0xca; 33], vec![0x11; 32])),
    });
    let adapter = AzureKmsRawSignerAdapter::new("oversized-key".to_string(), client).unwrap();

    let error = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap_err();

    assert_eq!(
        error,
        SignerError::Message(
            "Azure Key Vault: P-256K public key coordinate must be at most 32 bytes, got 33"
                .to_string()
        )
    );
}

#[tokio::test]
async fn azure_kms_adapter_rejects_empty_ec_coordinate() {
    let key_id = AzureKmsKeyId {
        name: "empty-key".to_string(),
        version: None,
    };
    let client = Arc::new(MockAzureKmsClient {
        key_id,
        ecdsa_signing_key: EcdsaSigningKey::from_slice(&[21u8; 32]).unwrap(),
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: Some((Vec::new(), vec![0x11; 32])),
    });
    let adapter = AzureKmsRawSignerAdapter::new("empty-key".to_string(), client).unwrap();

    let error = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap_err();

    assert_eq!(
        error,
        SignerError::Message(
            "Azure Key Vault: P-256K public key coordinate must not be empty".to_string()
        )
    );
}

/// X and Y of the mainnet DVN's Azure key as registered on chain (offset 17 of the Solana
/// DVN config account `EqkXVEeapm7JqrS1W3AGeN5ZwCRLDUHtr1XY9TuVr4rD`), pinned at `ded0f97`.
fn registered_solana_dvn_coordinates() -> (Vec<u8>, Vec<u8>) {
    (
        hex::decode("ca11e4b7d37870aca2ace4d5dee1dd296e6d76c7ff757c648d41f1e65d495d74").unwrap(),
        hex::decode("0897f8edc07fea309c99494ab3f2115c27f1f8aca0d0843ce485e6266ed351f1").unwrap(),
    )
}

#[tokio::test]
async fn azure_solana_signer_info_answers_the_registered_x_coordinate() {
    let (x, y) = registered_solana_dvn_coordinates();
    let client = Arc::new(MockAzureKmsClient {
        key_id: AzureKmsKeyId {
            name: "solana-key".to_string(),
            version: None,
        },
        ecdsa_signing_key: EcdsaSigningKey::from_slice(&[22u8; 32]).unwrap(),
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: Some((x.clone(), y.clone())),
    });
    let adapter = AzureKmsRawSignerAdapter::new("solana-key".to_string(), client).unwrap();
    let info = crate::chain_address::PillarSignerAdapterKind::for_chain_type(
        crate::types::ChainType::Solana,
        Arc::new(adapter),
        true,
    )
    .unwrap()
    .get_signer_info()
    .await
    .unwrap();

    assert_eq!(info.address, "EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy");
    assert_eq!(
        info.public_key,
        format!("0x{}{}", hex::encode(&x), hex::encode(&y))
    );
}

#[tokio::test]
async fn azure_solana_signature_carries_the_x_coordinate_address() {
    let signing_key = EcdsaSigningKey::from_slice(&[23u8; 32]).unwrap();
    let x = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .x()
        .unwrap()
        .to_vec();
    let client = Arc::new(MockAzureKmsClient {
        key_id: AzureKmsKeyId {
            name: "solana-sign-key".to_string(),
            version: None,
        },
        ecdsa_signing_key: signing_key,
        signature_encoding: MockAzureSignatureEncoding::Raw,
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
        coordinates: None,
    });
    let adapter = AzureKmsRawSignerAdapter::new("solana-sign-key".to_string(), client).unwrap();
    let signature = crate::chain_address::PillarSignerAdapterKind::for_chain_type(
        crate::types::ChainType::Solana,
        Arc::new(adapter),
        true,
    )
    .unwrap()
    .pillar_sign(&[0x42; 32])
    .await
    .unwrap();

    assert_eq!(signature.address, bs58::encode(&x).into_string());
}
