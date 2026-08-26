use async_trait::async_trait;
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::*;
use crate::types::{
    ChainTypeWalletDefinition, KmsProvider, SeedKind, SignRequest, WalletSignerKind,
};

struct MockAwsKmsClient {
    key_id: String,
    ecdsa_signing_key: EcdsaSigningKey,
    public_key_der: Vec<u8>,
    ed25519_signature: Vec<u8>,
    public_key_calls: Mutex<usize>,
    ecdsa_digests: Mutex<Vec<Vec<u8>>>,
    ed25519_messages: Mutex<Vec<Vec<u8>>>,
}

#[async_trait]
impl AwsKmsClient for MockAwsKmsClient {
    async fn sign_ecdsa_sha256_digest(
        &self,
        key_id: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        assert_eq!(key_id, self.key_id);
        self.ecdsa_digests.lock().await.push(digest.to_vec());
        let (signature, _) = self
            .ecdsa_signing_key
            .sign_prehash_recoverable(digest)
            .unwrap();
        Ok(signature.to_der().as_bytes().to_vec())
    }

    async fn sign_ed25519_raw(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        assert_eq!(key_id, self.key_id);
        self.ed25519_messages.lock().await.push(message.to_vec());
        Ok(self.ed25519_signature.clone())
    }

    async fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, SignerError> {
        assert_eq!(key_id, self.key_id);
        *self.public_key_calls.lock().await += 1;
        Ok(self.public_key_der.clone())
    }
}

fn ed25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    let mut der = hex::decode("302a300506032b6570032100").unwrap();
    der.extend_from_slice(public_key);
    der
}

fn secp256k1_spki_der(public_key: &[u8]) -> Vec<u8> {
    let mut der = hex::decode("3056301006072a8648ce3d020106052b8104000a034200").unwrap();
    der.extend_from_slice(public_key);
    der
}

#[tokio::test]
async fn aws_kms_adapter_signs_ecdsa_digest_and_recovers_signature_like_typescript() {
    let signing_key = EcdsaSigningKey::from_slice(&[11u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let public_key_der = secp256k1_spki_der(&public_key);
    let client = Arc::new(MockAwsKmsClient {
        key_id: "aws-key".to_string(),
        ecdsa_signing_key: signing_key.clone(),
        public_key_der,
        ed25519_signature: vec![0xee; 64],
        public_key_calls: Mutex::new(0),
        ecdsa_digests: Mutex::new(Vec::new()),
        ed25519_messages: Mutex::new(Vec::new()),
    });
    let adapter = AwsKmsRawSignerAdapter::new("aws-key".to_string(), client.clone());
    let digest = [0x44u8; 32];
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
    assert_eq!(client.ecdsa_digests.lock().await.as_slice(), &[digest]);
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
async fn aws_kms_adapter_signs_ed25519_raw_and_decodes_spki_public_key() {
    let ed_public_key = [0x23u8; 32];
    let client = Arc::new(MockAwsKmsClient {
        key_id: "aws-ed-key".to_string(),
        ecdsa_signing_key: EcdsaSigningKey::from_slice(&[12u8; 32]).unwrap(),
        public_key_der: ed25519_spki_der(&ed_public_key),
        ed25519_signature: vec![0x51; 64],
        public_key_calls: Mutex::new(0),
        ecdsa_digests: Mutex::new(Vec::new()),
        ed25519_messages: Mutex::new(Vec::new()),
    });
    let adapter = AwsKmsRawSignerAdapter::new("aws-ed-key".to_string(), client.clone());

    let signature = adapter
        .sign(SignRequest {
            data: b"raw-message".to_vec(),
            signature_type: SignatureType::Ed25519,
            private_key_signature_type: SignatureType::Ed25519,
            transform_recovery_id: false,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();
    assert_eq!(signature, vec![0x51; 64]);
    assert_eq!(
        client.ed25519_messages.lock().await.as_slice(),
        &[b"raw-message".to_vec()]
    );

    let public_key = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ed25519,
            private_key_signature_type: SignatureType::Ed25519,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();
    assert_eq!(public_key, ed_public_key);
}

#[tokio::test]
async fn aws_kms_factory_uses_secret_name_as_key_id_and_rejects_other_providers() {
    let signing_key = EcdsaSigningKey::from_slice(&[13u8; 32]).unwrap();
    let client = Arc::new(MockAwsKmsClient {
        key_id: "factory-key".to_string(),
        ecdsa_signing_key: signing_key.clone(),
        public_key_der: secp256k1_spki_der(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        ),
        ed25519_signature: vec![0x52; 64],
        public_key_calls: Mutex::new(0),
        ecdsa_digests: Mutex::new(Vec::new()),
        ed25519_messages: Mutex::new(Vec::new()),
    });
    let factory = AwsKmsRawSignerAdapterFactory::new(client.clone());
    let definition = ChainTypeWalletDefinition {
        secret_name: "factory-key".to_string(),
        signer_kind: Some(WalletSignerKind::Kms {
            provider: KmsProvider::Aws,
        }),
    };

    let adapter = factory.kms(KmsProvider::Aws, &definition).await.unwrap();
    adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();
    assert_eq!(*client.public_key_calls.lock().await, 1);

    let err = match factory.kms(KmsProvider::Gcp, &definition).await {
        Ok(_) => panic!("expected unsupported KMS provider"),
        Err(err) => err,
    };
    assert_eq!(err, SignerError::UnsupportedKmsProvider(KmsProvider::Gcp));
}
