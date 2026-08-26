use async_trait::async_trait;
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::*;
use crate::types::{
    ChainTypeWalletDefinition, KmsProvider, SeedKind, SignRequest, WalletSignerKind,
};

struct MockGcpKmsClient {
    version_name: String,
    ecdsa_signing_key: EcdsaSigningKey,
    public_key_pem: String,
    sign_digests: Mutex<Vec<Vec<u8>>>,
    public_key_calls: Mutex<usize>,
}

#[async_trait]
impl GcpKmsClient for MockGcpKmsClient {
    async fn asymmetric_sign_sha256_digest(
        &self,
        version_name: &str,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        assert_eq!(version_name, self.version_name);
        self.sign_digests.lock().await.push(digest.to_vec());
        let (signature, _) = self
            .ecdsa_signing_key
            .sign_prehash_recoverable(digest)
            .unwrap();
        Ok(signature.to_der().as_bytes().to_vec())
    }

    async fn get_public_key_pem(&self, version_name: &str) -> Result<String, SignerError> {
        assert_eq!(version_name, self.version_name);
        *self.public_key_calls.lock().await += 1;
        Ok(self.public_key_pem.clone())
    }
}

fn secp256k1_public_key_pem(public_key: &[u8]) -> String {
    let mut der = hex::decode("3056301006072a8648ce3d020106052b8104000a034200").unwrap();
    der.extend_from_slice(public_key);
    pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, &der).unwrap()
}

#[tokio::test]
async fn gcp_kms_adapter_signs_ecdsa_digest_and_decodes_pem_public_key() {
    let signing_key = EcdsaSigningKey::from_slice(&[14u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let version_name =
        "projects/project/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
            .to_string();
    let client = Arc::new(MockGcpKmsClient {
        version_name: version_name.clone(),
        ecdsa_signing_key: signing_key.clone(),
        public_key_pem: secp256k1_public_key_pem(&public_key),
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
    });
    let adapter = GcpKmsRawSignerAdapter::new(version_name, client.clone());
    let digest = [0x55u8; 32];
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

    let decoded_public_key = adapter
        .get_public_key(PublicKeyRequest {
            signature_type: SignatureType::Ecdsa,
            private_key_signature_type: SignatureType::Ecdsa,
            seed_kind: SeedKind::Bip39,
        })
        .await
        .unwrap();
    assert_eq!(decoded_public_key, public_key);
    assert_eq!(*client.public_key_calls.lock().await, 1);
}

#[tokio::test]
async fn gcp_kms_factory_builds_crypto_key_version_name_like_typescript() {
    let signing_key = EcdsaSigningKey::from_slice(&[15u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let expected_version =
        "projects/project/locations/global/keyRings/ring/cryptoKeys/key-a/cryptoKeyVersions/7"
            .to_string();
    let client = Arc::new(MockGcpKmsClient {
        version_name: expected_version,
        ecdsa_signing_key: signing_key,
        public_key_pem: secp256k1_public_key_pem(&public_key),
        sign_digests: Mutex::new(Vec::new()),
        public_key_calls: Mutex::new(0),
    });
    let factory = GcpKmsRawSignerAdapterFactory::new(
        GcpKmsOptions {
            project_id: "project".to_string(),
            location_id: "global".to_string(),
            key_ring_id: "ring".to_string(),
            key_version: "7".to_string(),
        },
        client.clone(),
    );
    let definition = ChainTypeWalletDefinition {
        secret_name: "key-a".to_string(),
        signer_kind: Some(WalletSignerKind::Kms {
            provider: KmsProvider::Gcp,
        }),
    };

    let adapter = factory.kms(KmsProvider::Gcp, &definition).await.unwrap();
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
