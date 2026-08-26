#[tokio::test]
async fn rejects_unsupported_signature_type() {
    struct ExactGcpKmsClient {
        public_key_pem: String,
    }

    #[async_trait::async_trait]
    impl GcpKmsClient for ExactGcpKmsClient {
        async fn asymmetric_sign_sha256_digest(
            &self,
            _version_name: &str,
            _digest: &[u8],
        ) -> Result<Vec<u8>, SignerError> {
            Ok(Vec::new())
        }

        async fn get_public_key_pem(&self, _version_name: &str) -> Result<String, SignerError> {
            Ok(self.public_key_pem.clone())
        }
    }

    struct ExactAzureKmsClient {
        key_id: AzureKmsKeyId,
        public_key_coordinates: tokio::sync::Mutex<(Vec<u8>, Vec<u8>)>,
    }

    #[async_trait::async_trait]
    impl AzureKmsClient for ExactAzureKmsClient {
        async fn sign_es256k_digest(
            &self,
            _key_id: &AzureKmsKeyId,
            _digest: &[u8],
        ) -> Result<Vec<u8>, SignerError> {
            Ok(Vec::new())
        }

        async fn get_ec_public_key_coordinates(
            &self,
            key_id: &AzureKmsKeyId,
        ) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
            assert_eq!(key_id, &self.key_id);
            Ok(self.public_key_coordinates.lock().await.clone())
        }
    }

    let signing_key = k256::ecdsa::SigningKey::from_slice(&[19u8; 32]).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let public_key_pem = pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, &{
        let mut der = hex::decode("3056301006072a8648ce3d020106052b8104000a034200").unwrap();
        der.extend_from_slice(&public_key);
        der
    })
    .unwrap();
    let gcp = GcpKmsRawSignerAdapter::new(
        "projects/project/locations/global/keyRings/ring/cryptoKeys/key/cryptoKeyVersions/1"
            .to_string(),
        std::sync::Arc::new(ExactGcpKmsClient { public_key_pem }),
    );
    let azure = AzureKmsRawSignerAdapter::new(
        "key-a".to_string(),
        std::sync::Arc::new(ExactAzureKmsClient {
            key_id: AzureKmsKeyId {
                name: "key-a".to_string(),
                version: None,
            },
            public_key_coordinates: tokio::sync::Mutex::new((
                public_key[1..33].to_vec(),
                public_key[33..].to_vec(),
            )),
        }),
    )
    .unwrap();
    let request = SignRequest {
        data: vec![0x55; 32],
        signature_type: SignatureType::Ed25519,
        private_key_signature_type: SignatureType::Ed25519,
        transform_recovery_id: false,
        seed_kind: SeedKind::Bip39,
    };

    let gcp_err = gcp.sign(request.clone()).await.unwrap_err();
    let azure_err = azure.sign(request).await.unwrap_err();

    assert_eq!(gcp_err.to_string(), "Unsupported signature type: Ed25519");
    assert_eq!(azure_err.to_string(), "Unsupported signature type: Ed25519");
}
