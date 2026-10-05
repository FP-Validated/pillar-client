struct RotatingAzureClient {
    first: EcdsaSigningKey,
    second: EcdsaSigningKey,
    rotated: std::sync::atomic::AtomicBool,
    signed_versions: Mutex<Vec<Option<String>>>,
}
#[async_trait]
impl AzureKmsClient for RotatingAzureClient {
    async fn sign_es256k_digest(&self, id: &AzureKmsKeyId, digest: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.signed_versions.lock().await.push(id.version.clone());
        let key = if id.version.as_deref() == Some("version-one") || !self.rotated.load(std::sync::atomic::Ordering::SeqCst) { &self.first } else { &self.second };
        Ok(key.sign_prehash_recoverable(digest).unwrap().0.to_bytes().to_vec())
    }
    async fn get_ec_public_key_coordinates(&self, id: &AzureKmsKeyId) -> Result<AzureEcPublicKey, SignerError> {
        let key = self.first.verifying_key().to_encoded_point(false);
        let mut resolved = id.clone(); resolved.version = Some("version-one".into());
        Ok(AzureEcPublicKey { key_id: resolved, reference: "https://test.invalid/keys/key-canary/version-one".into(), x: key.x().unwrap().to_vec(), y: key.y().unwrap().to_vec() })
    }
}
#[tokio::test]
async fn phase1_azure_latest_rotation_keeps_cached_key_and_signing_version_together() {
    let client = Arc::new(RotatingAzureClient {
        first: EcdsaSigningKey::from_slice(&[42; 32]).unwrap(),
        second: EcdsaSigningKey::from_slice(&[43; 32]).unwrap(),
        rotated: std::sync::atomic::AtomicBool::new(false), signed_versions: Mutex::new(Vec::new()),
    });
    let adapter = AzureKmsRawSignerAdapter::new("key-canary".into(), client.clone()).unwrap();
    adapter.get_public_key(PublicKeyRequest { signature_type: SignatureType::Ecdsa, private_key_signature_type: SignatureType::Ecdsa, seed_kind: SeedKind::Bip39 }).await.unwrap();
    client.rotated.store(true, std::sync::atomic::Ordering::SeqCst);
    let signature = adapter.sign(SignRequest { data: vec![9; 32], signature_type: SignatureType::Ecdsa, private_key_signature_type: SignatureType::Ecdsa, transform_recovery_id: false, seed_kind: SeedKind::Bip39 }).await.unwrap();
    assert_eq!(signature.len(), 65);
    assert_eq!(*client.signed_versions.lock().await, vec![Some("version-one".into())]);
    println!("PHASE1_KEY_ARTIFACT cache_and_attempt_version=version-one signature_recovered=true");
}
