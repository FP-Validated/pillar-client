use crate::common::{must, tokio_runtime};
use async_trait::async_trait;
use criterion::Criterion;
use pillar_signer::{
    AwsKmsClient, AwsKmsRawSignerAdapter, RawSignerAdapter, SeedKind, SignRequest, SignatureType,
    SignerError,
};
use std::{hint::black_box, sync::Arc, time::Duration};

pub(crate) fn bench(c: &mut Criterion) {
    let runtime = tokio_runtime();
    let signer = AwsKmsRawSignerAdapter::new(
        "mock-ed25519-key".to_string(),
        Arc::new(DelayedAwsKmsClient {
            delay: Duration::from_millis(1),
        }),
    );
    let request = SignRequest {
        data: vec![0xabu8; 32],
        signature_type: SignatureType::Ed25519,
        private_key_signature_type: SignatureType::Ed25519,
        transform_recovery_id: false,
        seed_kind: SeedKind::Bip39,
    };

    c.bench_function("signer_kms/mock_ed25519_latency", |b| {
        b.to_async(&runtime).iter(|| async {
            let signature = signer.sign(black_box(request.clone())).await;
            black_box(must(signature));
        });
    });
}

struct DelayedAwsKmsClient {
    delay: Duration,
}

#[async_trait]
impl AwsKmsClient for DelayedAwsKmsClient {
    async fn sign_ecdsa_sha256_digest(
        &self,
        _key_id: &str,
        _digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        tokio::time::sleep(self.delay).await;
        Ok(vec![0xcd; 64])
    }

    async fn sign_ed25519_raw(
        &self,
        _key_id: &str,
        _message: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        tokio::time::sleep(self.delay).await;
        Ok(vec![0xef; 64])
    }

    async fn get_public_key_der(&self, _key_id: &str) -> Result<Vec<u8>, SignerError> {
        Err(SignerError::Message(
            "public key is not used by the Ed25519 latency benchmark".to_string(),
        ))
    }
}
