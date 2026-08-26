use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::Mutex;

use super::adapter::sign_azure_es256k_digest_with_hedge;
use super::*;
use crate::types::SignerError;

#[derive(Debug)]
enum MockAzureSignOutcome {
    Ok(Vec<u8>),
    Err(&'static str),
    DelayThenOk(Duration, Vec<u8>),
}

struct MockHedgedAzureKmsClient {
    key_id: AzureKmsKeyId,
    outcomes: Mutex<Vec<MockAzureSignOutcome>>,
    sign_digests: Mutex<Vec<Vec<u8>>>,
}

#[async_trait]
impl AzureKmsClient for MockHedgedAzureKmsClient {
    async fn sign_es256k_digest(
        &self,
        key_id: &AzureKmsKeyId,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        assert_eq!(key_id, &self.key_id);
        self.sign_digests.lock().await.push(digest.to_vec());
        let outcome = self.outcomes.lock().await.remove(0);
        match outcome {
            MockAzureSignOutcome::Ok(signature) => Ok(signature),
            MockAzureSignOutcome::Err(message) => Err(SignerError::Message(message.to_string())),
            MockAzureSignOutcome::DelayThenOk(delay, signature) => {
                tokio::time::sleep(delay).await;
                Ok(signature)
            }
        }
    }

    async fn get_ec_public_key_coordinates(
        &self,
        key_id: &AzureKmsKeyId,
    ) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        assert_eq!(key_id, &self.key_id);
        Ok((vec![0x11; 32], vec![0x22; 32]))
    }
}

#[tokio::test]
async fn azure_kms_sign_hedge_retries_immediately_after_first_failure() {
    let key_id = AzureKmsKeyId {
        name: "hedged-key".to_string(),
        version: None,
    };
    let client = MockHedgedAzureKmsClient {
        key_id: key_id.clone(),
        outcomes: Mutex::new(vec![
            MockAzureSignOutcome::Err("transient azure failure"),
            MockAzureSignOutcome::Ok(vec![0xab; 64]),
        ]),
        sign_digests: Mutex::new(Vec::new()),
    };
    let digest = [0x88u8; 32];

    let signature =
        sign_azure_es256k_digest_with_hedge(&client, &key_id, &digest, Duration::from_secs(60))
            .await
            .unwrap();

    assert_eq!(signature, vec![0xab; 64]);
    assert_eq!(client.sign_digests.lock().await.len(), 2);
}

#[tokio::test]
async fn azure_kms_sign_hedge_uses_second_attempt_when_first_is_slow() {
    let key_id = AzureKmsKeyId {
        name: "slow-key".to_string(),
        version: None,
    };
    let client = MockHedgedAzureKmsClient {
        key_id: key_id.clone(),
        outcomes: Mutex::new(vec![
            MockAzureSignOutcome::DelayThenOk(Duration::from_millis(50), vec![0x01; 64]),
            MockAzureSignOutcome::Ok(vec![0xcd; 64]),
        ]),
        sign_digests: Mutex::new(Vec::new()),
    };
    let digest = [0x99u8; 32];

    let signature =
        sign_azure_es256k_digest_with_hedge(&client, &key_id, &digest, Duration::from_millis(1))
            .await
            .unwrap();

    assert_eq!(signature, vec![0xcd; 64]);
    assert_eq!(client.sign_digests.lock().await.len(), 2);
}
