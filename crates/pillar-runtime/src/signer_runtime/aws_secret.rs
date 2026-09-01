use super::*;

#[async_trait]
pub trait AwsMnemonicSecretClient: Send + Sync + 'static {
    async fn get_mnemonic(&self, secret_name: &str) -> Result<SignerLocalMnemonic, String>;
}

#[derive(Clone)]
pub struct AwsSecretsManagerMnemonicClient {
    client: aws_sdk_secretsmanager::Client,
}

/// `Debug` by hand, for the same reason as `pillar_signer::LocalMnemonic` and
/// `pillar_config::Mnemonic`: the derived one printed the plaintext BIP-39 phrase
/// fetched from Secrets Manager, so one `{:?}` on a deserialization error path
/// would have written the signing key's seed phrase to the log.
#[derive(Deserialize)]
pub(crate) struct AwsMnemonicSecret {
    #[serde(rename = "LAYERZERO_WALLET_MNEMONIC")]
    mnemonic: String,
    #[serde(rename = "LAYERZERO_WALLET_PATH")]
    path: String,
}

impl std::fmt::Debug for AwsMnemonicSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsMnemonicSecret")
            .field("mnemonic", &"<redacted>")
            .field("path", &self.path)
            .finish()
    }
}

impl AwsSecretsManagerMnemonicClient {
    pub fn new(client: aws_sdk_secretsmanager::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AwsMnemonicSecretClient for AwsSecretsManagerMnemonicClient {
    async fn get_mnemonic(&self, secret_name: &str) -> Result<SignerLocalMnemonic, String> {
        let response = self
            .client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let secret = response
            .secret_string()
            .ok_or_else(|| format!("AWS mnemonic secret {secret_name} has no SecretString"))?;
        let secret: AwsMnemonicSecret =
            serde_json::from_str(secret).map_err(|error| error.to_string())?;
        Ok(SignerLocalMnemonic {
            mnemonic: secret.mnemonic,
            path: secret.path,
        })
    }
}
