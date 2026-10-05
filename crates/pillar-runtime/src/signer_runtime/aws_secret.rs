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
    mnemonic: zeroize::Zeroizing<String>,
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
        parse_aws_mnemonic_secret(secret)
    }
}

pub(crate) fn parse_aws_mnemonic_secret(secret: &str) -> Result<SignerLocalMnemonic, String> {
    let secret: AwsMnemonicSecret = serde_json::from_str(secret).map_err(|error| {
        format!(
            "AWS mnemonic secret: {}",
            pillar_config::json_error_without_input(&error)
        )
    })?;
    Ok(SignerLocalMnemonic {
        mnemonic: secret.mnemonic,
        path: secret.path,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_aws_mnemonic_secret;

    #[test]
    fn aws_secret_shape_errors_name_the_position_but_not_the_value() {
        const SENTINEL: &str = "SYNTHETIC-SENTINEL-not-a-seed-phrase";
        for secret in [
            format!(r#""{SENTINEL}""#),
            format!(r#""LAYERZERO_WALLET_MNEMONIC: {SENTINEL}""#),
        ] {
            let error = parse_aws_mnemonic_secret(&secret).err().unwrap();
            assert!(!error.contains(SENTINEL), "{error}");
            assert!(
                error.starts_with("AWS mnemonic secret: JSON data error at line 1 column "),
                "{error}"
            );
        }
        let error =
            parse_aws_mnemonic_secret(&format!(r#"{{"LAYERZERO_WALLET_MNEMONIC":"{SENTINEL}"}}"#))
                .err()
                .unwrap();
        assert!(
            error.contains("missing field `LAYERZERO_WALLET_PATH`"),
            "{error}"
        );
        assert!(!error.contains(SENTINEL), "{error}");
    }
}
