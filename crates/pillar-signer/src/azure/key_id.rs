use crate::types::SignerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureKmsKeyId {
    pub name: String,
    pub version: Option<String>,
}

impl AzureKmsKeyId {
    pub(crate) fn display(&self) -> String {
        match &self.version {
            Some(version) => format!("{}/{}", self.name, version),
            None => self.name.clone(),
        }
    }
}

pub fn parse_azure_kms_key_id(key_id: &str) -> Result<AzureKmsKeyId, SignerError> {
    if !key_id.starts_with("http://") && !key_id.starts_with("https://") {
        return Ok(AzureKmsKeyId {
            name: key_id.to_string(),
            version: None,
        });
    }

    let path = key_id
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/').map(|(_, path)| path))
        .unwrap_or_default();
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let keys_index = segments
        .iter()
        .position(|segment| segment.eq_ignore_ascii_case("keys"));
    let Some(index) = keys_index else {
        return Err(SignerError::Message(format!(
            "Invalid Azure Key Vault key id: {key_id}"
        )));
    };
    let Some(name) = segments.get(index + 1).filter(|name| !name.is_empty()) else {
        return Err(SignerError::Message(format!(
            "Invalid Azure Key Vault key id: {key_id}"
        )));
    };

    Ok(AzureKmsKeyId {
        name: (*name).to_string(),
        version: segments
            .get(index + 2)
            .map(|version| (*version).to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_azure_kms_key_id_matches_typescript_key_name_and_url_forms() {
        assert_eq!(
            parse_azure_kms_key_id("key-a").unwrap(),
            AzureKmsKeyId {
                name: "key-a".to_string(),
                version: None,
            }
        );
        assert_eq!(
            parse_azure_kms_key_id("https://vault.vault.azure.net/keys/key-a/ver-1").unwrap(),
            AzureKmsKeyId {
                name: "key-a".to_string(),
                version: Some("ver-1".to_string()),
            }
        );

        let err =
            parse_azure_kms_key_id("https://vault.vault.azure.net/secrets/key-a").unwrap_err();
        assert_eq!(
            err,
            SignerError::Message(
                "Invalid Azure Key Vault key id: https://vault.vault.azure.net/secrets/key-a"
                    .to_string()
            )
        );
    }
}
