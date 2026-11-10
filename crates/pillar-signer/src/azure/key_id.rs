use crate::types::SignerError;

/// Azure names key objects case-insensitively, so two spellings of one key are one identity.
#[derive(Debug, Clone, Eq)]
pub struct AzureKmsKeyId {
    pub name: String,
    pub version: Option<String>,
}

impl PartialEq for AzureKmsKeyId {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq_ignore_ascii_case(&other.name)
            && match (&self.version, &other.version) {
                (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
                (None, None) => true,
                _ => false,
            }
    }
}

impl AzureKmsKeyId {
    pub(crate) fn display(&self) -> String {
        match &self.version {
            Some(version) => format!("{}/{}", self.name, version),
            None => self.name.clone(),
        }
    }
}

/// `scheme://host[:port]` of a key URL in lowercase, or `None` for a bare key name.
pub(crate) fn azure_key_vault_origin(key_id: &str) -> Option<String> {
    let url = reqwest::Url::parse(key_id).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

pub fn parse_azure_kms_key_id(key_id: &str) -> Result<AzureKmsKeyId, SignerError> {
    let has_http_scheme = |scheme: &str| {
        key_id
            .get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    };
    if !has_http_scheme("http://") && !has_http_scheme("https://") {
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
