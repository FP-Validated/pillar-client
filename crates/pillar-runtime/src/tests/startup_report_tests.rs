use super::*;

#[test]
fn startup_report_summarizes_runtime_without_raw_secrets() {
    let vars = HashMap::from([
        (SERVER_PORT.to_string(), "3000".to_string()),
        (pillar_config::PILLAR_API_AUTH_TOKENS.to_string(), "test-token-0123456789abcdef0123456789".to_string()),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (
            pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
            r#"["V2","V301"]"#.to_string(),
        ),
        (
            pillar_config::PILLAR_IMAGE_VERSION.to_string(),
            "pillar:test".to_string(),
        ),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            "ethereum,bsc".to_string(),
        ),
        (
            LZ_PROVIDER_CONFIG.to_string(),
            r#"{"ethereum":{"uris":[{"uri":"https://eth-mainnet.g.alchemy.com/v2/redaction-test-key-0123456789abcdef","headers":{"Authorization":"Bearer raw-token","X-API-Key":"raw-key","x-auth":"custom-raw"}}],"quorum":1},"bsc":{"uris":["https://bsc-rpc.example/path/abcdefghijklmnop"],"quorum":1}}"#
                .to_string(),
        ),
        (SIGNER_TYPE.to_string(), "KMS".to_string()),
        (
            pillar_config::LZ_KMS_CLOUD_TYPE.to_string(),
            "AWS".to_string(),
        ),
        (
            pillar_config::LZ_KMS_IDS.to_string(),
            "arn:aws:kms:ap-northeast-2:123456789012:key/abcdef123456".to_string(),
        ),
    ]);

    let report = startup_report_from_env_map(&vars).unwrap();
    let text = report.to_string();

    assert!(text.contains("environment: mainnet"));
    assert!(text.contains("image_version: pillar:test"));
    assert!(text.contains("mode: production"));
    assert!(text.contains("metrics: enabled"));
    assert!(text.contains("signer: KMS(AWS)"));
    assert!(text.contains("kms_keys: [AWS:...3456]"));
    assert!(text.contains("ethereum providers=1 quorum=1"));
    assert!(text.contains("https://eth-mainnet.g.alchemy.com/<redacted>"));
    assert!(text.contains("Authorization=<redacted>"));
    assert!(text.contains("X-API-Key=<redacted>"));
    assert!(text.contains("x-auth=<redacted>"));
    assert!(!text.contains("redaction-test-key-0123456789abcdef"));
    assert!(!text.contains("raw-token"));
    assert!(!text.contains("raw-key"));
    assert!(!text.contains("custom-raw"));
    assert!(!text.contains("abcdef123456"));
}
