use super::*;

pub(super) fn config_wallet_json(name: &str, chain_type: &str, secret_name: &str) -> String {
    format!(
        r#"[{{
                "name":"{name}",
                "walletSetName":"set-a",
                "byChainType":{{
                    "{chain_type}":{{"secretName":"{secret_name}"}}
                }}
            }}]"#
    )
}

pub(super) fn config_wallet_json_with_supported_chain_names(
    name: &str,
    chain_type: &str,
    secret_name: &str,
    chain_name: &str,
) -> String {
    format!(
        r#"[{{
                "name":"{name}",
                "walletSetName":"set-a",
                "supportedChainNames":["{chain_name}"],
                "byChainType":{{
                    "{chain_type}":{{"secretName":"{secret_name}"}}
                }}
            }}]"#
    )
}

#[test]
fn runtime_signer_config_loads_aws_mnemonic_wallets_from_env() {
    let signer_config = runtime_signer_config_from_env_map(
        &HashMap::from([
            (SIGNER_TYPE.to_string(), "MNEMONIC".to_string()),
            (
                LZ_CDK_DEPLOY_REGION.to_string(),
                "ap-northeast-2".to_string(),
            ),
            (
                pillar_config::LZ_WALLETS.to_string(),
                config_wallet_json("wallet-a", "EVM", "secret-a"),
            ),
        ]),
        &["ethereum".to_string()],
        &HashMap::from([("ethereum".to_string(), "EVM".to_string())]),
    )
    .unwrap();

    assert_eq!(
        signer_config.material,
        RuntimeSignerMaterial::AwsMnemonic {
            region: Some("ap-northeast-2".to_string())
        }
    );
    assert_eq!(signer_config.wallet_definitions[0].name, "wallet-a");
    assert_eq!(
        signer_config.wallet_definitions[0].by_chain_type[&ChainType::Evm].secret_name,
        "secret-a"
    );
    assert_eq!(
        signer_config.wallets_by_chain_name["ethereum"][0].wallet_name,
        "wallet-a"
    );
}

#[tokio::test]
async fn aws_mnemonic_signer_assembly_loads_wallet_secrets_like_typescript() {
    let vars = HashMap::from([
        (SIGNER_TYPE.to_string(), "MNEMONIC".to_string()),
        (
            pillar_config::LZ_WALLETS.to_string(),
            config_wallet_json("wallet-a", "EVM", "secret-a"),
        ),
    ]);
    let signer_config = runtime_signer_config_from_env_map(
        &vars,
        &["ethereum".to_string()],
        &HashMap::from([("ethereum".to_string(), "EVM".to_string())]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let assembly = aws_mnemonic_signer_assembly_from_secret_client(
        signer_config,
        HashMap::from([("ethereum".to_string(), ChainType::Evm)]),
        MockAwsMnemonicSecretClient {
            secrets: HashMap::from([(
                "secret-a".to_string(),
                SignerLocalMnemonic {
                    mnemonic: "test test test test test test test test test test test junk"
                        .to_string(),
                    path: "m/44'/60'/0'/0/0".to_string(),
                },
            )]),
            calls: calls.clone(),
        },
    )
    .await
    .unwrap();

    assert_eq!(calls.lock().unwrap().as_slice(), &["secret-a".to_string()]);
    assert_eq!(
        assembly.signer_info["ethereum"][0].address.as_deref(),
        Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    );
    let signature = assembly
        .signer_getter
        .pillar_sign(
            "ethereum",
            "wallet-a",
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .await
        .unwrap();
    assert_eq!(
        signature.address,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
}

#[test]
fn infers_chain_type_by_chain_name_from_supported_wallet_definitions() {
    let wallets = format!(
        "[{},{}]",
        config_wallet_json_with_supported_chain_names(
            "wallet-evm",
            "EVM",
            "secret-evm",
            "ethereum"
        )
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']'),
        config_wallet_json_with_supported_chain_names(
            "wallet-solana",
            "SOLANA",
            "secret-solana",
            "solana"
        )
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
    );
    let mapping = infer_chain_type_by_chain_name_from_signer_env_map(
        &HashMap::from([
            (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
            (pillar_config::LZ_WALLETS.to_string(), wallets),
            (
                pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
                "{}".to_string(),
            ),
        ]),
        &["ethereum".to_string(), "solana".to_string()],
    )
    .unwrap();

    assert_eq!(mapping["ethereum"], "EVM");
    assert_eq!(mapping["solana"], "SOLANA");
}

#[test]
fn chain_type_inference_rejects_ambiguous_wallet_definitions() {
    let err = infer_chain_type_by_chain_name_from_signer_env_map(
        &HashMap::from([
            (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
            (
                pillar_config::LZ_WALLETS.to_string(),
                r#"[{
                        "name":"wallet-a",
                        "walletSetName":"set-a",
                        "byChainType":{
                            "EVM":{"secretName":"secret-evm"},
                            "SOLANA":{"secretName":"secret-solana"}
                        }
                    }]"#
                .to_string(),
            ),
            (
                pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
                "{}".to_string(),
            ),
        ]),
        &["ethereum".to_string()],
    )
    .unwrap_err();

    assert_eq!(
        err,
        "Cannot infer signer chain type for ethereum: ambiguous wallet chain types EVM,SOLANA"
    );
}

#[test]
fn chain_type_inference_uses_static_config_for_kms() {
    let mapping = infer_chain_type_by_chain_name_from_signer_env_map(
        &HashMap::from([(SIGNER_TYPE.to_string(), "KMS".to_string())]),
        &[
            "ethereum".to_string(),
            "solana".to_string(),
            "initia".to_string(),
        ],
    )
    .unwrap();

    assert_eq!(mapping["ethereum"], "EVM");
    assert_eq!(mapping["solana"], "SOLANA");
    assert_eq!(mapping["initia"], "INITIA");
}

#[test]
fn chain_type_inference_rejects_unknown_static_chain_for_kms() {
    let err = infer_chain_type_by_chain_name_from_signer_env_map(
        &HashMap::from([(SIGNER_TYPE.to_string(), "KMS".to_string())]),
        &["unknown".to_string()],
    )
    .unwrap_err();

    assert_eq!(err, "Unknown static chain name: unknown");
}
