use super::*;

#[test]
fn signer_chain_type_mapping_accepts_static_config_names() {
    assert_eq!(
        signer_chain_type_from_config("APTOS").unwrap(),
        ChainType::Aptos
    );
    assert_eq!(
        signer_chain_type_from_config("EVM").unwrap(),
        ChainType::Evm
    );
    assert_eq!(
        signer_chain_type_from_config("TRON").unwrap(),
        ChainType::Tron
    );
    assert_eq!(
        signer_chain_type_from_config("INITIA").unwrap(),
        ChainType::Initia
    );
    assert_eq!(
        signer_chain_type_from_config("SOLANA").unwrap(),
        ChainType::Solana
    );
    assert_eq!(
        signer_chain_type_from_config("IOTAMOVE").unwrap(),
        ChainType::IotaMove
    );
    assert_eq!(
        signer_chain_type_from_config("SUI").unwrap(),
        ChainType::Sui
    );
    assert_eq!(
        signer_chain_type_from_config("TON").unwrap(),
        ChainType::Ton
    );
    assert_eq!(
        signer_chain_type_from_config("STARKNET").unwrap(),
        ChainType::Starknet
    );
    assert_eq!(
        signer_chain_type_from_config("STELLAR").unwrap(),
        ChainType::Stellar
    );
    assert_eq!(
        signer_chain_type_from_config("UNKNOWN").unwrap_err(),
        "Unsupported signer chain type: UNKNOWN"
    );
}

#[test]
fn signer_wallet_definitions_from_config_preserves_signer_kinds() {
    let wallets = signer_wallet_definitions_from_config(&[pillar_config::WalletDefinition {
        name: "wallet-a".to_string(),
        wallet_set_name: "set-a".to_string(),
        supported_chain_names: Some(vec!["ethereum".to_string()]),
        wallet_restrictions: None,
        by_chain_type: HashMap::from([
            (
                "EVM".to_string(),
                pillar_config::WalletSignerConfig {
                    secret_name: "mnemonic-secret".to_string(),
                    signer_type: None,
                    kms_provider: None,
                    address: Some("0xignored-runtime-hint".to_string()),
                },
            ),
            (
                "SOLANA".to_string(),
                pillar_config::WalletSignerConfig {
                    secret_name: "kms-key".to_string(),
                    signer_type: Some(pillar_config::SignerType::KMS),
                    kms_provider: Some(pillar_config::KmsProvider::AWS),
                    address: None,
                },
            ),
        ]),
    }])
    .unwrap();

    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].name, "wallet-a");
    assert_eq!(
        wallets[0].by_chain_type[&ChainType::Evm].secret_name,
        "mnemonic-secret"
    );
    assert_eq!(
        wallets[0].by_chain_type[&ChainType::Evm].signer_kind,
        Some(WalletSignerKind::Mnemonic)
    );
    assert_eq!(
        wallets[0].by_chain_type[&ChainType::Solana].signer_kind,
        Some(WalletSignerKind::Kms {
            provider: KmsProvider::Aws
        })
    );
}

#[test]
fn signer_wallet_definitions_reject_kms_without_provider() {
    let err = signer_wallet_definitions_from_config(&[pillar_config::WalletDefinition {
        name: "wallet-a".to_string(),
        wallet_set_name: "set-a".to_string(),
        supported_chain_names: None,
        wallet_restrictions: None,
        by_chain_type: HashMap::from([(
            "EVM".to_string(),
            pillar_config::WalletSignerConfig {
                secret_name: "kms-key".to_string(),
                signer_type: Some(pillar_config::SignerType::KMS),
                kms_provider: None,
                address: None,
            },
        )]),
    }])
    .unwrap_err();

    assert_eq!(
        err,
        "wallet wallet-a chain Evm: KMS signer requires kmsProvider"
    );
}

#[test]
fn signer_policy_accepts_runtime_core_kms_production_providers() {
    for provider in ["AWS", "GCP", "AZURE"] {
        let mut vars = HashMap::from([
            (SIGNER_TYPE.to_string(), "KMS".to_string()),
            (
                pillar_config::LZ_KMS_CLOUD_TYPE.to_string(),
                provider.to_string(),
            ),
        ]);
        if provider == "GCP" {
            vars.insert(
                pillar_config::GCP_PROJECT_ID.to_string(),
                "project".to_string(),
            );
            vars.insert(
                pillar_config::GCP_KEY_RING_ID.to_string(),
                "ring".to_string(),
            );
        }
        if provider == "AZURE" {
            vars.insert(
                pillar_config::AZURE_KEY_VAULT_URL.to_string(),
                "https://vault.example".to_string(),
            );
        }

        enforce_runtime_core_signer_production_policy(&vars).unwrap();
    }
}

#[test]
fn signer_policy_accepts_runtime_core_mnemonic_modes() {
    for signer_type in ["MNEMONIC", "LOCAL_MNEMONIC"] {
        enforce_runtime_core_signer_production_policy(&HashMap::from([(
            SIGNER_TYPE.to_string(),
            signer_type.to_string(),
        )]))
        .unwrap();
    }
}

#[test]
fn signer_policy_rejects_runtime_core_openbao_kms_provider() {
    let err = enforce_runtime_core_signer_production_policy(&HashMap::from([
        (SIGNER_TYPE.to_string(), "KMS".to_string()),
        (
            pillar_config::LZ_KMS_CLOUD_TYPE.to_string(),
            "OPENBAO".to_string(),
        ),
    ]))
    .unwrap_err();

    assert_eq!(err, "Unknown KMS cloud type: OPENBAO");
}
