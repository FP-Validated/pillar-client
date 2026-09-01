use super::*;

#[test]
fn runtime_signer_config_loads_local_mnemonic_files_before_inline_env() {
    let wallet_path = std::env::temp_dir().join(format!(
        "pillar-runtime-wallets-{}.json",
        std::process::id()
    ));
    let mnemonic_path = std::env::temp_dir().join(format!(
        "pillar-runtime-mnemonics-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &wallet_path,
        config_wallet_json("wallet-file", "SOLANA", "secret-file"),
    )
    .unwrap();
    std::fs::write(
        &mnemonic_path,
        r#"{"wallet-file-SOLANA":{"mnemonic":"file mnemonic","path":"m/44'/501'/0'/0'"}}"#,
    )
    .unwrap();

    let signer_config = runtime_signer_config_from_env_map(
        &HashMap::from([
            (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
            (
                pillar_config::LZ_WALLETS.to_string(),
                config_wallet_json("wallet-inline", "EVM", "secret-inline"),
            ),
            (
                pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
                r#"{"wallet-inline-EVM":{"mnemonic":"inline","path":"m/44'/60'/0'/0/0"}}"#
                    .to_string(),
            ),
            (
                LZ_WALLETS_FILE_PATH.to_string(),
                wallet_path.to_string_lossy().to_string(),
            ),
            (
                LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH.to_string(),
                mnemonic_path.to_string_lossy().to_string(),
            ),
        ]),
        &["solana".to_string()],
        &HashMap::from([("solana".to_string(), "SOLANA".to_string())]),
    )
    .unwrap();

    assert_eq!(signer_config.wallet_definitions[0].name, "wallet-file");
    assert_eq!(
        signer_config.wallets_by_chain_name["solana"][0].wallet_name,
        "wallet-file"
    );
    let RuntimeSignerMaterial::LocalMnemonic {
        wallet_to_mnemonic_map,
    } = signer_config.material
    else {
        panic!("expected local mnemonic material");
    };
    assert_eq!(
        wallet_to_mnemonic_map["wallet-file-SOLANA"].path,
        "m/44'/501'/0'/0'"
    );
    assert!(!wallet_to_mnemonic_map.contains_key("wallet-inline-EVM"));
    let signer_mnemonics = signer_local_mnemonic_map_from_config(&wallet_to_mnemonic_map);
    assert_eq!(
        signer_mnemonics["wallet-file-SOLANA"].mnemonic,
        "file mnemonic"
    );
    assert_eq!(
        signer_mnemonics["wallet-file-SOLANA"].path,
        "m/44'/501'/0'/0'"
    );

    let _ = std::fs::remove_file(wallet_path);
    let _ = std::fs::remove_file(mnemonic_path);
}

#[tokio::test]
async fn local_mnemonic_signer_getter_signs_with_runtime_config() {
    let vars = HashMap::from([
            (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
            (
                pillar_config::LZ_WALLETS.to_string(),
                config_wallet_json("wallet-a", "EVM", "secret-a"),
            ),
            (
                pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
                r#"{"wallet-a-EVM":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/60'/0'/0/0"}}"#
                    .to_string(),
            ),
        ]);
    let chain_type_by_chain_name = HashMap::from([("ethereum".to_string(), "EVM".to_string())]);
    let signer_config = runtime_signer_config_from_env_map(
        &vars,
        &["ethereum".to_string()],
        &chain_type_by_chain_name,
    )
    .unwrap();
    let signer_config_for_assembly = runtime_signer_config_from_env_map(
        &vars,
        &["ethereum".to_string()],
        &chain_type_by_chain_name,
    )
    .unwrap();
    let assembly = local_mnemonic_signer_assembly_from_config(
        signer_config_for_assembly,
        HashMap::from([("ethereum".to_string(), ChainType::Evm)]),
    )
    .await
    .unwrap();
    assert_eq!(
        assembly.signer_info["ethereum"][0].address.as_deref(),
        Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    );
    let assembly_signature = assembly
        .signer_getter
        .pillar_sign(
            "ethereum",
            "wallet-a",
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .await
        .unwrap();
    assert_eq!(
        assembly_signature.address,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );

    let RuntimeSignerMaterial::LocalMnemonic {
        wallet_to_mnemonic_map,
    } = signer_config.material
    else {
        panic!("expected local mnemonic material");
    };
    let wallets_by_chain_name = signer_config.wallets_by_chain_name.clone();
    let signer_getter = LocalMnemonicSignerGetter::new(
        HashMap::from([("ethereum".to_string(), ChainType::Evm)]),
        signer_config.wallet_definitions,
        signer_local_mnemonic_map_from_config(&wallet_to_mnemonic_map),
    )
    .unwrap();

    let signature = signer_getter
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
    assert_eq!(
        signature.signature,
        concat!(
            "0xc9707084087268bfd72c6593bedb608fcface1db084f932d5264903332749fb8",
            "0dc91cdb3fb8452ba7137f430e852f7b33d8e9e76bb24863253ae98f466eefa8",
            "1b"
        )
    );

    let signer_info = signer_getter
        .get_signer_info("ethereum", "wallet-a")
        .await
        .unwrap();
    assert_eq!(
        signer_info.address,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    assert_eq!(
        signer_info.public_key,
        concat!(
            "0x",
            "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
        )
    );

    let signer_info_map = signer_getter
        .signer_info_map(&wallets_by_chain_name)
        .await
        .unwrap();
    assert_eq!(
        signer_info_map["ethereum"][0].address.as_deref(),
        Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    );
    assert_eq!(
        signer_info_map["ethereum"][0].public_key.as_deref(),
        Some(concat!(
            "0x",
            "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
        ))
    );
}

/// Every type that transitively owns a plaintext BIP-39 phrase must redact it in
/// `Debug`, or one `{:?}` on an error path writes the signing key's seed phrase to
/// the operational log. `AwsMnemonicSecret` holds its own `String`; the runtime
/// material holds `pillar_config::Mnemonic`, and the signer adapter and factory
/// hold `pillar_signer::LocalMnemonic` - so this covers the containing types too.
#[test]
fn debug_never_prints_a_mnemonic_phrase_anywhere_in_the_signer_wiring() {
    const PHRASE: &str = "test test test test test test test test test test test junk";

    let secret: AwsMnemonicSecret = serde_json::from_value(json!({
        "LAYERZERO_WALLET_MNEMONIC": PHRASE,
        "LAYERZERO_WALLET_PATH": "m/44'/60'/0'/0/0",
    }))
    .unwrap();
    let rendered = format!("{secret:?}");
    assert!(
        !rendered.contains("junk") && !rendered.contains(PHRASE),
        "AwsMnemonicSecret Debug leaked the phrase: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>") && rendered.contains("m/44'/60'/0'/0/0"),
        "Debug must still identify the derivation path: {rendered}"
    );

    let material = RuntimeSignerMaterial::LocalMnemonic {
        wallet_to_mnemonic_map: HashMap::from([(
            "wallet-a-EVM".to_string(),
            pillar_config::Mnemonic {
                mnemonic: PHRASE.to_string(),
                path: "m/44'/60'/0'/0/0".to_string(),
            },
        )]),
    };
    let rendered = format!("{material:?}");
    assert!(
        !rendered.contains("junk") && !rendered.contains(PHRASE),
        "RuntimeSignerMaterial Debug leaked the phrase: {rendered}"
    );
}
