use super::*;

#[test]
fn runtime_signer_config_generates_kms_wallets_from_chain_types() {
    let signer_config = runtime_signer_config_from_env_map(
        &HashMap::from([
            (SIGNER_TYPE.to_string(), "KMS".to_string()),
            (
                pillar_config::LZ_KMS_IDS.to_string(),
                "key-a,key-b".to_string(),
            ),
            (
                pillar_config::LZ_KMS_CLOUD_TYPE.to_string(),
                "GCP".to_string(),
            ),
            (
                pillar_config::GCP_PROJECT_ID.to_string(),
                "project".to_string(),
            ),
            (
                pillar_config::GCP_KEY_RING_ID.to_string(),
                "ring".to_string(),
            ),
        ]),
        &["ethereum".to_string(), "solana".to_string()],
        &HashMap::from([
            ("ethereum".to_string(), "EVM".to_string()),
            ("solana".to_string(), "SOLANA".to_string()),
        ]),
    )
    .unwrap();

    assert_eq!(signer_config.wallet_definitions.len(), 2);
    assert_eq!(signer_config.wallet_definitions[0].name, "KmsWallet0");
    assert_eq!(
        signer_config.wallet_definitions[0].by_chain_type[&ChainType::Solana].signer_kind,
        Some(WalletSignerKind::Kms {
            provider: KmsProvider::Gcp
        })
    );
    assert_eq!(
        signer_config.wallets_by_chain_name["ethereum"]
            .iter()
            .map(|wallet| wallet.wallet_name.as_str())
            .collect::<Vec<_>>(),
        vec!["KmsWallet0", "KmsWallet1"]
    );
    assert!(matches!(
        signer_config.material,
        RuntimeSignerMaterial::Kms {
            options: KmsSignerAdapterFactoryOptions::Gcp { .. }
        }
    ));
}

#[tokio::test]
async fn kms_signer_assembly_uses_runtime_config_and_raw_factory() {
    let vars = HashMap::from([
        (SIGNER_TYPE.to_string(), "KMS".to_string()),
        (
            pillar_config::LZ_KMS_IDS.to_string(),
            "kms-key-a".to_string(),
        ),
        (
            pillar_config::LZ_KMS_CLOUD_TYPE.to_string(),
            "AWS".to_string(),
        ),
    ]);
    let chain_type_by_chain_name = HashMap::from([("ethereum".to_string(), "EVM".to_string())]);
    let signer_config = runtime_signer_config_from_env_map(
        &vars,
        &["ethereum".to_string()],
        &chain_type_by_chain_name,
    )
    .unwrap();
    let public_key = hex::decode(concat!(
        "04",
        "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
        "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
    ))
    .unwrap();
    let sign_requests = Arc::new(Mutex::new(Vec::new()));
    let kms_calls = Arc::new(Mutex::new(Vec::new()));
    let raw_factory: Arc<dyn RawSignerAdapterFactory> = Arc::new(FixedRawKmsFactory {
        provider: KmsProvider::Aws,
        expected_secret_name: "kms-key-a".to_string(),
        public_key,
        signature: vec![0x22; 65],
        sign_requests: sign_requests.clone(),
        kms_calls: kms_calls.clone(),
    });

    let assembly = kms_signer_assembly_from_raw_factory(
        signer_config,
        HashMap::from([("ethereum".to_string(), ChainType::Evm)]),
        raw_factory,
        KmsCredentialFlags {
            gcp_credentials_set: false,
            azure_credentials_set: false,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        assembly.signer_info["ethereum"][0].address.as_deref(),
        Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    );
    assert_eq!(
        assembly.signer_info["ethereum"][0].public_key.as_deref(),
        Some(concat!(
            "0x",
            "8318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75",
            "3547f11ca8696646f2f3acb08e31016afac23e630c5d11f59f61fef57b0d2aa5"
        ))
    );

    let signature = assembly
        .signer_getter
        .pillar_sign(
            "ethereum",
            "KmsWallet0",
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .await
        .unwrap();

    assert_eq!(
        signature.address,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    assert_eq!(signature.signature, format!("0x{}", "22".repeat(65)));
    assert_eq!(
        kms_calls.lock().unwrap().as_slice(),
        &[(KmsProvider::Aws, "kms-key-a".to_string())]
    );
    let sign_requests = sign_requests.lock().unwrap();
    assert_eq!(sign_requests.len(), 1);
    assert_eq!(sign_requests[0].signature_type, SignatureType::Ecdsa);
    assert_eq!(
        sign_requests[0].private_key_signature_type,
        SignatureType::Ecdsa
    );
    assert!(sign_requests[0].transform_recovery_id);
}
