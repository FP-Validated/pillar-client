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

struct RegisteredAzureKey;

#[async_trait]
impl pillar_signer::AzureKmsClient for RegisteredAzureKey {
    async fn get_ec_public_key_coordinates(
        &self,
        key: &pillar_signer::AzureKmsKeyId,
    ) -> Result<pillar_signer::AzureEcPublicKey, SignerError> {
        assert_eq!(key.name, "solana-key");
        Ok(pillar_signer::AzureEcPublicKey {
            key_id: pillar_signer::AzureKmsKeyId {
                name: key.name.clone(),
                version: Some("v1".to_string()),
            },
            reference: "https://synthetic.invalid/keys/solana-key/v1".to_string(),
            x: hex::decode("ca11e4b7d37870aca2ace4d5dee1dd296e6d76c7ff757c648d41f1e65d495d74")
                .unwrap(),
            y: hex::decode("0897f8edc07fea309c99494ab3f2115c27f1f8aca0d0843ce485e6266ed351f1")
                .unwrap(),
        })
    }

    async fn sign_es256k_digest(
        &self,
        _key: &pillar_signer::AzureKmsKeyId,
        _digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        Err(SignerError::Message("this test never signs".to_string()))
    }
}

#[derive(Clone)]
struct NoRpcTransport;

#[async_trait]
impl JsonRpcTransport for NoRpcTransport {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        Err(format!("no RPC in this test: {url}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("no RPC in this test: {url}"))
    }
}

/// The production Azure factory and adapter, assembled from the env map and served over
/// `/signer-info`, must answer the registered `base58(X)` and the 64-byte `X || Y`.
#[tokio::test]
async fn azure_solana_signer_info_route_answers_the_registered_address() {
    use tower::ServiceExt;

    let providers = r#"{"solana":{"uris":["https://solana-rpc.example"],"quorum":1}}"#;
    let vars = HashMap::from([
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
            "test-token-0123456789abcdef0123456789".to_string(),
        ),
        (SERVER_PORT.to_string(), "3000".to_string()),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            "solana".to_string(),
        ),
        (LZ_PROVIDER_CONFIG.to_string(), providers_json(providers)),
        (
            LZ_QUORUM_STRATEGY_CONFIG.to_string(),
            strategy_json(providers),
        ),
        (SIGNER_TYPE.to_string(), "KMS".to_string()),
        (
            pillar_config::LZ_KMS_CLOUD_TYPE.to_string(),
            "AZURE".to_string(),
        ),
        (
            pillar_config::LZ_KMS_IDS.to_string(),
            "solana-key".to_string(),
        ),
        (
            pillar_config::AZURE_KEY_VAULT_URL.to_string(),
            "https://synthetic.invalid".to_string(),
        ),
    ]);
    let factory: Arc<dyn RawSignerAdapterFactory> = Arc::new(
        pillar_signer::AzureKmsRawSignerAdapterFactory::new(Arc::new(RegisteredAzureKey)),
    );
    let app = crate::signer_runtime::TEST_KMS_RAW_FACTORY
        .scope(
            factory,
            RuntimeServerApp::from_env_map_with_runtime_core(vars, NoRpcTransport, || {
                1_767_323_045_000
            }),
        )
        .await
        .unwrap_or_else(|error| panic!("the production wiring did not assemble: {error}"));

    let response = pillar_api::router(app, "synthetic")
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/signer-info?chainName=solana")
                .header(
                    "authorization",
                    "Bearer test-token-0123456789abcdef0123456789",
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        body["body"],
        json!([{
            "address": "EboBSUoobiqt7JYcH46ro7TGBjtE2vczKnUmsiWy6Ffy",
            "publicKey": concat!(
                "0xca11e4b7d37870aca2ace4d5dee1dd296e6d76c7ff757c648d41f1e65d495d74",
                "0897f8edc07fea309c99494ab3f2115c27f1f8aca0d0843ce485e6266ed351f1"
            )
        }]),
        "{body}"
    );
}
