use super::*;

pub(super) fn core_api_app() -> CoreApiApp {
    let mut provider_health = ProviderHealthSnapshot::new();
    provider_health.insert("ethereum".to_string(), true);
    provider_health.insert("bsc".to_string(), true);
    CoreApiApp::new(
        PillarApp {
            available_chain_names: Arc::new(vec!["ethereum".to_string(), "bsc".to_string()]),
            wallets_by_chain_name: HashMap::from([(
                "bsc".to_string(),
                vec![WalletRef {
                    wallet_name: "wallet-1".to_string(),
                }],
            )]),
            hash_call_data_builders: HashMap::from([(
                "V302".to_string(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            )]),
            sent_event_resolver: Arc::new(FixedResolver),
            validator: Arc::new(NoopValidator),
            signer_getter: Arc::new(FixedSigner),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
            stage_observer: Arc::new(pillar_core::NoopSignStageObserver),
            debug_mode: true,
        },
        "mainnet".to_string(),
        BTreeMap::from([(
            "bsc".to_string(),
            vec![SignerInfo {
                address: Some("0xsigner".to_string()),
                public_key: Some("0xpublic".to_string()),
            }],
        )]),
        provider_health,
        json!({}),
    )
}

pub(super) fn request_v2() -> PillarApiRequestV2 {
    PillarApiRequestV2 {
        src_tx_hash: "0xtx".to_string(),
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 7,
            uln_send_version: Value::from("V302"),
        },
        signing_context: SigningContext::Message {
            expiration: 123,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: 1,
        },
        message_hash: "0xhash".to_string(),
    }
}

pub(super) async fn runtime_app_with_core() -> RuntimeServerApp<RecordingTransport> {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![])),
    };
    RuntimeServerApp::from_env_map(
            HashMap::from([
                (SERVER_PORT.to_string(), "3000".to_string()),
                (pillar_config::PILLAR_API_AUTH_TOKENS.to_string(), "test-token-0123456789abcdef0123456789".to_string()),
                (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
                (LZ_ENV.to_string(), "mainnet".to_string()),
                (
                    pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                    r#"["V2","V301"]"#.to_string(),
                ),
                (
                    pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                    "ethereum,bsc".to_string(),
                ),
                (
                    LZ_PROVIDER_CONFIG.to_string(),
                    r#"{"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1},"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#.to_string(),
                ),
            ]),
            transport,
            || 777,
        ).await
        .unwrap()
        .with_signing_app(Arc::new(core_api_app()))
}
