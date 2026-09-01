use super::*;

#[tokio::test]
async fn runtime_server_app_uses_local_provider_config_for_exposed_state() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": "0x38"})),
            Ok(json!({"result": "0x38"})),
        ])),
    };
    let app = RuntimeServerApp::from_env_map(
        HashMap::from([
            (SERVER_PORT.to_string(), "3000".to_string()),
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                r#"["V2","V301"]"#.to_string(),
            ),
            (
                pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                "bsc".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#.to_string(),
            ),
        ]),
        transport,
        || 777,
    )
    .await
    .unwrap();

    assert_eq!(app.get_available_chain_names(), vec!["bsc".to_string()]);
    assert_eq!(app.get_environment(), "mainnet");
    let health = app.get_provider_health().await.unwrap();
    assert!(health["bsc"]);
    let report = app.get_provider_health_report().await.unwrap();
    assert_eq!(report["bsc"]["checkedAtUnixMs"], 777);
    assert_eq!(report["bsc"]["providers"][0]["numericResponse"], "56");
}

#[tokio::test]
async fn runtime_server_app_provider_health_uses_cache() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "0x38"}))])),
    };
    let app = RuntimeServerApp::from_env_map(
        HashMap::from([
            (SERVER_PORT.to_string(), "3000".to_string()),
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                r#"["V2","V301"]"#.to_string(),
            ),
            (
                pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                "bsc".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#.to_string(),
            ),
        ]),
        transport,
        || 777,
    )
    .await
    .unwrap();

    assert!(app.get_provider_health().await.unwrap()["bsc"]);
    assert!(app.get_provider_health().await.unwrap()["bsc"]);
    assert_eq!(calls.lock().unwrap().len(), 1);
}

/// `/provider-health/report` used to probe every provider of every chain on
/// every request while `/provider-health` was served from a cache, so an
/// authenticated caller could aim a fan-out amplifier at the operator's own
/// fleet and trip the rate limits the signing path shares.
#[tokio::test]
async fn runtime_server_app_provider_health_report_uses_cache() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "0x38"}))])),
    };
    let app = RuntimeServerApp::from_env_map(
        HashMap::from([
            (SERVER_PORT.to_string(), "3000".to_string()),
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                r#"["V2","V301"]"#.to_string(),
            ),
            (
                pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                "bsc".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#.to_string(),
            ),
        ]),
        transport,
        || 777,
    )
    .await
    .unwrap();

    let first = app.get_provider_health_report().await.unwrap();
    let second = app.get_provider_health_report().await.unwrap();
    assert_eq!(first, second, "the cached report must be served verbatim");
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "a second report request must not re-probe the providers"
    );
}

#[tokio::test]
async fn runtime_sign_request_v2_delegates_to_core_app_when_wired() {
    let response = runtime_app_with_core()
        .await
        .sign_request_v2(request_v2())
        .await
        .unwrap();

    assert_eq!(response.payload, "0xresolved");
    assert_eq!(response.signatures.len(), 1);
    assert_eq!(response.signatures[0].signature, "sig:bsc:wallet-1:0xfeed");
    assert_eq!(response.debug_info.unwrap().dvn_hash_call_data, "0xfeed");
}

#[tokio::test]
async fn runtime_sign_request_v1_delegates_to_core_app_when_wired() {
    let response = runtime_app_with_core()
        .await
        .sign_request_v1(PillarApiRequestV1 {
            src_tx_hash: "0xtx".to_string(),
            lz_message_id: pillar_core::LegacyLzMessageId {
                src_chain_id: "1".to_string(),
                nonce: 9,
                dst_chain_id: "56".to_string(),
                src_ua_address: "0xsrc".to_string(),
                dst_ua_address: "0xdst".to_string(),
            },
            block_confirmation: 1,
            expiration: 123,
            uln_version: Value::from("V302"),
            skip_v_id: None,
            dvn_address: None,
            message_hash: "0xhash".to_string(),
        })
        .await
        .unwrap();

    assert_eq!(response.payload, "0xresolved");
    assert_eq!(response.signatures[0].signature, "sig:bsc:wallet-1:0xfeed");
}

#[tokio::test]
async fn runtime_signer_info_delegates_to_core_app_when_wired() {
    let signer_info = runtime_app_with_core()
        .await
        .get_signer_info("bsc".to_string())
        .await
        .unwrap();

    assert_eq!(signer_info.len(), 1);
    assert_eq!(signer_info[0].address.as_deref(), Some("0xsigner"));
    assert_eq!(signer_info[0].public_key.as_deref(), Some("0xpublic"));
}

#[tokio::test]
async fn runtime_server_app_from_env_map_with_core_dependencies_wires_local_mnemonic_core_app() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": "0x1"})),
            Ok(json!({"result": "0x38"})),
        ])),
    };
    let app = RuntimeServerApp::from_env_map_with_core_dependencies_inferred_chain_types(
            HashMap::from([
                (pillar_config::PILLAR_API_AUTH_TOKENS.to_string(), "test-token-0123456789abcdef0123456789".to_string()),
                (SERVER_PORT.to_string(), "3000".to_string()),
                (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
                (LZ_ENV.to_string(), "mainnet".to_string()),
                (
                    pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                    r#"["V2","V301"]"#.to_string(),
                ),
                (pillar_config::LZ_DEBUG_MODE.to_string(), "true".to_string()),
                (
                    pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                    "ethereum,bsc".to_string(),
                ),
                (
                    LZ_PROVIDER_CONFIG.to_string(),
                    r#"{"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1},"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#
                        .to_string(),
                ),
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
            ]),
            transport,
            || 777,
            RuntimeCoreAppDependencies {
                hash_call_data_builders: HashMap::from([(
                    "V302".to_string(),
                    Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
                )]),
                sent_event_resolver: Arc::new(FixedResolver),
                validator: Arc::new(NoopValidator),
                legacy_chain_name_resolver: Arc::new(FixedChainResolver),
            },
        )
        .await
        .unwrap();

    let signer_info = app.get_signer_info("bsc".to_string()).await.unwrap();
    assert_eq!(
        signer_info[0].address.as_deref(),
        Some("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    );

    let response = app.sign_request_v2(request_v2()).await.unwrap();
    assert_eq!(response.payload, "0xresolved");
    assert_eq!(
        response.signatures[0].address,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    assert_eq!(response.debug_info.unwrap().dvn_hash_call_data, "0xfeed");
}

/// The signer, the packet resolver and `/metrics` must all record into one
/// registry. If the app renders a different object than the one handed to the
/// dependencies, every signer/provider error metric silently reads zero.
#[tokio::test]
async fn runtime_server_app_renders_the_metrics_registry_it_was_given() {
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": "0x1"})),
            Ok(json!({"result": "0x38"})),
        ])),
    };
    let shared_metrics = Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new()));
    let app = RuntimeServerApp::from_env_map_with_core_dependencies(
        HashMap::from([
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (SERVER_PORT.to_string(), "3000".to_string()),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                r#"["V2","V301"]"#.to_string(),
            ),
            (
                pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                "bsc".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#.to_string(),
            ),
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
        ]),
        transport,
        || 777,
        RuntimeCoreAppDependencies {
            hash_call_data_builders: HashMap::from([(
                "V302".to_string(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            )]),
            sent_event_resolver: Arc::new(FixedResolver),
            validator: Arc::new(NoopValidator),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
        },
        HashMap::from([("bsc".to_string(), "EVM".to_string())]),
        RuntimeMode::Production,
        Arc::new(crate::provider_health::ProviderRankTracker::new()),
        None,
        crate::provider_snapshot::ProviderSnapshotHandle::new(
            serde_json::from_str(r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#)
                .unwrap(),
            vec!["bsc".to_string()],
        ),
        shared_metrics.clone(),
    )
    .await
    .unwrap();

    shared_metrics.lock().await.record_signer_error("kms_aws");
    shared_metrics
        .lock()
        .await
        .record_provider_request_error("bsc", "quorum");

    let rendered = pillar_api::ServerApp::metrics(&app)
        .expect("runtime app exposes its metrics registry")
        .lock()
        .await
        .render_prometheus("mainnet", "test-version");

    assert!(rendered.contains("pillar_signer_errors_total{backend=\"kms_aws\"} 1"));
    assert!(
        rendered.contains("pillar_provider_request_errors_total{chain=\"bsc\",kind=\"quorum\"} 1")
    );
}

#[tokio::test]
async fn runtime_server_app_refuses_provider_config_it_could_never_sign_with() {
    // Each of these used to boot. A chain with no URI then reported `/ready` as
    // READY and `/provider-health` as healthy - the snapshot treats an empty
    // provider list as healthy, which is upstream behaviour (TS:
    // `apps/gasolina/src/app/app.ts:318`) - while every sign request for it
    // failed with "No provider URI for chain bsc". A zero quorum was silently
    // raised to 1, so the operator got a single-provider trust root they did
    // not ask for.
    let cases = [
        (
            r#"{"bsc":{"uris":[],"quorum":1}}"#,
            "No provider URI for chain bsc",
        ),
        (
            r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":0}}"#,
            "Provider quorum 0 for chain bsc",
        ),
        (
            r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":2}}"#,
            "Provider quorum 2 exceeds 1 URIs for chain bsc",
        ),
    ];

    for (provider_config, expected) in cases {
        let transport = RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "0x38"}))])),
        };
        let error = RuntimeServerApp::from_env_map(
            HashMap::from([
                (SERVER_PORT.to_string(), "3000".to_string()),
                (
                    pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                    "test-token-0123456789abcdef0123456789".to_string(),
                ),
                (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
                (LZ_ENV.to_string(), "mainnet".to_string()),
                (
                    pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                    r#"["V2","V301"]"#.to_string(),
                ),
                (
                    pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                    "bsc".to_string(),
                ),
                (LZ_PROVIDER_CONFIG.to_string(), provider_config.to_string()),
            ]),
            transport,
            || 777,
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("{provider_config} must be refused at startup"));

        assert!(
            error.contains(expected),
            "{provider_config}: expected {expected:?}, got {error:?}"
        );
    }
}

#[tokio::test]
async fn runtime_server_app_refuses_a_chain_selection_that_matches_nothing() {
    // Upstream matches the CSV verbatim with no trim (TS:
    // `apps/gasolina/src/index.ts:288-292`), so " bsc" selects nothing. The
    // parsing stays; booting with zero operational chains does not.
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "0x38"}))])),
    };
    let error = RuntimeServerApp::from_env_map(
        HashMap::from([
            (SERVER_PORT.to_string(), "3000".to_string()),
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
                r#"["V2","V301"]"#.to_string(),
            ),
            (
                pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                " bsc".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#.to_string(),
            ),
        ]),
        transport,
        || 777,
    )
    .await
    .err()
    .expect("a selection that matches nothing must be refused at startup");

    assert!(
        error.contains("no operational chains remain"),
        "unexpected error: {error:?}"
    );
}
