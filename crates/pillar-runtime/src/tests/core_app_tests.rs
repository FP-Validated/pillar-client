use super::*;
use pillar_metrics::PillarMetrics;

#[tokio::test]
async fn runtime_core_dependencies_from_layerzero_parts_uses_layerzero_builder_factory() {
    let recorder = Arc::new(RuntimeLayerZeroRecorder::default());
    let checks = Arc::new(FixedValidationChecks {
        current_timestamp: 100,
        calls: Arc::new(Mutex::new(Vec::new())),
        ranges: Arc::new(Mutex::new(Vec::new())),
    });
    let recorder_for_uln_v2 = recorder.clone();
    let recorder_for_uln_v3 = recorder.clone();
    let recorder_for_uln_read = recorder.clone();
    let recorder_for_read = recorder.clone();
    let uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder> = recorder_for_uln_v2;
    let uln_v3_payload_builder: Arc<dyn UlnV3PayloadBuilder> = recorder_for_uln_v3;
    let uln_read_v1_payload_builder: Arc<dyn UlnReadV1PayloadBuilder> = recorder_for_uln_read;
    let read_payload_resolver: Arc<dyn ReadPayloadResolver> = recorder_for_read;
    let dependencies = runtime_core_dependencies_from_layerzero_parts(
        RuntimeLayerZeroDependencyParts {
            uln_v2_payload_builder,
            uln_v3_payload_builder,
            uln_read_v1_payload_builder,
            read_payload_resolver,
            sent_event_resolver: Arc::new(FixedResolver),
            validation_checks: checks.clone(),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
        },
        "mainnet",
        &["V2".to_string(), "V301".to_string()],
    );

    assert!(dependencies.hash_call_data_builders.contains_key("V2"));
    assert!(dependencies.hash_call_data_builders.contains_key("V301"));
    assert!(dependencies.hash_call_data_builders.contains_key("V302"));
    assert!(dependencies
        .hash_call_data_builders
        .contains_key("ReadV1002"));
    assert_eq!(dependencies.hash_call_data_builders.len(), 4);

    let request = request_v2();
    let mut lz_message_id = request.lz_message_id;
    lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(30_102_u64));
    let sent_event = LzSentEvent {
        lz_message_id,
        message: "0xabc".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::new(),
    };
    let result = dependencies.hash_call_data_builders["V302"]
        .build_dvn_hash_call_data(
            &sent_event,
            &SigningContext::Message {
                expiration: 9,
                skip_v_id: None,
                dvn_address: Some("0xdvn".to_string()),
                block_confirmation: 2,
            },
        )
        .await
        .unwrap();

    assert_eq!(result.hash_call_data, "0xv3");
    assert_eq!(
        recorder.calls.lock().await.as_slice(),
        &["v3:2:9:102:0xdvn".to_string()]
    );

    dependencies
        .validator
        .validate_expiration("bsc", 100)
        .await
        .unwrap();
    assert_eq!(
        checks.ranges.lock().unwrap().as_slice(),
        &[ExpirationValidRange {
            min: 100 - DEFAULT_MAXIMUM_EXPIRATION_SECONDS,
            max: 100 + DEFAULT_MAXIMUM_EXPIRATION_GRACE_PERIOD_SECONDS,
        }]
    );
}

#[test]
fn runtime_core_dependencies_apply_supported_ulns_only_to_legacy_builders() {
    let recorder = Arc::new(RuntimeLayerZeroRecorder::default());
    let dependencies = runtime_core_dependencies_from_layerzero_parts(
        RuntimeLayerZeroDependencyParts {
            uln_v2_payload_builder: recorder.clone(),
            uln_v3_payload_builder: recorder.clone(),
            uln_read_v1_payload_builder: recorder.clone(),
            read_payload_resolver: recorder,
            sent_event_resolver: Arc::new(FixedResolver),
            validation_checks: Arc::new(FixedValidationChecks {
                current_timestamp: 100,
                calls: Arc::new(Mutex::new(Vec::new())),
                ranges: Arc::new(Mutex::new(Vec::new())),
            }),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
        },
        "mainnet",
        &[],
    );

    assert!(!dependencies.hash_call_data_builders.contains_key("V2"));
    assert!(!dependencies.hash_call_data_builders.contains_key("V301"));
    assert!(dependencies.hash_call_data_builders.contains_key("V302"));
    assert!(dependencies
        .hash_call_data_builders
        .contains_key("ReadV1002"));
}

/// The production assembler's inputs, shared by the tests below so that a
/// composition defect shows up in every one of them rather than in whichever
/// test happened to rebuild the literal.
fn runtime_core_app_parts(metrics: Arc<tokio::sync::Mutex<PillarMetrics>>) -> RuntimeCoreAppParts {
    let mut provider_health = ProviderHealthSnapshot::new();
    provider_health.insert("ethereum".to_string(), true);
    provider_health.insert("bsc".to_string(), true);
    RuntimeCoreAppParts {
        runtime_config: RuntimeConfig {
            server_port: 3000,
            provider_config_type: pillar_config::ProviderConfigType::LOCAL,
            environment: Some("mainnet".to_string()),
            available_chain_names: Some(vec!["ethereum".to_string(), "bsc".to_string()]),
            supported_uln_versions: vec!["V2".to_string(), "V301".to_string()],
            debug_mode: true,
            extra_context_request_url: None,
            extra_context_request_auth_token: None,
            extra_context_aws_lambda_name: None,
            image_version: None,
            api_auth_tokens: vec!["test-token-0123456789abcdef0123456789".to_string()],
            max_connections: 1024,
            shutdown_grace_seconds: 25,
        },
        available_chain_names: Arc::new(vec!["ethereum".to_string(), "bsc".to_string()]),
        wallets_by_chain_name: HashMap::from([(
            "bsc".to_string(),
            vec![WalletRef {
                wallet_name: "wallet-1".to_string(),
            }],
        )]),
        signer_getter: Arc::new(FixedSigner),
        signer_info: BTreeMap::from([(
            "bsc".to_string(),
            vec![SignerInfo {
                address: Some("0xsigner".to_string()),
                public_key: Some("0xpublic".to_string()),
            }],
        )]),
        provider_health,
        provider_health_report: json!({
            "bsc": {
                "healthy": true
            }
        }),
        dependencies: RuntimeCoreAppDependencies {
            hash_call_data_builders: HashMap::from([(
                "V302".to_string(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            )]),
            sent_event_resolver: Arc::new(FixedResolver),
            validator: Arc::new(NoopValidator),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
        },
        metrics,
    }
}

#[tokio::test]
async fn core_api_app_from_runtime_parts_assembles_working_server_app() {
    let app = core_api_app_from_runtime_parts(runtime_core_app_parts(Arc::new(
        tokio::sync::Mutex::new(PillarMetrics::new()),
    )));

    assert_eq!(
        app.get_available_chain_names(),
        vec!["ethereum".to_string(), "bsc".to_string()]
    );
    assert_eq!(app.get_environment(), "mainnet");
    assert_eq!(
        app.get_signer_info("bsc".to_string()).await.unwrap()[0]
            .address
            .as_deref(),
        Some("0xsigner")
    );
    assert!(app.get_provider_health().await.unwrap()["bsc"]);
    assert_eq!(
        app.get_provider_health_report().await.unwrap()["bsc"]["healthy"],
        true
    );

    let response = app.sign_request_v2(request_v2()).await.unwrap();
    assert_eq!(response.payload, "0xresolved");
    assert_eq!(response.signatures[0].signature, "sig:bsc:wallet-1:0xfeed");
    assert_eq!(response.debug_info.unwrap().dvn_hash_call_data, "0xfeed");
}

/// The stage histogram is documented at `README.md:237-239` and shipped in the
/// snapshot fixture, so an operator builds dashboards on it. That only holds if
/// the *production* assembler injects a real observer: a unit test that calls
/// the observer directly proves the observer works and says nothing about
/// whether anything ever calls it. This test drives the assembler the
/// composition root uses and then reads the HTTP surface's own registry.
#[tokio::test]
async fn production_composition_records_every_sign_stage() {
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let app = core_api_app_from_runtime_parts(runtime_core_app_parts(metrics.clone()));

    app.sign_request_v2(request_v2()).await.unwrap();

    let rendered = metrics
        .lock()
        .await
        .render_prometheus("mainnet", "test-version");
    assert!(
        rendered.contains("pillar_sign_stage_duration_seconds"),
        "the family the README documents is absent from /metrics: {rendered}"
    );
    for stage in ["get_sent_event", "validate", "build_hash_call_data", "sign"] {
        assert!(
            rendered.contains(&format!("stage=\"{stage}\"")),
            "stage {stage} recorded nothing: {rendered}"
        );
    }
    assert!(
        rendered.contains("src_chain=\"ethereum\"") && rendered.contains("dst_chain=\"bsc\""),
        "the pathway labels are missing or transposed: {rendered}"
    );
}
