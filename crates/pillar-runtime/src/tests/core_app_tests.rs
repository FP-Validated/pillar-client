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

/// The stage histogram is documented in `README.md` and shipped in the
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

/// Answers by JSON-RPC method rather than by call order, so these tests do not
/// silently encode the sequence the runtime happens to use today. An unstubbed method
/// is an error naming itself, which is how this fixture set was discovered.
#[derive(Clone)]
struct VerticalTransport {
    calls: RecordedJsonCalls,
    receipt: Arc<Mutex<Option<Value>>>,
    dst_receive_uln_302: &'static str,
}

#[async_trait]
impl JsonRpcTransport for VerticalTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url, headers, body.clone()));
        match body["method"].as_str().unwrap_or_default() {
            "eth_getTransactionReceipt" => self
                .receipt
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| "receipt unavailable".to_string()),
            "eth_blockNumber" => Ok(json!({"result": "0x64"})),
            "eth_chainId" => Ok(json!({"result": "0x1"})),
            "eth_getBlockByNumber" => {
                Ok(json!({"result": {"number": "0x64", "timestamp": "0x6862d3a5"}}))
            }
            "eth_getTransactionByHash" => {
                Ok(json!({"result": {"from": "0x1111111111111111111111111111111111111111"}}))
            }
            // Selectors verified against the signatures the production call-data
            // builders use, by an independent Keccak-256 that reproduces the
            // well-known empty-input digest
            // 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470:
            //   0x402f8468 getReceiveLibrary(address,uint32)
            //   0x43ea4fa9 getUlnConfig(address,uint32)
            //   0x3c782a52 hashLookup(bytes32,bytes32,address)
            "eth_call" => {
                let data = body["params"][0]["data"].as_str().unwrap_or_default();
                match &data[..data.len().min(10)] {
                    // -> (address lib, bool isDefault)
                    "0x402f8468" => Ok(json!({"result": format!(
                        "0x{:0>64}{:0>64}",
                        self.dst_receive_uln_302[2..].to_lowercase(),
                        "1"
                    )})),
                    // one word read as the required confirmations (`abi.rs:344-350`)
                    "0x43ea4fa9" => Ok(json!({"result": format!("0x{:0>64}", "1")})),
                    // -> (bool submitted, uint64 confirmations) (`abi.rs:305-308`).
                    // Not yet submitted, which is what makes this payload signable.
                    "0x3c782a52" => Ok(json!({"result": format!("0x{}", "0".repeat(128))})),
                    _ => Ok(json!({"result": format!("0x{}", "0".repeat(64))})),
                }
            }
            other => Err(format!("unstubbed method {other}: {body}")),
        }
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url, headers, json!({"method": "GET"})));
        Err("unexpected GET on the EVM vertical".to_string())
    }
}

/// The addresses the production wiring actually trusts, per environment
/// (`layerzero_runtime/config/evm.rs:70-92` reads them from the generated deployment
/// table). The shared PacketSent fixture carries placeholder addresses that only the
/// hand-built resolver configs trust, so a vertical test that reuses it unchanged never
/// gets past the trusted-emitter check.
struct VerticalEnvironment {
    environment: &'static str,
    src_chain: &'static str,
    dst_chain: &'static str,
    src_eid: u32,
    dst_eid: u32,
    src_endpoint_v2: &'static str,
    src_send_uln_302: &'static str,
    dst_receive_uln_302: &'static str,
}

const MAINNET_VERTICAL: VerticalEnvironment = VerticalEnvironment {
    environment: "mainnet",
    src_chain: "ethereum",
    dst_chain: "bsc",
    src_eid: 30_101,
    dst_eid: 30_102,
    src_endpoint_v2: "0x1a44076050125825900e736c501f859c50fE728c",
    src_send_uln_302: "0xbB2Ea70C9E858123480642Cf96acbcCE1372dCe1",
    dst_receive_uln_302: "0xB217266c3A98C8B2709Ee26836C98cf12f6cCEC1",
};

/// Testnet is not mainnet with different numbers: `ethereum` has a testnet endpoint id
/// but no testnet deployment rows, so the production wiring rejects it there. `sepolia`
/// is the testnet source that does carry the full contract set.
const TESTNET_VERTICAL: VerticalEnvironment = VerticalEnvironment {
    environment: "testnet",
    src_chain: "sepolia",
    dst_chain: "bsc",
    src_eid: 40_161,
    dst_eid: 40_102,
    src_endpoint_v2: "0x6EDCE65403992e310A62460808c4b910D972f10f",
    src_send_uln_302: "0xcc1ae8Cf5D3904Cef3360A9532B477529b177cCE",
    dst_receive_uln_302: "0x188d4bbCeD671A7aA2b5055937F79510A32e9683",
};

fn vertical_receipt(env: &VerticalEnvironment) -> Value {
    let raw = serde_json::to_string(&packet_sent_endpoint_v2_data())
        .expect("the fixture serialises")
        .replace(
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            &env.src_endpoint_v2.to_lowercase(),
        )
        .replace(
            "0000000000000000000000003333333333333333333333333333333333333333",
            &format!(
                "000000000000000000000000{}",
                env.src_send_uln_302[2..].to_lowercase()
            ),
        )
        .replace("00007595", &format!("{:08x}", env.src_eid))
        .replace("00007596", &format!("{:08x}", env.dst_eid));
    let mut result: Value = serde_json::from_str(&raw).expect("the rewrite stays valid JSON");
    // The readiness check reads the receipt's own block, then compares it against
    // `eth_blockNumber`/`eth_getBlockByNumber`. 0x60 against a latest of 0x64 leaves
    // more than the single confirmation the request asks for.
    result["blockNumber"] = Value::from("0x60");
    result["blockHash"] =
        Value::from("0xabababababababababababababababababababababababababababababababab");
    json!({"result": result})
}

/// The request the observable names: a guid, a dvnAddress and extra context.
fn vertical_request(env: &VerticalEnvironment) -> PillarApiRequestV2 {
    let mut request = request_v2();
    request.lz_message_id = evm_packet_sent_request("V302");
    request.lz_message_id.pathway_id.src_chain_name = env.src_chain.to_string();
    request.lz_message_id.pathway_id.dst_chain_name = env.dst_chain.to_string();
    let extra = &mut request.lz_message_id.pathway_id.extra;
    extra.insert("srcEid".to_string(), Value::from(env.src_eid));
    extra.insert("dstEid".to_string(), Value::from(env.dst_eid));
    request.signing_context = SigningContext::Message {
        expiration: 1_751_500_000,
        skip_v_id: None,
        dvn_address: Some("0x4444444444444444444444444444444444444444".to_string()),
        block_confirmation: 1,
    };
    // The caller-supplied hash the request must agree with: `keccak256(0xdeadbeef)`,
    // the message carried by the shared PacketSent fixture
    // (`hash_sent_event_message_for_pillar`, pillar-core/src/lib.rs:778-789). Verified
    // against an independent Keccak-256 implementation, so this literal is not a copy
    // of whatever this crate happens to compute.
    request.message_hash =
        "0xd4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1".to_string();
    request
}

fn vertical_env_map(env: &VerticalEnvironment) -> HashMap<String, String> {
    HashMap::from([
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
            "test-token-0123456789abcdef0123456789".to_string(),
        ),
        (SERVER_PORT.to_string(), "3000".to_string()),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), env.environment.to_string()),
        (
            pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
            r#"["V2","V301","V302"]"#.to_string(),
        ),
        (pillar_config::LZ_DEBUG_MODE.to_string(), "true".to_string()),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            format!("{},{}", env.src_chain, env.dst_chain),
        ),
        (
            LZ_PROVIDER_CONFIG.to_string(),
            format!(
                r#"{{"{}":{{"uris":["https://src-rpc.example"],"quorum":1}},"{}":{{"uris":["https://dst-rpc.example"],"quorum":1}}}}"#,
                env.src_chain, env.dst_chain
            ),
        ),
        (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
        (
            pillar_config::LZ_WALLETS.to_string(),
            config_wallet_json("wallet-a", "EVM", "secret-a"),
        ),
        (
            pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            r#"{"wallet-a-EVM":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/60'/0'/0/0"}}"#.to_string(),
        ),
    ])
}

async fn vertical_app(
    env: &VerticalEnvironment,
    receipt: Option<Value>,
) -> (RuntimeServerApp<VerticalTransport>, RecordedJsonCalls) {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let transport = VerticalTransport {
        calls: calls.clone(),
        receipt: Arc::new(Mutex::new(receipt)),
        dst_receive_uln_302: env.dst_receive_uln_302,
    };
    let app =
        RuntimeServerApp::from_env_map_with_runtime_core(vertical_env_map(env), transport, || {
            1_767_323_045_000
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "the production wiring did not assemble for {}: {error}",
                env.environment
            )
        });
    (app, calls)
}

async fn stages_of(app: &RuntimeServerApp<VerticalTransport>) -> Vec<String> {
    let rendered = app
        .metrics()
        .expect("the production app exposes its registry")
        .lock()
        .await
        .render_prometheus("mainnet", "test-version");
    rendered
        .lines()
        .filter(|line| line.starts_with("pillar_sign_stage_duration_seconds_count"))
        .filter_map(|line| {
            let start = line.find("stage=\"")? + 7;
            let rest = &line[start..];
            Some(rest[..rest.find('"')?].to_string())
        })
        .collect()
}

fn observed_methods(calls: &RecordedJsonCalls) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, body)| {
            let method = body["method"].as_str().unwrap_or("?");
            match body["params"][0]["data"].as_str() {
                Some(data) => format!("{method}[sel={}]", &data[..data.len().min(10)]),
                None => method.to_string(),
            }
        })
        .collect()
}

/// The whole vertical on the production wiring: the real packet resolver, the real
/// validator, the real V302 hash-call-data builder and a real local-mnemonic signer,
/// driven by a request that carries a guid, a dvnAddress and extra context.
///
/// This test is also what makes the two error-path tests below non-vacuous: it proves a
/// `sign` sample exists when signing happens, so its absence there means something.
async fn assert_vertical_completes(env: &VerticalEnvironment) {
    let (app, calls) = vertical_app(env, Some(vertical_receipt(env))).await;

    let outcome = app.sign_request_v2(vertical_request(env)).await;

    let stages = stages_of(&app).await;
    let methods = observed_methods(&calls);
    let response = outcome.unwrap_or_else(|error| {
        panic!(
            "the {} vertical did not complete: {error}\nstages={stages:?}\nmethods={methods:?}",
            env.environment
        )
    });
    for stage in ["get_sent_event", "validate", "build_hash_call_data", "sign"] {
        assert!(
            stages.iter().any(|recorded| recorded == stage),
            "stage {stage} never ran on {}; stages={stages:?} methods={methods:?}",
            env.environment
        );
    }
    assert!(
        response.signatures.is_empty().eq(&false),
        "the {} vertical produced no signature",
        env.environment
    );
}

#[tokio::test]
async fn production_vertical_completes_every_stage_on_mainnet() {
    assert_vertical_completes(&MAINNET_VERTICAL).await;
}

#[tokio::test]
async fn production_vertical_completes_every_stage_on_testnet() {
    assert_vertical_completes(&TESTNET_VERTICAL).await;
}

/// A request that cannot be resolved must not reach the key, and must not reach the
/// validator either. Without the second half this test is satisfied by defence in depth
/// rather than by control flow: swallowing the resolution error and continuing with a
/// synthetic event also ends in no `sign` sample, because the validator rejects that
/// event anyway.
#[tokio::test]
async fn production_vertical_never_signs_when_the_source_event_cannot_be_resolved() {
    let (app, calls) = vertical_app(&MAINNET_VERTICAL, None).await;

    let outcome = app
        .sign_request_v2(vertical_request(&MAINNET_VERTICAL))
        .await;

    assert!(
        outcome.is_err(),
        "an unresolvable source event must fail the request, got {outcome:?}"
    );
    let stages = stages_of(&app).await;
    assert!(
        stages.iter().any(|stage| stage == "get_sent_event"),
        "the failing stage itself was not recorded, so this test would pass even if no \
         work happened at all; stages={stages:?}"
    );
    assert!(
        stages.iter().all(|stage| stage != "validate"),
        "the validator ran on an event that could not be resolved; stages={stages:?}"
    );
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "the signer was reached on a failed request; stages={stages:?}"
    );
    let methods = observed_methods(&calls);
    assert!(
        methods
            .iter()
            .all(|method| method.starts_with("eth_call").eq(&false)),
        "the builder ran despite an unresolved event: {methods:?}"
    );
}

/// The other half of the error path: resolution SUCCEEDS, so the vertical really does
/// reach the validator, and then validation rejects. A request that dies before the
/// validator runs proves nothing about whether a rejected validation would have been
/// signed anyway.
#[tokio::test]
async fn production_vertical_never_signs_when_validation_rejects_the_request() {
    let (app, _calls) =
        vertical_app(&MAINNET_VERTICAL, Some(vertical_receipt(&MAINNET_VERTICAL))).await;
    let mut request = vertical_request(&MAINNET_VERTICAL);
    request.message_hash =
        "0x0000000000000000000000000000000000000000000000000000000000000001".to_string();

    let outcome = app.sign_request_v2(request).await;

    assert!(
        outcome.is_err(),
        "a message-hash mismatch must fail the request, got {outcome:?}"
    );
    let stages = stages_of(&app).await;
    assert!(
        stages.iter().any(|stage| stage == "get_sent_event")
            && stages.iter().any(|stage| stage == "validate"),
        "the vertical did not reach the validator, so this test would pass without \
         proving anything; stages={stages:?}"
    );
    assert!(
        stages.iter().all(|stage| stage != "build_hash_call_data"),
        "the builder ran on a rejected request; stages={stages:?}"
    );
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "a rejected validation reached the key; stages={stages:?}"
    );
}
