//! A3: an EVM-sent ULN V2 packet to an Aptos receiver still on ULN V2, signed as upstream signs
//! it: `hashPropose(lookupHash, confirmations, expiration)` for the destination's V1 oracle, with
//! `skipVId` (`scripts/gasolina-parity/emit-aptos-ulnv2-destination.ts`,
//! `tests/gasolina_parity/aptos_ulnv2_destination.json`, upstream's own routing, feather proof,
//! vId, builder and signer adapter). Replayed through the production resolver, router, builders,
//! vId table, local-mnemonic signer and HTTP layer; block timestamp, readiness and extra context
//! are supplied, as in the historical-pathway comparison. What this does not show: that the
//! Aptos oracle accepts the signature on chain.

use super::gasolina_parity_tests::historical_signer;
use super::*;
use tower::ServiceExt;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/aptos_ulnv2_destination.json");
const SOURCE_RPC: &str = "https://src.example/";
const APTOS_RPC: &str = "https://aptos.example/v1";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn source_tx_hash() -> String {
    format!("0x{}", "5a".repeat(32))
}

fn source_block_hash() -> String {
    format!("0x{}", "b1".repeat(32))
}

fn src_chain(environment: &str) -> &'static str {
    if environment == "mainnet" {
        "ethereum"
    } else {
        "sepolia"
    }
}

/// Answers by what is asked: the source receipt and the Aptos `get_receive_msglib` view.
#[derive(Clone)]
struct A3Transport {
    receipt: Arc<Value>,
    receive_msglib: Arc<Value>,
    views: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl JsonRpcTransport for A3Transport {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if body["method"] == "eth_getTransactionReceipt" {
            return Ok(json!({"jsonrpc": "2.0", "id": 1, "result": (*self.receipt).clone()}));
        }
        if url.ends_with("/view")
            && body["function"]
                .as_str()
                .is_some_and(|function| function.ends_with("::endpoint_view::get_receive_msglib"))
        {
            self.views.lock().unwrap().push(body);
            return Ok((*self.receive_msglib).clone());
        }
        Err(format!("unrecorded request {url} {body}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unrecorded GET {url}"))
    }
}

fn providers(environment: &str) -> StaticProviderConfig {
    let names = vec![src_chain(environment).to_string(), "aptos".to_string()];
    StaticProviderConfig::new(
        IndexMap::from([
            (
                names[0].clone(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(SOURCE_RPC.to_string())],
                    1,
                ),
            ),
            (
                "aptos".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(APTOS_RPC.to_string())],
                    1,
                ),
            ),
        ]),
        Some(&names),
    )
    .unwrap()
}

/// Upstream's routing rows through the real quorum-backed lookup: same view, same arguments in
/// Aptos's JSON encoding, same ULN version.
#[tokio::test]
async fn aptos_receive_routing_matches_upstream_get_uln_receive_details() {
    let fixture = fixture();
    let rows = fixture["routing"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let environment = row["environment"].as_str().unwrap();
        let names = vec![src_chain(environment).to_string(), "aptos".to_string()];
        let getter = providers(environment);
        let views = Arc::new(Mutex::new(Vec::new()));
        let transport = A3Transport {
            receipt: Arc::new(Value::Null),
            receive_msglib: Arc::new(row["answer"].clone()),
            views: views.clone(),
        };
        let checks = runtime_rpc_validation_checks_from_evm_config(
            &ProviderSnapshotHandle::from_getter(&getter),
            transport,
            environment,
            &names,
        )
        .unwrap();
        let upstream = &row["calls"][0];
        let mut extra = IndexMap::new();
        for key in ["srcEid", "dstEid"] {
            let pathway = &fixture["payloads"]
                .as_array()
                .unwrap()
                .iter()
                .find(|payload| payload["environment"] == environment)
                .unwrap();
            extra.insert(key.to_string(), pathway[key].clone());
        }
        extra.insert(
            "sender".to_string(),
            Value::from("0x50002cdfe7ccb0c41f519c6eb0653158d11cd907"),
        );
        extra.insert(
            "receiver".to_string(),
            upstream["functionArguments"][0].clone(),
        );
        let lz_message_id = LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: names[0].clone(),
                dst_chain_name: "aptos".to_string(),
                extra,
            },
            nonce: 7,
            uln_send_version: Value::from("V2"),
        };
        let version = checks.uln_receive_version(&lz_message_id).await.unwrap();
        assert_eq!(
            version, row["outcome"]["ulnVersion"],
            "{environment} {}",
            row["answer"]
        );
        let views = views.lock().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0]["function"], upstream["function"]);
        assert_eq!(
            views[0]["arguments"],
            json!([
                upstream["functionArguments"][0],
                upstream["functionArguments"][1].to_string()
            ]),
            "u64 as a JSON string, as the Aptos view API requires"
        );
    }
}

/// The real checks for routing and payload-signed; the chain-time answers supplied.
struct A3Checks<T: JsonRpcTransport> {
    real: RuntimeRpcValidationChecks<T>,
    current_timestamp: i64,
}

#[async_trait]
impl<T: JsonRpcTransport> RuntimeValidationChecks for A3Checks<T> {
    async fn current_block_timestamp(
        &self,
        _: &str,
        _: ExpirationValidRange,
    ) -> Result<i64, AppCoreError> {
        Ok(self.current_timestamp)
    }

    async fn validate_readiness(
        &self,
        _: &LzSentEvent,
        _: &SigningContext,
    ) -> Result<Vec<pillar_core::ReadBlockPin>, AppCoreError> {
        Ok(Vec::new())
    }

    async fn validate_payload_not_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: Option<&str>,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        self.real
            .validate_payload_not_signed(sent_event, verifier_address, dst_chain_name)
            .await
    }

    async fn validate_extra_context(
        &self,
        _: &LzSentEvent,
        _: &SigningContext,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }

    async fn uln_receive_version(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError> {
        self.real.uln_receive_version(lz_message_id).await
    }
}

/// `UltraLightNodeV2.send`'s `RelayerParams` and `Packet` logs for the row's packet.
fn uln_v2_receipt(environment: &str, row: &Value) -> Value {
    let uln = pillar_config::layerzero_contract_address(
        src_chain(environment),
        environment,
        "UltraLightNodeV2",
    )
    .unwrap()
    .to_lowercase();
    let payload = row["packetPayload"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x")
        .to_string();
    let words = (payload.len() / 2).div_ceil(32);
    let data = format!(
        "0x{:064x}{:064x}{payload:0<width$}",
        0x20,
        payload.len() / 2,
        width = words * 64
    );
    let relayer_params = format!(
        "0x{:064x}{:064x}{:064x}0001{:064x}{}",
        0x40,
        2,
        34,
        200_000,
        "0".repeat(60)
    );
    let transaction_hash = source_tx_hash();
    let block_hash = source_block_hash();
    json!({
        "transactionHash": transaction_hash,
        "blockHash": block_hash,
        "blockNumber": "0x60",
        "status": "0x1",
        "logs": [
            {"address": uln, "transactionHash": transaction_hash, "blockHash": block_hash, "blockNumber": "0x60", "removed": false, "logIndex": "0x0", "topics": [pillar_layerzero::ULN_V2_RELAYER_PARAMS_TOPIC], "data": relayer_params},
            {"address": uln, "transactionHash": transaction_hash, "blockHash": block_hash, "blockNumber": "0x60", "removed": false, "logIndex": "0x1", "topics": [pillar_layerzero::LEGACY_ULN_V2_PACKET_TOPIC], "data": data},
        ],
    })
}

fn request_for(row: &Value, skip_v_id: Option<bool>, message_hash: &str) -> Value {
    let pathway = &row["sentEvent"]["lzMessageId"]["pathwayId"];
    let mut signing_context = json!({
        "expiration": row["expiration"],
        "blockConfirmation": row["blockConfirmation"],
        "dvnAddress": "0x589dEDbD617e0CBcB916A9223F4d1300c294236b",
        "protocolType": "MESSAGE",
    });
    if let Some(skip) = skip_v_id {
        signing_context["skipVId"] = Value::from(skip);
    }
    json!({
        "srcTxHash": source_tx_hash(),
        "lzMessageId": {
            "pathwayId": pathway,
            "nonce": row["nonce"],
            "ulnSendVersion": "V2",
        },
        "messageHash": message_hash,
        "signingContext": signing_context,
    })
}

struct A3Outcome {
    status: u16,
    body: Value,
    signer_calls: usize,
    receive_msglib_reads: usize,
}

/// The production service for one row, answered with `receive_msglib` for the routing view.
async fn sign_through_http(
    row: &Value,
    receive_msglib: Value,
    skip_v_id: Option<bool>,
    mutate: impl FnOnce(&mut Value),
) -> A3Outcome {
    let environment = row["environment"].as_str().unwrap();
    let src = src_chain(environment);
    let names = vec![src.to_string(), "aptos".to_string()];
    let getter = providers(environment);
    let snapshot = ProviderSnapshotHandle::from_getter(&getter);
    let views = Arc::new(Mutex::new(Vec::new()));
    let transport = A3Transport {
        receipt: Arc::new(uln_v2_receipt(environment, row)),
        receive_msglib: Arc::new(receive_msglib),
        views: views.clone(),
    };
    let real = runtime_rpc_validation_checks_from_evm_config(
        &snapshot,
        transport.clone(),
        environment,
        &names,
    )
    .unwrap();
    let recorder = Arc::new(RuntimeLayerZeroRecorder::default());
    let parts = runtime_layerzero_parts_from_evm_config(
        &snapshot,
        transport,
        environment,
        &names,
        RuntimeLayerZeroDependencyInputs {
            uln_v2_payload_builder: recorder.clone(),
            read_payload_resolver: recorder.clone(),
            validation_checks: Arc::new(A3Checks {
                real,
                current_timestamp: row["expiration"].as_i64().unwrap() - 100,
            }),
            legacy_chain_name_resolver: Arc::new(FixedChainResolver),
            metrics: Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new())),
        },
    )
    .unwrap();
    let resolver = parts.sent_event_resolver.clone();
    let request_id: LzMessageId = serde_json::from_value(json!({
        "pathwayId": row["sentEvent"]["lzMessageId"]["pathwayId"],
        "nonce": row["nonce"],
        "ulnSendVersion": "V2",
    }))
    .unwrap();
    let sent_event = resolver
        .get_lz_sent_event(&format!("0x{}", "5a".repeat(32)), &request_id)
        .await
        .unwrap();
    let message_hash = pillar_core::hash_sent_event_message_for_pillar(&sent_event).unwrap();
    let assembly = historical_signer("aptos", "APTOS").await.unwrap();
    let signer_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dependencies = runtime_core_dependencies_from_layerzero_parts(
        parts,
        runtime_v_id_by_chain_name(environment, &names).unwrap(),
    );
    let mut provider_health = ProviderHealthSnapshot::new();
    for name in &names {
        provider_health.insert(name.clone(), true);
    }
    let app = core_api_app_from_runtime_parts(RuntimeCoreAppParts {
        runtime_config: RuntimeConfig {
            server_port: 0,
            provider_config_type: pillar_config::ProviderConfigType::LOCAL,
            environment: Some(environment.to_string()),
            available_chain_names: Some(names.clone()),
            debug_mode: false,
            extra_context_request_url: None,
            extra_context_request_auth_token: None,
            extra_context_aws_lambda_name: None,
            image_version: None,
            api_auth_tokens: vec!["test-token-0123456789abcdef0123456789".to_string()],
            api_auth_enabled: true,
            public_sign_routes: false,
            max_connections: 16,
            shutdown_grace_seconds: 5,
            shutdown_withdrawal: std::time::Duration::from_secs(1),
            execution_limits: pillar_config::ExecutionLimits::default(),
            audit: None,
        },
        available_chain_names: Arc::new(names.clone()),
        wallets_by_chain_name: HashMap::from([(
            "aptos".to_string(),
            vec![WalletRef {
                wallet_name: "wallet-APTOS".to_string(),
            }],
        )]),
        signer_getter: Arc::new(CountingA3Signer {
            inner: assembly.signer_getter,
            calls: signer_calls.clone(),
        }),
        signer_info: BTreeMap::new(),
        provider_health,
        provider_health_report: json!({}),
        dependencies,
        metrics: Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new())),
    });
    let mut request = request_for(row, skip_v_id, &message_hash);
    mutate(&mut request);
    let response = pillar_api::router(app.with_public_sign_routes(true), "parity")
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v2/resolve-and-sign")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap(),
    )
    .unwrap();
    let receive_msglib_reads = views.lock().unwrap().len();
    A3Outcome {
        status,
        body,
        signer_calls: signer_calls.load(std::sync::atomic::Ordering::SeqCst),
        receive_msglib_reads,
    }
}

struct CountingA3Signer {
    inner: Arc<dyn SignerGetter>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl SignerGetter for CountingA3Signer {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<pillar_core::Signature, AppCoreError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner
            .pillar_sign(dst_chain_name, wallet_name, data_hex)
            .await
    }
}

/// Every upstream row through the production HTTP path: with `skipVId` the response carries
/// upstream's signature over upstream's `hashPropose` digest, byte for byte; with a vId it is
/// upstream's `VId is not supported on aptos yet` and nothing is signed.
#[tokio::test]
async fn evm_uln_v2_to_aptos_signs_like_gasolina_through_http() {
    let fixture = fixture();
    let rows = fixture["payloads"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    let mut signed = 0;
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let skip = row["skipVId"].as_bool().unwrap();
        let outcome = sign_through_http(row, json!(["1", 0]), Some(skip), |_| {}).await;
        assert_eq!(
            outcome.receive_msglib_reads, 1,
            "{name}: routed by the Aptos receive library"
        );
        if skip {
            let expected = json!({
                "statusCode": 200,
                "body": {
                    "signatures": [{
                        "signature": row["outcome"]["signed"]["signature"],
                        "address": row["outcome"]["signed"]["signerAddress"],
                    }],
                    "payload": row["message"],
                },
            });
            assert_eq!((outcome.status, &outcome.body), (200, &expected), "{name}");
            assert_eq!(outcome.signer_calls, 1, "{name}");
            // Equal bytes from the same key over the same data: the local mnemonic signs Aptos
            // with Ed25519 (`gasolina-signer-adapter/src/aptos/index.ts:16-18`), deterministic, so
            // this is upstream's own `hashPropose` digest. The oracle verifies secp256k1 only (v44
            // static reading); a KMS signature, not exercised offline, is the only kind it could
            // accept, and no acceptance has been observed on chain.
            signed += 1;
        } else {
            assert_eq!(row["outcome"]["error"], "VId is not supported on aptos yet");
            assert_eq!(
                (outcome.status, &outcome.body),
                (
                    500,
                    &json!({"statusCode": 500, "body": "VId is not supported on aptos yet"})
                ),
                "{name}"
            );
            assert_eq!(outcome.signer_calls, 0, "{name}");
        }
    }
    assert_eq!(signed, 4);
}

/// Pillar's bounded conditions, each refused before the signer.
#[tokio::test]
async fn a3_is_fail_closed_outside_its_identity() {
    let fixture = fixture();
    let mainnet = fixture["payloads"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "mainnet skipVId")
        .unwrap()
        .clone();

    // A receiver migrated to ULN301 routes to the V3 builder, which never takes a vId-less
    // request: refused right after routing, before resolution and before the already-signed
    // check, with or without a `dvnAddress`. Neither signs.
    for keep_dvn_address in [false, true] {
        let outcome = sign_through_http(&mainnet, json!(["2", 0]), Some(true), |request| {
            if !keep_dvn_address {
                request["signingContext"]
                    .as_object_mut()
                    .unwrap()
                    .remove("dvnAddress");
            }
        })
        .await;
        assert_eq!(
            (outcome.status, &outcome.body),
            (
                400,
                &json!({"statusCode": 400, "body": "skipVId is not supported for v2 requests"})
            ),
            "dvnAddress kept: {keep_dvn_address}"
        );
        assert_eq!(
            (outcome.signer_calls, outcome.receive_msglib_reads),
            (0, 1),
            "dvnAddress kept: {keep_dvn_address}"
        );
    }

    // Another destination or send version keeps the HTTP refusal.
    for (field, value) in [("dstChainName", "movement"), ("ulnSendVersion", "V302")] {
        let outcome = sign_through_http(&mainnet, json!(["1", 0]), Some(true), |request| {
            if field == "dstChainName" {
                request["lzMessageId"]["pathwayId"][field] = Value::from(value);
            } else {
                request["lzMessageId"][field] = Value::from(value);
            }
        })
        .await;
        assert_eq!(
            (outcome.status, &outcome.body),
            (
                400,
                &json!({"statusCode": 400, "body": "skipVId is not supported for v2 requests"})
            ),
            "{field}={value}"
        );
        assert_eq!(
            (outcome.signer_calls, outcome.receive_msglib_reads),
            (0, 0),
            "{field}={value}"
        );
    }
}
