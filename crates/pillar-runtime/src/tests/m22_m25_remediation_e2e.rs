//! Sentry Code audit Round 1, M-22 to M-25: one scenario per failure mode,
//! each through the production code path, each recorded as an artifact.
//!
//! * M-22: the already-signed verdict and the confirmation floor are compared
//!   with what the deployed TON `UlnConnection` code itself answers
//!   (`tests/ton_contract_semantics/confirmations.json`, emitted from that code
//!   in a TVM emulator by `scripts/ton-contract-semantics/emit-confirmations.mjs`).
//! * M-23: a committee-less Canton scan near the response cap.
//! * M-24: READ permit waits end at the request deadline.
//! * M-25: the `RawValue` re-parse cannot be reached from a request body, a
//!   body envelope or a provider response.
use super::*;
use std::time::{Duration, Instant};
use tower::ServiceExt;

const TON_SEMANTICS: &str = include_str!("../../tests/ton_contract_semantics/confirmations.json");
const RAW_VALUE_TOKEN: &str = "$serde_json::private::RawValue";
const DEPTH_CHILD: &str = "PILLAR_M25_DEPTH_CHILD";
const DEPTH_TEST: &str =
    "tests::m22_m25_remediation_e2e::m25_nested_raw_value_body_is_a_400_on_a_small_stack";

fn artifact(name: &str, value: Value) {
    audit_round_artifact("m22-m25", name, value);
}

fn semantics() -> Value {
    pillar_core::json::parse_value(TON_SEMANTICS).expect("semantics fixture parses")
}

/// The pathway of the fixture's packet: the live mainnet Ethereum -> TON pathway at
/// the nonce after the one it delivered, so the attestation's packet hash is the
/// hash this service derives.
fn ton_semantics_event(nonce: u64) -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "ton".to_string();
    event.lz_message_id.nonce = nonce;
    event.message =
        "0x00030000000000000000000000000000000000000016542ba463000000000000000000000000000000000000000000000000"
            .to_string();
    let extra = &mut event.lz_message_id.pathway_id.extra;
    extra.insert("srcEid".to_string(), Value::from(30_101));
    extra.insert("dstEid".to_string(), Value::from(30_343));
    extra.insert(
        "sender".to_string(),
        Value::from("0x1f748c76de468e9d11bd340fa9d5cbadf315dfb0"),
    );
    extra.insert(
        "receiver".to_string(),
        Value::from("0x1ddf580052174ed1dd0d66c35bfdc1a5fcc69af4f4ae36154b13dcfc6c14a35f"),
    );
    event.extra.insert(
        "guid".to_string(),
        Value::from("0xb017e830f88f78a02579795cc188eb417860be607e91924003f56c8674e408fe"),
    );
    event
}

fn ton_checks(
    responses: Vec<Result<Value, String>>,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://ton.example".to_string())],
                1,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses)),
        },
        "mainnet",
        &["ton".to_string()],
    )
    .unwrap()
    .with_evm_receive_contracts(HashMap::new())
}

fn storage(boc: &str) -> Result<Value, String> {
    Ok(json!({ "result": { "state": "active", "data": boc } }))
}

fn message_context(block_confirmation: i64) -> SigningContext {
    SigningContext::Message {
        expiration: 1,
        skip_v_id: None,
        dvn_address: Some(format!("0x{}", "aa".repeat(32))),
        block_confirmation,
    }
}

/// M-22, already-signed half: for every case the contract answers, this service's
/// verdict must be the contract's `verifiedView` at the pathway's requirement, so a
/// below-requirement attestation stays replaceable.
#[tokio::test]
async fn m22_ton_already_signed_matches_the_deployed_contract() {
    let fixture = semantics();
    let verifier = fixture["verifier"].as_str().unwrap();
    let event = ton_semantics_event(fixture["nonce"].as_u64().unwrap());
    let expected_packet = fixture["packetBoc"].as_str().unwrap();
    let mut rows = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        // committableView answers 0 (VERIFYING) in every case: the second required
        // DVN never attests, so only this DVN's attestation decides.
        assert_eq!(case["committableView"], 0, "{name}");
        let checks = ton_checks(vec![
            storage(case["connectionStorageBoc"].as_str().unwrap()),
            storage(case["ulnStorageBoc"].as_str().unwrap()),
            Ok(json!({"result": {"exit_code": 0, "stack": [["num", "0x0"]]}})),
        ]);
        let outcome = checks
            .validate_payload_not_signed(&event, Some(verifier), "ton", None)
            .await;
        let contract_counts_it = case["verifiedViewAtRequired"].as_bool().unwrap();
        let refused_as_signed = matches!(&outcome, Err(AppCoreError::BadRequest(message))
            if message.starts_with("Payload already signed"));
        assert!(
            outcome.is_ok() || refused_as_signed,
            "{name}: unexpected outcome {outcome:?}"
        );
        assert_eq!(
            refused_as_signed, contract_counts_it,
            "{name}: stored {} vs required {}: already-signed must equal the contract's verifiedView",
            case["storedConfirmations"], case["requiredConfirmations"]
        );
        rows.push(json!({
            "case": name,
            "stored": case["storedConfirmations"],
            "required": case["requiredConfirmations"],
            "contractVerifiedView": contract_counts_it,
            "pillarAlreadySigned": refused_as_signed,
        }));
    }
    let derived =
        pillar_layerzero::ton_payload_signed_targets(&pillar_layerzero::TonPayloadSignedRequest {
            src_eid: 30_101,
            dst_eid: 30_343,
            sender: "0x1f748c76de468e9d11bd340fa9d5cbadf315dfb0",
            receiver: "0x1ddf580052174ed1dd0d66c35bfdc1a5fcc69af4f4ae36154b13dcfc6c14a35f",
            guid: "0xb017e830f88f78a02579795cc188eb417860be607e91924003f56c8674e408fe",
            nonce: fixture["nonce"].as_u64().unwrap(),
            message: &event.message,
            uln_manager_address: pillar_config::ton_deployment_address("mainnet", "UlnManager")
                .unwrap(),
            code: &pillar_layerzero::TonContractCodeCells {
                uln: pillar_config::ton_code_cell("Uln").unwrap().to_string(),
                uln_connection: pillar_config::ton_code_cell("UlnConnection")
                    .unwrap()
                    .to_string(),
            },
        })
        .unwrap();
    assert_eq!(
        pillar_layerzero::boc_from_base64(&derived.packet_boc_base64).unwrap(),
        pillar_layerzero::boc_from_base64(expected_packet).unwrap(),
        "the packet this service derives is the packet the contract was asked about"
    );
    artifact(
        "m22-already-signed",
        json!({"codeHash": fixture["codeHash"], "nonce": fixture["nonce"], "cases": rows}),
    );
}

/// M-22, prevention half: a MESSAGE request below the pathway's requirement is
/// refused before any source RPC, at the requirement it passes the floor, and the
/// floor reads the effective value the contract resolves (custom, else default).
#[tokio::test]
async fn m22_ton_confirmation_floor_refuses_below_requirement_before_source_reads() {
    let fixture = semantics();
    let event = ton_semantics_event(fixture["nonce"].as_u64().unwrap());
    let mut rows = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let required = case["requiredConfirmations"].as_i64().unwrap();
        for requested in [required - 1, required] {
            if requested < 0 {
                continue;
            }
            let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
            let getter = StaticProviderConfig::new(
                IndexMap::from([(
                    "ton".to_string(),
                    ProviderConfig::with_distinct_entities(
                        vec![ProviderUri::Uri("https://ton.example".to_string())],
                        1,
                    ),
                )]),
                Some(&["ton".to_string()]),
            )
            .unwrap();
            let checks = runtime_rpc_validation_checks_from_evm_config(
                &ProviderSnapshotHandle::from_getter(&getter),
                RecordingTransport {
                    calls: calls.clone(),
                    responses: Arc::new(Mutex::new(vec![
                        storage(case["connectionStorageBoc"].as_str().unwrap()),
                        storage(case["ulnStorageBoc"].as_str().unwrap()),
                    ])),
                },
                "mainnet",
                &["ton".to_string()],
            )
            .unwrap();
            let outcome = checks
                .validate_readiness(&event, &message_context(requested))
                .await;
            let recorded: Vec<Value> = calls
                .lock()
                .unwrap()
                .iter()
                .map(|(url, _, body)| json!({"url": url, "method": body["method"]}))
                .collect();
            if requested < required {
                let error = outcome.expect_err("below the requirement must be refused");
                assert!(
                    matches!(&error, AppCoreError::BadRequest(message)
                        if message.contains(&format!("below the {required} confirmations"))),
                    "{name} requested {requested}: {error}"
                );
                assert_eq!(recorded.len(), 2, "{name}: only the two TON storage reads");
                assert!(
                    recorded
                        .iter()
                        .all(|call| call["url"] == "https://ton.example"),
                    "{name}: no source-chain RPC before the refusal: {recorded:?}"
                );
            } else {
                // At the requirement the floor passes and readiness moves on to the
                // source chain, which this test does not configure.
                let error = outcome.expect_err("the source chain has no provider here");
                assert!(
                    error
                        .to_string()
                        .contains("No provider config for chain ethereum"),
                    "{name} requested {requested}: the floor must pass, got {error}"
                );
            }
            rows.push(json!({
                "case": name, "required": required, "requested": requested,
                "refused": requested < required, "calls": recorded,
            }));
        }
    }
    artifact("m22-confirmation-floor", json!({ "cases": rows }));
}

fn nested_raw_value_body(levels: usize) -> String {
    let mut text = format!("{}{}", "[".repeat(127), "]".repeat(127));
    for _ in 0..levels {
        text = format!(
            "{}{{\"{RAW_VALUE_TOKEN}\":{}}}{}",
            "[".repeat(126),
            serde_json::to_string(&text).unwrap(),
            "]".repeat(126)
        );
    }
    text
}

async fn post_body(body: Vec<u8>, content_type: &str) -> (u16, Value) {
    let app = runtime_app_with_core().await;
    let response = pillar_api::router(app, "m25")
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v2/resolve-and-sign")
                .header("content-type", content_type)
                .header(
                    "authorization",
                    "Bearer test-token-0123456789abcdef0123456789",
                )
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        pillar_core::json::parse_value_slice(&bytes).unwrap(),
    )
}

/// M-25: the audit's shape - 14 nested re-parses, about 1,900 containers, under the
/// 100 KiB limit - must be a 400 naming the reserved key on tokio's default 2 MiB
/// worker stack, the one production runs on. Run in a child so an overflow aborts only
/// the child.
#[test]
fn m25_nested_raw_value_body_is_a_400_on_a_small_stack() {
    if std::env::var_os(DEPTH_CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", DEPTH_TEST, "--nocapture", "--test-threads=1"])
            .env(DEPTH_CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(
            output.status.success(),
            "child failed ({:?}): {stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let body = nested_raw_value_body(14);
    assert!(body.len() < 100 * 1024, "{}", body.len());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();
    let (status, envelope) = runtime.block_on(async {
        tokio::spawn(post_body(body.clone().into_bytes(), "application/json"))
            .await
            .unwrap()
    });
    assert_eq!(status, 400, "{envelope}");
    assert!(
        envelope["body"]
            .as_str()
            .unwrap()
            .contains("reserved JSON object key"),
        "{envelope}"
    );
    artifact(
        "m25-nested-raw-value",
        json!({"bodyBytes": body.len(), "levels": 14, "workerStackBytes": 2 * 1024 * 1024,
               "status": status, "body": envelope["body"]}),
    );
}

/// M-25: every spelling and position of the token, the body envelope, and a
/// provider response - each a refusal on its own path, never a re-parse. A valid
/// request wrapped in the token is the external discriminator: before the fix it
/// reached the signing schema, now it is a parse error.
#[tokio::test]
async fn m25_reserved_key_is_refused_on_every_ingress() {
    let valid = serde_json::to_string(&request_v2()).unwrap();
    let escaped_token = RAW_VALUE_TOKEN.replace('$', "\\u0024");
    let cases = [
        (
            "first_key",
            format!(
                "{{\"{RAW_VALUE_TOKEN}\":{}}}",
                serde_json::to_string(&valid).unwrap()
            ),
        ),
        (
            "escaped_key",
            format!(
                "{{\"{escaped_token}\":{}}}",
                serde_json::to_string(&valid).unwrap()
            ),
        ),
        (
            "nested_not_first",
            format!("{{\"a\":1,\"b\":{{\"x\":2,\"{RAW_VALUE_TOKEN}\":\"[]\"}}}}"),
        ),
        (
            "number_token",
            "{\"$serde_json::private::Number\":\"1\"}".to_string(),
        ),
        (
            "envelope",
            json!({"body": format!("{{\"{RAW_VALUE_TOKEN}\":\"[]\"}}")}).to_string(),
        ),
    ];
    let mut rows = Vec::new();
    for (name, body) in cases {
        let (status, envelope) = post_body(body.into_bytes(), "application/json").await;
        let message = envelope["body"].as_str().unwrap_or_default().to_string();
        assert!(
            message.contains("reserved JSON object key"),
            "{name}: {status} {envelope}"
        );
        assert!(
            status == 400 || (name == "envelope" && status == 500),
            "{name}: {status}"
        );
        rows.push(json!({"case": name, "status": status, "body": message}));
    }
    let provider = format!("{{\"result\":{{\"{RAW_VALUE_TOKEN}\":\"[]\"}}}}");
    for ton in [false, true] {
        let error = crate::provider_health::parse_json_with_limits(provider.as_bytes(), ton)
            .expect_err("a provider response carrying the token is not a value");
        assert!(error.contains("reserved JSON object key"), "{error}");
        rows.push(json!({"case": format!("provider_ton_{ton}"), "error": error}));
    }
    // `serde_json`'s own limit still applies to the plain document: 127 levels parse,
    // 128 do not.
    let at_limit = format!("{}{}", "[".repeat(127), "]".repeat(127));
    let over_limit = format!("{}{}", "[".repeat(128), "]".repeat(128));
    assert!(pillar_core::json::parse_value(&at_limit).is_ok());
    assert!(pillar_core::json::parse_value(&over_limit).is_err());
    artifact("m25-ingress", json!({ "cases": rows }));
}

/// M-25: the replacement parser gives `serde_json`'s answer on every committed JSON
/// fixture, so nothing upstream-compatible changed shape.
#[test]
fn m25_hardened_parser_matches_serde_json_on_every_fixture() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut pending = vec![root];
    let mut compared = 0usize;
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap().path();
            if entry.is_dir() {
                if !entry.ends_with("target") {
                    pending.push(entry);
                }
            } else if entry.extension().is_some_and(|ext| ext == "json") {
                let bytes = std::fs::read(&entry).unwrap();
                #[allow(clippy::disallowed_methods)] // The reference this is compared with.
                let reference = serde_json::from_slice::<Value>(&bytes);
                let hardened = pillar_core::json::parse_value_slice(&bytes);
                match (reference, hardened) {
                    (Ok(left), Ok(right)) => assert_eq!(left, right, "{}", entry.display()),
                    (Err(_), Err(_)) => {}
                    (left, right) => panic!("{}: {left:?} vs {right:?}", entry.display()),
                }
                compared += 1;
            }
        }
    }
    assert!(compared > 50, "{compared}");
    artifact("m25-fixture-equivalence", json!({ "files": compared }));
}

#[derive(Clone)]
struct ScanTransport {
    text: Arc<String>,
}

#[async_trait]
impl JsonRpcTransport for ScanTransport {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        Err(format!("unexpected POST {url}"))
    }
    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
    async fn get_text(
        &self,
        _: String,
        _: HashMap<String, String>,
    ) -> Result<(u16, String), String> {
        Ok((200, (*self.text).clone()))
    }
}

/// M-23: a committee-less sequencer answers a scan near the 4 MiB cap with an
/// events array that matches nothing. The lookup must end in its ordinary refusal,
/// bounded in time, with the array moved out of the response rather than copied.
#[tokio::test]
async fn m23_committee_less_scan_near_the_cap_is_bounded() {
    let mut events = Vec::new();
    let mut size = 0;
    while size < 3 * 1024 * 1024 {
        let event = json!({"nonce": "1", "data": "a".repeat(200)});
        size += event.to_string().len() + 1;
        events.push(event);
    }
    let count = events.len();
    let body = json!({
        "events": events, "latestNonce": "1", "isLatest": true,
        "stateRoot": "0x00", "signatures": [],
    })
    .to_string();
    assert!(body.len() < 4 * 1024 * 1024, "{}", body.len());
    let config = ProviderConfig::with_distinct_entities(
        vec![ProviderUri::Uri(
            "https://ledger.example/?admin-api=admin.example:5002&wallet-url=https://wallet.example"
                .to_string(),
        )],
        1,
    )
    .with_sequencer(vec![ProviderUri::UriWithHeaders {
        uri: "https://sequencer.example/".to_string(),
        headers: HashMap::from([("authorization".to_string(), "Bearer token".to_string())]),
    }]);
    let sequencer = canton_sequencer("canton", &config).unwrap();
    let transport = ScanTransport {
        text: Arc::new(body.clone()),
    };
    let started = Instant::now();
    let error = crate::layerzero_runtime::resolve_canton_packet_sent(
        &transport,
        &sequencer,
        "0xabc",
        &request_v2().lz_message_id,
    )
    .await
    .expect_err("an events array that decodes to nothing is not a packet");
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    artifact(
        "m23-canton-scan",
        json!({"bodyBytes": body.len(), "events": count, "elapsedMs": elapsed.as_millis(),
               "error": error.to_string()}),
    );
}

#[derive(Clone)]
struct StalledReadTransport;

#[async_trait]
impl JsonRpcTransport for StalledReadTransport {
    async fn post_json(
        &self,
        _: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Err("stalled".to_string())
    }
    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

/// M-24: with every READ permit held by a stalled target, a call that has to wait
/// for one gives up at the request deadline rather than at the outer CLI timeout.
#[tokio::test]
async fn m24_read_permit_wait_ends_at_the_request_deadline() {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let resolver = Arc::new(RuntimeEvmReadPayloadResolver::new_with_call_limits(
        &ProviderSnapshotHandle::from_getter(&getter),
        StalledReadTransport,
        HashMap::from([(30_102, "bsc".to_string())]),
        ReadCallLimits {
            process: 1,
            per_chain: 1,
        },
    ));
    let mut event = read_command_sent_event(evm_read_command_with_block_marker());
    event.read_block_pins = bsc_read_block_pins();
    let context = SigningContext::Read {
        expiration: 123,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: Vec::new(),
    };
    let holder = {
        let (resolver, event, context) = (resolver.clone(), event.clone(), context.clone());
        tokio::spawn(async move { resolver.resolve_payload(&event, &context).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let deadline = Duration::from_millis(300);
    let started = Instant::now();
    let result = pillar_core::execution::RequestContext::new(deadline)
        .scope(resolver.resolve_payload(&event, &context))
        .await;
    let elapsed = started.elapsed();
    holder.abort();
    let error = result.expect_err("no permit is free before the deadline");
    assert!(
        matches!(
            error,
            AppCoreError::Admission(pillar_core::execution::BudgetError::Deadline)
        ),
        "{error:?}"
    );
    assert!(
        elapsed >= deadline && elapsed < deadline + Duration::from_secs(1),
        "{elapsed:?}"
    );
    artifact(
        "m24-read-permit-deadline",
        json!({"deadlineMs": deadline.as_millis(), "elapsedMs": elapsed.as_millis(),
               "error": format!("{error:?}")}),
    );
}
