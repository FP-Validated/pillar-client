//! Sentry Code audit, M-89 to M-95: one scenario per failure mode, each through the production
//! code path, all recorded as one artifact.
//!
//! * M-89: Solana readiness refuses a transaction whose re-fetched slot is not the resolved one.
//! * M-90: a Stellar `Verified` view is "already signed" only for a committed packet.
//! * M-91: a stored READ hash no longer counts as this DVN having signed.
//! * M-92: an unchanged provider refresh keeps its generation and the health history.
//! * M-93: reorg observations vote as one side in readiness and in the ULNv2 MPT re-read.
//! * M-94: literal loopback requests bypass the process-wide proxy.
//! * M-95: READ timestamp blocks must be parent and child, not just neighbours.
//!
//! The M-94 scenario needs `HTTP_PROXY` in the environment of the process that builds the
//! transport, so the test runs itself once more as a child with that set.
use super::*;
use pillar_core::PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST: &str = "tests::m89_m95_remediation_e2e::m89_m95_remediation_e2e";
const PROXY_CHILD: &str = "PILLAR_M94_PROXY_CHILD";
const ADMISSION_REFUSAL: &str = "Provider JSON parser capacity exhausted";

fn already_signed<T: std::fmt::Debug>(outcome: &Result<T, AppCoreError>) -> bool {
    matches!(outcome, Err(AppCoreError::BadRequest(message))
        if message.starts_with(PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX))
}

fn providers(chain: &str, names: &[&str], quorum: u64) -> StaticProviderConfig {
    StaticProviderConfig::new(
        IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(
                names
                    .iter()
                    .map(|name| ProviderUri::Uri(format!("https://{name}.example")))
                    .collect(),
                quorum,
            ),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------------------------
// M-89
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct SolanaSlotTransport {
    transaction_slot: u64,
    finalized_slot: u64,
}

#[async_trait]
impl JsonRpcTransport for SolanaSlotTransport {
    async fn post_json(
        &self,
        _: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        match body["method"].as_str() {
            Some("getTransaction") => Ok(json!({"result": {"slot": self.transaction_slot}})),
            Some("getSlot") => Ok(json!({"result": self.finalized_slot})),
            other => Err(format!("unexpected Solana method {other:?}")),
        }
    }

    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

async fn solana_readiness(
    resolved_slot: Option<u64>,
    transaction_slot: u64,
) -> Result<Vec<pillar_core::ReadBlockPin>, AppCoreError> {
    let getter = providers("solana", &["solana-rpc"], 1);
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        SolanaSlotTransport {
            transaction_slot,
            finalized_slot: 1_200,
        },
    );
    let mut event = solana_readiness_sent_event();
    event.source_evidence = resolved_slot.map(|slot| {
        pillar_core::SourceEvidence::Solana(pillar_core::SolanaSourceEvidence { slot })
    });
    checks
        .validate_readiness(
            &event,
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 128,
            },
        )
        .await
}

async fn m89_solana_slot() -> Value {
    // The report's reproduction: resolved in slot 900, re-fetched in slot 1000, head at 1200.
    let moved = solana_readiness(Some(900), 1_000).await;
    let error = moved.expect_err("a re-fetch in another slot must not count confirmations");
    assert!(
        error.to_string().contains(
            "source receipt binding changed: Solana transaction slot changed from 900 to 1000"
        ),
        "{error}"
    );
    let same = solana_readiness(Some(1_000), 1_000).await;
    same.expect("the resolved slot with the same depth is accepted");
    let missing = solana_readiness(None, 1_000)
        .await
        .expect_err("readiness without resolved Solana evidence fails closed");
    assert!(
        missing
            .to_string()
            .contains("Missing Solana source evidence for readiness"),
        "{missing}"
    );
    json!({
        "resolved_900_refetched_1000_head_1200": error.to_string(),
        "resolved_1000_refetched_1000_head_1200": "accepted",
        "no_resolved_slot": missing.to_string(),
    })
}

// ---------------------------------------------------------------------------------------------
// M-90
// ---------------------------------------------------------------------------------------------

type StellarRead = (&'static str, Result<&'static str, &'static str>);

fn stellar_reads(
    confirmations: &'static str,
    inbound_nonce: Result<&'static str, &'static str>,
    stored_hash: Result<&'static str, &'static str>,
) -> [StellarRead; 7] {
    [
        ("get_receive_library", Ok("defaultLibrary")),
        ("is_valid_receive_library", Ok("valid")),
        ("effective_receive_uln_config", Ok("config15")),
        ("confirmations", Ok(confirmations)),
        ("uln_verifiable", Ok("verified")),
        ("inbound_nonce", inbound_nonce),
        ("inbound_payload_hash", stored_hash),
    ]
}

async fn m90_stellar_verified() -> Value {
    let mut rows = Vec::new();
    // `uln_verifiable` answers `Verified` in every case below; what differs is the endpoint.
    for (name, confirmations, inbound_nonce, stored_hash, signed, endpoint_reads) in [
        (
            "nonce_already_consumed",
            "noConfirmations",
            Ok("inboundNonce7"),
            Ok("noStoredHash"),
            true,
            vec!["inbound_nonce"],
        ),
        (
            "this_payload_already_committed",
            "noConfirmations",
            Ok("inboundNonce6"),
            Ok("storedPayloadHash"),
            true,
            vec!["inbound_nonce", "inbound_payload_hash"],
        ),
        (
            "endpoint_will_not_take_the_nonce_yet",
            "noConfirmations",
            Ok("inboundNonce6"),
            Ok("noStoredHash"),
            false,
            vec!["inbound_nonce", "inbound_payload_hash"],
        ),
        (
            "another_payload_hash_stored",
            "noConfirmations",
            Ok("inboundNonce6"),
            Ok("otherStoredHash"),
            false,
            vec!["inbound_nonce", "inbound_payload_hash"],
        ),
        (
            "this_dvn_confirmed_and_view_verified",
            "confirmations15",
            Ok("inboundNonce6"),
            Ok("noStoredHash"),
            true,
            vec![],
        ),
    ] {
        let (outcome, seen) = stellar_payload_signed_tests::run(stellar_reads(
            confirmations,
            inbound_nonce,
            stored_hash,
        ))
        .await;
        assert_eq!(already_signed(&outcome), signed, "{name}: {outcome:?}");
        if !signed {
            assert_eq!(outcome, Ok(Some(15)), "{name}");
        }
        let reads = seen
            .iter()
            .filter(|read| read.starts_with("inbound_"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(reads, endpoint_reads, "{name}: endpoint reads");
        rows.push(json!({
            "case": name,
            "refused_as_already_signed": signed,
            "endpoint_reads": reads,
        }));
    }
    let (outcome, _) = stellar_payload_signed_tests::run(stellar_reads(
        "noConfirmations",
        Err("HostError: Error(Storage, MissingValue) entry not found"),
        Ok("noStoredHash"),
    ))
    .await;
    let error = outcome.expect_err("an endpoint read that fails refuses instead of signing");
    assert!(
        error
            .to_string()
            .contains("Contract call simulation failed"),
        "{error}"
    );
    rows.push(json!({"case": "endpoint_read_fails", "refused": error.to_string()}));
    json!(rows)
}

// ---------------------------------------------------------------------------------------------
// M-91
// ---------------------------------------------------------------------------------------------

const READ_LIB: &str = "0x3333333333333333333333333333333333333333";

async fn payload_signed_reads(
    responses: Vec<Result<Value, String>>,
) -> (Result<Option<u64>, AppCoreError>, Vec<String>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(responses, calls.clone());
    let outcome = checks
        .validate_payload_not_signed(&payload_signed_sent_event(), Some(READ_LIB), "bsc", None)
        .await;
    let selectors = calls
        .lock()
        .unwrap()
        .iter()
        .map(|call| call.2["params"][0]["data"].as_str().unwrap_or_default()[..10].to_string())
        .collect();
    (outcome, selectors)
}

async fn m91_read_already_signed() -> Value {
    const GET_RECEIVE_LIBRARY: &str = "0x402f8468";
    const GET_READ_LIB_CONFIG: &str = "0x8eb0bf30";
    const HASH_LOOKUP: &str = "0x3c782a52";
    const VERIFIABLE: &str = "0x27d12cd9";
    let mut rows = Vec::new();
    // Verifying (0) and Reorged (4): the chain still needs this DVN's attestation, whatever
    // hash it may have stored before.
    for (name, state, signed) in [
        ("verifying_with_a_hash_possibly_stored", 0, false),
        ("verified_on_chain", 2, true),
        ("reorged", 4, false),
    ] {
        let (outcome, selectors) = payload_signed_reads(vec![
            eth_call_result(&abi_address_bool(READ_LIB, true)),
            eth_call_result(&abi_word(0)),
            eth_call_result(&abi_word(state)),
        ])
        .await;
        assert_eq!(already_signed(&outcome), signed, "{name}: {outcome:?}");
        if !signed {
            assert_eq!(outcome, Ok(None), "{name}");
        }
        assert_eq!(
            selectors,
            [GET_RECEIVE_LIBRARY, GET_READ_LIB_CONFIG, VERIFIABLE],
            "{name}: READ never asks for a stored hash"
        );
        rows.push(json!({"case": name, "refused_as_already_signed": signed, "reads": selectors}));
    }
    // The message libraries still compare the stored confirmation with the requirement.
    let (outcome, selectors) = payload_signed_reads(vec![
        eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, true)),
        eth_call_result(&abi_word(64)),
        eth_call_result(&abi_bool_uint64(true, 64)),
        eth_call_result(&abi_word(0)),
    ])
    .await;
    assert!(already_signed(&outcome), "{outcome:?}");
    assert!(selectors.iter().any(|selector| selector == HASH_LOOKUP));
    rows.push(
        json!({"case": "message_library_control", "refused_as_already_signed": true,
        "reads": selectors}),
    );
    json!(rows)
}

// ---------------------------------------------------------------------------------------------
// M-92
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct ProbeWire {
    admission_limited: Arc<AtomicBool>,
}

#[async_trait]
impl JsonRpcTransport for ProbeWire {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        if self.admission_limited.load(Ordering::SeqCst) {
            return Err(ADMISSION_REFUSAL.to_string());
        }
        Ok(json!({"result": if url.contains("bsc") { "0x38" } else { "0x1" }}))
    }

    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

fn two_chain_configs(bsc_uri: &str) -> pillar_config::ProviderConfigs {
    ["ethereum", "bsc"]
        .into_iter()
        .map(|chain| {
            let uri = if chain == "bsc" {
                bsc_uri.to_string()
            } else {
                "https://eth-1.example".to_string()
            };
            (
                chain.to_string(),
                ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(uri)], 1),
            )
        })
        .collect()
}

async fn m92_refresh_keeps_health_history() -> Value {
    let providers = ProviderSnapshotHandle::new(
        two_chain_configs("https://bsc-1.example"),
        vec!["ethereum".to_string(), "bsc".to_string()],
    );
    let wire = ProbeWire {
        admission_limited: Arc::new(AtomicBool::new(false)),
    };
    let source = RpcProviderHealthSource::from_serving_snapshot(
        providers.clone(),
        wire.clone(),
        || 1,
        HashMap::new(),
    );
    let healthy = |report: &pillar_core::ProviderHealthReport| {
        (report["ethereum"].healthy, report["bsc"].healthy)
    };

    let first = source.get_provider_health_report().await.unwrap();
    assert_eq!(healthy(&first), (true, true));

    // The 60-second poll publishes the same providers again.
    let before = providers.load();
    let after = providers.publish(providers.candidate(two_chain_configs("https://bsc-1.example")));
    assert!(
        Arc::ptr_eq(&before, &after),
        "unchanged config keeps its generation"
    );
    assert_eq!(providers.generation(), 0);

    // Every probe is now refused admission, which is what a busy signing lane does to them.
    wire.admission_limited.store(true, Ordering::SeqCst);
    let busy = source.get_provider_health_report().await.unwrap();
    assert_eq!(
        healthy(&busy),
        (true, true),
        "recent healthy verdicts carry over"
    );
    assert!(busy["ethereum"]
        .providers
        .iter()
        .all(|entry| !entry.observed));

    // A real change to bsc alone: bsc's history is gone, ethereum's is not.
    providers.publish(providers.candidate(two_chain_configs("https://bsc-2.example")));
    assert_eq!(providers.generation(), 1);
    let changed = source.get_provider_health_report().await.unwrap();
    assert_eq!(healthy(&changed), (true, false));

    wire.admission_limited.store(false, Ordering::SeqCst);
    let recovered = source.get_provider_health_report().await.unwrap();
    assert_eq!(healthy(&recovered), (true, true));
    json!({
        "round_1_normal": [first["ethereum"].healthy, first["bsc"].healthy],
        "unchanged_publish_generation": 0,
        "round_2_admission_limited_after_unchanged_publish": [busy["ethereum"].healthy, busy["bsc"].healthy],
        "bsc_changed_generation": 1,
        "round_3_admission_limited_after_bsc_change": [changed["ethereum"].healthy, changed["bsc"].healthy],
        "round_4_normal": [recovered["ethereum"].healthy, recovered["bsc"].healthy],
    })
}

// ---------------------------------------------------------------------------------------------
// M-93
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Receipt {
    Original,
    Moved,
    Missing,
}

const PROVIDER_NAMES: [&str; 4] = ["a", "b", "c", "d"];

fn provider_index(url: &str) -> usize {
    PROVIDER_NAMES
        .iter()
        .position(|name| url.contains(&format!("eth-{name}.")))
        .unwrap_or_else(|| panic!("unknown provider {url}"))
}

#[derive(Clone)]
struct ReorgReadiness {
    receipts: [Receipt; 4],
}

#[async_trait]
impl JsonRpcTransport for ReorgReadiness {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if body["method"] != "eth_getTransactionReceipt" {
            return Ok(latest_block("0x65"));
        }
        Ok(match self.receipts[provider_index(&url)] {
            Receipt::Original => bound_receipt("0xaaa", "0x64", "0x1", "0x0"),
            Receipt::Moved => bound_receipt("0xbbb", "0x64", "0x1", "0x0"),
            Receipt::Missing => json!({"result": null}),
        })
    }

    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

async fn m93_readiness_votes(receipts: [Receipt; 4]) -> Result<(), AppCoreError> {
    let getter = providers("ethereum", &["eth-a", "eth-b", "eth-c", "eth-d"], 2);
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReorgReadiness { receipts },
    )
    .validate_readiness(
        &readiness_sent_event_bound_to("0xaaa", 100, 0),
        &SigningContext::Message {
            expiration: 1,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: 1,
        },
    )
    .await
    .map(|_| ())
}

const MPT_BLOCK_HASH: &str = "0x0202020202020202020202020202020202020202020202020202020202020202";
const MOVED_BLOCK_HASH: &str = "0x0909090909090909090909090909090909090909090909090909090909090909";

fn mpt_receipt(block_hash: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "result": {
        "transactionHash": "0xtx",
        "status": "0x1",
        "blockHash": block_hash,
        "blockNumber": "0x64",
        "logs": [{
            "address": "0x1a44076050125825900e736c501f859c50fe728c",
            "topics": ["0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f"],
            "data": "0x00",
            "transactionHash": "0xtx",
            "blockHash": block_hash,
            "blockNumber": "0x64",
            "logIndex": "0x0",
            "removed": false
        }]
    }})
}

#[derive(Clone)]
struct ReorgMpt {
    receipts: [Receipt; 4],
    destination: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl JsonRpcTransport for ReorgMpt {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if url.contains("bsc-rpc") {
            let mut destination = self.destination.lock().unwrap();
            return if destination.is_empty() {
                Err("unexpected destination call".to_string())
            } else {
                Ok(destination.remove(0))
            };
        }
        match body["method"].as_str() {
            Some("eth_getTransactionReceipt") => Ok(match self.receipts[provider_index(&url)] {
                Receipt::Original => mpt_receipt(MPT_BLOCK_HASH),
                Receipt::Moved => mpt_receipt(MOVED_BLOCK_HASH),
                Receipt::Missing => json!({"jsonrpc": "2.0", "id": 1, "result": null}),
            }),
            Some("eth_getBlockByHash") => Ok(json!({"jsonrpc": "2.0", "id": 1, "result": {
                "hash": body["params"][0],
                "receiptsRoot": "0x0303030303030303030303030303030303030303030303030303030303030303"
            }})),
            other => Err(format!("unexpected source method {other:?}")),
        }
    }

    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

async fn m93_mpt_votes(
    receipts: [Receipt; 4],
) -> Result<pillar_core::HashCallDataResult, AppCoreError> {
    let getter = StaticProviderConfig::new(
        IndexMap::from([
            (
                "ethereum".to_string(),
                ProviderConfig::with_distinct_entities(
                    PROVIDER_NAMES
                        .iter()
                        .map(|name| ProviderUri::Uri(format!("https://eth-{name}.example")))
                        .collect(),
                    2,
                ),
            ),
            (
                "bsc".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                    1,
                ),
            ),
        ]),
        Some(&["ethereum".to_string(), "bsc".to_string()]),
    )
    .unwrap();
    let destination = vec![
        eth_call_result(&abi_uln_v2_app_config_result(
            2,
            64,
            "0x1111111111111111111111111111111111111111",
            1,
            12,
            "0x2222222222222222222222222222222222222222",
        )),
        eth_call_result(&abi_address_word(
            "0x5555555555555555555555555555555555555555",
        )),
        eth_call_result(&abi_word(1)),
        eth_call_result(&abi_word(1)),
    ];
    let builder = RuntimeEvmUlnV2PayloadBuilder::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReorgMpt {
            receipts,
            destination: Arc::new(Mutex::new(
                destination.into_iter().map(Result::unwrap).collect(),
            )),
        },
        EvmUlnPayloadBuilder::new(HashMap::from([(
            "bsc".to_string(),
            test_receive_contracts(),
        )])),
    );
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(30_101_u64));
    pathway_extra.insert("dstEid".to_string(), Value::from(30_102_u64));
    pathway_extra.insert(
        "receiver".to_string(),
        Value::from("0x2222222222222222222222222222222222222222"),
    );
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: pathway_extra,
            },
            nonce: 7,
            uln_send_version: Value::from(pillar_layerzero::ULN_VERSION_V2),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        source_evidence: Some(pillar_core::SourceEvidence::Evm(
            pillar_core::EvmSourceEvidence {
                block_hash: MPT_BLOCK_HASH.to_string(),
                block_number: 100,
                status: "1".to_string(),
                packet_log_index: 0,
                transaction_hash: "0xtx".to_string(),
                packet_log_address: "0x1a44076050125825900e736c501f859c50fe728c".to_string(),
                packet_log_topics: vec![
                    "0x1ab700d4ced0c005b164c0f789fd09fcbb0156d4c2041b8a3bfbcd961cd1567f"
                        .to_string(),
                ],
                packet_log_data: "0x00".to_string(),
            },
        )),
        read_block_pins: Vec::new(),
        extra: IndexMap::new(),
    };
    builder
        .build_uln_v2_verify_payload(&sent_event, 64, 1, "102".to_string())
        .await
}

async fn m93_reorg_votes() -> Value {
    use Receipt::{Missing, Moved, Original};
    let mut rows = Vec::new();
    // Readiness: every case runs against four providers and `any: 2`.
    for (name, receipts, accepted) in [
        ("all_original", [Original; 4], true),
        // The changed side is outvoted, as before.
        ("one_moved", [Original, Original, Original, Moved], true),
        // The report's case: two providers see the reorg, differently described.
        (
            "moved_and_missing",
            [Original, Original, Moved, Missing],
            false,
        ),
        ("moved_and_moved", [Original, Original, Moved, Moved], false),
        (
            "moved_and_two_missing",
            [Moved, Missing, Missing, Moved],
            false,
        ),
    ] {
        let outcome = m93_readiness_votes(receipts).await;
        assert_eq!(outcome.is_ok(), accepted, "readiness {name}: {outcome:?}");
        rows.push(
            json!({"stage": "readiness", "case": name, "receipts": format!("{receipts:?}"),
            "accepted": accepted, "outcome": format!("{outcome:?}")}),
        );
    }
    let unanimous = m93_readiness_votes([Moved; 4])
        .await
        .expect_err("four providers on a moved receipt refuse");
    assert!(
        unanimous
            .to_string()
            .contains("source receipt binding changed"),
        "{unanimous}"
    );
    rows.push(
        json!({"stage": "readiness", "case": "all_moved", "accepted": false,
        "outcome": unanimous.to_string()}),
    );
    // The MPT re-read: a changed or vanished receipt is a vote, not an absent provider.
    for (name, receipts, accepted) in [
        ("all_original", [Original; 4], true),
        ("one_moved", [Original, Original, Original, Moved], true),
        (
            "moved_and_missing",
            [Original, Original, Moved, Missing],
            false,
        ),
        ("moved_and_moved", [Original, Original, Moved, Moved], false),
    ] {
        let outcome = m93_mpt_votes(receipts).await;
        assert_eq!(
            outcome.is_ok(),
            accepted,
            "mpt {name}: {:?}",
            outcome.as_ref().err()
        );
        rows.push(
            json!({"stage": "mpt", "case": name, "receipts": format!("{receipts:?}"),
            "accepted": accepted, "outcome": outcome.err().map(|error| error.to_string())}),
        );
    }
    let unanimous = m93_mpt_votes([Moved; 4])
        .await
        .expect_err("four providers on a moved receipt refuse");
    assert!(
        unanimous
            .to_string()
            .contains("source receipt binding changed"),
        "{unanimous}"
    );
    rows.push(
        json!({"stage": "mpt", "case": "all_moved", "accepted": false,
        "outcome": unanimous.to_string()}),
    );
    json!(rows)
}

// ---------------------------------------------------------------------------------------------
// M-94
// ---------------------------------------------------------------------------------------------

/// Answers every request with `answer`, recording the request line it was sent.
async fn http_server(answer: &'static str, seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                let body_start = loop {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let head = String::from_utf8_lossy(&request[..body_start]).to_string();
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while request.len() < body_start + length {
                    let read = stream.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                seen.lock()
                    .unwrap()
                    .push(head.lines().next().unwrap_or_default().to_string());
                let body = json!({"jsonrpc": "2.0", "id": 1, "result": answer}).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

/// Runs in the child, whose environment names the hostile proxy.
async fn proxy_child() {
    let transport = ReqwestJsonRpcTransport::new().unwrap();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []});
    let loopback = std::env::var("PILLAR_M94_LOOPBACK").unwrap();
    let hostname = std::env::var("PILLAR_M94_HOSTNAME").unwrap();
    let answer = |result: Result<Value, String>| match result {
        Ok(value) => value["result"].as_str().unwrap_or("none").to_string(),
        Err(error) => format!("error: {error}"),
    };
    let report = json!({
        "reqwest_loopback": answer(transport.post_json(loopback.clone(), HashMap::new(), body.clone()).await),
        "read_loopback": answer(
            crate::provider_health::read_target_scope(
                transport.post_json(loopback, HashMap::new(), body.clone())
            )
            .await
        ),
        "reqwest_hostname": answer(transport.post_json(hostname, HashMap::new(), body).await),
    });
    println!("M94_RESULT {report}");
}

async fn m94_loopback_bypasses_proxy() -> Value {
    let honest_seen = Arc::new(Mutex::new(Vec::new()));
    let proxy_seen = Arc::new(Mutex::new(Vec::new()));
    let honest = http_server("honest", honest_seen.clone()).await;
    let proxy = http_server("forged", proxy_seen.clone()).await;
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
            .env(PROXY_CHILD, "1")
            .env("HTTP_PROXY", format!("http://127.0.0.1:{proxy}"))
            .env("http_proxy", format!("http://127.0.0.1:{proxy}"))
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env(
                "PILLAR_M94_LOOPBACK",
                format!("http://127.0.0.1:{honest}/rpc"),
            )
            .env(
                "PILLAR_M94_HOSTNAME",
                format!("http://localhost:{honest}/rpc"),
            )
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        output.status.success(),
        "child failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = stdout
        .lines()
        .find_map(|line| line.split_once("M94_RESULT ").map(|(_, result)| result))
        .map(|line| serde_json::from_str(line).unwrap())
        .unwrap_or_else(|| panic!("child printed no result: {stdout}"));
    // The literal loopback address never reaches the proxy, on either HTTP path.
    assert_eq!(result["reqwest_loopback"], "honest", "{result}");
    assert_eq!(result["read_loopback"], "honest", "{result}");
    // The proxy is live: a host name still goes through it.
    assert_eq!(result["reqwest_hostname"], "forged", "{result}");
    let proxy_seen = proxy_seen.lock().unwrap().clone();
    assert_eq!(proxy_seen.len(), 1, "{proxy_seen:?}");
    assert!(proxy_seen[0].contains("localhost"), "{proxy_seen:?}");
    let honest_seen = honest_seen.lock().unwrap().clone();
    assert_eq!(honest_seen.len(), 2, "{honest_seen:?}");
    json!({"child": result, "proxy_saw": proxy_seen, "honest_listener_saw": honest_seen})
}

// ---------------------------------------------------------------------------------------------
// M-95
// ---------------------------------------------------------------------------------------------

const TARGET_TIMESTAMP: i64 = 1_700_000_000;
const NEW_PARENT: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const OLD_BLOCK_64: &str = "0x6464646464646464646464646464646464646464646464646464646464646464";
const OLD_PARENT: &str = "0x0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d";

#[derive(Clone, Copy)]
enum Fork {
    /// Block 64 is the first block at or after the target; its parent is below it.
    Boundary,
    /// Block 64's parent is already at the target, so block 64 is not the boundary.
    Replacement,
    /// An older fork: block 64 has another hash and another parent.
    Superseded,
    /// Follows the new fork for block 64 and the old fork for block 63.
    Splicer,
}

#[derive(Clone)]
struct ForkedHeaders {
    forks: [Fork; 3],
}

impl ForkedHeaders {
    fn header(fork: Fork, tag: &str) -> Value {
        match (fork, tag) {
            (Fork::Boundary, "0x40") => {
                block_time_with_parent(64, BSC_BLOCK_64_HASH, OLD_PARENT, TARGET_TIMESTAMP + 5)
            }
            (Fork::Boundary | Fork::Superseded | Fork::Splicer, "0x3f") => {
                block_time_with_parent(63, OLD_PARENT, "0x3e", TARGET_TIMESTAMP - 5)
            }
            (Fork::Replacement | Fork::Splicer, "0x40") => {
                block_time_with_parent(64, BSC_BLOCK_64_HASH, NEW_PARENT, TARGET_TIMESTAMP + 5)
            }
            (Fork::Replacement, "0x3f") => {
                block_time_with_parent(63, NEW_PARENT, "0x3e", TARGET_TIMESTAMP)
            }
            (Fork::Superseded, "0x40") => {
                block_time_with_parent(64, OLD_BLOCK_64, OLD_PARENT, TARGET_TIMESTAMP + 5)
            }
            (_, "latest") => block_time_with_parent(80, "0x80", "0x7f", TARGET_TIMESTAMP + 100),
            (_, other) => panic!("unexpected block tag {other}"),
        }
    }
}

#[async_trait]
impl JsonRpcTransport for ForkedHeaders {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let provider = ["bsc-a.", "bsc-b.", "bsc-m."]
            .iter()
            .position(|name| url.contains(name))
            .unwrap();
        Ok(Self::header(
            self.forks[provider],
            body["params"][0].as_str().unwrap_or_default(),
        ))
    }

    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

async fn m95_timestamp_readiness(
    forks: [Fork; 3],
) -> Result<Vec<pillar_core::ReadBlockPin>, AppCoreError> {
    let getter = providers("bsc", &["bsc-a", "bsc-b", "bsc-m"], 2);
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        ForkedHeaders { forks },
    )
    .with_evm_chain_names(HashMap::from([(30_102, "bsc".to_string())]))
    .validate_readiness(
        &read_command_sent_event(evm_read_command_with_timestamp_marker()),
        &read_command_signing_context(64, TARGET_TIMESTAMP, 12),
    )
    .await
}

async fn m95_fork_splice() -> Value {
    let honest = m95_timestamp_readiness([Fork::Boundary; 3])
        .await
        .expect("one fork, parent and child agree: the boundary is accepted");
    assert_eq!(
        honest,
        vec![pillar_core::ReadBlockPin {
            chain_name: "bsc".to_string(),
            block_number: 64,
            block_hash: BSC_BLOCK_64_HASH.to_string(),
        }]
    );
    // A and the splicer settle block 64 on the new fork, B and the splicer settle block 63 on
    // the old one: each round has a quorum, and the pair is not a real chain.
    let spliced = m95_timestamp_readiness([Fork::Replacement, Fork::Superseded, Fork::Splicer])
        .await
        .expect_err("a block 63 that is not block 64's parent must not prove the boundary");
    assert!(
        matches!(&spliced, AppCoreError::BadRequest(message)
            if message.contains("does not cover timestamp")),
        "{spliced}"
    );
    json!({
        "single_fork": "accepted, pin is block 64 of that fork",
        "spliced_forks": spliced.to_string(),
    })
}

// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m89_m95_remediation_e2e() {
    if std::env::var_os(PROXY_CHILD).is_some() {
        proxy_child().await;
        return;
    }
    let report = json!({
        "m89_solana_slot": m89_solana_slot().await,
        "m90_stellar_verified": m90_stellar_verified().await,
        "m91_read_already_signed": m91_read_already_signed().await,
        "m92_refresh_keeps_health_history": m92_refresh_keeps_health_history().await,
        "m93_reorg_votes": m93_reorg_votes().await,
        "m94_loopback_bypasses_proxy": m94_loopback_bypasses_proxy().await,
        "m95_fork_splice": m95_fork_splice().await,
    });
    audit_round_artifact("m89-m95", "remediation", report);
}
