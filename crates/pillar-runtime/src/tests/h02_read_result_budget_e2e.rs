//! H-02: a READ command's returned data is bounded per `eth_call`, per command phase and in
//! flight across the process, and the signing path neither concatenates nor decodes a
//! second full copy of it.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt;

const MAX: usize = pillar_core::MAX_READ_RESULT_BYTES;
const RSS_CHILD: &str = "PILLAR_H02_RSS_CHILD";

fn artifact(name: &str, value: Value) {
    audit_round_artifact("h02-m21", name, value);
}

fn selector(signature: &str) -> String {
    use sha3::{Digest, Keccak256};
    format!(
        "0x{}",
        hex::encode(&Keccak256::digest(signature.as_bytes())[..4])
    )
}

fn abi_bytes_hex(bytes: usize) -> String {
    let padding = (64 - (bytes * 2) % 64) % 64;
    format!(
        "0x{:064x}{bytes:064x}{}{}",
        32,
        "cd".repeat(bytes),
        "0".repeat(padding)
    )
}

type RequestSize = Arc<dyn Fn(&str, &str) -> usize + Send + Sync>;

/// Answers every READ `eth_call` with a result of a chosen size and records how many calls
/// are in flight at once, overall and per provider URL.
#[derive(Clone)]
struct SizedReadTransport {
    request_bytes: RequestSize,
    map_bytes: usize,
    reduce_bytes: usize,
    delay: Duration,
    /// Overrides `delay` for URLs containing any of these keys.
    slow: Vec<(&'static str, Duration)>,
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    url_in_flight: Arc<Mutex<HashMap<String, (usize, usize)>>>,
}

impl SizedReadTransport {
    fn new(request_bytes: impl Fn(&str, &str) -> usize + Send + Sync + 'static) -> Self {
        Self {
            request_bytes: Arc::new(request_bytes),
            map_bytes: 32,
            reduce_bytes: 32,
            delay: Duration::ZERO,
            slow: Vec::new(),
            calls: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            url_in_flight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn url_peaks(&self) -> HashMap<String, usize> {
        self.url_in_flight
            .lock()
            .unwrap()
            .iter()
            .map(|(url, (_, peak))| (url.clone(), *peak))
            .collect()
    }
}

#[async_trait]
impl JsonRpcTransport for SizedReadTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if body["method"] != "eth_call" {
            return Err(format!("unexpected READ request {body}"));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        {
            let mut in_flight = self.url_in_flight.lock().unwrap();
            let (active, peak) = in_flight.entry(url.clone()).or_default();
            *active += 1;
            *peak = (*peak).max(*active);
        }
        let delay = self
            .slow
            .iter()
            .find(|(key, _)| url.contains(key))
            .map_or(self.delay, |(_, delay)| *delay);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.url_in_flight
            .lock()
            .unwrap()
            .get_mut(&url)
            .expect("counted above")
            .0 -= 1;
        let to = body["params"][0]["to"].as_str().unwrap_or_default();
        let data = body["params"][0]["data"].as_str().unwrap_or_default();
        let result = if to.eq_ignore_ascii_case(READ_TARGET) {
            format!("0x{}", "ab".repeat((self.request_bytes)(&url, data)))
        } else if data.starts_with(&selector("lzMap(bytes,bytes)")) {
            abi_bytes_hex(self.map_bytes)
        } else if data.starts_with(&selector("lzReduce(bytes,bytes[])")) {
            abi_bytes_hex(self.reduce_bytes)
        } else {
            return Err(format!("unexpected READ eth_call {body}"));
        };
        Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

fn sized_resolver(
    transport: SizedReadTransport,
    uris: &[&str],
    quorum: u64,
) -> RuntimeEvmReadPayloadResolver<SizedReadTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                uris.iter()
                    .map(|uri| ProviderUri::Uri(uri.to_string()))
                    .collect(),
                quorum,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    RuntimeEvmReadPayloadResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        HashMap::from([(30_102, "bsc".to_string())]),
    )
}

/// READ target chains for the fairness scenarios: bsc plus three more, one provider each at
/// `https://{chain}-rpc.example`.
const CHAINS: [(&str, u32); 4] = [
    ("bsc", 30_102),
    ("ethereum", 30_101),
    ("arbitrum", 30_110),
    ("polygon", 30_109),
];

fn multi_chain_resolver(
    transport: SizedReadTransport,
) -> RuntimeEvmReadPayloadResolver<SizedReadTransport> {
    let chains = CHAINS.map(|(chain, _)| chain.to_string());
    let getter = StaticProviderConfig::new(
        chains
            .iter()
            .map(|chain| {
                (
                    chain.clone(),
                    ProviderConfig::with_distinct_entities(
                        vec![ProviderUri::Uri(format!("https://{chain}-rpc.example"))],
                        1,
                    ),
                )
            })
            .collect(),
        Some(&chains),
    )
    .unwrap();
    RuntimeEvmReadPayloadResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        CHAINS
            .iter()
            .map(|(chain, eid)| (*eid, chain.to_string()))
            .collect(),
    )
}

/// `count` block-marker requests against `chain`, with that chain's pinned blocks.
fn chain_command(chain: &str, count: usize) -> LzSentEvent {
    let eid = CHAINS
        .iter()
        .find(|(name, _)| *name == chain)
        .expect("known chain")
        .1;
    let command = evm_read_command_with_repeated_block_markers(count);
    assert_eq!(
        command.matches("7596").count(),
        count,
        "one eid per request"
    );
    let mut event = read_command_sent_event(command.replace("7596", &format!("{eid:04x}")));
    event.read_block_pins = bsc_read_block_pins()
        .into_iter()
        .map(|mut pin| {
            pin.chain_name = chain.to_string();
            pin
        })
        .collect();
    event
}

async fn resolve_event(
    resolver: &RuntimeEvmReadPayloadResolver<SizedReadTransport>,
    event: LzSentEvent,
) -> Result<String, AppCoreError> {
    resolver
        .resolve_payload(
            &event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
}

async fn resolve(
    resolver: &RuntimeEvmReadPayloadResolver<SizedReadTransport>,
    command: String,
) -> Result<String, AppCoreError> {
    let mut event = read_command_sent_event(command);
    event.read_block_pins = bsc_read_block_pins();
    resolve_event(resolver, event).await
}

/// Two requests whose calldata differ (`0xdeadbeef`, `0xdeadbeee`), so each can be sized.
fn two_request_command() -> String {
    let single = evm_read_command_with_block_marker();
    let body = &single[2..];
    let request = &body[12..];
    format!(
        "0x{}0002{request}{}",
        &body[..8],
        request.replace("deadbeef", "deadbeee")
    )
}

/// `count` copies of the block-marker request followed by a compute of `setting`.
fn compute_command(count: usize, setting: u8) -> String {
    let single = evm_read_command_with_compute_setting(setting);
    let body = &single[2..];
    let request = &body[12..12 + 92];
    format!(
        "0x{}{count:04x}{}{}",
        &body[..8],
        request.repeat(count),
        &body[12 + 92..]
    )
}

fn outcome(result: &Result<String, AppCoreError>) -> Value {
    match result {
        Ok(payload) => json!({"ok": true, "payload_hex_chars": payload.len()}),
        Err(AppCoreError::UnresolvableCommand(reason)) => {
            json!({"ok": false, "class": "UnresolvableCommand", "reason": reason})
        }
        Err(error) => json!({"ok": false, "class": "other", "reason": error.to_string()}),
    }
}

fn assert_unresolvable(result: &Result<String, AppCoreError>, reason: &str) {
    match result {
        Err(AppCoreError::UnresolvableCommand(message)) => {
            assert_eq!(message, reason, "unexpected refusal text");
        }
        other => panic!("expected UnresolvableCommand({reason}), got {other:?}"),
    }
}

fn call_limit_reason() -> String {
    format!("ReadV1002 command is unresolvable: an eth_call result exceeds {MAX} bytes at the pinned block")
}

fn phase_reason(phase: &str) -> String {
    format!("ReadV1002 command is unresolvable: {phase} exceed {MAX} bytes")
}

/// Boundaries: a single result and a two-request total of exactly the cap resolve; one byte
/// more of either is a non-retryable refusal.
#[tokio::test]
async fn h02_per_call_and_per_phase_boundaries_are_exact() {
    let single = |bytes: usize| {
        sized_resolver(
            SizedReadTransport::new(move |_, _| bytes),
            &["https://bsc-rpc.example"],
            1,
        )
    };
    let at_call_cap = resolve(&single(MAX), evm_read_command_with_block_marker()).await;
    let over_call_cap = resolve(&single(MAX + 1), evm_read_command_with_block_marker()).await;

    let pair = |second: usize| {
        sized_resolver(
            SizedReadTransport::new(move |_, data| {
                if data == "0xdeadbeee" {
                    second
                } else {
                    MAX / 2
                }
            }),
            &["https://bsc-rpc.example"],
            1,
        )
    };
    let at_phase_cap = resolve(&pair(MAX / 2), two_request_command()).await;
    let over_phase_cap = resolve(&pair(MAX / 2 + 1), two_request_command()).await;

    artifact(
        "h02-boundaries",
        json!({
            "max_read_result_bytes": MAX,
            "one_result_at_cap": outcome(&at_call_cap),
            "one_result_cap_plus_one": outcome(&over_call_cap),
            "two_results_totalling_cap": outcome(&at_phase_cap),
            "two_results_totalling_cap_plus_one": outcome(&over_phase_cap),
        }),
    );
    assert_eq!(at_call_cap.unwrap(), "ab".repeat(MAX));
    assert_unresolvable(&over_call_cap, &call_limit_reason());
    assert_eq!(at_phase_cap.unwrap().len(), MAX * 2);
    assert_unresolvable(&over_phase_cap, &phase_reason("request results"));
}

/// The audit's shape: 256 requests, each legal on its own. The command is refused as soon
/// as the total passes the cap, without dispatching the remaining requests.
#[tokio::test]
async fn h02_many_legal_results_are_refused_before_the_rest_are_read() {
    let per_request = 64 * 1024;
    let mut transport = SizedReadTransport::new(move |_, _| per_request);
    transport.delay = Duration::from_millis(1);
    let calls = transport.calls.clone();
    let resolver = sized_resolver(transport, &["https://bsc-rpc.example"], 1);
    let result = resolve(&resolver, evm_read_command_with_repeated_block_markers(256)).await;
    let dispatched = calls.load(Ordering::SeqCst);
    // 16 results fill the cap, the 17th exceeds it, and at most three others of the command are in flight.
    let fits = MAX / per_request;
    artifact(
        "h02-early-refusal",
        json!({
            "requests": 256,
            "bytes_per_result": per_request,
            "results_that_fit": fits,
            "eth_calls_dispatched": dispatched,
            "outcome": outcome(&result),
        }),
    );
    assert_unresolvable(&result, &phase_reason("request results"));
    assert!(
        dispatched <= fits + 4,
        "{dispatched} calls dispatched for a command refused after {} results",
        fits + 1
    );
}

/// One provider answering an oversized result is one vote; the honest quorum still signs.
/// When the honest providers agree the result is oversized, that agreement is the refusal.
#[tokio::test]
async fn h02_an_oversized_vote_is_one_vote() {
    let uris = [
        "https://bsc-rpc-hostile.example",
        "https://bsc-rpc-a.example",
        "https://bsc-rpc-b.example",
    ];
    let hostile = sized_resolver(
        SizedReadTransport::new(|url, _| if url.contains("hostile") { MAX + 1 } else { 2 }),
        &uris,
        2,
    );
    let with_hostile = resolve(&hostile, evm_read_command_with_block_marker()).await;
    let honest_oversized = sized_resolver(
        SizedReadTransport::new(|url, _| if url.contains("hostile") { 2 } else { MAX + 1 }),
        &uris,
        2,
    );
    let agreed_oversized = resolve(&honest_oversized, evm_read_command_with_block_marker()).await;
    artifact(
        "h02-oversized-vote",
        json!({
            "one_oversized_provider": outcome(&with_hostile),
            "two_providers_agree_oversized": outcome(&agreed_oversized),
        }),
    );
    assert_eq!(with_hostile.unwrap(), "abab");
    assert_unresolvable(&agreed_oversized, &call_limit_reason());
}

/// lzMap results are a phase of their own, and the lzReduce result is one `eth_call`. Both
/// are ABI `bytes`, so the cap applies to the decoded data: exactly the cap resolves.
#[tokio::test]
async fn h02_compute_results_are_bounded() {
    let compute = |map_bytes: usize, reduce_bytes: usize, command: String| async move {
        let mut transport = SizedReadTransport::new(|_, _| 32);
        transport.map_bytes = map_bytes;
        transport.reduce_bytes = reduce_bytes;
        resolve(
            &sized_resolver(transport, &["https://bsc-rpc.example"], 1),
            command,
        )
        .await
    };
    let only_map = compute(64 * 1024, 32, compute_command(32, 0)).await;
    let map_at_cap = compute(MAX, 32, compute_command(1, 0)).await;
    let map_over_cap = compute(MAX + 1, 32, compute_command(1, 0)).await;
    let reduce_at_cap = compute(32, MAX, compute_command(2, 1)).await;
    let only_reduce = compute(32, MAX + 1, compute_command(2, 1)).await;
    let map_reduce = compute(32, 32, compute_command(2, 2)).await;
    artifact(
        "h02-compute",
        json!({
            "only_map_32_results_of_64_kib": outcome(&only_map),
            "one_lz_map_result_decoded_at_cap": outcome(&map_at_cap),
            "one_lz_map_result_decoded_cap_plus_one": outcome(&map_over_cap),
            "lz_reduce_result_decoded_at_cap": outcome(&reduce_at_cap),
            "only_reduce_result_cap_plus_one": outcome(&only_reduce),
            "map_reduce_small": outcome(&map_reduce),
        }),
    );
    assert_unresolvable(&only_map, &phase_reason("lzMap results"));
    assert_eq!(map_at_cap.unwrap(), "cd".repeat(MAX));
    assert_unresolvable(&map_over_cap, &call_limit_reason());
    assert_eq!(reduce_at_cap.unwrap(), "cd".repeat(MAX));
    assert_unresolvable(&only_reduce, &call_limit_reason());
    assert_eq!(map_reduce.unwrap(), "cd".repeat(32));
}

/// Calls are bounded per target chain, which also bounds each command phase, and across the
/// process, and every permit is held until a call's quorum resolves, so concurrent commands
/// cannot multiply the votes held in flight.
#[tokio::test]
async fn h02_concurrent_commands_share_the_nested_call_limits() {
    let mut transport = SizedReadTransport::new(|_, _| 32);
    transport.delay = Duration::from_millis(20);
    let peak = transport.peak.clone();
    let active = transport.active.clone();
    let observed = transport.clone();
    let resolver = multi_chain_resolver(transport);
    let lone = resolve_event(&resolver, chain_command("bsc", 16)).await;
    let lone_peak = peak.swap(0, Ordering::SeqCst);
    let results = futures::future::join_all(
        CHAINS
            .iter()
            .flat_map(|(chain, _)| [chain_command(chain, 16), chain_command(chain, 16)])
            .map(|event| resolve_event(&resolver, event)),
    )
    .await;
    let peak = peak.load(Ordering::SeqCst);
    let chain_peaks = observed.url_peaks();
    artifact(
        "h02-nested-call-limits",
        json!({
            "one_command_peak_calls_in_flight": lone_peak,
            "commands": results.len(),
            "chains": CHAINS.len(),
            "requests_per_command": 16,
            "peak_calls_in_flight": peak,
            "peak_calls_in_flight_per_chain": chain_peaks,
            "all_resolved": results.iter().all(Result::is_ok),
        }),
    );
    assert_eq!(lone.unwrap().len(), 16 * 64);
    assert_eq!(lone_peak, 4, "a lone command uses its chain's whole limit");
    for result in results {
        assert_eq!(result.unwrap().len(), 16 * 64);
    }
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(
        peak, 16,
        "four chains of four, inside the process-wide limit"
    );
    for (chain, chain_peak) in chain_peaks {
        assert_eq!(chain_peak, 4, "{chain} per-chain READ call limit");
    }
}

/// Chains whose providers stall every call cannot hold the permits other chains need: with
/// three of the four chains stalled under four large commands each, the fourth chain's READ
/// resolves without waiting for any stalled call.
#[tokio::test(start_paused = true)]
async fn h02_stalled_chains_do_not_delay_another_chains_reads() {
    let stall = Duration::from_secs(50);
    let stalled_chains = ["bsc", "arbitrum", "polygon"];
    let mut transport = SizedReadTransport::new(|_, _| 32);
    transport.slow = stalled_chains.iter().map(|chain| (*chain, stall)).collect();
    let resolver = multi_chain_resolver(transport);
    let started = tokio::time::Instant::now();
    let stalled = futures::future::join_all(
        stalled_chains
            .iter()
            .flat_map(|chain| (0..4).map(|_| resolve_event(&resolver, chain_command(chain, 16)))),
    );
    let other = async {
        tokio::task::yield_now().await;
        let result = resolve_event(&resolver, chain_command("ethereum", 1)).await;
        (result, started.elapsed())
    };
    let (stalled, (other, other_elapsed)) = tokio::join!(stalled, other);
    let stalled_elapsed = started.elapsed();
    artifact(
        "h02-stalled-chain-isolation",
        json!({
            "stalled_chains": stalled_chains,
            "stall_per_call_ms": stall.as_millis(),
            "stalled_commands_per_chain": 4,
            "requests_per_stalled_command": 16,
            "other_chain_elapsed_ms": other_elapsed.as_millis(),
            "stalled_commands_elapsed_ms": stalled_elapsed.as_millis(),
            "other_chain_outcome": outcome(&other),
        }),
    );
    assert_eq!(other.unwrap().len(), 64);
    assert!(
        other_elapsed < stall,
        "ethereum waited {other_elapsed:?} behind calls stalled for {stall:?}"
    );
    for result in stalled {
        assert_eq!(result.unwrap().len(), 16 * 64);
    }
}

/// Within one chain, permits go in arrival order and a command only queues as many calls as
/// the chain limit, so a small command arriving behind three large ones waits for a few
/// calls, not for the large commands to finish.
#[tokio::test(start_paused = true)]
async fn h02_a_large_command_does_not_hold_a_later_command_behind_it() {
    let delay = Duration::from_millis(100);
    let mut transport = SizedReadTransport::new(|_, _| 32);
    transport.delay = delay;
    let resolver = multi_chain_resolver(transport);
    let started = tokio::time::Instant::now();
    let large = futures::future::join_all(
        (0..3).map(|_| resolve_event(&resolver, chain_command("bsc", 64))),
    );
    let small = async {
        tokio::time::sleep(Duration::from_millis(1)).await;
        let arrived = tokio::time::Instant::now();
        let result = resolve_event(&resolver, chain_command("bsc", 1)).await;
        (result, arrived.elapsed())
    };
    let (large, (small, small_elapsed)) = tokio::join!(large, small);
    let large_elapsed = started.elapsed();
    artifact(
        "h02-same-chain-arrival-order",
        json!({
            "call_delay_ms": delay.as_millis(),
            "large_commands": 3,
            "requests_per_large_command": 64,
            "small_command_elapsed_ms": small_elapsed.as_millis(),
            "large_commands_elapsed_ms": large_elapsed.as_millis(),
            "small_outcome": outcome(&small),
        }),
    );
    assert_eq!(small.unwrap().len(), 64);
    assert!(
        small_elapsed <= delay * 4,
        "the small command waited {small_elapsed:?} behind {large_elapsed:?} of large commands"
    );
    for result in large {
        assert_eq!(result.unwrap().len(), 64 * 64);
    }
}

/// The limits must not refuse what upstream signs: a lone 256-request command with lzMap and
/// lzReduce, at 200 ms per call, resolves inside the 58 s request deadline.
#[tokio::test(start_paused = true)]
async fn h02_a_maximal_command_resolves_inside_the_request_deadline() {
    let delay = Duration::from_millis(200);
    let mut transport = SizedReadTransport::new(|_, _| 32);
    transport.delay = delay;
    let calls = transport.calls.clone();
    let resolver = sized_resolver(transport, &["https://bsc-rpc.example"], 1);
    let started = tokio::time::Instant::now();
    let result = resolve(&resolver, compute_command(256, 2)).await;
    let elapsed = started.elapsed();
    artifact(
        "h02-maximal-command-latency",
        json!({
            "requests": 256,
            "compute": "map-reduce",
            "call_delay_ms": delay.as_millis(),
            "eth_calls": calls.load(Ordering::SeqCst),
            "elapsed_ms": elapsed.as_millis(),
            "request_deadline_ms": 58_000,
            "outcome": outcome(&result),
        }),
    );
    assert_eq!(result.unwrap(), "cd".repeat(32));
    assert!(elapsed < Duration::from_secs(58), "took {elapsed:?}");
}

/// `resolvedPayloadHash` is `keccak256(guid || payload)` with an odd payload left-padded,
/// whatever chunk the hasher splits it at, and invalid hex fails as the full decode did.
#[tokio::test]
async fn h02_streamed_resolved_payload_hash_matches_the_full_decode() {
    use sha3::{Digest, Keccak256};

    let builder = EvmUlnPayloadBuilder::new(HashMap::from([(
        "bsc".to_string(),
        test_receive_contracts(),
    )]));
    let mut event = payload_signed_sent_event();
    event.lz_message_id.uln_send_version = Value::from("ReadV1002");
    let guid = hex::decode(
        event.extra["guid"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let padded = |payload: &str| {
        let digits = payload.strip_prefix("0x").unwrap_or(payload);
        if digits.len().is_multiple_of(2) {
            digits.to_string()
        } else {
            format!("0{digits}")
        }
    };
    let mut cases = Vec::new();
    for payload in [
        String::new(),
        "0x".to_string(),
        "1234".to_string(),
        "0x1234".to_string(),
        "abc".to_string(),
        "0xabc".to_string(),
        "ab".repeat(10_000),
        "a".repeat(8_193),
    ] {
        let result = builder
            .build_uln_read_v1_verify_payload(
                &event,
                payload.clone(),
                1_900_000_000,
                "9".to_string(),
                None,
            )
            .await
            .unwrap();
        let expected = format!(
            "0x{}",
            hex::encode(Keccak256::digest(
                [guid.clone(), hex::decode(padded(&payload)).unwrap()].concat()
            ))
        );
        assert_eq!(
            result.details["ulnCallData"]["resolvedPayloadHash"],
            expected,
            "payload of {} hex chars",
            payload.len()
        );
        assert_eq!(result.details["proof"]["resolvedPayload"], payload);
        cases.push(json!({"payload_hex_chars": payload.len(), "hash": expected}));
    }
    let mut errors = Vec::new();
    for invalid in [
        "0xzz12".to_string(),
        "0xz12".to_string(),
        format!("{}zz", "ab".repeat(4096)),
    ] {
        let error = builder
            .build_uln_read_v1_verify_payload(
                &event,
                invalid.clone(),
                1_900_000_000,
                "9".to_string(),
                None,
            )
            .await
            .unwrap_err();
        let expected = hex::decode(padded(&invalid)).unwrap_err().to_string();
        assert_eq!(error.to_string(), expected, "{invalid:.16}");
        errors
            .push(json!({"payload_prefix": &invalid[..invalid.len().min(16)], "error": expected}));
    }
    artifact(
        "h02-streamed-hash",
        json!({"cases": cases, "invalid": errors}),
    );
}

/// Serves the READ vertical, except that the READ target answers a result of a fixed size.
#[derive(Clone)]
struct SizedVerticalTransport {
    inner: ReadVerticalTransport,
    result_bytes: usize,
}

#[async_trait]
impl JsonRpcTransport for SizedVerticalTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if url.contains("bsc-rpc")
            && body["method"] == "eth_call"
            && body["params"][0]["to"]
                .as_str()
                .is_some_and(|to| to.eq_ignore_ascii_case(READ_TARGET))
        {
            return Ok(json!({"result": format!("0x{}", "ab".repeat(self.result_bytes))}));
        }
        self.inner.post_json(url, headers, body).await
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.inner.get_json(url, headers).await
    }
}

async fn sign_over_http(result_bytes: usize, debug: bool) -> (u16, Value, Vec<String>) {
    let mut env = read_vertical_env_map();
    env.insert(pillar_config::LZ_DEBUG_MODE.to_string(), debug.to_string());
    let transport = SizedVerticalTransport {
        inner: ReadVerticalTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            receipt: read_vertical_receipt(ReadMarker::BlockNumber),
            chain: ReadChain::Stable,
        },
        result_bytes,
    };
    let app =
        RuntimeServerApp::from_env_map_with_runtime_core(env, transport, || 1_767_323_045_000)
            .await
            .unwrap_or_else(|error| panic!("the production wiring did not assemble: {error}"));
    let metrics = app.metrics().expect("production metrics registry");
    let response = pillar_api::router(app, "h02-read-budget")
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v2/resolve-and-sign")
                .header("content-type", "application/json")
                .header(
                    "authorization",
                    "Bearer test-token-0123456789abcdef0123456789",
                )
                .body(axum::body::Body::from(
                    serde_json::to_vec(&read_vertical_request(ReadMarker::BlockNumber)).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    let stages = metrics
        .lock()
        .await
        .render_prometheus("mainnet", "h02-read-budget")
        .lines()
        .filter(|line| line.starts_with("pillar_sign_stage_duration_seconds_count"))
        .filter_map(|line| {
            let start = line.find("stage=\"")? + 7;
            let rest = &line[start..];
            Some(rest[..rest.find('"')?].to_string())
        })
        .collect();
    (status, body, stages)
}

/// Production wiring over the public route: a result at the cap signs and is returned as the
/// payload, with and without debug output; one byte more is a 400 `UNRESOLVABLE_COMMAND`
/// that never reaches the signer.
#[tokio::test]
async fn h02_http_route_signs_at_the_cap_and_refuses_above_it() {
    let mut cases = Vec::new();
    for debug in [true, false] {
        let (status, body, stages) = sign_over_http(MAX, debug).await;
        let payload = body["body"]["payload"].as_str().unwrap_or_default();
        let signatures = body["body"]["signatures"].as_array().map_or(0, Vec::len);
        cases.push(json!({
            "case": format!("result-at-cap-debug-{debug}"),
            "http_status": status,
            "payload_hex_chars": payload.len(),
            "signatures": signatures,
            "sign_stage": stages.iter().any(|stage| stage == "sign"),
        }));
        assert_eq!(status, 200, "debug {debug}: {:.512}", body.to_string());
        assert_eq!(payload.len(), MAX * 2, "debug {debug}");
        assert!(payload.bytes().all(|byte| byte == b'a' || byte == b'b'));
        assert_eq!(signatures, 1, "debug {debug}");
        assert_eq!(
            body["body"]["debugInfo"].is_object(),
            debug,
            "debug {debug}"
        );
    }
    let (status, body, stages) = sign_over_http(MAX + 1, true).await;
    cases.push(json!({
        "case": "result-cap-plus-one",
        "http_status": status,
        "body": body,
        "sign_stage": stages.iter().any(|stage| stage == "sign"),
    }));
    artifact("h02-http-route", json!({ "cases": cases }));
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "UNRESOLVABLE_COMMAND");
    assert_eq!(body["retryable"], false);
    assert_eq!(body["body"], call_limit_reason());
    assert!(
        stages.iter().all(|stage| stage != "sign"),
        "stages={stages:?}"
    );
}

/// The audit measured 1.75 GiB peak RSS for 256 cap-legal results. In a child process, the
/// same command at the largest legal per-call size against a 2-of-3 quorum, then a command
/// that fills the cap exactly, must both stay far below that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h02_peak_rss_of_max_size_commands_stays_bounded() {
    if std::env::var_os(RSS_CHILD).is_none() {
        let mut command = std::process::Command::new("/usr/bin/time");
        if cfg!(target_os = "macos") {
            command.arg("-l");
        } else {
            command.args(["-f", "%M maximum resident set size"]);
        }
        let output = command
            .arg(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "tests::read_vertical_tests::h02_read_result_budget_e2e::h02_peak_rss_of_max_size_commands_stays_bounded",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RSS_CHILD, "1")
            .output()
            .expect("spawn the isolated H-02 child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let report = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "H-02 child failed ({}): {stdout}\n{report}",
            output.status
        );
        let reported = report
            .lines()
            .find(|line| line.contains("maximum resident set size"))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|number| number.parse::<u64>().ok())
            .expect("time reports maximum resident set size");
        let peak_rss_bytes = if cfg!(target_os = "macos") {
            reported
        } else {
            reported * 1024
        };
        let budget = 256 * 1024 * 1024u64;
        // libtest prints `test <name> ... ` before the child's own output on the same line.
        let child_outcomes = stdout
            .lines()
            .find_map(|line| line.split_once("h02-child-outcomes: "))
            .and_then(|(_, line)| serde_json::from_str::<Value>(line).ok())
            .expect("the H-02 child reports its outcomes");
        artifact(
            "h02-peak-rss",
            json!({
                "peak_rss_bytes": peak_rss_bytes,
                "rss_budget_bytes": budget,
                "audit_reported_peak_rss_bytes": 1_875_902_464u64,
                "child": child_outcomes,
                "resource_source": if cfg!(target_os = "macos") {
                    "/usr/bin/time -l (bytes)"
                } else {
                    "/usr/bin/time -f %M (KiB converted to bytes)"
                },
            }),
        );
        assert!(
            peak_rss_bytes <= budget,
            "H-02 child peak RSS {peak_rss_bytes} exceeds {budget}"
        );
        return;
    }

    let uris = [
        "https://bsc-rpc-a.example",
        "https://bsc-rpc-b.example",
        "https://bsc-rpc-c.example",
    ];
    let mut attack = SizedReadTransport::new(|_, _| MAX);
    attack.delay = Duration::from_millis(5);
    let attack_calls = attack.calls.clone();
    let refused = resolve(
        &sized_resolver(attack, &uris, 2),
        evm_read_command_with_repeated_block_markers(256),
    )
    .await;
    let full = resolve(
        &sized_resolver(SizedReadTransport::new(|_, _| MAX / 256), &uris, 2),
        evm_read_command_with_repeated_block_markers(256),
    )
    .await;
    println!(
        "h02-child-outcomes: {}",
        json!({
            "attack": outcome(&refused),
            "attack_eth_calls": attack_calls.load(Ordering::SeqCst),
            "full_command": outcome(&full),
        })
    );
    assert_unresolvable(&refused, &phase_reason("request results"));
    assert_eq!(full.unwrap().len(), MAX * 2);
}
