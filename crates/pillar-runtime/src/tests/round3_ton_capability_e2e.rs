use super::*;

const V2_C: &str = "https://ton-c.example";
const V2_D: &str = "https://ton-d.example";
const V3_A: &str = "https://ton-a.example?v3-endpoint=https%3A%2F%2Fton-v3-a.example";
const V3_B: &str = "https://ton-b.example?v3-endpoint=https%3A%2F%2Fton-v3-b.example";

/// Answers `masterchainInfo` on the two v3 endpoints and records every request, so a
/// provider without a v3 endpoint that is dialled anyway shows up in `calls`.
#[derive(Clone)]
struct TonMasterchain {
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for TonMasterchain {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(url.clone());
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(url.clone());
        if url.starts_with("https://ton-v3-a.example/")
            || url.starts_with("https://ton-v3-b.example/")
        {
            Ok(json!({"last": {"seqno": 110}}))
        } else {
            Err(format!("unexpected GET {url}"))
        }
    }
}

async fn ton_readiness(
    config: ProviderConfig,
    block_number: Option<i64>,
) -> (Result<(), AppCoreError>, Vec<String>, std::time::Duration) {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([("ton".to_string(), config)]),
        None,
    )
    .unwrap();
    let mut sent_event = readiness_sent_event();
    sent_event.lz_message_id.pathway_id.src_chain_name = "ton".to_string();
    if let Some(block_number) = block_number {
        sent_event
            .extra
            .insert("blockNumber".to_string(), Value::from(block_number));
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let started = tokio::time::Instant::now();
    let result = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        TonMasterchain {
            calls: calls.clone(),
        },
    )
    .validate_readiness(
        &sent_event,
        &SigningContext::Message {
            expiration: 1,
            skip_v_id: None,
            dvn_address: None,
            block_confirmation: 5,
        },
    )
    .await
    .map(|_| ());
    let elapsed = started.elapsed();
    let calls = calls.lock().unwrap().clone();
    (result, calls, elapsed)
}

fn pool(uris: &[&str]) -> ProviderConfig {
    ProviderConfig::with_distinct_entities(
        uris.iter()
            .map(|uri| ProviderUri::Uri(uri.to_string()))
            .collect(),
        2,
    )
}

/// Round 3 M-13: a provider without a `v3-endpoint` cannot observe TON source
/// readiness, so it must not vote. Listed first, it must not delay the providers that can.
#[tokio::test(start_paused = true)]
async fn round3_m13_ton_readiness_ignores_providers_without_v3_endpoint() {
    let (result, calls, elapsed) = ton_readiness(pool(&[V2_C, V2_D, V3_A, V3_B]), Some(100)).await;

    result.unwrap();
    assert_eq!(
        elapsed,
        std::time::Duration::ZERO,
        "no stall timeout behind v2-only URIs"
    );
    let mut calls = calls;
    calls.sort();
    assert_eq!(
        calls,
        [
            "https://ton-v3-a.example/masterchainInfo",
            "https://ton-v3-b.example/masterchainInfo"
        ]
    );
}

/// Too few v3-capable entities is a configuration error, reported as one, before any
/// RPC - never a quorum of fabricated `Missing` votes.
#[tokio::test(start_paused = true)]
async fn round3_m13_ton_readiness_refuses_when_v3_entities_cannot_meet_the_strategy() {
    let mut same_entity = pool(&[V3_A, V3_B, V2_C, V2_D]);
    same_entity.voters[1].entity = same_entity.voters[0].entity.clone();

    for (case, config) in [
        ("one v3 provider", pool(&[V3_A, V2_C, V2_D])),
        ("two v3 URIs of one entity", same_entity),
    ] {
        let (result, calls, _) = ton_readiness(config, Some(100)).await;
        let error = result.expect_err(case).to_string();
        assert!(error.contains("v3-endpoint"), "{case}: {error}");
        assert!(calls.is_empty(), "{case}: {calls:?}");
    }
}

/// Without a quorum-agreed packet seqno nothing can be observed, so nothing is asked.
#[tokio::test(start_paused = true)]
async fn round3_m13_ton_readiness_without_agreed_seqno_dials_no_provider() {
    let (result, calls, _) = ton_readiness(pool(&[V3_A, V3_B]), None).await;

    assert!(result.is_err());
    assert!(calls.is_empty(), "{calls:?}");
}

#[derive(Clone)]
struct TonObservationTransport {
    calls: Arc<Mutex<Vec<String>>>,
    trace_response: Value,
}

#[async_trait]
impl JsonRpcTransport for TonObservationTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(url.clone());
        Err(format!("unexpected POST {url}"))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(url.clone());
        if url.ends_with("/masterchainInfo") {
            return Ok(json!({"last": {"gen_utime": 1_767_323_050, "seqno": 110}}));
        }
        if url.contains("/events?tx_hash=") {
            return Ok(self.trace_response.clone());
        }
        Err(format!("unexpected GET {url}"))
    }
}

fn recorded_ton_trace_and_hash() -> (Value, String) {
    let response: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/ton-v3-events.response.json"
    ))
    .unwrap();
    let root_hash = response
        .pointer("/events/0/trace/tx_hash")
        .unwrap()
        .as_str()
        .unwrap();
    let transaction_hash = response["events"][0]["transactions"][root_hash]["hash"]
        .as_str()
        .unwrap();
    let hash_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, transaction_hash)
            .unwrap();
    (response, format!("0x{}", hex::encode(hash_bytes)))
}

fn ton_observation_checks(
    config: ProviderConfig,
    calls: Arc<Mutex<Vec<String>>>,
) -> RuntimeRpcValidationChecks<TonObservationTransport> {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([("ton".to_string(), config)]),
        None,
    )
    .unwrap();
    let (trace_response, _) = recorded_ton_trace_and_hash();
    RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        TonObservationTransport {
            calls,
            trace_response,
        },
    )
}

const TON_TIMESTAMP_RANGE: ExpirationValidRange = ExpirationValidRange {
    min: 1_767_323_000,
    max: 1_767_323_100,
};

#[tokio::test(start_paused = true)]
async fn round3_m13_ton_timestamp_ignores_v2_only_providers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let started = tokio::time::Instant::now();
    let checks = ton_observation_checks(pool(&[V2_C, V2_D, V3_A, V3_B]), calls.clone());

    assert_eq!(
        checks
            .current_block_timestamp_with_quorum("ton", TON_TIMESTAMP_RANGE)
            .await
            .unwrap(),
        1_767_323_050
    );
    assert_eq!(
        tokio::time::Instant::now() - started,
        std::time::Duration::ZERO
    );
    let mut actual_calls = calls.lock().unwrap().clone();
    actual_calls.sort();
    assert_eq!(
        actual_calls,
        [
            "https://ton-v3-a.example/masterchainInfo",
            "https://ton-v3-b.example/masterchainInfo"
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn round3_m13_ton_timestamp_refuses_too_few_v3_providers_without_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = ton_observation_checks(pool(&[V2_C, V3_A, V2_D]), calls.clone());

    let error = checks
        .current_block_timestamp_with_quorum("ton", TON_TIMESTAMP_RANGE)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("v3-endpoint"), "{error}");
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn round3_m13_ton_extra_context_ignores_v2_only_providers() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = ton_observation_checks(pool(&[V2_C, V2_D, V3_A, V3_B]), calls.clone());
    let started = tokio::time::Instant::now();
    let (_, tx_hash) = recorded_ton_trace_and_hash();
    let result = checks
        .source_transaction_from_address("ton", &tx_hash)
        .await;
    assert!(result.is_ok(), "{:?}: {:?}", result, calls.lock().unwrap());
    assert_eq!(
        tokio::time::Instant::now() - started,
        std::time::Duration::ZERO
    );
    let mut actual_calls = calls.lock().unwrap().clone();
    actual_calls.sort();
    assert_eq!(
        actual_calls,
        [
            format!("https://ton-v3-a.example/events?tx_hash={tx_hash}"),
            format!("https://ton-v3-b.example/events?tx_hash={tx_hash}")
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn round3_m13_ton_extra_context_refuses_too_few_v3_providers_without_rpc() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = ton_observation_checks(pool(&[V2_C, V3_A, V2_D]), calls.clone());

    let error = checks
        .source_transaction_from_address("ton", &"11".repeat(32))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("v3-endpoint"), "{error}");
    assert!(calls.lock().unwrap().is_empty());
}
