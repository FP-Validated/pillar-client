//! M-18 and M-19: what a health probe records is the rank of the provider identity dispatch
//! looks up, and nothing else, including TON's v3 endpoint. M-20: the IOTA sender lookup
//! votes on what it consumes.

use super::*;
use crate::provider_health::{
    plan_dispatch, plan_ton_v3_dispatch, provider_rank_key, required_provider_quorum,
};

fn artifact(name: &str, value: Value) {
    audit_round_artifact("h02-m21", name, value);
}

type ProbeAnswer =
    Arc<dyn Fn(&str, &HashMap<String, String>) -> Result<Value, String> + Send + Sync>;

/// Answers GET and POST separately and by the `authorization` header, so a probe's
/// credential decides its answer.
#[derive(Clone)]
struct ProbeTransport {
    get: ProbeAnswer,
    post: ProbeAnswer,
}

#[async_trait]
impl JsonRpcTransport for ProbeTransport {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        (self.post)(&url, &headers)
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        (self.get)(&url, &headers)
    }
}

fn probe_transport(
    get: impl Fn(&str, &HashMap<String, String>) -> Result<Value, String> + Send + Sync + 'static,
    post: impl Fn(&str, &HashMap<String, String>) -> Result<Value, String> + Send + Sync + 'static,
) -> ProbeTransport {
    ProbeTransport {
        get: Arc::new(get),
        post: Arc::new(post),
    }
}

/// Probes `chain` once, seeds a tracker from the report and plans one dispatch with
/// quorum `quorum`, the path every signing RPC round takes.
async fn probe_then_plan(
    chain: &str,
    chain_type: &str,
    uris: Vec<ProviderUri>,
    quorum: u64,
    transport: ProbeTransport,
) -> (Value, Result<Vec<usize>, String>) {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(uris, quorum),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap();
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([(chain.to_string(), chain_type.to_string())]),
    );
    let report = source.get_provider_health_report().await.unwrap();
    let tracker = crate::provider_health::ProviderRankTracker::new();
    tracker.seed_from_report(&report).await;
    let pool = pillar_config::ProviderConfigGetter::get_provider_config(&getter, chain).unwrap();
    let rule = required_provider_quorum(pool, chain).unwrap();
    let plan = plan_dispatch(&tracker, chain, rule)
        .await
        .map(|plan| plan.into_iter().map(|entry| entry.index).collect())
        .map_err(|error| error.to_string());
    (serde_json::to_value(&report).unwrap(), plan)
}

const COLLIDING_APTOS: &str =
    "https://aptos-rpc.example/v1?no-code-indexer=https%3A%2F%2Faptos-rpc.example%2Fv1";
const COLLIDING_INITIA: &str =
    "https://initia-rpc.example/lcd?event-indexer=https%3A%2F%2Finitia-rpc.example%2Flcd";

/// M-18: an indexer configured at the RPC's own base shares its old rank key. Its failure
/// must not exclude the RPC signing reads, and its success must not hide an RPC that fails.
#[tokio::test]
async fn m18_auxiliary_probes_never_write_the_voting_rank() {
    let healthy_rpc_failing_indexer = probe_then_plan(
        "aptos",
        "APTOS",
        vec![ProviderUri::Uri(COLLIDING_APTOS.to_string())],
        1,
        probe_transport(
            |_, _| Ok(json!({"chain_id": 1})),
            |_, _| Err("HTTP 404 Not Found".to_string()),
        ),
    )
    .await;
    let failing_rpc_healthy_indexer = probe_then_plan(
        "aptos",
        "APTOS",
        vec![ProviderUri::Uri(COLLIDING_APTOS.to_string())],
        1,
        probe_transport(
            |_, _| Err("HTTP 503".to_string()),
            |_, _| Ok(json!({"data": {"processor_status": [{"last_success_version": 7}]}})),
        ),
    )
    .await;
    let initia_failing_rpc_healthy_indexer = probe_then_plan(
        "initia",
        "INITIA",
        vec![ProviderUri::Uri(COLLIDING_INITIA.to_string())],
        1,
        probe_transport(
            |_, _| Err("HTTP 503".to_string()),
            |_, _| {
                Ok(json!({"data": {"move_events_aggregate": {"aggregate": {"max": {"block_height": 9}}}}}))
            },
        ),
    )
    .await;
    artifact(
        "m18-auxiliary-rank",
        json!({
            "aptos_healthy_rpc_failing_indexer": {"report": healthy_rpc_failing_indexer.0, "plan": format!("{:?}", healthy_rpc_failing_indexer.1)},
            "aptos_failing_rpc_healthy_indexer": {"report": failing_rpc_healthy_indexer.0, "plan": format!("{:?}", failing_rpc_healthy_indexer.1)},
            "initia_failing_rpc_healthy_indexer": {"report": initia_failing_rpc_healthy_indexer.0, "plan": format!("{:?}", initia_failing_rpc_healthy_indexer.1)},
        }),
    );

    let entries = healthy_rpc_failing_indexer.0["aptos"]["providers"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(entries.len(), 2, "both probes stay visible");
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry["diagnostic"] == true)
            .count(),
        1
    );
    assert_eq!(healthy_rpc_failing_indexer.1, Ok(vec![0]));
    for (name, (_, plan)) in [
        ("aptos", failing_rpc_healthy_indexer),
        ("initia", initia_failing_rpc_healthy_indexer),
    ] {
        assert!(
            plan.as_ref()
                .is_err_and(|error| error.contains("Not enough healthy providers")),
            "{name}: a failing RPC must stay excluded: {plan:?}"
        );
    }
}

fn with_headers(uri: &str, headers: &[(&str, &str)]) -> ProviderUri {
    ProviderUri::UriWithHeaders {
        uri: uri.to_string(),
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
    }
}

/// M-19: two entries dialling one URL with different credentials are two providers. A dead
/// backup key, probed after the live one, leaves the live entry dispatchable.
#[tokio::test]
async fn m19_a_dead_credential_does_not_rank_the_live_one() {
    let live = with_headers(
        "https://bsc-rpc.example",
        &[("authorization", "Bearer live")],
    );
    let dead = with_headers(
        "https://bsc-rpc.example",
        &[("authorization", "Bearer dead")],
    );
    let transport = || {
        probe_transport(
            |url, _| Err(format!("unexpected GET {url}")),
            |_, headers| match headers.get("authorization").map(String::as_str) {
                Some("Bearer live") => Ok(json!({"jsonrpc": "2.0", "id": 1, "result": "0x38"})),
                _ => Err("HTTP 401 Unauthorized".to_string()),
            },
        )
    };
    let only_live = probe_then_plan("bsc", "EVM", vec![live.clone()], 1, transport()).await;
    let live_then_dead = probe_then_plan(
        "bsc",
        "EVM",
        vec![live.clone(), dead.clone()],
        1,
        transport(),
    )
    .await;
    let dead_then_live = probe_then_plan(
        "bsc",
        "EVM",
        vec![dead.clone(), live.clone()],
        1,
        transport(),
    )
    .await;
    let serialized = serde_json::to_string(&live_then_dead.0).unwrap();
    artifact(
        "m19-credential-rank",
        json!({
            "only_live": format!("{:?}", only_live.1),
            "live_then_dead": format!("{:?}", live_then_dead.1),
            "dead_then_live": format!("{:?}", dead_then_live.1),
            "live_key_differs_from_dead_key": provider_rank_key("bsc", &live) != provider_rank_key("bsc", &dead),
            "report": live_then_dead.0,
        }),
    );
    assert_eq!(only_live.1, Ok(vec![0]));
    assert_eq!(
        live_then_dead.1,
        Ok(vec![0, 1]),
        "the live entry first, the dead one at the back"
    );
    assert_eq!(dead_then_live.1, Ok(vec![1, 0]));
    assert!(
        !serialized.contains("headers:") && !serialized.contains("Bearer"),
        "the rank key and credentials never reach /provider-health: {serialized}"
    );
}

/// The key is the identity dialled: the Aptos `?auth=` and header forms of one credential
/// agree, header names are case-insensitive, and an entry without headers keeps its URL.
#[test]
fn m19_rank_key_names_the_identity_dialled() {
    let base = "https://aptos-rpc.example/v1";
    let query = ProviderUri::Uri(format!("{base}?auth=k1"));
    let header = with_headers(base, &[("authorization", "Bearer k1")]);
    let other = ProviderUri::Uri(format!("{base}?auth=k2"));
    let upper = with_headers("https://bsc-rpc.example", &[("Authorization", "Bearer k1")]);
    let lower = with_headers("https://bsc-rpc.example", &[("authorization", "Bearer k1")]);
    let plain = ProviderUri::Uri("https://bsc-rpc.example/v2/key".to_string());
    let keys = json!({
        "aptos_query_auth": provider_rank_key("aptos", &query),
        "aptos_header_auth": provider_rank_key("aptos", &header),
        "aptos_other_auth": provider_rank_key("aptos", &other),
        "header_upper": provider_rank_key("bsc", &upper),
        "header_lower": provider_rank_key("bsc", &lower),
        "no_headers": provider_rank_key("bsc", &plain),
    });
    artifact("m19-rank-keys", keys.clone());
    assert_eq!(keys["aptos_query_auth"], keys["aptos_header_auth"]);
    assert_ne!(keys["aptos_query_auth"], keys["aptos_other_auth"]);
    assert_eq!(keys["header_upper"], keys["header_lower"]);
    assert_eq!(keys["no_headers"], "https://bsc-rpc.example/v2/key");
}

const TON_DEAD_V3: &str = "https://ton-a.example?v3-endpoint=https%3A%2F%2Fton-v3-a.example";
const TON_LIVE_V3: &str = "https://ton-b.example?v3-endpoint=https%3A%2F%2Fton-v3-b.example";

/// Probes the TON pool once and plans both a v2 and a v3 dispatch from that report.
async fn ton_probe_then_plan(
    uris: &[&str],
) -> (
    Value,
    Result<Vec<usize>, String>,
    Result<Vec<usize>, String>,
) {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                uris.iter()
                    .map(|uri| ProviderUri::Uri(uri.to_string()))
                    .collect(),
                1,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let transport = probe_transport(
        |url, _| {
            if url.starts_with("https://ton-v3-b.example") {
                Ok(json!({"last": {"seqno": 9}}))
            } else {
                Err("HTTP 503 Service Unavailable".to_string())
            }
        },
        |_, _| Ok(json!({"jsonrpc": "2.0", "id": "1", "result": {"last": {"seqno": 9}}})),
    );
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([("ton".to_string(), "TON".to_string())]),
    );
    let report = source.get_provider_health_report().await.unwrap();
    let tracker = crate::provider_health::ProviderRankTracker::new();
    tracker.seed_from_report(&report).await;
    let pool = pillar_config::ProviderConfigGetter::get_provider_config(&getter, "ton").unwrap();
    let v2 = plan_dispatch(
        &tracker,
        "ton",
        required_provider_quorum(pool, "ton").unwrap(),
    )
    .await
    .map(|plan| plan.into_iter().map(|entry| entry.index).collect())
    .map_err(|error| error.to_string());
    let v3 = plan_ton_v3_dispatch(&tracker, required_provider_quorum(pool, "ton").unwrap())
        .await
        .map(|plan| plan.into_iter().map(|entry| entry.index).collect())
        .map_err(|error| error.to_string());
    (serde_json::to_value(&report).unwrap(), v2, v3)
}

/// M-18 class for TON: the v3 probe ranks the v3 endpoint that v3 reads dial, so a dead v3
/// endpoint behind a live v2 one is excluded from v3 dispatch and leaves v2 dispatch alone.
#[tokio::test]
async fn m18_ton_v3_dispatch_ranks_by_the_v3_probe() {
    let alone = ton_probe_then_plan(&[TON_DEAD_V3]).await;
    let with_live = ton_probe_then_plan(&[TON_DEAD_V3, TON_LIVE_V3]).await;
    let serialized = serde_json::to_string(&with_live.0).unwrap();
    artifact(
        "m18-ton-v3-rank",
        json!({
            "dead_v3_alone": {"v2_plan": format!("{:?}", alone.1), "v3_plan": format!("{:?}", alone.2)},
            "dead_v3_then_live_v3": {"v2_plan": format!("{:?}", with_live.1), "v3_plan": format!("{:?}", with_live.2)},
            "report": with_live.0,
        }),
    );
    assert_eq!(
        alone.1,
        Ok(vec![0]),
        "v2 dispatch keeps the live v2 endpoint"
    );
    assert!(
        alone
            .2
            .as_ref()
            .is_err_and(|error| error.contains("Not enough healthy providers")),
        "a dead v3 endpoint must not serve v3 reads: {:?}",
        alone.2
    );
    assert_eq!(with_live.1.map(|plan| plan.len()), Ok(2));
    assert_eq!(
        with_live.2,
        Ok(vec![1, 0]),
        "the live v3 endpoint first, the dead one last"
    );
    assert!(
        !serialized.contains("ton-v3 "),
        "the v3 rank key never reaches /provider-health: {serialized}"
    );
}

const IOTA_DIGEST: &str = "8GTGoiWbNHGYp4dYV6qKAmKZRMRpUd9VhJ6nNqzm6JEH";

/// `iota_getTransactionBlock` with the PTB rendered as a fullnode (`vector<address>`) or an
/// indexer (`0x1::option::Option<address>`) renders an `Option<address>` pure input.
fn iota_transaction(sender: &str, checkpoint: &str, rendering: &str) -> Value {
    let value_type = match rendering {
        "fullnode" => "vector<address>",
        _ => "0x1::option::Option<address>",
    };
    json!({"jsonrpc": "2.0", "id": 1, "result": {
        "digest": IOTA_DIGEST,
        "checkpoint": checkpoint,
        "transaction": {"data": {
            "sender": sender,
            "transaction": {
                "kind": "ProgrammableTransaction",
                "inputs": [{"type": "pure", "valueType": value_type, "value": [sender]}],
            },
        }},
        "effects": {"status": {"status": "success"}},
    }})
}

async fn iota_sender(answers: [Value; 2]) -> Result<String, AppCoreError> {
    let urls = [
        "https://iota-fullnode.example",
        "https://iota-indexer.example",
    ];
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "iotal1".to_string(),
            ProviderConfig::with_distinct_entities(
                urls.iter()
                    .map(|url| ProviderUri::Uri(url.to_string()))
                    .collect(),
                2,
            ),
        )]),
        Some(&["iotal1".to_string()]),
    )
    .unwrap();
    let answers = Arc::new(answers);
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        probe_transport(
            |url, _| Err(format!("unexpected GET {url}")),
            move |url, _| Ok(answers[usize::from(url.contains("indexer"))].clone()),
        ),
    );
    checks
        .source_transaction_from_address("iotal1", IOTA_DIGEST)
        .await
}

/// M-20: a fullnode and an indexer agreeing on the sender of one transaction agree, however
/// each renders its PTB; a different sender or checkpoint still splits the quorum.
#[tokio::test]
async fn m20_iota_sender_quorum_ignores_the_rendered_ptb() {
    let sender = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let other = "0x2222222222222222222222222222222222222222222222222222222222222222";
    let mixed = iota_sender([
        iota_transaction(sender, "42", "fullnode"),
        iota_transaction(sender, "42", "indexer"),
    ])
    .await;
    let wrong_sender = iota_sender([
        iota_transaction(sender, "42", "fullnode"),
        iota_transaction(other, "42", "indexer"),
    ])
    .await;
    let wrong_checkpoint = iota_sender([
        iota_transaction(sender, "42", "fullnode"),
        iota_transaction(sender, "43", "indexer"),
    ])
    .await;
    artifact(
        "m20-iota-sender",
        json!({
            "fullnode_and_indexer_same_sender": format!("{mixed:?}"),
            "different_sender": format!("{wrong_sender:?}"),
            "different_checkpoint": format!("{wrong_checkpoint:?}"),
        }),
    );
    assert_eq!(mixed.unwrap(), sender);
    for (name, result) in [("sender", wrong_sender), ("checkpoint", wrong_checkpoint)] {
        let error = result.expect_err(name).to_string();
        assert!(error.contains("quorum"), "{name}: {error}");
    }
}
