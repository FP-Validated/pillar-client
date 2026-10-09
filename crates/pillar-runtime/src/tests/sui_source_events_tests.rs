//! Upstream's own Sui-family source resolution (`EndpointV2SuiSdk`/`EndpointV2IotaSdk.getLZSentEvent`,
//! `scripts/gasolina-parity/emit-sui-source-events.ts`, `tests/gasolina_parity/sui_source_events.json`)
//! replayed through this resolver with the production sui and iotal1 configuration: the resolved
//! identity, guid, message, send library and options, or the same refusal.

use super::move_source_events_tests::outcome_of;
use super::*;

const FIXTURE: &str = include_str!("../../tests/gasolina_parity/sui_source_events.json");

/// Pillar-stricter, not parity: what this resolver answers where upstream differs, and why.
fn pillar_stricter(name: &str, digest: &str) -> Option<String> {
    match name {
        // Upstream matches the identity alone; the call data is built for the requested
        // version, so the resolved one must agree.
        "V301 request for a V302 event" | "without send_library" | "empty send_library" => Some(
            format!("Did not find correct PacketSent() event in tx {digest}"),
        ),
        // Upstream's `PacketSerializer.deserialize` reads any version byte.
        "encoded_packet as hex string" => Some("unsupported packet version: 0".to_string()),
        _ => None,
    }
}

#[derive(Clone)]
struct ScriptedSui {
    events: Value,
    /// A provider URL fragment whose reads fail, so only the others can vote.
    unavailable_at: Option<&'static str>,
}

#[async_trait]
impl JsonRpcTransport for ScriptedSui {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        if self
            .unavailable_at
            .is_some_and(|unavailable| url.contains(unavailable))
        {
            return Err("provider unavailable".to_string());
        }
        if body.get("query").and_then(Value::as_str).is_none() {
            assert!(
                body["method"].as_str().unwrap().starts_with("iota"),
                "{body}"
            );
            let all = self.events["data"].as_array().unwrap();
            assert_eq!(body["params"][3], false, "IOTA events must be ascending");
            let start = body["params"][1].as_u64().unwrap_or(0) as usize;
            let end = (start + 50).min(all.len());
            let data = all[start..end]
                .iter()
                .map(|event| {
                    let mut event = event.clone();
                    event["id"]["txDigest"] = body["params"][0]["Transaction"].clone();
                    event
                })
                .collect::<Vec<_>>();
            let page = json!({"data":data,"hasNextPage":end < all.len(),"nextCursor":if end < all.len() {Value::from(end as u64)} else {Value::Null}});
            return Ok(json!({"jsonrpc":"2.0","id":1,"result":page}));
        }
        assert!(
            body["query"]
                .as_str()
                .unwrap()
                .contains("transaction(digest: $digest)"),
            "{body}"
        );
        let all = self.events["data"].as_array().unwrap();
        let after = body["variables"]["after"].as_str();
        let start = after
            .and_then(|cursor| cursor.parse::<usize>().ok())
            .unwrap_or(0);
        let end = (start + 50).min(all.len());
        let nodes = all[start..end].iter().map(|event| json!({"contents":{"type":{"repr":event["type"]},"json":event["parsedJson"]}})).collect::<Vec<_>>();
        let has_next = end < all.len();
        Ok(
            json!({"data":{"transaction":{"digest":self.events.get("digestOverride").and_then(Value::as_str).unwrap_or(body["variables"]["digest"].as_str().unwrap()),"effects":{"events":{"nodes":nodes,"pageInfo":{"hasNextPage":has_next,"endCursor":if has_next {end.to_string()} else {String::new()}}}}}}}),
        )
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

fn scripted_resolver(
    environment: &str,
    chain: &str,
    events: &Value,
) -> EvmPacketSentResolver<ScriptedSui> {
    let config =
        runtime_evm_layerzero_config(environment, &[chain.to_string(), "ethereum".to_string()])
            .unwrap();
    let providers = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!("https://{chain}.example/"))],
                1,
            ),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&providers),
        ScriptedSui {
            events: events.clone(),
            unavailable_at: None,
        },
        config.packet_sent_resolver_config,
    )
}

#[tokio::test]
async fn sui_source_events_match_gasolina() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let digest = fixture["digest"].as_str().unwrap();
    let mut mismatches = Vec::new();
    let mut exact = 0;
    let mut stricter_refused = 0;
    let mut dst_name_refused = 0;
    for scenario in fixture["scenarios"].as_array().unwrap() {
        let chain = scenario["chain"].as_str().unwrap();
        let name = scenario["name"].as_str().unwrap();
        let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
        let result = scripted_resolver(environment, chain, &scenario["response"])
            .get_lz_sent_event(digest, &request)
            .await;
        let resolved = result.is_ok();
        // GraphQL renders `vector<u8>` as base64, so a JSON-RPC-only digit-string encoding
        // reaching the Sui GraphQL path is a malformed provider answer, not a packet.
        if chain == "sui" && name == "options as a type-1 digit string" {
            assert!(
                matches!(&result, Err(AppCoreError::Internal(message))
                    if message.starts_with("No Sui transaction events quorum")),
                "{chain} {name}: {result:?}"
            );
            stricter_refused += 1;
            continue;
        }
        match (
            pillar_stricter(name, digest),
            outcome_of(&result, &scenario["outcome"]),
        ) {
            (Some(ours), _) => {
                assert_eq!(
                    result.unwrap_err(),
                    AppCoreError::Internal(ours),
                    "{chain} {name}"
                );
                stricter_refused += 1;
            }
            (None, Some(difference)) => mismatches.push(format!("{chain} {name}: {difference}")),
            (None, None) => exact += 1,
        }
        // Pillar-stricter, not parity: upstream would resolve these with any destination name.
        if resolved {
            let mut renamed = request.clone();
            renamed.pathway_id.dst_chain_name = chain.to_string();
            assert_eq!(
                scripted_resolver(environment, chain, &scenario["response"])
                    .get_lz_sent_event(digest, &renamed)
                    .await
                    .unwrap_err(),
                AppCoreError::Internal(format!(
                    "Did not find correct PacketSent() event in tx {digest}"
                )),
                "{chain} {name}: another destination name"
            );
            dst_name_refused += 1;
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    assert_eq!(
        exact + stricter_refused,
        42,
        "every upstream scenario is replayed"
    );
    // Eight version/encoding refusals across both chains, plus the Sui GraphQL digit-string one.
    assert_eq!(stricter_refused, 9);
    assert_eq!(dst_name_refused, 11);
}

/// The resolver must retain the first event across ascending pages and reject a transaction
/// whose event list exceeds the protocol bound.
#[tokio::test]
async fn sui_source_resolution_includes_leading_packet_and_rejects_overbound_transactions() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["chain"] == "sui" && scenario["name"] == "V302 match")
        .unwrap();
    let mut source = scenario["response"].clone();
    let mut events = source["data"].as_array().unwrap().clone();
    let packet_event = events
        .iter()
        .find(|event| {
            event["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("PacketSentEvent"))
        })
        .unwrap()
        .clone();
    let noise = json!({"type":"0x2::noise::Noise","parsedJson":{}});
    events.resize(51, noise.clone());
    events[50] = packet_event.clone();
    source["data"] = Value::Array(events);
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let resolver = scripted_resolver(fixture["environment"].as_str().unwrap(), "sui", &source);
    resolver
        .get_lz_sent_event(fixture["digest"].as_str().unwrap(), &request)
        .await
        .unwrap();

    let mut oversized = source;
    let mut events = oversized["data"].as_array().unwrap().clone();
    events.resize(1025, noise);
    events[0] = packet_event;
    oversized["data"] = Value::Array(events);
    let resolver = scripted_resolver(fixture["environment"].as_str().unwrap(), "sui", &oversized);
    let error = resolver
        .get_lz_sent_event(fixture["digest"].as_str().unwrap(), &request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::Internal(ref message) if message.starts_with("No Sui transaction events quorum")),
        "{error:?}"
    );
}

#[tokio::test]
async fn iota_source_resolution_follows_ascending_event_cursors() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["chain"] == "iotal1" && scenario["name"] == "V302 match")
        .unwrap();
    let mut source = scenario["response"].clone();
    let mut events = source["data"].as_array().unwrap().clone();
    let packet = events
        .iter()
        .find(|event| {
            event["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("PacketSentEvent"))
        })
        .unwrap()
        .clone();
    events.resize(51, json!({"type":"0x2::noise::Noise","parsedJson":{}}));
    events[50] = packet;
    source["data"] = Value::Array(events);
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let resolver = scripted_resolver(fixture["environment"].as_str().unwrap(), "iotal1", &source);
    resolver
        .get_lz_sent_event(fixture["digest"].as_str().unwrap(), &request)
        .await
        .unwrap();
}
/// Two URLs of one entity agreeing on the events are one vote, as on every quorum read.
#[tokio::test]
async fn sui_events_from_two_urls_of_one_entity_do_not_meet_a_two_entity_quorum() {
    use pillar_config::provider_validation::{
        ProviderVoter, Quorum, QuorumStrategy, PROVIDER_CATEGORY_ANY,
    };

    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let environment = fixture["environment"].as_str().unwrap();
    let digest = fixture["digest"].as_str().unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["chain"] == "sui" && scenario["name"] == "V302 match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let config =
        runtime_evm_layerzero_config(environment, &["sui".to_string(), "ethereum".to_string()])
            .unwrap();
    let resolve = |entities: [(&str, &str); 3]| {
        let voters = entities
            .iter()
            .map(|(category, entity)| ProviderVoter {
                category: category.to_string(),
                entity: entity.to_string(),
            })
            .collect();
        let pool = ProviderConfig::new(
            ["sui-a", "sui-b", "sui-unavailable"]
                .iter()
                .map(|host| ProviderUri::Uri(format!("https://{host}.example/")))
                .collect(),
            voters,
            QuorumStrategy {
                all_of: vec![std::collections::BTreeMap::from([(
                    PROVIDER_CATEGORY_ANY.to_string(),
                    Quorum::Count(2),
                )])],
                one_of: Vec::new(),
            },
        )
        .unwrap();
        let providers = StaticProviderConfig::new(
            indexmap::IndexMap::from([("sui".to_string(), pool)]),
            Some(&["sui".to_string()]),
        )
        .unwrap();
        EvmPacketSentResolver::new(
            &ProviderSnapshotHandle::from_getter(&providers),
            ScriptedSui {
                events: scenario["response"].clone(),
                unavailable_at: Some("sui-unavailable"),
            },
            config.packet_sent_resolver_config.clone(),
        )
    };

    let distinct = resolve([
        ("shared_external", "alchemy"),
        ("internal", "operator"),
        ("shared_external", "quicknode"),
    ]);
    distinct
        .get_lz_sent_event(digest, &request)
        .await
        .expect("two distinct entities meet any:2");

    let one_entity = resolve([
        ("shared_external", "alchemy"),
        ("shared_external", "alchemy"),
        ("internal", "operator"),
    ]);
    let error = one_entity
        .get_lz_sent_event(digest, &request)
        .await
        .expect_err("two URLs of one entity cannot meet any:2");
    assert!(
        matches!(&error, AppCoreError::Internal(message)
            if message.starts_with("No Sui transaction events quorum")),
        "{error:?}"
    );
}
#[tokio::test]
async fn sui_provider_with_wrong_transaction_digest_loses_its_vote() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let scenario = fixture["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["chain"] == "sui" && scenario["name"] == "V302 match")
        .unwrap();
    let request: LzMessageId = serde_json::from_value(scenario["request"].clone()).unwrap();
    let mut wrong = scenario["response"].clone();
    wrong["digestOverride"] = Value::from("another-transaction-digest");
    let error = scripted_resolver(fixture["environment"].as_str().unwrap(), "sui", &wrong)
        .get_lz_sent_event(fixture["digest"].as_str().unwrap(), &request)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::Internal(ref message) if message.starts_with("No Sui transaction events quorum")),
        "{error:?}"
    );
}
