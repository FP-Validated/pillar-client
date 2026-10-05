//! Fixture builders for tests that express provider pools as `{ uris, quorum }`.
use indexmap::IndexMap;
use serde_json::{json, Value};

/// Rewrites a `{ "<chain>": { "uris": [...], "quorum": n } }` fixture as the
/// `(providers-v2.json, quorum-strategy.json)` pair the loader accepts: every URI is its own
/// entity and each chain's `rpc` strategy is `{ allOf: [{ any: n }] }`, so the fixture keeps
/// meaning "n agreeing URIs". A missing quorum is 1. Chain order is kept.
pub fn providers_v2_from_uris_json(fixture: &str) -> (String, String) {
    let fixture: IndexMap<String, Value> =
        serde_json::from_str(fixture).expect("fixture is a JSON object of chains");
    let mut entities = Vec::new();
    let mut chains = IndexMap::new();
    let mut strategies = IndexMap::new();
    for (chain, config) in fixture {
        let entries = config["uris"]
            .as_array()
            .expect("fixture chain has uris")
            .iter()
            .enumerate()
            .map(|(index, uri)| {
                let entity = format!("{chain}-{index}");
                entities.push(entity.clone());
                let mut entry = match uri {
                    Value::String(uri) => json!({ "uri": uri }),
                    Value::Object(object) => Value::Object(object.clone()),
                    other => panic!("unsupported fixture uri {other}"),
                };
                entry["category"] = Value::from("internal");
                entry["entity"] = Value::from(entity);
                entry
            })
            .collect::<Vec<_>>();
        let quorum = config.get("quorum").and_then(Value::as_u64).unwrap_or(1);
        chains.insert(chain.clone(), json!({ "rpc": entries }));
        strategies.insert(chain, json!({ "rpc": { "allOf": [{ "any": quorum }] } }));
    }
    #[derive(serde::Serialize)]
    struct ProvidersFile {
        entities: Vec<String>,
        chains: IndexMap<String, Value>,
    }
    #[derive(serde::Serialize)]
    struct StrategyFile {
        default: Value,
        chains: IndexMap<String, Value>,
    }
    (
        serde_json::to_string(&ProvidersFile { entities, chains }).expect("fixture serializes"),
        serde_json::to_string(&StrategyFile {
            default: json!({ "allOf": [{ "any": 1 }] }),
            chains: strategies,
        })
        .expect("fixture serializes"),
    )
}

/// [`providers_v2_from_uris_json`] loaded through the production validator.
pub fn provider_configs_from_uris_json(fixture: &str) -> crate::ProviderConfigs {
    let (providers, strategy) = providers_v2_from_uris_json(fixture);
    crate::provider_validation::provider_configs_from_v2(&providers, &strategy)
        .expect("fixture converts to a valid providers-v2 pair")
}

/// The providers-v2.json half of [`providers_v2_from_uris_json`].
pub fn providers_json(fixture: impl AsRef<str>) -> String {
    providers_v2_from_uris_json(fixture.as_ref()).0
}

/// The quorum-strategy.json half of [`providers_v2_from_uris_json`].
pub fn strategy_json(fixture: impl AsRef<str>) -> String {
    providers_v2_from_uris_json(fixture.as_ref()).1
}
