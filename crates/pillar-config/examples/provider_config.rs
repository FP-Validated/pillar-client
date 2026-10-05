//! Offline operator tool for the providers-v2 cutover. Nothing is fetched or sent.
//!
//! ```text
//! cargo run -p pillar-config --example provider_config -- convert <legacy.json> <labels.json> <out-dir>
//! cargo run -p pillar-config --example provider_config -- validate <providers-v2.json> <quorum-strategy.json> [chain,chain,...]
//! ```
//!
//! `convert` rewrites a retired `{ "<chain>": { "uris": [...], "quorum": n } }` file as
//! `providers-v2.json` + `quorum-strategy.json`. Every URI host must be labelled in
//! `labels.json` as `{ "<host>": { "category": "...", "entity": "..." } }`; a legacy quorum
//! of `n` becomes `{ "allOf": [{ "any": n }] }`, i.e. `n` distinct entities, so a file whose
//! quorum relied on several URIs of one operator no longer validates. `validate` runs the
//! exact loader the service starts with and prints a redacted summary.
use pillar_config::{
    provider_validation::canonical_strategy_key, redact_url, ProviderConfigGetter, ProviderUri,
    StaticProviderConfig,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["convert", legacy, labels, out_dir] => convert(legacy, labels, out_dir),
        ["validate", providers, strategy] => validate(providers, strategy, None),
        ["validate", providers, strategy, chains] => validate(providers, strategy, Some(chains)),
        _ => Err(
            "usage: provider_config convert <legacy.json> <labels.json> <out-dir> | \
                  validate <providers-v2.json> <quorum-strategy.json> [chain,chain,...]"
                .to_string(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))
}

fn host(uri: &str) -> Result<String, String> {
    url::Url::parse(uri)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .ok_or_else(|| format!("{}: not an absolute URL", redact_url(uri)))
}

fn convert(legacy: &str, labels: &str, out_dir: &str) -> Result<(), String> {
    let legacy: indexmap::IndexMap<String, Value> =
        serde_json::from_str(&read(legacy)?).map_err(|error| format!("legacy file: {error}"))?;
    let labels: BTreeMap<String, Value> =
        serde_json::from_str(&read(labels)?).map_err(|error| format!("labels file: {error}"))?;
    let mut entities = Vec::<String>::new();
    let mut unlabelled = Vec::new();
    let mut chains = indexmap::IndexMap::new();
    let mut strategies = indexmap::IndexMap::new();
    for (chain, config) in &legacy {
        let uris = config["uris"]
            .as_array()
            .ok_or_else(|| format!("chain {chain}: no uris array"))?;
        let mut entries = Vec::new();
        for uri in uris {
            let (address, headers) = match uri {
                Value::String(address) => (address.clone(), None),
                Value::Object(object) => (
                    object["uri"]
                        .as_str()
                        .ok_or_else(|| format!("chain {chain}: uri object without uri"))?
                        .to_string(),
                    object.get("headers").cloned(),
                ),
                _ => return Err(format!("chain {chain}: unsupported uri entry")),
            };
            let host = host(&address)?;
            let Some(label) = labels.get(&host) else {
                unlabelled.push(host);
                continue;
            };
            let entity = label["entity"].as_str().unwrap_or_default().to_string();
            if !entities.contains(&entity) {
                entities.push(entity.clone());
            }
            let mut entry = Map::new();
            entry.insert("uri".to_string(), Value::from(address));
            entry.insert("category".to_string(), label["category"].clone());
            entry.insert("entity".to_string(), Value::from(entity));
            if let Some(headers) = headers {
                entry.insert("headers".to_string(), headers);
            }
            entries.push(Value::Object(entry));
        }
        let quorum = config.get("quorum").and_then(Value::as_u64).unwrap_or(1);
        chains.insert(chain.clone(), json!({ "rpc": entries }));
        strategies.insert(
            chain.clone(),
            json!({ "rpc": { "allOf": [{ "any": quorum }] } }),
        );
    }
    if !unlabelled.is_empty() {
        unlabelled.sort();
        unlabelled.dedup();
        return Err(format!(
            "label these hosts in the labels file first: {}",
            unlabelled.join(", ")
        ));
    }
    // Structs rather than `json!`: a `serde_json::Value` object would sort the chains.
    #[derive(serde::Serialize)]
    struct ProvidersFile {
        entities: Vec<String>,
        chains: indexmap::IndexMap<String, Value>,
    }
    #[derive(serde::Serialize)]
    struct StrategyFile {
        default: Value,
        chains: indexmap::IndexMap<String, Value>,
    }
    let providers = serde_json::to_string_pretty(&ProvidersFile { entities, chains })
        .map_err(|error| error.to_string())?;
    let strategy = serde_json::to_string_pretty(&StrategyFile {
        default: json!({ "allOf": [{ "any": 1 }] }),
        chains: strategies,
    })
    .map_err(|error| error.to_string())?;
    // Refuse to write a pair the service would refuse to start with.
    let roster = legacy.keys().cloned().collect::<Vec<_>>();
    let loaded = StaticProviderConfig::from_v2(&providers, &strategy, Some(&roster))
        .map_err(|error| format!("converted pair does not validate: {error}"))?;
    let out = std::path::Path::new(out_dir);
    std::fs::create_dir_all(out).map_err(|error| format!("{out_dir}: {error}"))?;
    for (name, body) in [
        ("providers-v2.json", &providers),
        ("quorum-strategy.json", &strategy),
    ] {
        std::fs::write(out.join(name), format!("{body}\n"))
            .map_err(|error| format!("{out_dir}/{name}: {error}"))?;
    }
    summarize(&loaded);
    Ok(())
}

fn validate(providers: &str, strategy: &str, chains: Option<&str>) -> Result<(), String> {
    let roster = chains.map(|chains| chains.split(',').map(str::to_string).collect::<Vec<_>>());
    let loaded =
        StaticProviderConfig::from_v2(&read(providers)?, &read(strategy)?, roster.as_deref())
            .map_err(|error| error.to_string())?;
    summarize(&loaded);
    Ok(())
}

fn summarize(loaded: &StaticProviderConfig) {
    for (chain, config) in loaded.get_provider_configs() {
        let pool = config
            .uris
            .iter()
            .zip(&config.voters)
            .map(|(uri, voter)| {
                let address = match uri {
                    ProviderUri::Uri(uri) | ProviderUri::UriWithHeaders { uri, .. } => uri,
                };
                format!(
                    "{}/{}={}",
                    voter.category,
                    voter.entity,
                    redact_url(address)
                )
            })
            .collect::<Vec<_>>();
        println!(
            "{chain}: quorum={}{} [{}]",
            canonical_strategy_key(&config.strategy),
            if config.single_entity_trust_root() {
                " single-entity-trust-root"
            } else {
                ""
            },
            pool.join(", ")
        );
    }
}
