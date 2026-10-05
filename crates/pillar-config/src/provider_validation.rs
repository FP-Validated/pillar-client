//! Entity-aware provider-v2 configuration: `providers-v2.json` plus `quorum-strategy.json`,
//! validated and resolved as upstream does, and turned into the per-chain `rpc` pool the
//! runtime dispatches and votes over.
use crate::{ConfigError, ProviderConfig, ProviderConfigs, ProviderUri};
use indexmap::IndexMap;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const PROVIDER_CATEGORY_INTERNAL: &str = "internal";
pub const PROVIDER_CATEGORY_DEDICATED_EXTERNAL: &str = "dedicated_external";
pub const PROVIDER_CATEGORY_SHARED_EXTERNAL: &str = "shared_external";
pub const PROVIDER_CATEGORY_ANY: &str = "any";
const PROVIDER_CATEGORIES: [&str; 3] = [
    PROVIDER_CATEGORY_INTERNAL,
    PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
    PROVIDER_CATEGORY_SHARED_EXTERNAL,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    Count(u64),
    Max,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEntryV2 {
    pub uri: String,
    pub category: String,
    pub entity: String,
    pub headers: BTreeMap<String, String>,
}
pub type ProviderConfigV2 = BTreeMap<String, Vec<ProviderEntryV2>>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvidersFileV2 {
    pub entities: Vec<String>,
    pub chains: BTreeMap<String, ProviderConfigV2>,
}
pub type CategoryRequirement = BTreeMap<String, Quorum>;
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuorumStrategy {
    pub all_of: Vec<CategoryRequirement>,
    pub one_of: Vec<CategoryRequirement>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuorumStrategyFileContent {
    pub default: Option<QuorumStrategy>,
    pub chains: BTreeMap<String, BTreeMap<String, QuorumStrategy>>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrategyRestrictions {
    pub minimum_max_entities: Option<u64>,
}

pub fn validate_provider_entry(
    entry: &ProviderEntryV2,
    known_entities: &BTreeSet<String>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if entry.uri.is_empty() {
        errors.push(r#"entry is missing required "uri""#.to_string());
    }
    if entry.category.is_empty() {
        errors.push(r#"entry is missing required "category""#.to_string());
    } else if !PROVIDER_CATEGORIES.contains(&entry.category.as_str()) {
        errors.push(format!(
            r#"has unknown category "{}" - must be one of: {}"#,
            entry.category,
            PROVIDER_CATEGORIES.join(", ")
        ));
    }
    if entry.entity.is_empty() {
        errors.push(r#"entry is missing required "entity""#.to_string());
    } else if !known_entities.contains(&entry.entity) {
        errors.push(format!(r#"has entity "{}" which is not in the registered entities list - add it to entities[] first"#, entry.entity));
    }
    errors
}

pub fn validate_provider_config(
    file: &ProvidersFileV2,
    known: &[String],
) -> Result<(), ConfigError> {
    let known = known.iter().cloned().collect::<BTreeSet<_>>();
    let mut errors = Vec::new();
    for (chain, endpoints) in &file.chains {
        for (endpoint, entries) in endpoints {
            for entry in entries {
                let prefix = format!(r#"chain "{chain}" {endpoint}[]"#);
                errors.extend(
                    validate_provider_entry(entry, &known)
                        .into_iter()
                        .map(|e| format!("{prefix} {e}")),
                );
            }
        }
    }
    validation_result("providers-v2.json validation failed", errors)
}

pub fn check_strategy_config(
    file: &ProvidersFileV2,
    strategy: &QuorumStrategyFileContent,
) -> Result<(), ConfigError> {
    check_strategy_config_with_restrictions(file, strategy, &StrategyRestrictions::default())
}

pub fn check_strategy_config_with_restrictions(
    file: &ProvidersFileV2,
    strategy_file: &QuorumStrategyFileContent,
    restrictions: &StrategyRestrictions,
) -> Result<(), ConfigError> {
    let Some(default) = &strategy_file.default else {
        return Err(ConfigError::ProviderValidation(
            r#"quorum-strategy.json: missing required "default" strategy"#.to_string(),
        ));
    };
    let mut errors = Vec::new();
    for (chain, endpoints) in &file.chains {
        for (endpoint, entries) in endpoints {
            let raw = strategy_file
                .chains
                .get(chain)
                .and_then(|m| m.get(endpoint))
                .unwrap_or(default);
            let counts = entities_per_category(entries);
            let resolved = match resolve_max(raw, &counts, restrictions.minimum_max_entities) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(format!("Chain \"{chain}\" {endpoint}: {error}."));
                    continue;
                }
            };
            if !is_strategy_satisfiable(&counts, &resolved) {
                errors.push(format!(
                    r#"Chain "{chain}" {endpoint}: strategy not satisfiable. Strategy: {}."#,
                    strategy_debug(&resolved)
                ));
            }
        }
    }
    validation_result("Strategy config validation failed", errors)
}

fn validation_result(prefix: &str, errors: Vec<String>) -> Result<(), ConfigError> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::ProviderValidation(format!(
            "{prefix}:\n{}",
            errors
                .into_iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        )))
    }
}

pub fn entities_per_category(entries: &[ProviderEntryV2]) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = PROVIDER_CATEGORIES
        .into_iter()
        .map(|c| (c.to_string(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for entry in entries {
        if let Some(entities) = out.get_mut(&entry.category) {
            entities.insert(entry.entity.clone());
        }
    }
    out
}

pub fn is_strategy_satisfiable(
    counts: &BTreeMap<String, BTreeSet<String>>,
    strategy: &QuorumStrategy,
) -> bool {
    if strategy.one_of.is_empty() {
        return check_requirement_set(counts, &strategy.all_of, &CategoryRequirement::new());
    }
    strategy
        .one_of
        .iter()
        .any(|alt| check_requirement_set(counts, &strategy.all_of, alt))
}

fn check_requirement_set(
    counts: &BTreeMap<String, BTreeSet<String>>,
    all_of: &[CategoryRequirement],
    one_of: &CategoryRequirement,
) -> bool {
    let pool = counts
        .values()
        .flat_map(|s| s.iter())
        .collect::<BTreeSet<_>>()
        .len();
    let mut categories = Vec::new();
    let mut any_quorum = 0usize;
    for req in all_of.iter().chain(std::iter::once(one_of)) {
        for (category, quorum) in req {
            let Quorum::Count(n) = quorum else {
                return false;
            };
            let Ok(n) = usize::try_from(*n) else {
                return false;
            };
            if category == PROVIDER_CATEGORY_ANY {
                any_quorum = any_quorum.saturating_add(n);
            } else {
                // Each slot needs its own entity, so more slots than entities is unmet;
                // checked before expanding so a mistyped count cannot exhaust memory.
                if n > pool.saturating_sub(categories.len()) {
                    return false;
                }
                categories.extend(std::iter::repeat_n(category.clone(), n));
            }
        }
    }
    pool >= any_quorum.max(categories.len())
        && assign_entities(counts, &categories, 0, &mut BTreeSet::new())
}

fn assign_entities(
    counts: &BTreeMap<String, BTreeSet<String>>,
    categories: &[String],
    at: usize,
    used: &mut BTreeSet<String>,
) -> bool {
    if at == categories.len() {
        return true;
    }
    let Some(candidates) = counts.get(&categories[at]) else {
        return false;
    };
    for entity in candidates {
        if used.insert(entity.clone()) {
            if assign_entities(counts, categories, at + 1, used) {
                return true;
            }
            used.remove(entity);
        }
    }
    false
}

fn resolve_max(
    strategy: &QuorumStrategy,
    counts: &BTreeMap<String, BTreeSet<String>>,
    minimum: Option<u64>,
) -> Result<QuorumStrategy, String> {
    let mut resolved = strategy.clone();
    let distinct = counts
        .values()
        .flat_map(|s| s.iter())
        .collect::<BTreeSet<_>>()
        .len() as u64;
    for req in resolved.all_of.iter_mut().chain(resolved.one_of.iter_mut()) {
        for (category, quorum) in req {
            if matches!(quorum, Quorum::Max) {
                let actual = if category == PROVIDER_CATEGORY_ANY {
                    distinct
                } else {
                    counts.get(category).map_or(0, |set| set.len() as u64)
                };
                if let Some(floor) = minimum {
                    if actual < floor {
                        return Err(format!("RestrictionViolationError: category={category}, resolved={actual}, minimumMaxEntities={floor}"));
                    }
                }
                *quorum = Quorum::Count(actual);
            }
        }
    }
    Ok(resolved)
}

fn strategy_debug(strategy: &QuorumStrategy) -> String {
    format!(
        "{{allOf:{:?},oneOf:{:?}}}",
        strategy.all_of, strategy.one_of
    )
}

pub fn is_trivial_strategy(strategy: &QuorumStrategy) -> bool {
    if !strategy.one_of.is_empty() {
        return false;
    }
    strategy
        .all_of
        .iter()
        .flat_map(|req| req.values())
        .try_fold(0u64, |sum, q| match q {
            Quorum::Count(n) => sum.checked_add(*n),
            Quorum::Max => None,
        })
        .is_some_and(|n| n <= 1)
}

pub fn canonical_strategy_key(strategy: &QuorumStrategy) -> String {
    fn object(reqs: &[CategoryRequirement]) -> String {
        format!(
            "[{}]",
            reqs.iter()
                .map(|req| format!(
                    "{{{}}}",
                    req.iter()
                        .map(|(key, value)| format!(
                            "\"{key}\":{}",
                            match value {
                                Quorum::Count(n) => n.to_string(),
                                Quorum::Max => "\"max\"".to_string(),
                            }
                        ))
                        .collect::<Vec<_>>()
                        .join(",")
                ))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
    format!(
        "{{\"allOf\":{},\"oneOf\":{}}}",
        object(&strategy.all_of),
        object(&strategy.one_of)
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderableProvider {
    pub category: String,
    pub entity: String,
    pub id: String,
    pub rank: i32,
}

pub fn order_providers_for_quorum(
    providers: &[OrderableProvider],
    strategy: &QuorumStrategy,
) -> Vec<OrderableProvider> {
    let required = strategy
        .all_of
        .iter()
        .flat_map(|r| r.keys().cloned())
        .collect::<BTreeSet<_>>();
    let any_required = required.contains(PROVIDER_CATEGORY_ANY);
    let mut categories = PROVIDER_CATEGORIES
        .iter()
        .filter(|c| providers.iter().any(|p| p.category == **c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>();
    categories.sort_by_key(|category| {
        (
            if any_required || required.contains(category) {
                0
            } else {
                1
            },
            providers
                .iter()
                .filter(|p| p.category == *category)
                .map(|p| p.rank)
                .min()
                .unwrap_or(0),
            PROVIDER_CATEGORIES
                .iter()
                .position(|c| *c == category)
                .unwrap_or(usize::MAX),
        )
    });
    let mut output = Vec::with_capacity(providers.len());
    for category in categories {
        let mut buckets: BTreeMap<String, Vec<OrderableProvider>> = BTreeMap::new();
        let mut order = Vec::new();
        for p in providers.iter().filter(|p| p.category == category) {
            if !buckets.contains_key(&p.entity) {
                order.push(p.entity.clone());
            }
            buckets.entry(p.entity.clone()).or_default().push(p.clone());
        }
        order.sort_by_key(|entity| {
            buckets
                .get(entity)
                .and_then(|b| b.first())
                .map_or(0, |p| p.rank)
        });
        loop {
            let mut moved = false;
            for entity in &order {
                if let Some(p) = buckets
                    .get_mut(entity)
                    .and_then(|b| (!b.is_empty()).then(|| b.remove(0)))
                {
                    output.push(p);
                    moved = true;
                }
            }
            if !moved {
                break;
            }
        }
    }
    output
}

pub fn min_providers_for_strategy(
    providers: &[OrderableProvider],
    strategy: &QuorumStrategy,
) -> usize {
    let mut votes = BTreeMap::<String, BTreeSet<String>>::new();
    for (index, provider) in providers.iter().enumerate() {
        votes
            .entry(provider.category.clone())
            .or_default()
            .insert(provider.entity.clone());
        if is_strategy_satisfiable(&votes, strategy) {
            return index + 1;
        }
    }
    providers.len()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedStrategyFileContent {
    pub default: Option<QuorumStrategy>,
    pub chains: BTreeMap<String, BTreeMap<String, QuorumStrategy>>,
}

pub fn precompute_resolved_strategy(
    providers: &ProvidersFileV2,
    raw: &QuorumStrategyFileContent,
    restrictions: &StrategyRestrictions,
) -> Result<ResolvedStrategyFileContent, String> {
    let empty_pool = BTreeMap::new();
    let default = raw
        .default
        .as_ref()
        .map(|s| resolve_max(s, &empty_pool, None))
        .transpose()?;
    let mut chains = BTreeMap::new();
    for (chain, endpoints) in &providers.chains {
        let mut endpoint_strategies = BTreeMap::new();
        for (endpoint, entries) in endpoints {
            let Some(raw_strategy) = raw
                .chains
                .get(chain)
                .and_then(|m| m.get(endpoint))
                .or(raw.default.as_ref())
            else {
                continue;
            };
            let pool = entities_per_category(entries);
            let resolved = resolve_max(raw_strategy, &pool, restrictions.minimum_max_entities)
                .map_err(|e| format!("{chain}.{endpoint}: {e}"))?;
            endpoint_strategies.insert(endpoint.clone(), resolved);
        }
        chains.insert(chain.clone(), endpoint_strategies);
    }
    Ok(ResolvedStrategyFileContent { default, chains })
}

/// The only endpoint pool this service dispatches: upstream's `DEFAULT_ENDPOINT_TYPE`
/// (`packages/multiprovider/src/common.ts:36`). Other endpoint types are validated with the
/// rest of the file but never dialled.
pub const RPC_ENDPOINT_TYPE: &str = "rpc";

/// The `(category, entity)` one configured URI votes as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderVoter {
    pub category: String,
    pub entity: String,
}

/// Distinct entities per category among `voters`, the shape the strategy is evaluated over.
pub fn voter_entities<'a>(
    voters: impl IntoIterator<Item = &'a ProviderVoter>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::<String, BTreeSet<String>>::new();
    for voter in voters {
        out.entry(voter.category.clone())
            .or_default()
            .insert(voter.entity.clone());
    }
    out
}

impl<'de> Deserialize<'de> for Quorum {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Count(u64),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Count(count) => Ok(Quorum::Count(count)),
            Raw::Text(text) if text == "max" => Ok(Quorum::Max),
            Raw::Text(text) => Err(serde::de::Error::custom(format!(
                r#"quorum count must be a non-negative integer or "max", got "{text}""#
            ))),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvidersFile {
    entities: Vec<String>,
    chains: IndexMap<String, IndexMap<String, Vec<RawProviderEntry>>>,
}

// Fields default to empty so `validate_provider_entry` reports every missing one, as upstream does.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProviderEntry {
    #[serde(default)]
    uri: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    entity: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

// Top-level keys starting with `_` are documentation upstream lets through
// (`dynamic-config/src/providerConfig/index.ts:102-104`); any other unknown key is refused.
#[derive(Deserialize)]
struct RawStrategyFile {
    default: Option<RawStrategy>,
    #[serde(default)]
    chains: BTreeMap<String, BTreeMap<String, RawStrategy>>,
    #[serde(default)]
    restrictions: RawRestrictions,
    #[serde(flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawRestrictions {
    minimum_max_entities: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawStrategy {
    #[serde(default)]
    all_of: Vec<CategoryRequirement>,
    #[serde(default)]
    one_of: Vec<CategoryRequirement>,
}

impl From<RawStrategy> for QuorumStrategy {
    fn from(raw: RawStrategy) -> Self {
        Self {
            all_of: raw.all_of,
            one_of: raw.one_of,
        }
    }
}

pub const LEGACY_PROVIDER_CONFIG_ERROR: &str = "the legacy `{ uris, quorum }` provider \
     configuration is no longer accepted; supply providers-v2.json (`entities` + \
     `chains.<chain>.rpc[{uri, category, entity}]`) with quorum-strategy.json";

/// Refuses a provider file in the retired `{ uris, quorum }` shape by name, so an operator
/// who has not migrated is told so rather than shown a schema error.
pub fn reject_legacy_provider_config(raw: &str) -> Result<(), ConfigError> {
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|error| ConfigError::Json(format!("providers-v2.json: {error}")))?;
    let looks_legacy = value.as_object().is_some_and(|object| {
        !object.contains_key("chains")
            && object
                .values()
                .any(|chain| chain.get("uris").is_some() || chain.get("quorum").is_some())
    });
    if looks_legacy {
        return Err(ConfigError::ProviderValidation(
            LEGACY_PROVIDER_CONFIG_ERROR.to_string(),
        ));
    }
    Ok(())
}

fn parse_providers_file(raw: &str) -> Result<RawProvidersFile, ConfigError> {
    reject_legacy_provider_config(raw)?;
    // From the text: a `serde_json::Value` object is sorted, which would lose the file's
    // chain order.
    serde_json::from_str(raw)
        .map_err(|error| ConfigError::Json(format!("providers-v2.json: {error}")))
}

fn parse_strategy_file(
    raw: &str,
) -> Result<(QuorumStrategyFileContent, StrategyRestrictions), ConfigError> {
    let raw = serde_json::from_str::<RawStrategyFile>(raw)
        .map_err(|error| ConfigError::Json(format!("quorum-strategy.json: {error}")))?;
    if let Some(key) = raw.extra.keys().find(|key| !key.starts_with('_')) {
        return Err(ConfigError::Json(format!(
            "quorum-strategy.json: unknown field `{key}`, expected `default`, `chains`, \
             `restrictions` or a `_`-prefixed documentation field"
        )));
    }
    Ok((
        QuorumStrategyFileContent {
            default: raw.default.map(Into::into),
            chains: raw
                .chains
                .into_iter()
                .map(|(chain, endpoints)| {
                    (
                        chain,
                        endpoints
                            .into_iter()
                            .map(|(endpoint, strategy)| (endpoint, strategy.into()))
                            .collect(),
                    )
                })
                .collect(),
        },
        StrategyRestrictions {
            minimum_max_entities: raw.restrictions.minimum_max_entities,
        },
    ))
}

/// Validates a `providers-v2.json` / `quorum-strategy.json` pair as one unit and returns
/// each chain's `rpc` pool with its voters and resolved strategy, in file order. Chains
/// without an `rpc` pool are omitted; the roster check reports any that were required.
pub fn provider_configs_from_v2(
    providers_raw: &str,
    strategy_raw: &str,
) -> Result<ProviderConfigs, ConfigError> {
    let providers = parse_providers_file(providers_raw)?;
    let (strategy, restrictions) = parse_strategy_file(strategy_raw)?;
    let file = ProvidersFileV2 {
        entities: providers.entities.clone(),
        chains: providers
            .chains
            .iter()
            .map(|(chain, endpoints)| {
                (
                    chain.clone(),
                    endpoints
                        .iter()
                        .map(|(endpoint, entries)| {
                            (
                                endpoint.clone(),
                                entries
                                    .iter()
                                    .map(|entry| ProviderEntryV2 {
                                        uri: entry.uri.clone(),
                                        category: entry.category.clone(),
                                        entity: entry.entity.clone(),
                                        headers: entry.headers.clone(),
                                    })
                                    .collect(),
                            )
                        })
                        .collect(),
                )
            })
            .collect(),
    };
    validate_provider_config(&file, &file.entities)?;
    check_strategy_config_with_restrictions(&file, &strategy, &restrictions)?;
    let resolved = precompute_resolved_strategy(&file, &strategy, &restrictions)
        .map_err(ConfigError::ProviderValidation)?;
    let mut configs = ProviderConfigs::new();
    for (chain, endpoints) in providers.chains {
        let Some(entries) = endpoints.get(RPC_ENDPOINT_TYPE) else {
            continue;
        };
        let strategy = resolved
            .chains
            .get(&chain)
            .and_then(|endpoints| endpoints.get(RPC_ENDPOINT_TYPE))
            .cloned()
            .ok_or_else(|| {
                ConfigError::ProviderValidation(format!(
                    r#"Chain "{chain}" {RPC_ENDPOINT_TYPE}: no resolved strategy"#
                ))
            })?;
        let uris = entries.iter().map(provider_uri).collect();
        let voters = entries
            .iter()
            .map(|entry| ProviderVoter {
                category: entry.category.clone(),
                entity: entry.entity.clone(),
            })
            .collect();
        let config = ProviderConfig::new(uris, voters, strategy)
            .map_err(|error| {
                ConfigError::ProviderValidation(format!(
                    "Chain \"{chain}\" {RPC_ENDPOINT_TYPE}: {error}"
                ))
            })?
            .with_sequencer(
                endpoints
                    .get(SEQUENCER_ENDPOINT_TYPE)
                    .map(|entries| entries.iter().map(provider_uri).collect())
                    .unwrap_or_default(),
            );
        configs.insert(chain, config);
    }
    Ok(configs)
}

/// The endpoint type Canton's sequencer read and scan clients come from.
pub const SEQUENCER_ENDPOINT_TYPE: &str = "sequencer";

fn provider_uri(entry: &RawProviderEntry) -> ProviderUri {
    if entry.headers.is_empty() {
        ProviderUri::Uri(entry.uri.clone())
    } else {
        ProviderUri::UriWithHeaders {
            uri: entry.uri.clone(),
            headers: entry
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<HashMap<_, _>>(),
        }
    }
}
