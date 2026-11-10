//! Entity-aware provider-v2 configuration: `providers-v2.json` plus `quorum-strategy.json`,
//! validated and resolved as upstream does, and turned into the per-chain `rpc` pool the
//! runtime dispatches and votes over.
use crate::{ConfigError, ProviderConfig, ProviderConfigs, ProviderUri};
use indexmap::IndexMap;
use serde::Deserialize;
use sha2::Digest;
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

/// A configured key appears in a diagnostic only as a name this build defines; anything else
/// is input, possibly a pasted credential, and is shown as a placeholder.
fn chain_label(chain: &str) -> &'static str {
    crate::static_chain_name(chain).unwrap_or("<unlisted chain>")
}

fn endpoint_label(endpoint: &str) -> &'static str {
    [RPC_ENDPOINT_TYPE, SEQUENCER_ENDPOINT_TYPE]
        .into_iter()
        .find(|known| *known == endpoint)
        .unwrap_or("<unlisted endpoint type>")
}

fn category_label(category: &str) -> &'static str {
    PROVIDER_CATEGORIES
        .into_iter()
        .chain([PROVIDER_CATEGORY_ANY])
        .find(|known| *known == category)
        .unwrap_or("<unlisted category>")
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
            "has an unknown category - must be one of: {}",
            PROVIDER_CATEGORIES.join(", ")
        ));
    }
    if entry.entity.is_empty() {
        errors.push(r#"entry is missing required "entity""#.to_string());
    } else if !known_entities.contains(&entry.entity) {
        errors.push("has an entity which is not in the registered entities list - add it to entities[] first".to_string());
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
            for (index, entry) in entries.iter().enumerate() {
                let prefix = format!(
                    r#"chain "{}" {}[{index}]"#,
                    chain_label(chain),
                    endpoint_label(endpoint)
                );
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
    for (source, strategy) in std::iter::once(("default", default)).chain(
        strategy_file.chains.values().flat_map(|endpoints| {
            endpoints
                .values()
                .map(|strategy| ("chain override", strategy))
        }),
    ) {
        for requirement in strategy.all_of.iter().chain(&strategy.one_of) {
            for category in requirement.keys() {
                if !PROVIDER_CATEGORIES.contains(&category.as_str())
                    && category != PROVIDER_CATEGORY_ANY
                {
                    errors.push(format!(
                        "{source}: unlisted category {}",
                        category_label(category)
                    ));
                }
            }
        }
    }
    if !errors.is_empty() {
        return validation_result("Strategy config validation failed", errors);
    }
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
                    errors.push(format!(
                        r#"Chain "{}" {}: {error}."#,
                        chain_label(chain),
                        endpoint_label(endpoint)
                    ));
                    continue;
                }
            };
            if !is_strategy_satisfiable(&counts, &resolved) {
                errors.push(format!(
                    r#"Chain "{}" {}: strategy not satisfiable. Strategy: {}."#,
                    chain_label(chain),
                    endpoint_label(endpoint),
                    strategy_diagnostic(&resolved)
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

/// Slots per named category and the `any` slots a requirement asks for; `None` when a quorum is
/// not a count.
fn requirement_demand(
    all_of: &[CategoryRequirement],
    one_of: &CategoryRequirement,
) -> Option<(BTreeMap<String, usize>, usize)> {
    let mut demand = BTreeMap::<String, usize>::new();
    let mut any_quorum = 0usize;
    for req in all_of.iter().chain(std::iter::once(one_of)) {
        for (category, quorum) in req {
            let Quorum::Count(n) = quorum else {
                return None;
            };
            let n = usize::try_from(*n).ok()?;
            if category == PROVIDER_CATEGORY_ANY {
                any_quorum = any_quorum.saturating_add(n);
            } else if n > 0 {
                let slots = demand.entry(category.clone()).or_default();
                *slots = slots.saturating_add(n);
            }
        }
    }
    Some((demand, any_quorum))
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
    let Some((demand, any_quorum)) = requirement_demand(all_of, one_of) else {
        return false;
    };
    // Each slot needs its own entity, so more slots than entities is unmet.
    let total = demand.values().fold(0usize, |sum, n| sum.saturating_add(*n));
    pool >= any_quorum.max(total) && every_category_subset_has_enough_entities(counts, &demand)
}

/// Whether every named-category slot can hold its own entity. By Hall's condition that holds
/// exactly when, for every subset of the demanded categories, the entities they can draw on
/// number at least the slots they ask for. There are only a few named categories, so the work
/// is linear in the pool, however many slots a policy asks for.
fn every_category_subset_has_enough_entities(
    counts: &BTreeMap<String, BTreeSet<String>>,
    demand: &BTreeMap<String, usize>,
) -> bool {
    let mut sets = Vec::with_capacity(demand.len());
    for category in demand.keys() {
        match counts.get(category) {
            Some(entities) => sets.push((entities, demand[category])),
            None => return false,
        }
    }
    if sets.len() > MAX_HALL_CATEGORIES {
        return false;
    }
    for subset in 1u32..(1u32 << sets.len()) {
        let mut union = BTreeSet::<&str>::new();
        let mut needed = 0usize;
        for (bit, (entities, slots)) in sets.iter().enumerate() {
            if subset & (1 << bit) != 0 {
                needed = needed.saturating_add(*slots);
                union.extend(entities.iter().map(String::as_str));
            }
        }
        if union.len() < needed {
            return false;
        }
    }
    true
}

/// Only the provider categories can be named, so this bounds nothing real; it keeps the subset
/// enumeration finite for any caller.
const MAX_HALL_CATEGORIES: usize = 8;

/// The distinct entities of a changing pool, grouped by which demanded categories each serves,
/// so Hall's condition is a sum over a constant number of group counts after every change.
struct HallPool {
    bit_of: BTreeMap<String, usize>,
    slots: Vec<usize>,
    providers: BTreeMap<(String, String), usize>,
    mask_of: BTreeMap<String, u32>,
    pairs_of: BTreeMap<String, usize>,
    groups: Vec<usize>,
}

impl HallPool {
    fn new(demand: &BTreeMap<String, usize>) -> Option<Self> {
        if demand.len() > 4 {
            return None;
        }
        Some(Self {
            bit_of: demand
                .keys()
                .enumerate()
                .map(|(bit, category)| (category.clone(), bit))
                .collect(),
            slots: demand.values().copied().collect(),
            providers: BTreeMap::new(),
            mask_of: BTreeMap::new(),
            pairs_of: BTreeMap::new(),
            groups: vec![0; 1 << demand.len()],
        })
    }

    fn add(&mut self, category: &str, entity: &str) {
        let count = self
            .providers
            .entry((category.to_string(), entity.to_string()))
            .or_default();
        *count += 1;
        if *count == 1 {
            *self.pairs_of.entry(entity.to_string()).or_default() += 1;
            if let Some(bit) = self.bit_of.get(category).copied() {
                let old = self.mask_of.get(entity).copied().unwrap_or(0);
                self.regroup(entity, old, old | (1 << bit));
            }
        }
    }

    fn remove(&mut self, category: &str, entity: &str) {
        let key = (category.to_string(), entity.to_string());
        let count = self.providers.get_mut(&key).expect("provider counted");
        *count -= 1;
        if *count == 0 {
            self.providers.remove(&key);
            let pairs = self.pairs_of.get_mut(entity).expect("entity counted");
            *pairs -= 1;
            if *pairs == 0 {
                self.pairs_of.remove(entity);
            }
            if let Some(bit) = self.bit_of.get(category).copied() {
                let old = self.mask_of.get(entity).copied().unwrap_or(0);
                self.regroup(entity, old, old & !(1 << bit));
            }
        }
    }

    fn regroup(&mut self, entity: &str, old: u32, new: u32) {
        if old != 0 {
            self.groups[old as usize] -= 1;
        }
        if new != 0 {
            self.groups[new as usize] += 1;
            self.mask_of.insert(entity.to_string(), new);
        } else {
            self.mask_of.remove(entity);
        }
    }

    fn satisfies(&self, any_quorum: usize) -> bool {
        let total = self.slots.iter().sum::<usize>();
        if self.pairs_of.len() < any_quorum.max(total) {
            return false;
        }
        (1u32..(1u32 << self.slots.len())).all(|subset| {
            let needed = self
                .slots
                .iter()
                .enumerate()
                .filter(|(bit, _)| subset & (1 << bit) != 0)
                .map(|(_, slots)| *slots)
                .sum::<usize>();
            let available = (1u32..(1u32 << self.slots.len()))
                .filter(|mask| mask & subset != 0)
                .map(|mask| self.groups[mask as usize])
                .sum::<usize>();
            available >= needed
        })
    }
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
                        return Err(format!(
                            "RestrictionViolationError: category={}, resolved={actual}, minimumMaxEntities={floor}",
                            category_label(category)
                        ));
                    }
                }
                *quorum = Quorum::Count(actual);
            }
        }
    }
    Ok(resolved)
}

/// The canonical form with every category passed through `category_label`, for messages.
pub(crate) fn strategy_diagnostic(strategy: &QuorumStrategy) -> String {
    render_strategy(strategy, |key| category_label(key))
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
    render_strategy(strategy, |key| key)
}

fn render_strategy<'a>(
    strategy: &'a QuorumStrategy,
    key: impl Fn(&'a str) -> &'a str + Copy,
) -> String {
    let object = |reqs: &'a [CategoryRequirement]| {
        format!(
            "[{}]",
            reqs.iter()
                .map(|req| format!(
                    "{{{}}}",
                    req.iter()
                        .map(|(category, value)| format!(
                            "\"{}\":{}",
                            key(category),
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
    };
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
    if strategy.one_of.is_empty() {
        return output;
    }

    let mut best: Option<(usize, i64, Vec<bool>)> = None;
    for alternative in &strategy.one_of {
        let candidate = QuorumStrategy {
            all_of: strategy.all_of.clone(),
            one_of: vec![alternative.clone()],
        };
        let Some(selected) = minimal_satisfying_selection(&output, &candidate) else {
            continue;
        };
        let count = selected.iter().filter(|selected| **selected).count();
        let rank = output
            .iter()
            .zip(&selected)
            .filter(|(_, selected)| **selected)
            .fold(0i64, |sum, (provider, _)| {
                sum.saturating_add(i64::from(provider.rank))
            });
        if best
            .as_ref()
            .is_none_or(|(best_count, best_rank, _)| (count, rank) < (*best_count, *best_rank))
        {
            best = Some((count, rank, selected));
        }
    }
    match best {
        Some((_, _, selected)) => selected_first(output, selected),
        None => output,
    }
}

/// Puts a minimal `allOf`-only quorum first; upstream's ordering, kept by `order_providers_for_quorum`, does not.
pub fn prioritize_minimal_quorum(
    ordered: Vec<OrderableProvider>,
    strategy: &QuorumStrategy,
) -> Vec<OrderableProvider> {
    if !strategy.one_of.is_empty() {
        return ordered;
    }
    match minimal_satisfying_selection(&ordered, strategy) {
        Some(selected) => selected_first(ordered, selected),
        None => ordered,
    }
}

/// The providers a minimal satisfying set keeps, dropping from the back; `None` when `candidate` cannot be met.
fn minimal_satisfying_selection(
    output: &[OrderableProvider],
    candidate: &QuorumStrategy,
) -> Option<Vec<bool>> {
    let empty = CategoryRequirement::new();
    if candidate.one_of.len() > 1 {
        return minimal_satisfying_selection_by_recheck(output, candidate);
    }
    let (demand, any_quorum) = requirement_demand(
        &candidate.all_of,
        candidate.one_of.first().unwrap_or(&empty),
    )?;
    let Some(mut pool) = HallPool::new(&demand) else {
        return minimal_satisfying_selection_by_recheck(output, candidate);
    };
    for provider in output {
        pool.add(&provider.category, &provider.entity);
    }
    if !pool.satisfies(any_quorum) {
        return None;
    }
    let mut selected = vec![true; output.len()];
    for (index, provider) in output.iter().enumerate().rev() {
        pool.remove(&provider.category, &provider.entity);
        if pool.satisfies(any_quorum) {
            selected[index] = false;
        } else {
            pool.add(&provider.category, &provider.entity);
        }
    }
    Some(selected)
}

fn minimal_satisfying_selection_by_recheck(
    output: &[OrderableProvider],
    candidate: &QuorumStrategy,
) -> Option<Vec<bool>> {
    let mut counts = BTreeMap::<(String, String), usize>::new();
    let mut entities = BTreeMap::<String, BTreeSet<String>>::new();
    for provider in output {
        *counts
            .entry((provider.category.clone(), provider.entity.clone()))
            .or_default() += 1;
        entities
            .entry(provider.category.clone())
            .or_default()
            .insert(provider.entity.clone());
    }
    if !is_strategy_satisfiable(&entities, candidate) {
        return None;
    }
    let mut selected = vec![true; output.len()];
    for (index, provider) in output.iter().enumerate().rev() {
        let key = (provider.category.clone(), provider.entity.clone());
        let count = counts.get_mut(&key).expect("provider counted");
        *count -= 1;
        if *count == 0 {
            entities
                .get_mut(&provider.category)
                .expect("category counted")
                .remove(&provider.entity);
        }
        if is_strategy_satisfiable(&entities, candidate) {
            selected[index] = false;
        } else {
            *count += 1;
            entities
                .get_mut(&provider.category)
                .expect("category counted")
                .insert(provider.entity.clone());
        }
    }
    Some(selected)
}

fn selected_first(output: Vec<OrderableProvider>, selected: Vec<bool>) -> Vec<OrderableProvider> {
    let (first, rest): (Vec<_>, Vec<_>) = output
        .into_iter()
        .zip(selected)
        .partition(|(_, selected)| *selected);
    first
        .into_iter()
        .chain(rest)
        .map(|(provider, _)| provider)
        .collect()
}

pub fn min_providers_for_strategy(
    providers: &[OrderableProvider],
    strategy: &QuorumStrategy,
) -> usize {
    let satisfied_by = |length: usize| {
        let mut votes = BTreeMap::<String, BTreeSet<String>>::new();
        for provider in &providers[..length] {
            votes
                .entry(provider.category.clone())
                .or_default()
                .insert(provider.entity.clone());
        }
        is_strategy_satisfiable(&votes, strategy)
    };
    // More providers only add entities, so satisfiability is monotone in the prefix length.
    let (mut low, mut high) = (1usize, providers.len());
    if providers.is_empty() || !satisfied_by(high) {
        return providers.len();
    }
    while low < high {
        let middle = low + (high - low) / 2;
        if satisfied_by(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
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
                .map_err(|e| format!("{}.{}: {e}", chain_label(chain), endpoint_label(endpoint)))?;
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
            Raw::Text(_) => Err(serde::de::Error::custom(QUORUM_LITERAL_ERROR)),
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

pub(crate) const QUORUM_LITERAL_ERROR: &str =
    r#"quorum count must be a non-negative integer or "max""#;

pub const LEGACY_PROVIDER_CONFIG_ERROR: &str = "the legacy `{ uris, quorum }` provider \
     configuration is no longer accepted; supply providers-v2.json (`entities` + \
     `chains.<chain>.rpc[{uri, category, entity}]`) with quorum-strategy.json";

/// Refuses a provider file in the retired `{ uris, quorum }` shape by name, so an operator
/// who has not migrated is told so rather than shown a schema error.
pub fn reject_legacy_provider_config(raw: &str) -> Result<(), ConfigError> {
    let value = pillar_core::json::parse_value(raw).map_err(|error| {
        ConfigError::Json(format!(
            "providers-v2.json: {}",
            crate::json_error_without_input(&error)
        ))
    })?;
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

/// The `_`-prefixed strategy key holding the SHA-256 of the exact `providers-v2.json` text it was written for.
pub const PROVIDERS_BINDING_KEY: &str = "_providersSha256";

/// A strategy that names its providers file is only valid with that file, so a bucket
/// holding the two objects from different rollouts is refused instead of served.
fn check_providers_binding(
    providers_raw: &str,
    bound_to: Option<&serde_json::Value>,
) -> Result<(), ConfigError> {
    let Some(bound_to) = bound_to else {
        static UNBOUND: std::sync::Once = std::sync::Once::new();
        UNBOUND.call_once(|| {
            tracing::warn!(
                "quorum-strategy.json has no `{PROVIDERS_BINDING_KEY}`; replacing the two files one at a time can briefly pair documents from different rollouts"
            );
        });
        return Ok(());
    };
    let expected = bound_to
        .as_str()
        .filter(|text| text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            ConfigError::ProviderValidation(format!(
                "quorum-strategy.json: `{PROVIDERS_BINDING_KEY}` must be the SHA-256 of providers-v2.json as 64 hex digits"
            ))
        })?;
    let actual = hex::encode(sha2::Sha256::digest(providers_raw.as_bytes()));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(ConfigError::ProviderValidation(format!(
            "quorum-strategy.json: `{PROVIDERS_BINDING_KEY}` does not match providers-v2.json; the two files are from different rollouts"
        )));
    }
    Ok(())
}

fn parse_providers_file(raw: &str) -> Result<RawProvidersFile, ConfigError> {
    reject_legacy_provider_config(raw)?;
    // From the text: a `serde_json::Value` object is sorted, which would lose the file's
    // chain order.
    pillar_core::json::from_str(raw).map_err(|error| {
        ConfigError::Json(format!(
            "providers-v2.json: {}",
            crate::json_error_without_input(&error)
        ))
    })
}

fn parse_strategy_file(
    raw: &str,
) -> Result<
    (
        QuorumStrategyFileContent,
        StrategyRestrictions,
        Option<serde_json::Value>,
    ),
    ConfigError,
> {
    let raw = pillar_core::json::from_str::<RawStrategyFile>(raw).map_err(|error| {
        ConfigError::Json(format!(
            "quorum-strategy.json: {}",
            crate::json_error_without_input(&error)
        ))
    })?;
    if raw.extra.keys().any(|key| !key.starts_with('_')) {
        return Err(ConfigError::Json(
            "quorum-strategy.json: unknown top-level field, expected `default`, `chains`, \
             `restrictions` or a `_`-prefixed documentation field"
                .to_string(),
        ));
    }
    let bound_to = raw.extra.get(PROVIDERS_BINDING_KEY).cloned();
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
        bound_to,
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
    let (strategy, restrictions, bound_to) = parse_strategy_file(strategy_raw)?;
    check_providers_binding(providers_raw, bound_to.as_ref())?;
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
    for (chain, endpoints) in &strategy.chains {
        let Some(provider_endpoints) = providers.chains.get(chain) else {
            tracing::warn!(target: "pillar_config", chain = chain_label(chain), "quorum strategy chain does not match a configured provider chain");
            continue;
        };
        for endpoint in endpoints.keys() {
            if !provider_endpoints.contains_key(endpoint) {
                tracing::warn!(target: "pillar_config", chain = chain_label(chain), endpoint = endpoint_label(endpoint), "quorum strategy endpoint does not match a configured provider endpoint");
            }
        }
    }
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
                    r#"Chain "{}" {RPC_ENDPOINT_TYPE}: no resolved strategy"#,
                    chain_label(&chain)
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
                    r#"Chain "{}" {RPC_ENDPOINT_TYPE}: {error}"#,
                    chain_label(&chain)
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
