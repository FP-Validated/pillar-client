//! Validation for the richer, entity-aware provider file shape.
//!
//! **Nothing in the runtime calls this.** The provider configuration this
//! service actually loads and signs against is `ProviderConfig` in the crate
//! root - a URI list and an integer quorum - and its quorum counts matching
//! responses, not distinct operators. See "Operator responsibilities" in
//! `SECURITY.md`.
//!
//! The same split exists upstream: the `providers.json` the service consumes is
//! `{ uris, quorum }` (`packages/common-model/src/provider.ts:6-9`), while the
//! category/entity model and its `allOf`/`oneOf` strategy evaluation live in
//! separate modules (`provider.ts:120-155`,
//! `packages/common-utils/src/quorumStrategy.ts:11-73`) that the service's
//! provider path never reaches either. This module mirrors that validation so
//! the shapes stay comparable; wiring it into signing would be a new trust
//! model, not parity, and would need its own review.

use crate::ConfigError;
use std::collections::{BTreeMap, BTreeSet};

pub const PROVIDER_CATEGORY_INTERNAL: &str = "internal";
pub const PROVIDER_CATEGORY_DEDICATED_EXTERNAL: &str = "dedicated_external";
pub const PROVIDER_CATEGORY_SHARED_EXTERNAL: &str = "shared_external";
pub const PROVIDER_CATEGORY_ANY: &str = "any";

const PROVIDER_CATEGORIES: [&str; 3] = [
    PROVIDER_CATEGORY_INTERNAL,
    PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
    PROVIDER_CATEGORY_SHARED_EXTERNAL,
];

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

pub type CategoryRequirement = BTreeMap<String, u64>;

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
        errors.push(format!(
            r#"has entity "{}" which is not in the registered entities list - add it to entities[] first"#,
            entry.entity
        ));
    }
    errors
}

pub fn validate_provider_config(
    providers_file: &ProvidersFileV2,
    known_entities: &[String],
) -> Result<(), ConfigError> {
    let context = known_entities.iter().cloned().collect::<BTreeSet<_>>();
    let mut errors = Vec::new();
    for (chain_name, per_endpoint) in &providers_file.chains {
        for (endpoint_type, entries) in per_endpoint {
            for entry in entries {
                let prefix = format!(r#"chain "{chain_name}" {endpoint_type}[]"#);
                for entry_error in validate_provider_entry(entry, &context) {
                    errors.push(format!("{prefix} {entry_error}"));
                }
            }
        }
    }
    validation_result("providers-v2.json validation failed", errors)
}

pub fn check_strategy_config(
    providers_file: &ProvidersFileV2,
    strategy_file: &QuorumStrategyFileContent,
) -> Result<(), ConfigError> {
    let Some(default_strategy) = &strategy_file.default else {
        return Err(ConfigError::ProviderValidation(
            r#"quorum-strategy.json: missing required "default" strategy"#.to_string(),
        ));
    };

    let mut errors = Vec::new();
    for (chain_name, per_endpoint) in &providers_file.chains {
        for (endpoint_type, entries) in per_endpoint {
            let strategy = strategy_file
                .chains
                .get(chain_name)
                .and_then(|entry| entry.get(endpoint_type))
                .unwrap_or(default_strategy);
            let counts = entities_per_category(entries);
            if !is_strategy_satisfiable(&counts, strategy) {
                errors.push(format!(
                    r#"Chain "{chain_name}" {endpoint_type}: strategy not satisfiable. Strategy: {}."#,
                    strategy_debug(strategy)
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
                .map(|error| format!("  - {error}"))
                .collect::<Vec<_>>()
                .join("\n")
        )))
    }
}

fn entities_per_category(entries: &[ProviderEntryV2]) -> BTreeMap<String, BTreeSet<String>> {
    let mut counts = PROVIDER_CATEGORIES
        .into_iter()
        .map(|category| (category.to_string(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for entry in entries {
        if let Some(category_counts) = counts.get_mut(&entry.category) {
            category_counts.insert(entry.entity.clone());
        }
    }
    counts
}

fn is_strategy_satisfiable(
    counts: &BTreeMap<String, BTreeSet<String>>,
    strategy: &QuorumStrategy,
) -> bool {
    let all_of_met = strategy.all_of.is_empty()
        || strategy
            .all_of
            .iter()
            .all(|req| requirement_met(counts, req));
    let one_of_met = strategy.one_of.is_empty()
        || strategy
            .one_of
            .iter()
            .any(|req| requirement_met(counts, req));
    all_of_met && one_of_met
}

fn requirement_met(
    counts: &BTreeMap<String, BTreeSet<String>>,
    requirement: &CategoryRequirement,
) -> bool {
    requirement.iter().all(|(category, quorum)| {
        if category == PROVIDER_CATEGORY_ANY {
            any_count(counts) >= *quorum as usize
        } else {
            counts.get(category).map(BTreeSet::len).unwrap_or_default() >= *quorum as usize
        }
    })
}

fn any_count(counts: &BTreeMap<String, BTreeSet<String>>) -> usize {
    counts
        .values()
        .flat_map(|entities| entities.iter())
        .collect::<BTreeSet<_>>()
        .len()
}

fn strategy_debug(strategy: &QuorumStrategy) -> String {
    format!(
        "{{allOf:{:?},oneOf:{:?}}}",
        strategy.all_of, strategy.one_of
    )
}
