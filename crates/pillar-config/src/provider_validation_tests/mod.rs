use super::provider_validation::*;
use std::collections::{BTreeMap, BTreeSet};

fn entry(uri: &str, category: &str, entity: &str) -> ProviderEntryV2 {
    ProviderEntryV2 {
        uri: uri.into(),
        category: category.into(),
        entity: entity.into(),
        headers: BTreeMap::new(),
    }
}
fn providers(overrides: BTreeMap<String, ProviderConfigV2>) -> ProvidersFileV2 {
    let mut chains = BTreeMap::from([(
        "ethereum".to_string(),
        BTreeMap::from([(
            "rpc".to_string(),
            vec![
                entry(
                    "https://internal.lzrpcs.com",
                    PROVIDER_CATEGORY_INTERNAL,
                    "operator",
                ),
                entry(
                    "https://eth.alchemy.com",
                    PROVIDER_CATEGORY_SHARED_EXTERNAL,
                    "alchemy",
                ),
            ],
        )]),
    )]);
    chains.extend(overrides);
    ProvidersFileV2 {
        entities: vec![
            "operator".into(),
            "alchemy".into(),
            "quicknode".into(),
            "ankr".into(),
        ],
        chains,
    }
}
fn rpc_entries(entries: Vec<ProviderEntryV2>) -> BTreeMap<String, ProviderConfigV2> {
    BTreeMap::from([(
        "ethereum".to_string(),
        BTreeMap::from([("rpc".to_string(), entries)]),
    )])
}
fn category_req(entries: &[(&str, u64)]) -> CategoryRequirement {
    entries
        .iter()
        .map(|(category, count)| ((*category).to_string(), Quorum::Count(*count)))
        .collect()
}
fn strategy_all(reqs: Vec<CategoryRequirement>) -> QuorumStrategy {
    QuorumStrategy {
        all_of: reqs,
        one_of: vec![],
    }
}
fn strategy_one(reqs: Vec<CategoryRequirement>) -> QuorumStrategy {
    QuorumStrategy {
        all_of: vec![],
        one_of: reqs,
    }
}

mod config;
mod entry_validation;
mod strategy;
mod upstream_any;
mod upstream_cross_category;
mod upstream_grouping;
mod upstream_minimum_prefix;
mod upstream_ordering;
mod upstream_precompute;
mod upstream_precompute_restrictions;
mod upstream_satisfiability;
mod upstream_strategy;
mod upstream_utilities;
mod upstream_validation;
mod v2_files;
