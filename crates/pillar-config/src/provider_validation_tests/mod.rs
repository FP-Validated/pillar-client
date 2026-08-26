use super::provider_validation::*;
use std::collections::{BTreeMap, BTreeSet};

fn entry(uri: &str, category: &str, entity: &str) -> ProviderEntryV2 {
    ProviderEntryV2 {
        uri: uri.to_string(),
        category: category.to_string(),
        entity: entity.to_string(),
        headers: BTreeMap::new(),
    }
}

fn providers(chain_overrides: BTreeMap<String, ProviderConfigV2>) -> ProvidersFileV2 {
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
    chains.extend(chain_overrides);
    ProvidersFileV2 {
        entities: vec![
            "operator".to_string(),
            "alchemy".to_string(),
            "quicknode".to_string(),
            "ankr".to_string(),
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
        .map(|(category, count)| ((*category).to_string(), *count))
        .collect()
}

fn strategy_all(reqs: Vec<CategoryRequirement>) -> QuorumStrategy {
    QuorumStrategy {
        all_of: reqs,
        one_of: Vec::new(),
    }
}

fn strategy_one(reqs: Vec<CategoryRequirement>) -> QuorumStrategy {
    QuorumStrategy {
        all_of: Vec::new(),
        one_of: reqs,
    }
}

mod config;
mod entry_validation;
mod strategy;
