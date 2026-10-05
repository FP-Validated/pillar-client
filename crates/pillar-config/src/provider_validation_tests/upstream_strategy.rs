use super::*;

#[test]
fn rejects_entity_reuse_across_all_of_requirements() {
    // Upstream quorumStrategy.test.ts: “single entity in two categories cannot fill both a dedicated AND second shared slot”
    let entries = vec![
        entry(
            "https://dedicated.example",
            PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
            "alchemy",
        ),
        entry(
            "https://shared.example",
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            "alchemy",
        ),
        entry(
            "https://shared2.example",
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            "infura",
        ),
    ];
    let file = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let requirement = category_req(&[
        (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1),
        (PROVIDER_CATEGORY_SHARED_EXTERNAL, 2),
    ]);
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![requirement])),
        chains: BTreeMap::new(),
    };
    assert!(check_strategy_config(&file, &strategy).is_err());
}

#[test]
fn resolves_max_and_enforces_minimum_max_entities() {
    // Upstream quorumStrategy.test.ts: “passes when every resolved max is >= floor”
    let entries = vec![
        entry("https://a.example", PROVIDER_CATEGORY_SHARED_EXTERNAL, "a"),
        entry("https://b.example", PROVIDER_CATEGORY_SHARED_EXTERNAL, "b"),
        entry("https://c.example", PROVIDER_CATEGORY_SHARED_EXTERNAL, "c"),
    ];
    let file = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let raw =
        CategoryRequirement::from([(PROVIDER_CATEGORY_SHARED_EXTERNAL.to_string(), Quorum::Max)]);
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![raw])),
        chains: BTreeMap::new(),
    };
    let restrictions = StrategyRestrictions {
        minimum_max_entities: Some(3),
    };
    assert!(check_strategy_config_with_restrictions(&file, &strategy, &restrictions).is_ok());
}

#[test]
fn rejects_max_below_minimum_max_entities() {
    // Upstream quorumStrategy.test.ts: “throws for the first chain that falls below the floor”
    let file = providers(BTreeMap::new());
    let raw =
        CategoryRequirement::from([(PROVIDER_CATEGORY_SHARED_EXTERNAL.to_string(), Quorum::Max)]);
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![raw])),
        chains: BTreeMap::new(),
    };
    let restrictions = StrategyRestrictions {
        minimum_max_entities: Some(2),
    };
    let err = check_strategy_config_with_restrictions(&file, &strategy, &restrictions).unwrap_err();
    assert!(err.to_string().contains("minimumMaxEntities"));
}
