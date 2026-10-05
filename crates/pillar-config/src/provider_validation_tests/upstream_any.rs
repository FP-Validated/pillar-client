use super::*;

#[test]
fn any_numeric_quorum_counts_cross_category_entity_once() {
    // quorumStrategy.test.ts › isStrategySatisfiable › “any deduplicates entities present in multiple categories”
    let entries = vec![
        entry("https://i", PROVIDER_CATEGORY_INTERNAL, "operator"),
        entry("https://s", PROVIDER_CATEGORY_SHARED_EXTERNAL, "operator"),
    ];
    let file = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_ANY,
            2,
        )])])),
        chains: BTreeMap::new(),
    };
    assert!(check_strategy_config(&file, &strategy).is_err());
}
