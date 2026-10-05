use super::*;

fn max_strategy(category: &str) -> QuorumStrategyFileContent {
    QuorumStrategyFileContent {
        default: Some(strategy_all(vec![CategoryRequirement::from([(
            category.into(),
            Quorum::Max,
        )])])),
        chains: BTreeMap::new(),
    }
}

#[test]
fn max_and_floor_validation_matches_upstream_cases() {
    // Upstream providerValidate.test.ts › checkStrategyConfig › “'max' literal resolves against the configured pool and passes”.
    // Upstream providerValidate.test.ts › checkStrategyConfig › “'any: max' is satisfiable against a non-empty pool”.
    // Upstream providerValidate.test.ts › checkStrategyConfig › “'max' in a chain-specific override resolves against that chain's pool”.
    let plain = providers(BTreeMap::new());
    assert!(
        check_strategy_config(&plain, &max_strategy(PROVIDER_CATEGORY_SHARED_EXTERNAL)).is_ok()
    );
    assert!(check_strategy_config(&plain, &max_strategy(PROVIDER_CATEGORY_ANY)).is_ok());

    let override_providers = providers(BTreeMap::from([(
        "polygon".into(),
        BTreeMap::from([(
            "rpc".into(),
            vec![
                entry("https://p1", PROVIDER_CATEGORY_SHARED_EXTERNAL, "p1"),
                entry("https://p2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "p2"),
            ],
        )]),
    )]));
    let mut overrides = BTreeMap::new();
    overrides.insert(
        "rpc".into(),
        strategy_all(vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_SHARED_EXTERNAL.into(),
            Quorum::Max,
        )])]),
    );
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_ANY,
            1,
        )])])),
        chains: BTreeMap::from([("polygon".into(), overrides)]),
    };
    assert!(check_strategy_config(&override_providers, &strategy).is_ok());

    // Upstream providerValidate.test.ts › checkStrategyConfig › “throws when a chain's resolved max is below the floor”.
    // Upstream providerValidate.test.ts › checkStrategyConfig › “reports the violation per (chain, endpoint) and continues the sweep”.
    let floor = StrategyRestrictions {
        minimum_max_entities: Some(2),
    };
    let err = check_strategy_config_with_restrictions(
        &plain,
        &max_strategy(PROVIDER_CATEGORY_SHARED_EXTERNAL),
        &floor,
    )
    .unwrap_err();
    assert!(err.to_string().contains("minimumMaxEntities"));
    assert!(err.to_string().contains("category=shared_external"));
    assert!(err.to_string().contains("resolved=1"));
    assert!(err.to_string().contains("minimumMaxEntities=2"));
    assert!(err.to_string().contains("ethereum"));

    // Upstream providerValidate.test.ts › checkStrategyConfig › “passes when every per-chain resolved max meets the floor”.
    // Upstream providerValidate.test.ts › checkStrategyConfig › “numeric requirements are not subject to the floor”.
    let pool = vec![
        entry("https://p1", PROVIDER_CATEGORY_SHARED_EXTERNAL, "p1"),
        entry("https://p2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "p2"),
    ];
    let enough = providers(BTreeMap::from([
        (
            "ethereum".into(),
            BTreeMap::from([("rpc".into(), pool.clone())]),
        ),
        ("polygon".into(), BTreeMap::from([("rpc".into(), pool)])),
    ]));
    assert!(check_strategy_config_with_restrictions(
        &enough,
        &max_strategy(PROVIDER_CATEGORY_SHARED_EXTERNAL),
        &floor
    )
    .is_ok());
    let numeric = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            1,
        )])])),
        chains: BTreeMap::new(),
    };
    assert!(check_strategy_config_with_restrictions(&plain, &numeric, &floor).is_ok());

    // Upstream providerValidate.test.ts › checkStrategyConfig › “missing restrictions or undefined minimumMaxEntities is a no-op”.
    assert!(
        check_strategy_config(&plain, &max_strategy(PROVIDER_CATEGORY_SHARED_EXTERNAL)).is_ok()
    );
}
