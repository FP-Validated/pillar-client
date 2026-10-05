use super::*;

fn raw(
    all_of: Vec<CategoryRequirement>,
    one_of: Vec<CategoryRequirement>,
) -> QuorumStrategyFileContent {
    QuorumStrategyFileContent {
        default: Some(QuorumStrategy { all_of, one_of }),
        chains: BTreeMap::new(),
    }
}

#[test]
fn resolves_max_values_per_endpoint_pool() {
    let entries = vec![
        entry("https://i", PROVIDER_CATEGORY_INTERNAL, "operator"),
        entry("https://s1", PROVIDER_CATEGORY_SHARED_EXTERNAL, "a"),
        entry("https://s2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "b"),
        entry("https://s3", PROVIDER_CATEGORY_SHARED_EXTERNAL, "c"),
    ];
    let providers = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let req = CategoryRequirement::from([
        (PROVIDER_CATEGORY_INTERNAL.into(), Quorum::Max),
        (PROVIDER_CATEGORY_SHARED_EXTERNAL.into(), Quorum::Max),
        (PROVIDER_CATEGORY_ANY.into(), Quorum::Max),
    ]);
    let result = precompute_resolved_strategy(
        &providers,
        &raw(vec![req], vec![]),
        &StrategyRestrictions::default(),
    )
    .unwrap();
    let resolved = &result.chains["ethereum"]["rpc"].all_of[0];
    assert_eq!(resolved[PROVIDER_CATEGORY_INTERNAL], Quorum::Count(1)); // “'max' on each category resolves to that category's pool size”
    assert_eq!(
        resolved[PROVIDER_CATEGORY_SHARED_EXTERNAL],
        Quorum::Count(3)
    );
    assert_eq!(resolved[PROVIDER_CATEGORY_ANY], Quorum::Count(4)); // “'max' on 'any' resolves to distinct-entity union across categories”
}

#[test]
fn resolves_any_max_using_cross_category_entity_union() {
    let entries = vec![
        entry("https://i", PROVIDER_CATEGORY_INTERNAL, "same"),
        entry("https://s", PROVIDER_CATEGORY_SHARED_EXTERNAL, "same"),
    ];
    let providers = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let strategy = raw(
        vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_ANY.into(),
            Quorum::Max,
        )])],
        vec![],
    );
    let result =
        precompute_resolved_strategy(&providers, &strategy, &StrategyRestrictions::default())
            .unwrap();
    assert_eq!(
        result.chains["ethereum"]["rpc"].all_of[0][PROVIDER_CATEGORY_ANY],
        Quorum::Count(1)
    ); // “'any: max' deduplicates entities that appear in multiple categories”
}

#[test]
fn resolves_empty_pool_max_to_zero_and_does_not_apply_floor_to_default() {
    let providers = ProvidersFileV2 {
        entities: vec![],
        chains: BTreeMap::new(),
    };
    let strategy = raw(
        vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_ANY.into(),
            Quorum::Max,
        )])],
        vec![],
    );
    let restrictions = StrategyRestrictions {
        minimum_max_entities: Some(3),
    };
    let result = precompute_resolved_strategy(&providers, &strategy, &restrictions).unwrap();
    assert_eq!(
        result.default.as_ref().unwrap().all_of[0][PROVIDER_CATEGORY_ANY],
        Quorum::Count(0)
    ); // “'max' against an empty pool resolves to 0”; “`default`'s empty-pool resolution skips the floor”
}

#[test]
fn keeps_numeric_quorums_and_resolves_max_in_one_of() {
    let providers = providers(BTreeMap::new());
    let strategy = raw(
        vec![CategoryRequirement::from([
            (PROVIDER_CATEGORY_INTERNAL.into(), Quorum::Count(1)),
            (PROVIDER_CATEGORY_SHARED_EXTERNAL.into(), Quorum::Max),
        ])],
        vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_ANY.into(),
            Quorum::Max,
        )])],
    );
    let result =
        precompute_resolved_strategy(&providers, &strategy, &StrategyRestrictions::default())
            .unwrap();
    let selected = &result.chains["ethereum"]["rpc"];
    assert_eq!(
        selected.all_of[0][PROVIDER_CATEGORY_INTERNAL],
        Quorum::Count(1)
    ); // “mixed numeric + 'max' in a single row only resolves 'max'”
    assert_eq!(selected.one_of[0][PROVIDER_CATEGORY_ANY], Quorum::Count(2)); // “'max' in oneOf rows is resolved alongside allOf rows”
}

#[test]
fn resolves_defaults_and_drops_orphan_overrides() {
    let providers = providers(BTreeMap::from([(
        "polygon".into(),
        BTreeMap::from([(
            "rpc".into(),
            vec![
                entry("https://p1", PROVIDER_CATEGORY_SHARED_EXTERNAL, "p1"),
                entry("https://p2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "p2"),
            ],
        )]),
    )]));
    let mut strategy = raw(
        vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_SHARED_EXTERNAL.into(),
            Quorum::Max,
        )])],
        vec![],
    );
    strategy.chains.insert(
        "ethereum".into(),
        BTreeMap::from([
            (
                "rpc".into(),
                QuorumStrategy {
                    all_of: vec![CategoryRequirement::from([(
                        PROVIDER_CATEGORY_ANY.into(),
                        Quorum::Count(1),
                    )])],
                    one_of: vec![],
                },
            ),
            ("orphan".into(), QuorumStrategy::default()),
        ]),
    );
    let result =
        precompute_resolved_strategy(&providers, &strategy, &StrategyRestrictions::default())
            .unwrap();
    assert_eq!(result.chains.len(), 2); // “every (chain, endpointType) in providers appears in the result's chains table”
    assert_eq!(
        result.chains["ethereum"]["rpc"].all_of[0][PROVIDER_CATEGORY_ANY],
        Quorum::Count(1)
    ); // “chain-specific overrides win over `default` and resolve against that chain”
    assert_eq!(
        result.chains["polygon"]["rpc"].all_of[0][PROVIDER_CATEGORY_SHARED_EXTERNAL],
        Quorum::Count(2)
    ); // “'max' in `default` resolves per-chain against that chain's pool”
    assert!(!result.chains["ethereum"].contains_key("orphan")); // “endpoints present in strategy.chains but absent from providers are dropped”
    assert_eq!(
        result.default.as_ref().unwrap().all_of[0][PROVIDER_CATEGORY_SHARED_EXTERNAL],
        Quorum::Count(0)
    );
}

#[test]
fn non_max_default_round_trips_and_resolved_pool_satisfies() {
    let providers = providers(BTreeMap::new());
    let strategy = raw(
        vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        vec![],
    );
    let result =
        precompute_resolved_strategy(&providers, &strategy, &StrategyRestrictions::default())
            .unwrap();
    assert_eq!(result.default, strategy.default); // “a strategy with no `max` literal round-trips structurally”
    assert!(check_strategy_config(&providers, &strategy).is_ok()); // “resolved strategy is satisfiable against the same pool”
}

#[test]
fn reports_restriction_error_with_chain_and_endpoint_context() {
    let providers = ProvidersFileV2 {
        entities: vec![],
        chains: BTreeMap::from([("ethereum".into(), BTreeMap::from([("rpc".into(), vec![])]))]),
    };
    let strategy = raw(
        vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_INTERNAL.into(),
            Quorum::Max,
        )])],
        vec![],
    );
    let restrictions = StrategyRestrictions {
        minimum_max_entities: Some(2),
    };
    let err = precompute_resolved_strategy(&providers, &strategy, &restrictions).unwrap_err();
    assert!(err.contains("ethereum.rpc")); // “error context identifies the chain.endpoint pair”; “throws for the first chain that falls below the floor”
}
