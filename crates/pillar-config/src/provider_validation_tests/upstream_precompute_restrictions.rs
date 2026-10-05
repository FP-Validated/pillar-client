use super::*;

#[test]
fn per_chain_max_floor_passes_and_overrides_are_enforced_with_context() {
    // quorumStrategy.test.ts › precomputeResolvedStrategy restrictions.minimumMaxEntities › “passes when every per-chain resolved max meets the floor”
    let pool = vec![
        entry("https://a", PROVIDER_CATEGORY_INTERNAL, "a"),
        entry("https://b", PROVIDER_CATEGORY_INTERNAL, "b"),
    ];
    let providers = ProvidersFileV2 {
        entities: vec![],
        chains: BTreeMap::from([
            (
                "chain-a".into(),
                BTreeMap::from([("rpc".into(), pool.clone())]),
            ),
            (
                "chain-b".into(),
                BTreeMap::from([("rpc".into(), pool.clone())]),
            ),
        ]),
    };
    let raw = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![CategoryRequirement::from([(
            PROVIDER_CATEGORY_INTERNAL.into(),
            Quorum::Max,
        )])])),
        chains: BTreeMap::new(),
    };
    let floor = StrategyRestrictions {
        minimum_max_entities: Some(2),
    };
    assert!(precompute_resolved_strategy(&providers, &raw, &floor).is_ok());

    // “chain-specific override is also checked against the floor”; “error context identifies the chain.endpoint pair”.
    let providers = ProvidersFileV2 {
        entities: vec![],
        chains: BTreeMap::from([(
            "chain-a".into(),
            BTreeMap::from([(
                "rpc".into(),
                vec![entry("https://a", PROVIDER_CATEGORY_INTERNAL, "a")],
            )]),
        )]),
    };
    let raw = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_ANY,
            1,
        )])])),
        chains: BTreeMap::from([(
            "chain-a".into(),
            BTreeMap::from([(
                "rpc".into(),
                QuorumStrategy {
                    all_of: vec![CategoryRequirement::from([(
                        PROVIDER_CATEGORY_INTERNAL.into(),
                        Quorum::Max,
                    )])],
                    one_of: vec![],
                },
            )]),
        )]),
    };
    let error = precompute_resolved_strategy(&providers, &raw, &floor).unwrap_err();
    assert!(error.contains("chain-a.rpc"));
    assert!(error.contains("category=internal"));
    assert!(error.contains("resolved=1"));
    assert!(error.contains("minimumMaxEntities=2"));
}
