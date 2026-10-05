use super::*;

#[test]
fn mixed_strategy_prefix_stops_on_cheapest_satisfied_alternative() {
    // quorumStrategy.test.ts › minProvidersForStrategy › “combined strategy: internal + (dedicated OR shared:2) — cheapest path satisfies first”
    let providers = vec![
        OrderableProvider {
            category: PROVIDER_CATEGORY_INTERNAL.into(),
            entity: "operator".into(),
            id: "i".into(),
            rank: 0,
        },
        OrderableProvider {
            category: PROVIDER_CATEGORY_DEDICATED_EXTERNAL.into(),
            entity: "alchemy".into(),
            id: "d".into(),
            rank: 0,
        },
        OrderableProvider {
            category: PROVIDER_CATEGORY_SHARED_EXTERNAL.into(),
            entity: "quicknode".into(),
            id: "s1".into(),
            rank: 0,
        },
        OrderableProvider {
            category: PROVIDER_CATEGORY_SHARED_EXTERNAL.into(),
            entity: "ankr".into(),
            id: "s2".into(),
            rank: 0,
        },
    ];
    let strategy = QuorumStrategy {
        all_of: vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        one_of: vec![
            category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1)]),
            category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)]),
        ],
    };
    assert_eq!(min_providers_for_strategy(&providers, &strategy), 2);
}
