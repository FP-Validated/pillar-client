use super::*;

fn check_entries(
    entries: Vec<ProviderEntryV2>,
    requirement: CategoryRequirement,
    expected: bool,
    title: &str,
) {
    let file = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![requirement])),
        chains: BTreeMap::new(),
    };
    assert_eq!(
        check_strategy_config(&file, &strategy).is_ok(),
        expected,
        "upstream quorumStrategy.test.ts case: {title}"
    );
}

#[test]
fn respects_cross_category_entity_ownership() {
    check_entries(
        vec![
            entry(
                "https://a1",
                PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
                "alchemy",
            ),
            entry("https://a2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "alchemy"),
            entry("https://q", PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode"),
        ],
        category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 1)]),
        true,
        "entity in two categories fills the slot the requirement asks for",
    );
    check_entries(
        vec![
            entry(
                "https://a1",
                PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
                "alchemy",
            ),
            entry("https://a2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "alchemy"),
            entry("https://q", PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode"),
        ],
        category_req(&[
            (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1),
            (PROVIDER_CATEGORY_SHARED_EXTERNAL, 1),
        ]),
        true,
        "alchemy in dedicated+shared satisfies one tier; quicknode covers the other",
    );
    check_entries(
        vec![
            entry(
                "https://a1",
                PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
                "alchemy",
            ),
            entry("https://a2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "alchemy"),
        ],
        category_req(&[
            (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1),
            (PROVIDER_CATEGORY_SHARED_EXTERNAL, 1),
        ]),
        false,
        "alchemy in dedicated+shared cannot fill BOTH dedicated AND shared alone",
    );
    check_entries(
        vec![
            entry("https://a", PROVIDER_CATEGORY_INTERNAL, "operator"),
            entry("https://b", PROVIDER_CATEGORY_SHARED_EXTERNAL, "operator"),
            entry("https://q", PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode"),
        ],
        category_req(&[
            (PROVIDER_CATEGORY_INTERNAL, 1),
            (PROVIDER_CATEGORY_SHARED_EXTERNAL, 1),
        ]),
        true,
        "distinct entities across categories are unaffected",
    );
}
