use super::*;

fn check(
    title: &str,
    requirements: Vec<CategoryRequirement>,
    one_of: Vec<CategoryRequirement>,
    expected: bool,
) {
    let entries = vec![
        entry(
            "https://internal.example",
            PROVIDER_CATEGORY_INTERNAL,
            "operator",
        ),
        entry(
            "https://dedicated.example",
            PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
            "alchemy",
        ),
        entry(
            "https://shared-a.example",
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            "quicknode",
        ),
        entry(
            "https://shared-b.example",
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            "ankr",
        ),
    ];
    let file = providers(BTreeMap::from([(
        "ethereum".into(),
        BTreeMap::from([("rpc".into(), entries)]),
    )]));
    let strategy = QuorumStrategyFileContent {
        default: Some(QuorumStrategy {
            all_of: requirements,
            one_of,
        }),
        chains: BTreeMap::new(),
    };
    assert_eq!(
        check_strategy_config(&file, &strategy).is_ok(),
        expected,
        "upstream quorumStrategy.test.ts case: {title}"
    );
}

#[test]
fn matches_upstream_satisfiability_truth_table() {
    let cases = [
        (
            "allOf all met",
            vec![category_req(&[
                (PROVIDER_CATEGORY_INTERNAL, 1),
                (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1),
            ])],
            vec![],
            true,
        ),
        (
            "allOf one not met",
            vec![category_req(&[
                (PROVIDER_CATEGORY_INTERNAL, 1),
                (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 2),
            ])],
            vec![],
            false,
        ),
        (
            "oneOf: at least one alternative satisfiable",
            vec![],
            vec![
                category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 2)]),
                category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)]),
            ],
            true,
        ),
        (
            "oneOf: no alternative satisfiable",
            vec![],
            vec![
                category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 2)]),
                category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 3)]),
            ],
            false,
        ),
        (
            "allOf + oneOf: both must be satisfied",
            vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
            vec![
                category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1)]),
                category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)]),
            ],
            true,
        ),
        (
            "oneOf: succeeds via the second alternative when the first cannot be satisfied",
            vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
            vec![
                category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 3)]),
                category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1)]),
            ],
            true,
        ),
        (
            "voter pool short-circuit: too few distinct entities for the requirement count",
            vec![category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 3)])],
            vec![],
            false,
        ),
        (
            "multi-key AND within one requirement: all keys met",
            vec![category_req(&[
                (PROVIDER_CATEGORY_INTERNAL, 1),
                (PROVIDER_CATEGORY_SHARED_EXTERNAL, 2),
            ])],
            vec![],
            true,
        ),
        (
            "multi-key AND within one requirement: one key not met",
            vec![category_req(&[
                (PROVIDER_CATEGORY_INTERNAL, 1),
                (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 2),
            ])],
            vec![],
            false,
        ),
        (
            "any pools distinct voters across categories",
            vec![category_req(&[(PROVIDER_CATEGORY_ANY, 4)])],
            vec![],
            true,
        ),
        (
            "any deduplicates entities present in multiple categories",
            vec![category_req(&[(PROVIDER_CATEGORY_ANY, 5)])],
            vec![],
            false,
        ),
        ("empty strategy is satisfiable", vec![], vec![], true),
    ];
    for (title, all_of, one_of, expected) in cases {
        check(title, all_of, one_of, expected);
    }
}
