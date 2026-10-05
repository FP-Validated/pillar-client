use super::*;

fn p(category: &str, entity: &str, id: &str, rank: i32) -> OrderableProvider {
    OrderableProvider {
        category: category.into(),
        entity: entity.into(),
        id: id.into(),
        rank,
    }
}
fn ids(ps: &[OrderableProvider]) -> Vec<&str> {
    ps.iter().map(|p| p.id.as_str()).collect()
}

#[test]
fn entity_interleaving_and_category_priorities_match_upstream() {
    // quorumStrategy.test.ts › orderProvidersForQuorum: “spreads same-entity providers within a single category”
    let x = order_providers_for_quorum(
        &[
            p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode", "QN1", 0),
            p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode", "QN2", 0),
            p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "ankr", "Ankr", 0),
            p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "infura", "Infura", 0),
        ],
        &strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 2)])]),
    );
    assert_eq!(ids(&x), vec!["QN1", "Ankr", "Infura", "QN2"]);
}

#[test]
fn orders_required_categories_before_alternatives() {
    // quorumStrategy.test.ts › orderProvidersForQuorum: “puts allOf-required categories before oneOf-only categories”
    let input = [
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode", "QN1", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "ankr", "Ankr", 0),
        p(PROVIDER_CATEGORY_INTERNAL, "operator", "Operator", 0),
        p(
            PROVIDER_CATEGORY_DEDICATED_EXTERNAL,
            "alchemy",
            "AlchDed",
            0,
        ),
    ];
    let s = QuorumStrategy {
        all_of: vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        one_of: vec![
            category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1)]),
            category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)]),
        ],
    };
    assert_eq!(
        ids(&order_providers_for_quorum(&input, &s)),
        vec!["Operator", "AlchDed", "QN1", "Ankr"]
    );
}

#[test]
fn prioritizes_all_categories_for_any_and_ranks_categories() {
    // quorumStrategy.test.ts › orderProvidersForQuorum: “any in allOf treats all categories as priority”
    let input = [
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "q", "Q", 0),
        p(PROVIDER_CATEGORY_INTERNAL, "o", "O", 0),
    ];
    assert_eq!(
        order_providers_for_quorum(
            &input,
            &strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])])
        )
        .len(),
        2
    );
    // “demotes a category whose only provider is degraded behind a NORMAL-rank category”
    let input = [
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "chainop", "C1", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "chainop", "C2", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "alchemy", "A", 0),
        p(PROVIDER_CATEGORY_INTERNAL, "operator", "O", 1),
    ];
    assert_eq!(
        ids(&order_providers_for_quorum(
            &input,
            &strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])])
        ),),
        vec!["C1", "A", "C2", "O"]
    );
}

#[test]
fn stable_category_and_entity_encounter_ties() {
    // quorumStrategy.test.ts › orderProvidersForQuorum: “breaks ties between equally-ranked categories using PROVIDER_CATEGORIES enum order”
    let input = [
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "q", "Q", 0),
        p(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, "a", "A", 0),
        p(PROVIDER_CATEGORY_INTERNAL, "o", "O", 0),
    ];
    assert_eq!(
        ids(&order_providers_for_quorum(
            &input,
            &strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])])
        ),),
        vec!["O", "A", "Q"]
    );
    // “breaks ties between equally-ranked entity buckets using encounter order”
    let input = [
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "q", "Q", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "a", "A", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "i", "I", 0),
    ];
    assert_eq!(
        ids(&order_providers_for_quorum(
            &input,
            &strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])])
        ),),
        vec!["Q", "A", "I"]
    );
}

#[test]
fn rank_can_demote_one_of_only_but_not_all_of_category() {
    // quorumStrategy.test.ts › orderProvidersForQuorum: “oneOf: degraded internal slides back so the shared_external fallback clears in the first wave”
    let input = [
        p(PROVIDER_CATEGORY_INTERNAL, "operator", "O", 1),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "q", "Q", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "a", "A", 0),
        p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "n", "N", 0),
    ];
    let s = strategy_one(vec![
        category_req(&[
            (PROVIDER_CATEGORY_INTERNAL, 1),
            (PROVIDER_CATEGORY_SHARED_EXTERNAL, 2),
        ]),
        category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 3)]),
    ]);
    assert_eq!(
        ids(&order_providers_for_quorum(&input, &s)),
        vec!["Q", "A", "N", "O"]
    );
    // “keeps an allOf-required category in priority even when its only provider is degraded”
    let s = QuorumStrategy {
        all_of: vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        one_of: vec![category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 1)])],
    };
    assert_eq!(ids(&order_providers_for_quorum(&input, &s))[0], "O");
}

#[test]
fn prefix_count_deduplicates_entities_and_returns_list_length_if_impossible() {
    let two = strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])]);
    let cases = [
        (
            "strategy { any: 1 } is satisfied by the first provider regardless of category",
            vec![p(PROVIDER_CATEGORY_INTERNAL, "x", "x", 0)],
            two.clone(),
            1,
        ),
        (
            "strategy { any: 1 } counts the first provider even if it is shared_external",
            vec![p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "x", "x", 0)],
            two.clone(),
            1,
        ),
        (
            "strategy { any: 3 } dedupes entities across categories",
            vec![
                p(PROVIDER_CATEGORY_INTERNAL, "x", "x", 0),
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "x", "x2", 0),
                p(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, "y", "y", 0),
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "z", "z", 0),
            ],
            strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 3)])]),
            4,
        ),
        (
            "shared_external: 2 needs 3 providers when first two share entity",
            vec![
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "x", "x1", 0),
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "x", "x2", 0),
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "y", "y", 0),
            ],
            strategy_all(vec![category_req(&[(
                PROVIDER_CATEGORY_SHARED_EXTERNAL,
                2,
            )])]),
            3,
        ),
        (
            "shared_external: 2 with already-interleaved entities needs 2",
            vec![
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "x", "x", 0),
                p(PROVIDER_CATEGORY_SHARED_EXTERNAL, "y", "y", 0),
            ],
            strategy_all(vec![category_req(&[(
                PROVIDER_CATEGORY_SHARED_EXTERNAL,
                2,
            )])]),
            2,
        ),
        (
            "returns providers.length when strategy is not satisfiable",
            vec![p(PROVIDER_CATEGORY_INTERNAL, "x", "x", 0)],
            strategy_all(vec![category_req(&[(
                PROVIDER_CATEGORY_SHARED_EXTERNAL,
                1,
            )])]),
            1,
        ),
    ];
    for (title, providers, strategy, expected) in cases {
        assert_eq!(
            min_providers_for_strategy(&providers, &strategy),
            expected,
            "upstream minProvidersForStrategy case: {title}"
        );
    }
}
