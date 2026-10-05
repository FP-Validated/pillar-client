use super::*;

fn strategy(all_of: Vec<CategoryRequirement>, one_of: Vec<CategoryRequirement>) -> QuorumStrategy {
    QuorumStrategy { all_of, one_of }
}

#[test]
fn is_trivial_for_single_any_requirement() {
    // quorumStrategy.test.ts › isTrivialStrategy › “{ allOf: [{ any: 1 }] } is trivial”
    assert!(is_trivial_strategy(&strategy(
        vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])],
        vec![]
    )));
}

#[test]
fn is_trivial_for_single_category_requirement() {
    // quorumStrategy.test.ts › isTrivialStrategy › “{ allOf: [{ internal: 1 }] } is trivial”
    assert!(is_trivial_strategy(&strategy(
        vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        vec![]
    )));
}

#[test]
fn rejects_nontrivial_two_any_requirement() {
    // quorumStrategy.test.ts › isTrivialStrategy › “{ allOf: [{ any: 2 }] } is not trivial”
    assert!(!is_trivial_strategy(&strategy(
        vec![category_req(&[(PROVIDER_CATEGORY_ANY, 2)])],
        vec![]
    )));
}

#[test]
fn one_of_makes_strategy_nontrivial() {
    // quorumStrategy.test.ts › isTrivialStrategy › “strategy with oneOf is not trivial”
    assert!(!is_trivial_strategy(&strategy(
        vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        vec![category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1)])]
    )));
}

#[test]
fn empty_strategy_is_trivial() {
    // quorumStrategy.test.ts › isTrivialStrategy › “empty strategy is trivial (total 0 <= 1)”
    assert!(is_trivial_strategy(&QuorumStrategy::default()));
}

#[test]
fn sums_all_of_requirements_when_checking_triviality() {
    // quorumStrategy.test.ts › isTrivialStrategy › “multiple allOf entries summing to > 1 are not trivial”
    assert!(!is_trivial_strategy(&strategy(
        vec![
            category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)]),
            category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 1)])
        ],
        vec![]
    )));
}

#[test]
fn canonical_key_ignores_map_and_object_key_order() {
    // quorumStrategy.test.ts › canonicalStrategyKey › “same strategy with different key order produces identical string”
    let a = QuorumStrategy {
        all_of: vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
        one_of: vec![category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)])],
    };
    let b = QuorumStrategy {
        one_of: vec![category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)])],
        all_of: vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])],
    };
    assert_eq!(canonical_strategy_key(&a), canonical_strategy_key(&b));
}

#[test]
fn canonical_keys_distinguish_different_quorums() {
    // quorumStrategy.test.ts › canonicalStrategyKey › “different strategies produce different strings”
    let a = strategy(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 1)])], vec![]);
    let b = strategy(vec![category_req(&[(PROVIDER_CATEGORY_ANY, 2)])], vec![]);
    assert_ne!(canonical_strategy_key(&a), canonical_strategy_key(&b));
}

#[test]
fn canonical_key_sorts_nested_requirement_keys() {
    // quorumStrategy.test.ts › canonicalStrategyKey › “nested keys are also sorted”
    let a = strategy(
        vec![category_req(&[
            (PROVIDER_CATEGORY_SHARED_EXTERNAL, 1),
            (PROVIDER_CATEGORY_INTERNAL, 1),
        ])],
        vec![],
    );
    let b = strategy(
        vec![category_req(&[
            (PROVIDER_CATEGORY_INTERNAL, 1),
            (PROVIDER_CATEGORY_SHARED_EXTERNAL, 1),
        ])],
        vec![],
    );
    assert_eq!(canonical_strategy_key(&a), canonical_strategy_key(&b));
}
