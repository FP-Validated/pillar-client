use super::*;

fn counts(rows: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
    rows.iter()
        .map(|(category, entities)| {
            (
                (*category).to_string(),
                entities
                    .iter()
                    .map(|entity| (*entity).to_string())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn an_entity_that_a_greedy_pick_took_is_handed_on_to_make_room() {
    let counts = counts(&[("a", &["e1", "e2"]), ("b", &["e1"])]);
    let strategy = strategy_all(vec![category_req(&[("a", 1), ("b", 1)])]);
    assert!(is_strategy_satisfiable(&counts, &strategy));
}

#[test]
fn two_categories_that_can_only_use_one_entity_are_unsatisfiable() {
    let counts = counts(&[("a", &["e1"]), ("b", &["e1"])]);
    let strategy = strategy_all(vec![category_req(&[("a", 1), ("b", 1)])]);
    assert!(!is_strategy_satisfiable(&counts, &strategy));
}

#[test]
fn a_policy_with_thousands_of_entities_is_decided_on_a_small_stack() {
    let entities: BTreeSet<String> = (0..9_000).map(|index| format!("entity-{index}")).collect();
    let counts = BTreeMap::from([("a".to_string(), entities)]);
    let strategy = strategy_all(vec![category_req(&[("a", 9_000)])]);
    let decided = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || is_strategy_satisfiable(&counts, &strategy))
        .unwrap()
        .join()
        .unwrap();
    assert!(decided);
}
