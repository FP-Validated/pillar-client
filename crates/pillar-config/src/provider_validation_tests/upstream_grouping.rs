use super::*;

#[test]
fn groups_distinct_entities_by_provider_category() {
    // quorumStrategy.test.ts › entitiesPerCategory › “groups entities by category”
    let grouped = entities_per_category(&[
        entry("https://i", PROVIDER_CATEGORY_INTERNAL, "operator"),
        entry("https://q1", PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode"),
        entry("https://a", PROVIDER_CATEGORY_SHARED_EXTERNAL, "ankr"),
        entry("https://q2", PROVIDER_CATEGORY_SHARED_EXTERNAL, "quicknode"),
    ]);
    assert_eq!(grouped[PROVIDER_CATEGORY_INTERNAL].len(), 1);
    assert_eq!(grouped[PROVIDER_CATEGORY_SHARED_EXTERNAL].len(), 2);
    assert!(grouped[PROVIDER_CATEGORY_DEDICATED_EXTERNAL].is_empty());
}
