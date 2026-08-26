use super::*;

#[test]
fn returns_no_errors_for_a_valid_entry() {
    let known_entities = BTreeSet::from(["operator".to_string(), "alchemy".to_string()]);
    let errors = validate_provider_entry(
        &entry(
            "https://eth.alchemy.com",
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            "alchemy",
        ),
        &known_entities,
    );
    assert!(errors.is_empty());
}

#[test]
fn returns_one_error_per_missing_required_field_excluding_the_prefix() {
    let known_entities = BTreeSet::from(["operator".to_string(), "alchemy".to_string()]);
    let errors = validate_provider_entry(&entry("", "", ""), &known_entities);
    assert!(errors.contains(&r#"entry is missing required "uri""#.to_string()));
    assert!(errors.contains(&r#"entry is missing required "category""#.to_string()));
    assert!(errors.contains(&r#"entry is missing required "entity""#.to_string()));
    assert!(errors.iter().all(|message| !message.starts_with("chain ")));
}

#[test]
fn flags_an_unknown_entity() {
    let known_entities = BTreeSet::from(["operator".to_string(), "alchemy".to_string()]);
    let errors = validate_provider_entry(
        &entry(
            "https://rpc.example.com",
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            "mystery-provider",
        ),
        &known_entities,
    );
    assert_eq!(
        errors,
        vec![
            r#"has entity "mystery-provider" which is not in the registered entities list - add it to entities[] first"#.to_string()
        ]
    );
}
