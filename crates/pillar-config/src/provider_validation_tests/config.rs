use super::*;

#[test]
fn passes_for_a_valid_config() {
    let file = providers(BTreeMap::new());

    let result = validate_provider_config(&file, &file.entities);
    assert!(
        result.is_ok(),
        "valid provider config should pass: {result:?}"
    );
}

#[test]
fn throws_for_missing_uri() {
    let file = providers(rpc_entries(vec![entry(
        "",
        PROVIDER_CATEGORY_INTERNAL,
        "operator",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err.to_string().contains(r#"missing required "uri""#));
}

#[test]
fn throws_for_missing_category() {
    let file = providers(rpc_entries(vec![entry(
        "https://rpc.example.com",
        "",
        "operator",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err.to_string().contains(r#"missing required "category""#));
}

#[test]
fn throws_for_unknown_category() {
    let file = providers(rpc_entries(vec![entry(
        "https://rpc.example.com",
        "private_cloud",
        "operator",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err
        .to_string()
        .contains(r#"unknown category "private_cloud""#));
}

#[test]
fn throws_for_missing_entity() {
    let file = providers(rpc_entries(vec![entry(
        "https://rpc.example.com",
        PROVIDER_CATEGORY_INTERNAL,
        "",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err.to_string().contains(r#"missing required "entity""#));
}

#[test]
fn throws_for_add_entity_placeholder() {
    let file = providers(rpc_entries(vec![entry(
        "https://unknown.com",
        PROVIDER_CATEGORY_SHARED_EXTERNAL,
        "ADD_ENTITY",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err.to_string().contains(r#""ADD_ENTITY""#));
    assert!(err
        .to_string()
        .contains("not in the registered entities list"));
}

#[test]
fn throws_for_entity_not_in_registered_list() {
    let file = providers(rpc_entries(vec![entry(
        "https://rpc.example.com",
        PROVIDER_CATEGORY_INTERNAL,
        "unknown-provider",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err.to_string().contains(r#""unknown-provider""#));
    assert!(err
        .to_string()
        .contains("not in the registered entities list"));
}

#[test]
fn aggregates_multiple_errors_into_a_single_throw() {
    let file = providers(rpc_entries(vec![
        entry("", PROVIDER_CATEGORY_INTERNAL, "operator"),
        entry(
            "https://rpc.example.com",
            PROVIDER_CATEGORY_INTERNAL,
            "ADD_ENTITY",
        ),
    ]));
    let err = validate_provider_config(&file, &["operator".to_string()]).unwrap_err();
    assert!(err.to_string().contains(r#"missing required "uri""#));
    assert!(err.to_string().contains(r#""ADD_ENTITY""#));
}
