use super::*;

// Upstream providerValidate.test.ts › validateProviderConfig › “passes for a valid config”.
#[test]
fn passes_for_a_valid_config() {
    let file = providers(BTreeMap::new());

    let result = validate_provider_config(&file, &file.entities);
    assert!(
        result.is_ok(),
        "valid provider config should pass: {result:?}"
    );
}

// Upstream providerValidate.test.ts › validateProviderConfig › “throws for missing uri”.
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

// Upstream providerValidate.test.ts › validateProviderConfig › “throws for missing category”.
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

// Upstream providerValidate.test.ts › validateProviderConfig › “throws for unknown category”.
#[test]
fn throws_for_unknown_category() {
    let file = providers(rpc_entries(vec![entry(
        "https://rpc.example.com",
        "private_cloud",
        "operator",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(r#"chain "ethereum" rpc[0] has an unknown category - must be one of:"#),
        "{err}"
    );
    assert!(!err.contains("private_cloud"), "{err}");
}

// Upstream providerValidate.test.ts › validateProviderConfig › “throws for missing entity”.
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

// Upstream providerValidate.test.ts › validateProviderConfig › “throws for ADD_ENTITY placeholder”.
#[test]
fn throws_for_add_entity_placeholder() {
    let file = providers(rpc_entries(vec![entry(
        "https://unknown.com",
        PROVIDER_CATEGORY_SHARED_EXTERNAL,
        "ADD_ENTITY",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(
            r#"chain "ethereum" rpc[0] has an entity which is not in the registered entities list"#
        ),
        "{err}"
    );
    assert!(!err.contains("ADD_ENTITY"), "{err}");
}

// Upstream providerValidate.test.ts › validateProviderConfig › “throws for entity not in registered list”.
#[test]
fn throws_for_entity_not_in_registered_list() {
    let file = providers(rpc_entries(vec![entry(
        "https://rpc.example.com",
        PROVIDER_CATEGORY_INTERNAL,
        "unknown-provider",
    )]));
    let err = validate_provider_config(&file, &["operator".to_string()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("not in the registered entities list"), "{err}");
    assert!(!err.contains("unknown-provider"), "{err}");
}

// Upstream providerValidate.test.ts › validateProviderConfig › “aggregates multiple errors into a single throw”.
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
    let err = validate_provider_config(&file, &["operator".to_string()])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(r#"chain "ethereum" rpc[0] entry is missing required "uri""#),
        "{err}"
    );
    assert!(
        err.contains(r#"chain "ethereum" rpc[1] has an entity which is not"#),
        "{err}"
    );
}
