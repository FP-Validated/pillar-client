use super::*;

#[test]
fn passes_when_strategy_is_satisfiable() {
    let file = providers(BTreeMap::new());
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_ANY,
            2,
        )])])),
        chains: BTreeMap::new(),
    };
    assert!(check_strategy_config(&file, &strategy).is_ok());
}

#[test]
fn throws_when_default_strategy_is_missing() {
    let file = providers(BTreeMap::new());
    let err = check_strategy_config(&file, &QuorumStrategyFileContent::default()).unwrap_err();
    assert!(err.to_string().contains(r#"missing required "default""#));
}

#[test]
fn throws_when_all_of_is_unsatisfiable() {
    let file = ProvidersFileV2 {
        entities: vec!["operator".to_string()],
        chains: BTreeMap::from([(
            "solana".to_string(),
            BTreeMap::from([(
                "rpc".to_string(),
                vec![entry(
                    "https://internal.lzrpcs.com",
                    PROVIDER_CATEGORY_INTERNAL,
                    "operator",
                )],
            )]),
        )]),
    };
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[
            (PROVIDER_CATEGORY_INTERNAL, 1),
            (PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1),
        ])])),
        chains: BTreeMap::new(),
    };
    let err = check_strategy_config(&file, &strategy).unwrap_err();
    assert!(err.to_string().contains("not satisfiable"));
}

#[test]
fn throws_when_no_one_of_alternative_is_satisfiable() {
    let file = ProvidersFileV2 {
        entities: vec!["operator".to_string()],
        chains: BTreeMap::from([(
            "solana".to_string(),
            BTreeMap::from([(
                "rpc".to_string(),
                vec![entry(
                    "https://internal.lzrpcs.com",
                    PROVIDER_CATEGORY_INTERNAL,
                    "operator",
                )],
            )]),
        )]),
    };
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_one(vec![
            category_req(&[(PROVIDER_CATEGORY_DEDICATED_EXTERNAL, 1)]),
            category_req(&[(PROVIDER_CATEGORY_SHARED_EXTERNAL, 2)]),
        ])),
        chains: BTreeMap::new(),
    };
    let err = check_strategy_config(&file, &strategy).unwrap_err();
    assert!(err.to_string().contains("not satisfiable"));
}

#[test]
fn uses_endpoint_specific_strategy_over_default() {
    let file = ProvidersFileV2 {
        entities: vec!["operator".to_string()],
        chains: BTreeMap::from([(
            "ethereum".to_string(),
            BTreeMap::from([(
                "rpc".to_string(),
                vec![entry(
                    "https://internal.lzrpcs.com",
                    PROVIDER_CATEGORY_INTERNAL,
                    "operator",
                )],
            )]),
        )]),
    };
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_ANY,
            2,
        )])])),
        chains: BTreeMap::from([(
            "ethereum".to_string(),
            BTreeMap::from([(
                "rpc".to_string(),
                strategy_all(vec![category_req(&[(PROVIDER_CATEGORY_INTERNAL, 1)])]),
            )]),
        )]),
    };
    assert!(check_strategy_config(&file, &strategy).is_ok());
}

#[test]
fn aggregates_errors_across_multiple_chains() {
    let file = ProvidersFileV2 {
        entities: vec!["operator".to_string()],
        chains: BTreeMap::from([
            (
                "chainA".to_string(),
                BTreeMap::from([(
                    "rpc".to_string(),
                    vec![entry(
                        "https://a.lzrpcs.com",
                        PROVIDER_CATEGORY_INTERNAL,
                        "operator",
                    )],
                )]),
            ),
            (
                "chainB".to_string(),
                BTreeMap::from([(
                    "rpc".to_string(),
                    vec![entry(
                        "https://b.lzrpcs.com",
                        PROVIDER_CATEGORY_INTERNAL,
                        "operator",
                    )],
                )]),
            ),
        ]),
    };
    let strategy = QuorumStrategyFileContent {
        default: Some(strategy_all(vec![category_req(&[(
            PROVIDER_CATEGORY_SHARED_EXTERNAL,
            2,
        )])])),
        chains: BTreeMap::new(),
    };
    let err = check_strategy_config(&file, &strategy).unwrap_err();
    assert!(err.to_string().contains("chainA"));
    assert!(err.to_string().contains("chainB"));
}
