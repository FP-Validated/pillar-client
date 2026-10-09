//! The providers-v2 / quorum-strategy pair as the loader reads it: what loads, what each
//! chain's `rpc` pool becomes, and every way a pair is refused before it can serve.
use super::*;
use crate::{ConfigError, ProviderConfigGetter, ProviderUri, StaticProviderConfig};

const PROVIDERS: &str = r#"{
    "entities": ["operator", "alchemy", "quicknode"],
    "chains": {
        "ethereum": {
            "rpc": [
                {"uri": "https://internal.example", "category": "internal", "entity": "operator"},
                {"uri": "https://eth.alchemy.example", "category": "shared_external", "entity": "alchemy",
                 "headers": {"x-api-key": "k"}},
                {"uri": "https://eth.quicknode.example", "category": "shared_external", "entity": "quicknode"}
            ],
            "indexer": [
                {"uri": "https://indexer.example", "category": "internal", "entity": "operator"}
            ]
        },
        "bsc": {
            "rpc": [
                {"uri": "https://bsc-a.alchemy.example", "category": "shared_external", "entity": "alchemy"},
                {"uri": "https://bsc-b.alchemy.example", "category": "shared_external", "entity": "alchemy"}
            ]
        }
    }
}"#;

fn load(providers: &str, strategy: &str) -> Result<StaticProviderConfig, ConfigError> {
    StaticProviderConfig::from_v2(providers, strategy, None)
}

fn message(result: Result<StaticProviderConfig, ConfigError>) -> String {
    result.expect_err("the pair must be refused").to_string()
}

#[test]
fn loads_each_chain_rpc_pool_with_voters_and_resolved_strategy() {
    let config = load(
        PROVIDERS,
        r#"{"default": {"allOf": [{"any": 1}]},
            "chains": {"ethereum": {"rpc": {"allOf": [{"internal": 1}, {"shared_external": "max"}]}}}}"#,
    )
    .unwrap();
    let chains = config.get_provider_configs().keys().collect::<Vec<_>>();
    assert_eq!(chains, ["ethereum", "bsc"], "file order is kept");
    let ethereum = config.get_provider_config("ethereum").unwrap();
    assert_eq!(
        ethereum.uris[1],
        ProviderUri::UriWithHeaders {
            uri: "https://eth.alchemy.example".to_string(),
            headers: [("x-api-key".to_string(), "k".to_string())].into(),
        }
    );
    assert_eq!(
        ethereum
            .voters
            .iter()
            .map(|voter| voter.entity.as_str())
            .collect::<Vec<_>>(),
        ["operator", "alchemy", "quicknode"],
        "only the rpc pool is loaded; the indexer entry is not dialled"
    );
    assert_eq!(
        canonical_strategy_key(&ethereum.strategy),
        r#"{"allOf":[{"internal":1},{"shared_external":2}],"oneOf":[]}"#,
        "max resolves to the pool's distinct shared_external entities"
    );
    assert!(!ethereum.single_entity_trust_root());
    assert!(config
        .get_provider_config("bsc")
        .unwrap()
        .single_entity_trust_root());
}

#[test]
fn two_uris_of_one_entity_cannot_satisfy_a_two_entity_strategy() {
    let error = message(load(
        PROVIDERS,
        r#"{"default": {"allOf": [{"any": 1}]}, "chains": {"bsc": {"rpc": {"allOf": [{"any": 2}]}}}}"#,
    ));
    assert!(
        error.contains(r#"Chain "bsc" rpc: strategy not satisfiable"#),
        "{error}"
    );
}

#[test]
fn the_retired_uris_quorum_format_is_refused_with_a_migration_hint() {
    let error = message(load(
        r#"{"ethereum": {"uris": ["https://rpc.example"], "quorum": 1}}"#,
        r#"{"default": {"allOf": [{"any": 1}]}}"#,
    ));
    assert_eq!(error, LEGACY_PROVIDER_CONFIG_ERROR);
}

#[test]
fn refuses_pairs_that_would_weaken_or_misread_the_quorum() {
    let cases = [
        (
            "missing default",
            PROVIDERS,
            r#"{"chains": {}}"#,
            r#"missing required "default""#,
        ),
        (
            "misspelled strategy key",
            PROVIDERS,
            r#"{"default": {"allof": [{"any": 1}]}}"#,
            "quorum-strategy.json: JSON data error: unknown field at line ",
        ),
        (
            "no agreement required",
            PROVIDERS,
            r#"{"default": {"allOf": [{"any": 0}]}}"#,
            "requires no provider agreement",
        ),
        (
            "empty strategy",
            PROVIDERS,
            r#"{"default": {}}"#,
            "requires no provider agreement",
        ),
        (
            "max below the floor",
            PROVIDERS,
            r#"{"default": {"allOf": [{"shared_external": "max"}]}, "restrictions": {"minimumMaxEntities": 2}}"#,
            "RestrictionViolationError",
        ),
        (
            "bad quorum literal",
            PROVIDERS,
            r#"{"default": {"allOf": [{"any": "all"}]}}"#,
            r#"quorum-strategy.json: JSON data error: quorum count must be a non-negative integer or "max" at line "#,
        ),
        (
            "unregistered entity in an unused pool",
            &PROVIDERS.replace(
                r#"indexer.example", "category": "internal", "entity": "operator""#,
                r#"indexer.example", "category": "internal", "entity": "nobody""#,
            ),
            r#"{"default": {"allOf": [{"any": 1}]}}"#,
            r#"chain "ethereum" <unlisted endpoint type>[0] has an entity which is not in the registered entities list"#,
        ),
        (
            "unknown category",
            &PROVIDERS.replace(
                r#""category": "internal", "entity": "operator"}"#,
                r#""category": "private", "entity": "operator"}"#,
            ),
            r#"{"default": {"allOf": [{"any": 1}]}}"#,
            r#"chain "ethereum" rpc[0] has an unknown category"#,
        ),
        (
            "unknown entry field",
            &PROVIDERS.replace(
                r#""entity": "quicknode"}"#,
                r#""entity": "quicknode", "weight": 2}"#,
            ),
            r#"{"default": {"allOf": [{"any": 1}]}}"#,
            "providers-v2.json: JSON data error: unknown field at line ",
        ),
    ];
    for (name, providers, strategy, expected) in cases {
        let error = message(load(providers, strategy));
        assert!(error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn a_required_chain_without_an_rpc_pool_does_not_load() {
    let providers = r#"{"entities": ["operator"], "chains": {"ton": {"v3": [
        {"uri": "https://ton.example", "category": "internal", "entity": "operator"}]}}}"#;
    let strategy = r#"{"default": {"allOf": [{"any": 1}]}}"#;
    assert!(load(providers, strategy)
        .unwrap()
        .get_provider_configs()
        .is_empty());
    assert_eq!(
        StaticProviderConfig::from_v2(providers, strategy, Some(&["ton".to_string()])).unwrap_err(),
        ConfigError::MissingChainNames("ton".to_string())
    );
}

#[test]
fn upstream_documentation_keys_load_and_other_unknown_keys_do_not() {
    let documented = r#"{"_note": "shared with gasolina", "_semantics": {"any": "distinct entities"},
        "default": {"allOf": [{"any": 1}]}}"#;
    assert!(load(PROVIDERS, documented).is_ok());
    let error = message(load(
        PROVIDERS,
        r#"{"note": "no underscore", "default": {"allOf": [{"any": 1}]}}"#,
    ));
    assert!(
        error.starts_with("quorum-strategy.json: unknown top-level field"),
        "{error}"
    );
    assert!(!error.contains("note"), "{error}");
}

#[test]
fn an_impossible_category_count_is_refused_without_expanding_it() {
    for count in ["10000000000", "18446744073709551615"] {
        let strategy = format!(r#"{{"default": {{"allOf": [{{"internal": {count}}}]}}}}"#);
        let error = message(load(PROVIDERS, &strategy));
        assert!(
            error.contains("strategy not satisfiable"),
            "{count}: {error}"
        );
    }
}

#[test]
fn provider_shape_errors_name_the_position_but_not_the_value() {
    const SENTINEL: &str = "SYNTHETIC-SENTINEL-not-a-credential";
    let strategy = r#"{"default": {"allOf": [{"any": 1}]}}"#;
    for providers in [
        PROVIDERS.replace(r#"{"x-api-key": "k"}"#, &format!(r#""Bearer {SENTINEL}""#)),
        format!(
            r#"{{"entities": ["operator"], "chains": {{"bsc": {{"rpc": "https://rpc.example/{SENTINEL}"}}}}}}"#
        ),
        format!(
            r#"{{"entities": ["operator"], "chains": {{"bsc": "https://rpc.example/{SENTINEL}"}}}}"#
        ),
    ] {
        let error = message(load(&providers, strategy));
        assert!(!error.contains(SENTINEL), "{error}");
        assert!(
            error.starts_with("providers-v2.json: JSON data error at line "),
            "{error}"
        );
    }
    let missing = message(load(r#"{"chains": {}}"#, strategy));
    assert!(missing.contains("missing field `entities`"), "{missing}");
}

#[test]
fn provider_and_strategy_diagnostics_never_echo_input_keys_or_values() {
    const SENTINEL: &str = "SYNTHETIC-SENTINEL-not-a-credential";
    let ok_strategy = r#"{"default": {"allOf": [{"any": 1}]}}"#;
    let cases: [(&str, String, String, &str); 11] = [
        (
            "unknown entry key",
            PROVIDERS.replace(
                r#""entity": "quicknode"}"#,
                &format!(r#""entity": "quicknode", "{SENTINEL}": 1}}"#),
            ),
            ok_strategy.into(),
            "providers-v2.json: JSON data error: unknown field at line ",
        ),
        (
            "unknown top-level providers key",
            PROVIDERS.replacen('{', &format!(r#"{{"{SENTINEL}": 1, "#), 1),
            ok_strategy.into(),
            "providers-v2.json: JSON data error: unknown field at line ",
        ),
        (
            "unknown strategy key",
            PROVIDERS.into(),
            format!(r#"{{"default": {{"{SENTINEL}": [{{"any": 1}}]}}}}"#),
            "quorum-strategy.json: JSON data error: unknown field at line ",
        ),
        (
            "unknown top-level strategy key",
            PROVIDERS.into(),
            format!(r#"{{"{SENTINEL}": 1, "default": {{"allOf": [{{"any": 1}}]}}}}"#),
            "quorum-strategy.json: unknown top-level field",
        ),
        (
            "bad quorum literal",
            PROVIDERS.into(),
            format!(r#"{{"default": {{"allOf": [{{"any": "{SENTINEL}"}}]}}}}"#),
            r#"quorum count must be a non-negative integer or "max" at line "#,
        ),
        (
            "category value",
            PROVIDERS.replace(
                r#""category": "internal""#,
                &format!(r#""category": "{SENTINEL}""#),
            ),
            ok_strategy.into(),
            r#"chain "ethereum" rpc[0] has an unknown category"#,
        ),
        (
            "entity value",
            PROVIDERS.replace(
                r#""entity": "quicknode"}"#,
                &format!(r#""entity": "{SENTINEL}"}}"#),
            ),
            ok_strategy.into(),
            r#"chain "ethereum" rpc[2] has an entity which is not in the registered entities list"#,
        ),
        (
            "chain and endpoint keys",
            PROVIDERS.replace(
                r#""bsc": {"#,
                &format!(r#""{SENTINEL}": {{"{SENTINEL}": [], "#),
            ),
            r#"{"default": {"allOf": [{"any": 2}]}}"#.into(),
            r#"Chain "<unlisted chain>" <unlisted endpoint type>: strategy not satisfiable"#,
        ),
        (
            "strategy category key below the floor",
            PROVIDERS.into(),
            format!(
                r#"{{"default": {{"allOf": [{{"{SENTINEL}": "max"}}]}}, "restrictions": {{"minimumMaxEntities": 1}}}}"#
            ),
            "<unlisted category>",
        ),
        (
            "strategy category key unsatisfiable",
            PROVIDERS.into(),
            format!(r#"{{"default": {{"allOf": [{{"{SENTINEL}": 1}}]}}}}"#),
            "<unlisted category>",
        ),
        (
            "syntax error after a value",
            format!(r#"{{"entities": ["{SENTINEL}" "#),
            ok_strategy.into(),
            "providers-v2.json: JSON unexpected end of input at line 1 column ",
        ),
    ];
    for (name, providers, strategy, expected) in cases {
        let error = message(load(&providers, &strategy));
        assert!(!error.contains(SENTINEL), "{name}: {error}");
        assert!(error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn unknown_strategy_categories_are_rejected_in_defaults_and_overrides() {
    for strategy in [
        r#"{"default":{"allOf":[{"typo":0}]}}"#,
        r#"{"default":{"allOf":[{"any":2}]},"chains":{"ethereum":{"rpc":{"oneOf":[{"typo":0}]}}}}"#,
    ] {
        let error = message(load(PROVIDERS, strategy));
        assert!(error.contains("<unlisted category>"), "{error}");
    }
    assert!(load(PROVIDERS, r#"{"default":{"allOf":[{"any":1}]}}"#).is_ok());
}
#[test]
fn misspelled_max_category_is_rejected_and_corrected_category_resolves() {
    let providers = r#"{"entities":["op1","op2","alchemy"],"chains":{"ethereum":{"rpc":[
      {"uri":"https://one.example","category":"internal","entity":"op1"},
      {"uri":"https://two.example","category":"internal","entity":"op2"},
      {"uri":"https://external.example","category":"dedicated_external","entity":"alchemy"}
    ]}}}"#;
    let error = message(load(
        providers,
        r#"{"default":{"allOf":[{"internal":"max"},{"dedicated-external":"max"}]}}"#,
    ));
    assert!(error.contains("<unlisted category>"), "{error}");
    let loaded = load(
        providers,
        r#"{"default":{"allOf":[{"internal":"max"},{"dedicated_external":"max"}]}}"#,
    )
    .unwrap();
    let resolved = &loaded.get_provider_configs()["ethereum"].strategy;
    assert_eq!(
        crate::provider_validation::canonical_strategy_key(resolved),
        r#"{"allOf":[{"internal":2},{"dedicated_external":1}],"oneOf":[]}"#
    );
}
#[test]
fn unmatched_strategy_chain_and_endpoint_keys_warn_without_rejecting() {
    #[derive(Clone)]
    struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Writer(logs.clone());
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let strategy = r#"{"default":{"allOf":[{"any":1}]},"chains":{"ghost":{"rpc":{"allOf":[{"any":1}]}},"ethereum":{"rest":{"allOf":[{"any":1}]}}}}"#;
    assert!(load(PROVIDERS, strategy).is_ok());
    let logged = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(
        logged.contains("quorum strategy chain does not match"),
        "{logged}"
    );
    assert!(
        logged.contains("quorum strategy endpoint does not match"),
        "{logged}"
    );
}
#[test]
fn any_is_a_separate_threshold_that_overlaps_category_slots() {
    // `internal: 1` plus `any: 2` is met by two entities, not three.
    let strategy = QuorumStrategy {
        all_of: vec![
            category_req(&[("internal", 1)]),
            category_req(&[("any", 2)]),
        ],
        one_of: vec![],
    };
    let two = BTreeMap::from([
        (
            "internal".to_string(),
            BTreeSet::from(["operator".to_string()]),
        ),
        (
            "shared_external".to_string(),
            BTreeSet::from(["alchemy".to_string()]),
        ),
    ]);
    assert!(is_strategy_satisfiable(&two, &strategy));
}
