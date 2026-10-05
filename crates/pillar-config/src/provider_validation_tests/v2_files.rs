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
            "unknown field `allof`",
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
            r#"quorum count must be a non-negative integer or "max", got "all""#,
        ),
        (
            "unregistered entity in an unused pool",
            &PROVIDERS.replace(
                r#"indexer.example", "category": "internal", "entity": "operator""#,
                r#"indexer.example", "category": "internal", "entity": "nobody""#,
            ),
            r#"{"default": {"allOf": [{"any": 1}]}}"#,
            r#"has entity "nobody" which is not in the registered entities list"#,
        ),
        (
            "unknown category",
            &PROVIDERS.replace(
                r#""category": "internal", "entity": "operator"}"#,
                r#""category": "private", "entity": "operator"}"#,
            ),
            r#"{"default": {"allOf": [{"any": 1}]}}"#,
            r#"has unknown category "private""#,
        ),
        (
            "unknown entry field",
            &PROVIDERS.replace(
                r#""entity": "quicknode"}"#,
                r#""entity": "quicknode", "weight": 2}"#,
            ),
            r#"{"default": {"allOf": [{"any": 1}]}}"#,
            "unknown field `weight`",
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
    assert!(error.contains("unknown field `note`"), "{error}");
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
