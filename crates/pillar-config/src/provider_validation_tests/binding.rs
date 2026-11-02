use super::*;
use sha2::{Digest, Sha256};

const PROVIDERS: &str = r#"{"entities":["ops"],"chains":{"ethereum":{"rpc":[{"uri":"https://rpc.example","category":"internal","entity":"ops"}]}}}"#;
const OTHER_PROVIDERS: &str = r#"{"entities":["ops"],"chains":{"ethereum":{"rpc":[{"uri":"https://other.example","category":"internal","entity":"ops"}]}}}"#;

fn strategy_bound_to(binding: &str) -> String {
    format!(r#"{{"_providersSha256":{binding},"default":{{"allOf":[{{"any":1}}]}}}}"#)
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[test]
fn a_strategy_bound_to_its_providers_file_loads() {
    let strategy = strategy_bound_to(&format!("\"{}\"", sha256_hex(PROVIDERS)));
    assert!(provider_configs_from_v2(PROVIDERS, &strategy).is_ok());
}

#[test]
fn a_strategy_bound_to_another_providers_file_is_refused_so_a_torn_rollout_is_not_served() {
    let strategy = strategy_bound_to(&format!("\"{}\"", sha256_hex(PROVIDERS)));
    let error = provider_configs_from_v2(OTHER_PROVIDERS, &strategy).unwrap_err();
    assert!(error.to_string().contains("_providersSha256"), "{error}");
}

#[test]
fn the_binding_covers_the_exact_bytes_of_the_providers_file() {
    let strategy = strategy_bound_to(&format!("\"{}\"", sha256_hex(PROVIDERS)));
    let reformatted = format!("{PROVIDERS}\n");
    assert!(provider_configs_from_v2(&reformatted, &strategy).is_err());
}

#[test]
fn a_binding_that_is_not_a_sha256_is_refused_rather_than_ignored() {
    for binding in ["\"abc\"", "12", "null", "\"zz\""] {
        let error = provider_configs_from_v2(PROVIDERS, &strategy_bound_to(binding)).unwrap_err();
        assert!(
            error.to_string().contains("_providersSha256"),
            "{binding}: {error}"
        );
    }
}

#[test]
fn a_strategy_without_a_binding_still_loads() {
    let strategy = r#"{"default":{"allOf":[{"any":1}]}}"#;
    assert!(provider_configs_from_v2(PROVIDERS, strategy).is_ok());
}
