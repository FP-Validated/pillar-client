use super::*;
use pillar_core::execution::ExecutionResources;

async fn resources_from_env(extra: &[(&str, &str)]) -> Result<Arc<ExecutionResources>, String> {
    let mut vars = HashMap::from([
        (SERVER_PORT.to_string(), "0".to_string()),
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
            "test-token-0123456789abcdef0123456789".to_string(),
        ),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            "ethereum,bsc".to_string(),
        ),
        (
            LZ_PROVIDER_CONFIG.to_string(),
            providers_json(
                r#"{"ethereum":{"uris":["https://eth.example"],"quorum":1},"bsc":{"uris":["https://bsc.example"],"quorum":1}}"#,
            ),
        ),
        (
            LZ_QUORUM_STRATEGY_CONFIG.to_string(),
            strategy_json(
                r#"{"ethereum":{"uris":["https://eth.example"],"quorum":1},"bsc":{"uris":["https://bsc.example"],"quorum":1}}"#,
            ),
        ),
    ]);
    vars.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let runtime = RuntimeServerApp::from_env_map(
        vars,
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
        },
        || 777,
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(runtime.execution_resources().expect("runtime resources"))
}

/// Takes permits on `key` for `lane` until the budget refuses, returning them.
fn drain(
    budget: &pillar_core::execution::FairBudget,
    lane: &str,
    key: &str,
) -> Vec<pillar_core::execution::BudgetPermit> {
    let mut permits = Vec::new();
    while permits.len() < 16 {
        match budget.try_acquire_for(lane, Some(key)).unwrap() {
            Some(permit) => permits.push(permit),
            None => break,
        }
    }
    permits
}

#[tokio::test]
async fn default_runtime_kms_leaves_a_same_key_slot_for_another_source() {
    let resources = resources_from_env(&[]).await.unwrap();

    let source = drain(&resources.kms, "ethereum", "K");
    let other = resources.kms.try_acquire_for("bsc", Some("K")).unwrap();
    let rpc = drain(&resources.rpc, "ethereum", "K");
    let signing = drain(&resources.signing, "ethereum", "K");
    println!(
        "GA1_ARTIFACT kms_same_source_max={} kms_other_source_admitted={} rpc_same_source_max={} signing_same_source_max={}",
        source.len(),
        other.is_some(),
        rpc.len(),
        signing.len()
    );

    assert_eq!(source.len(), 3);
    assert!(other.is_some());
    assert_eq!(rpc.len(), 8, "RPC budget keeps its per-lane resource limit");
    assert_eq!(signing.len(), 8, "signing budget keeps its per-lane limit");
}

#[tokio::test]
async fn explicit_lane_key_limit_is_applied_and_invalid_values_stop_startup() {
    let resources = resources_from_env(&[("PILLAR_KMS_CHAIN_KEY_CONCURRENCY", "2")])
        .await
        .unwrap();
    assert_eq!(drain(&resources.kms, "ethereum", "K").len(), 2);

    for bad in ["0", "4", "5", "x"] {
        let error = resources_from_env(&[("PILLAR_KMS_CHAIN_KEY_CONCURRENCY", bad)])
            .await
            .err()
            .unwrap_or_else(|| panic!("{bad} must be rejected at startup"));
        assert!(
            error.contains("PILLAR_KMS_CHAIN_KEY_CONCURRENCY"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn key_cap_one_allows_pair_one_without_same_key_headroom() {
    let resources = resources_from_env(&[("PILLAR_KMS_KEY_CONCURRENCY", "1")])
        .await
        .unwrap();

    let source = drain(&resources.kms, "ethereum", "K");

    assert_eq!(source.len(), 1);
    assert!(resources
        .kms
        .try_acquire_for("bsc", Some("K"))
        .unwrap()
        .is_none());
}
