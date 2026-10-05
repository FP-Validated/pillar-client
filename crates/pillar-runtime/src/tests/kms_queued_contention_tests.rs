use super::*;
use pillar_core::execution::{BudgetPermit, ExecutionResources};
use tokio::time::Instant;

async fn kms_resources() -> Arc<ExecutionResources> {
    let vars = HashMap::from([
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
        ("PILLAR_ADMISSION_WAIT_MS".to_string(), "2000".to_string()),
    ]);
    RuntimeServerApp::from_env_map(
        vars,
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
        },
        || 777,
    )
    .await
    .expect("runtime")
    .execution_resources()
    .expect("runtime resources")
}

/// Under the paused clock yielding never advances time, so this only waits for the spawned task to reach the budget.
async fn settle(kms: &pillar_core::execution::FairBudget, in_budget: usize) {
    for _ in 0..100 {
        let totals = kms.totals();
        if totals.active + totals.waiting == in_budget {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("budget never reached {in_budget} active+waiting permits");
}

#[tokio::test(start_paused = true)]
async fn a_queued_fourth_request_from_one_source_does_not_starve_another_source() {
    let resources = kms_resources().await;
    let kms = resources.kms.clone();

    let mut held: Vec<BudgetPermit> = Vec::new();
    for _ in 0..3 {
        held.push(kms.acquire_for("ethereum", Some("K")).await.unwrap());
    }
    let fourth = tokio::spawn({
        let kms = kms.clone();
        async move { kms.acquire_for("ethereum", Some("K")).await }
    });
    settle(&kms, 4).await;
    let before = kms.totals();
    let fourth_finished = fourth.is_finished();

    let started = Instant::now();
    let other = kms.acquire_for("bsc", Some("K")).await;
    let elapsed = started.elapsed();
    let other_outcome = match &other {
        Ok(_) => "granted".to_string(),
        Err(error) => format!("{error:?}"),
    };
    drop(other);

    fourth.abort();
    let fourth_outcome = match fourth.await {
        Ok(Ok(permit)) => {
            drop(permit);
            "granted_before_b"
        }
        _ => "queued_until_aborted",
    };
    drop(held);

    let after = kms.totals();
    let lanes_idle = kms
        .snapshot()
        .iter()
        .all(|lane| lane.active == 0 && lane.waiting == 0);
    let mut probe = Vec::new();
    while probe.len() < 16 {
        match kms.try_acquire_for("ethereum", Some("K")).unwrap() {
            Some(permit) => probe.push(permit),
            None => break,
        }
    }
    let probe_len = probe.len();
    drop(probe);

    println!(
        "OBS a_active={} a_waiting={} fourth_finished={fourth_finished} fourth={fourth_outcome} b={other_outcome} b_elapsed_ms={} final_active={} final_waiting={} lanes_idle={lanes_idle} reacquire_after_cleanup={probe_len}",
        before.active,
        before.waiting,
        elapsed.as_millis(),
        after.active,
        after.waiting,
    );

    assert_eq!((before.active, before.waiting), (3, 1));
    assert!(!fourth_finished);
    assert_eq!(fourth_outcome, "queued_until_aborted");
    assert_eq!(other_outcome, "granted");
    assert_eq!(elapsed.as_millis(), 0);
    assert_eq!((after.active, after.waiting), (0, 0));
    assert!(lanes_idle);
    assert_eq!(probe_len, 3);
}
