use super::*;
use pillar_core::{
    execution::{BudgetLimits, ExecutionResources, FairBudget, RequestContext},
    ProviderHealthSource,
};
use std::{
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};
use tower::ServiceExt;

#[derive(Clone)]
struct HealthWire {
    stall_bsc: Arc<AtomicBool>,
    delay: Duration,
    physical: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}
struct Call(Arc<AtomicUsize>);
impl Drop for Call {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl JsonRpcTransport for HealthWire {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: Value,
    ) -> Result<Value, String> {
        let count = self.physical.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(count, Ordering::SeqCst);
        let _call = Call(self.physical.clone());
        if url.contains("bsc") && self.stall_bsc.load(Ordering::SeqCst) {
            return std::future::pending().await;
        }
        tokio::time::sleep(self.delay).await;
        Ok(json!({"result":"0x1"}))
    }
    async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
        panic!("unexpected GET")
    }
}
fn wire(delay: Duration, stall: bool) -> HealthWire {
    HealthWire {
        stall_bsc: Arc::new(AtomicBool::new(stall)),
        delay,
        physical: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    }
}
fn resources(chains: Vec<String>, cap: usize) -> Arc<ExecutionResources> {
    let mut lanes = chains;
    lanes.push("background".into());
    let limits = BudgetLimits {
        active: 64,
        per_lane: 8,
        waiting: 512,
        per_lane_waiting: 64,
        wait: Duration::from_secs(2),
    };
    let rpc = FairBudget::new(lanes.clone(), limits).unwrap();
    rpc.cap_lane("background", cap).unwrap();
    Arc::new(ExecutionResources {
        signing: FairBudget::new(lanes.clone(), limits).unwrap(),
        rpc,
        kms: FairBudget::new(lanes, limits).unwrap(),
    })
}
fn artifact(name: &str, value: Value) {
    let directory = std::env::var_os("PILLAR_E2E_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../local/e2e-runs")
        });
    static RUN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let directory = directory.join(RUN.get_or_init(|| {
        format!(
            "run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(format!("{name}.json")), value.to_string()).unwrap();
    println!("{value}");
}
#[tokio::test(start_paused = true)]
async fn health_timeout_isolated_and_startup_ready_beyond_stale_window() {
    let wire = wire(Duration::from_millis(1), true);
    let now = Arc::new(AtomicU64::new(1));
    let clock = now.clone();
    let app = RuntimeServerApp::from_env_map_with_runtime_core(
        read_vertical_env_map(),
        wire.clone(),
        move || clock.load(Ordering::SeqCst),
    )
    .await
    .expect("one stalled provider must not prevent startup");
    let report: Value = pillar_api::ServerApp::get_provider_health_report(&app)
        .await
        .unwrap();
    assert!(report["ethereum"]["healthy"].as_bool().unwrap());
    assert!(!report["bsc"]["healthy"].as_bool().unwrap());
    assert!(report["bsc"]["providers"][0]["response"]
        .as_str()
        .unwrap()
        .contains("timed out"));
    now.store(130_001, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(130)).await;
    let response = pillar_api::router(app, "synthetic")
        .oneshot(
            axum::http::Request::builder()
                .uri("/ready")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    artifact(
        "R1-health-availability",
        json!({"startup_succeeded":true,"stalled_chain_healthy":report["bsc"]["healthy"],"other_chain_healthy":report["ethereum"]["healthy"],"clock_ms":now.load(Ordering::SeqCst),"ready_status":response.status().as_u16()}),
    );
}
#[tokio::test(start_paused = true)]
async fn health_hundred_chains_complete_in_bounded_parallel_round() {
    let chains: Vec<String> = (0..100).map(|index| format!("chain{index}")).collect();
    let getter = StaticProviderConfig::new(
        chains
            .iter()
            .map(|chain| {
                (
                    chain.clone(),
                    ProviderConfig::with_distinct_entities(
                        vec![ProviderUri::Uri(format!("https://{chain}.invalid"))],
                        1,
                    ),
                )
            })
            .collect(),
        None,
    )
    .unwrap();
    let wire = wire(Duration::from_millis(150), false);
    let source = RpcProviderHealthSource::from_getter(&getter, wire.clone(), || 1)
        .with_execution_resources(resources(chains, 4));
    let started = tokio::time::Instant::now();
    let report = source.get_provider_health_report().await.unwrap();
    let elapsed = started.elapsed();
    assert_eq!(report.len(), 100);
    assert!(report.values().all(|chain| chain.healthy));
    assert!(elapsed < Duration::from_secs(5), "round took {elapsed:?}");
    assert!(wire.peak.load(Ordering::SeqCst) <= 4);
    artifact(
        "R1-hundred-chains",
        json!({"chains":report.len(),"round_ms":elapsed.as_millis(),"physical_peak":wire.peak.load(Ordering::SeqCst)}),
    );
}
#[tokio::test(start_paused = true)]
async fn overlapping_health_rounds_share_background_cap_and_leave_foreground_permit() {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "bsc".into(),
            ProviderConfig::with_distinct_entities(
                (0..16)
                    .map(|index| ProviderUri::Uri(format!("https://bsc.invalid/{index}")))
                    .collect(),
                1,
            ),
        )]),
        None,
    )
    .unwrap();
    let wire = wire(Duration::ZERO, false);
    let resources = resources(vec!["bsc".into()], 4);
    let source = RpcProviderHealthSource::from_getter(&getter, wire.clone(), || 1)
        .with_execution_resources(resources.clone());
    assert!(source.get_provider_health().await.unwrap()["bsc"]);
    wire.stall_bsc.store(true, Ordering::SeqCst);
    let first = tokio::spawn({
        let source = source.clone();
        async move { source.get_provider_health_report().await }
    });
    let second = tokio::spawn({
        let source = source.clone();
        async move { source.get_provider_health_report().await }
    });
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(wire.physical.load(Ordering::SeqCst), 4);
    let mut context = RequestContext::new(Duration::from_secs(1));
    context.resources = Some(resources.clone());
    context.source_chain = Some(Arc::from("bsc"));
    let foreground = context
        .scope(resources.rpc.acquire_for("bsc", Some("bsc")))
        .await
        .unwrap();
    assert!(wire.peak.load(Ordering::SeqCst) <= 4);
    drop(foreground);
    let reports = [
        first.await.unwrap().unwrap(),
        second.await.unwrap().unwrap(),
    ];
    assert!(reports.iter().all(|report| report.contains_key("bsc")));
    artifact(
        "R2-overlapping-rounds",
        json!({"rounds":reports.len(),"background_peak":wire.peak.load(Ordering::SeqCst),"foreground_permit_acquired":true}),
    );
}

#[tokio::test(start_paused = true)]
async fn quorum_counts_started_timeout_and_keeps_observed_disagreement_over_admission() {
    let wire = wire(Duration::ZERO, true);
    let mut context = RequestContext::new(Duration::from_millis(20));
    context.resources = Some(resources(vec!["bsc".into()], 4));
    context.source_chain = Some(Arc::from("bsc"));
    let timeout = context
        .scope(wire.post_json_on(
            "bsc",
            "https://bsc.invalid".into(),
            HashMap::new(),
            json!({}),
        ))
        .await;
    assert!(matches!(
        timeout,
        Err(crate::provider_health::RpcError::Remote(_))
    ));
    let requests = futures::stream::FuturesUnordered::new();
    requests.push(futures::future::ready((0, Ok(Some(("a".into(), 1))))));
    requests.push(futures::future::ready((
        1,
        timeout.map(|_| Some(("a".into(), 1))),
    )));
    let two_of_two = pillar_config::ProviderConfig::with_distinct_entities(
        vec![
            pillar_config::ProviderUri::Uri("https://a.invalid".to_string()),
            pillar_config::ProviderUri::Uri("https://b.invalid".to_string()),
        ],
        2,
    );
    let quorum = crate::provider_health::required_provider_quorum(&two_of_two, "smoke").unwrap();
    let error =
        crate::provider_health::resolve_provider_quorum(requests, 2, quorum, "timeout smoke")
            .await
            .unwrap_err();
    assert!(error.to_string().contains("1 errors"));
    let requests = futures::stream::FuturesUnordered::new();
    requests.push(futures::future::ready((0, Ok(Some(("a".into(), 1))))));
    requests.push(futures::future::ready((1, Ok(Some(("b".into(), 2))))));
    requests.push(futures::future::ready((
        2,
        Err(crate::provider_health::RpcError::Admission(
            pillar_core::execution::BudgetError::Overloaded,
        )),
    )));
    let two_of_three = pillar_config::ProviderConfig::with_distinct_entities(
        vec![
            pillar_config::ProviderUri::Uri("https://a.invalid".to_string()),
            pillar_config::ProviderUri::Uri("https://b.invalid".to_string()),
            pillar_config::ProviderUri::Uri("https://c.invalid".to_string()),
        ],
        2,
    );
    let quorum = crate::provider_health::required_provider_quorum(&two_of_three, "smoke").unwrap();
    let disagreement =
        crate::provider_health::resolve_provider_quorum(requests, 3, quorum, "disagreement smoke")
            .await
            .unwrap_err();
    assert!(matches!(disagreement, AppCoreError::Internal(_)));
    assert!(disagreement
        .to_string()
        .contains("2 distinct successful responses, 0 errors"));
    artifact(
        "R1-R10-quorum",
        json!({"timeout_error":error.to_string(),"disagreement_error":disagreement.to_string()}),
    );
}
