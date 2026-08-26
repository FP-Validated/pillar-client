use super::*;
use pillar_metrics::PillarMetrics;

/// Answers whatever the health probes ask, so advancing a paused clock cannot
/// exhaust a scripted response queue.
#[derive(Clone)]
struct AlwaysOkTransport;

#[async_trait]
impl JsonRpcTransport for AlwaysOkTransport {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        Ok(json!({"result": "0x38"}))
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Ok(json!({"result": "0x38"}))
    }
}

/// Answers every probe and counts them, so the silence after a drop is
/// measurable. `RecordingTransport` pops a scripted queue and panics once it is
/// empty, which cannot survive a loop running for a simulated hour.
#[derive(Clone)]
struct CountingTransport {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl JsonRpcTransport for CountingTransport {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"result": "0x38"}))
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"result": "0x38"}))
    }
}

/// Hands out one scripted bucket read per refresh.
struct ScriptedLoader {
    responses: Arc<tokio::sync::Mutex<Vec<Result<String, pillar_config::ConfigError>>>>,
}

#[async_trait]
impl pillar_config::RemoteProviderConfigLoader for ScriptedLoader {
    async fn load_provider_config(
        &self,
        _request: pillar_config::RemoteProviderConfigRequest,
    ) -> Result<String, pillar_config::ConfigError> {
        let mut responses = self.responses.lock().await;
        if responses.is_empty() {
            return Err(pillar_config::ConfigError::Json(
                "script exhausted".to_string(),
            ));
        }
        responses.remove(0)
    }
}

/// Serves one bucket read, then never returns. The shape of a provider endpoint
/// that accepts the connection and stops answering.
struct HangsAfterFirstReadLoader {
    reads: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl pillar_config::RemoteProviderConfigLoader for HangsAfterFirstReadLoader {
    async fn load_provider_config(
        &self,
        _request: pillar_config::RemoteProviderConfigRequest,
    ) -> Result<String, pillar_config::ConfigError> {
        if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return Ok(REPLACEMENT.to_string());
        }
        std::future::pending().await
    }
}

const SERVING: &str = r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#;
const REPLACEMENT: &str = r#"{"bsc":{"uris":["https://bsc-rpc-2.example"],"quorum":1}}"#;
const UNSIGNABLE: &str = r#"{"bsc":{"uris":[],"quorum":1}}"#;

fn runtime_vars() -> HashMap<String, String> {
    HashMap::from([
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
            "test-token-0123456789abcdef0123456789".to_string(),
        ),
        (SERVER_PORT.to_string(), "3000".to_string()),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (
            pillar_config::LZ_SUPPORTED_ULN_VERSIONS.to_string(),
            r#"["V2"]"#.to_string(),
        ),
        (LZ_PROVIDER_CONFIG.to_string(), SERVING.to_string()),
        (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
        (
            pillar_config::LZ_WALLETS.to_string(),
            config_wallet_json("wallet-a", "EVM", "secret-a"),
        ),
        (
            pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            r#"{"wallet-a-EVM":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/60'/0'/0/0"}}"#
                .to_string(),
        ),
    ])
}

fn core_dependencies() -> RuntimeCoreAppDependencies {
    RuntimeCoreAppDependencies {
        hash_call_data_builders: HashMap::from([(
            "V302".to_string(),
            Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
        )]),
        sent_event_resolver: Arc::new(FixedResolver),
        validator: Arc::new(NoopValidator),
        legacy_chain_name_resolver: Arc::new(FixedChainResolver),
    }
}

/// Advances the paused clock past one refresh interval and lets the spawned
/// loop actually run: on a current-thread runtime the task only progresses at
/// yield points.
async fn tick_one_refresh() {
    // Let the spawned loop reach its `sleep` and register the timer first:
    // advancing before it has ever been polled just moves the clock past a
    // timer that does not exist yet.
    settle().await;
    tokio::time::advance(std::time::Duration::from_secs(61)).await;
    settle().await;
}

async fn settle() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
}

async fn rendered(app_metrics: &Arc<tokio::sync::Mutex<PillarMetrics>>) -> String {
    app_metrics
        .lock()
        .await
        .render_prometheus("mainnet", "test-version")
}

/// Builds the production wiring: a remote owner whose refresh loop is running,
/// plus the rank and health-cache loops the composition root spawns.
async fn app_with_every_background_loop<T>(
    transport: T,
    metrics: &Arc<tokio::sync::Mutex<PillarMetrics>>,
) -> RuntimeServerApp<T>
where
    T: JsonRpcTransport,
{
    let mut owner = Some(RemoteProviderConfigOwner::with_loader_for_test(
        serde_json::from_str(SERVING).unwrap(),
        Arc::new(ScriptedLoader {
            responses: Arc::new(tokio::sync::Mutex::new(vec![Ok(REPLACEMENT.to_string())])),
        }),
        Some(vec!["bsc".to_string()]),
    ));
    let providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(SERVING).unwrap(),
            Some(&["bsc".to_string()]),
        )
        .unwrap(),
        &["bsc".to_string()],
        Some("bsc"),
        metrics.clone(),
    )
    .await
    .unwrap();
    RuntimeServerApp::from_env_map_with_core_dependencies(
        runtime_vars(),
        transport,
        || 777,
        core_dependencies(),
        HashMap::from([("bsc".to_string(), "EVM".to_string())]),
        RuntimeMode::Development,
        Arc::new(ProviderRankTracker::new()),
        owner,
        providers,
        metrics.clone(),
    )
    .await
    .unwrap()
}

fn single_gauge(rendered: &str, name: &str) -> f64 {
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(format!("{name} ").as_str()))
        .unwrap_or_else(|| panic!("no sample for {name} in:\n{rendered}"))
        .trim()
        .parse()
        .expect("gauge value")
}

fn heartbeat_age(rendered: &str, task: &str) -> f64 {
    let prefix = format!("pillar_background_task_heartbeat_age_seconds{{task=\"{task}\"}} ");
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no heartbeat for {task} in:\n{rendered}"))
        .trim()
        .parse()
        .expect("heartbeat age")
}

/// Every loop this process runs has to be visible as a loop, and a loop that
/// has stopped has to look different from one that is keeping up.
///
/// Nothing awaited these handles, so a loop that died - panicked, wedged, or
/// aborted - left no trace: the only age on `/metrics` was the one the config
/// refresh wrote for itself, and its accepting branch wrote zero.
#[tokio::test(start_paused = true)]
async fn every_background_loop_reports_a_heartbeat_that_ages_when_it_stops() {
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let app = app_with_every_background_loop(AlwaysOkTransport, &metrics).await;

    // Past the slowest interval, so all three have completed an iteration.
    settle().await;
    tokio::time::advance(std::time::Duration::from_secs(151)).await;
    settle().await;

    let running = rendered(&metrics).await;
    for task in [
        "provider_config_refresh",
        "provider_rank_refresh",
        "provider_health_cache_refresh",
    ] {
        assert!(
            heartbeat_age(&running, task) < 151.0,
            "{task} is running, so its heartbeat cannot be a whole interval old:\n{running}"
        );
    }

    // Dropping the app is what stops every loop, including the config refresh
    // the owner it holds is responsible for.
    drop(app);
    settle().await;
    tokio::time::advance(std::time::Duration::from_secs(3_600)).await;
    settle().await;

    let stopped = rendered(&metrics).await;
    for task in [
        "provider_config_refresh",
        "provider_rank_refresh",
        "provider_health_cache_refresh",
    ] {
        assert!(
            heartbeat_age(&stopped, task) >= 3_600.0,
            "{task} stopped an hour ago and has to read that way:\n{stopped}"
        );
    }
}

/// A loop hung inside its own work is not a healthy loop.
///
/// This does **not** pin where the stamp goes, and an earlier version of this
/// comment claimed it did. A hung loop stamps at most once and never returns, so
/// stamping on entry and stamping on completion differ by one work duration and
/// nothing else - verified by mutation: moving the stamp to entry leaves this
/// test passing. The placement is a conservatism choice with no separate
/// observable, and the HELP text is what has to agree with it.
///
/// What this does pin: a loop wedged in its own work reads as a growing age
/// rather than a fresh one, and it does not spin through further reads while
/// wedged. Nothing else covered either.
#[tokio::test(start_paused = true)]
async fn a_loop_hung_inside_its_work_reports_a_growing_age() {
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut owner = Some(RemoteProviderConfigOwner::with_loader_for_test(
        serde_json::from_str(SERVING).unwrap(),
        Arc::new(HangsAfterFirstReadLoader {
            reads: reads.clone(),
        }),
        Some(vec!["bsc".to_string()]),
    ));
    let _providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(SERVING).unwrap(),
            Some(&["bsc".to_string()]),
        )
        .unwrap(),
        &["bsc".to_string()],
        Some("bsc"),
        metrics.clone(),
    )
    .await
    .unwrap();
    let owner = owner.expect("the owner keeps the refresh loop alive");

    // One iteration completes.
    tick_one_refresh().await;
    assert!(
        heartbeat_age(&rendered(&metrics).await, "provider_config_refresh") < 61.0,
        "the first refresh completed, so the loop is keeping up"
    );

    // The second read hangs, and the clock runs on for an hour.
    tick_one_refresh().await;
    tokio::time::advance(std::time::Duration::from_secs(3_600)).await;
    settle().await;

    assert_eq!(
        reads.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the loop must be stuck in its second read, not spinning through more"
    );
    assert!(
        heartbeat_age(&rendered(&metrics).await, "provider_config_refresh") >= 3_600.0,
        "a loop that has not completed an iteration for an hour has to read that way"
    );
    drop(owner);
}

/// A scrape taken before any loop has completed an interval still has to answer.
///
/// The loop-written gauge was absent for the first sixty seconds of every
/// process, because nothing had written it yet - so a crash-looping deployment
/// that never reached its first refresh published no staleness at all, and an
/// alert on the metric could not fire on the one case that most needed it.
#[tokio::test(start_paused = true)]
async fn the_first_scrape_already_carries_every_age() {
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let app = app_with_every_background_loop(AlwaysOkTransport, &metrics).await;
    settle().await;

    let text = rendered(&metrics).await;
    // Parsed, not matched as a substring: `contains("... 0")` also accepts
    // `0.4`, and would accept a hardcoded zero that never moves.
    assert!(
        single_gauge(&text, "pillar_provider_config_age_seconds") < 1.0,
        "the startup load is an accepted snapshot, so its age starts near zero:\n{text}"
    );
    for task in [
        "provider_config_refresh",
        "provider_rank_refresh",
        "provider_health_cache_refresh",
    ] {
        assert!(
            heartbeat_age(&text, task) < 1.0,
            "{task} must be registered at startup, not on its first tick:\n{text}"
        );
    }
    drop(app);
}

/// Construction that fails after the loops would have been spawned must not
/// leave them behind.
///
/// `Drop` only runs on a value that exists. Two fallible steps sit between the
/// old spawn site and `Ok(Self { .. })` - the health-report serialisation and
/// `StartupReport::from_parts`, which rejects a chain with no provider config -
/// so an error there returned straight past the struct and both loops stayed
/// detached, probing providers, with no owner able to stop them.
#[tokio::test(start_paused = true)]
async fn a_failed_construction_leaves_no_loop_behind() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = CountingTransport {
        calls: calls.clone(),
    };
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    // The roster advertises `ethereum`, the provider configuration does not
    // carry it, and the wallet is by chain *type* so the signer step still
    // passes. The first thing to object is `StartupReport::from_parts`, which is
    // past the point the loops used to be spawned.
    let providers = crate::provider_snapshot::ProviderSnapshotHandle::new(
        serde_json::from_str(SERVING).unwrap(),
        vec!["bsc".to_string(), "ethereum".to_string()],
    );
    let owner = RemoteProviderConfigOwner::with_loader_for_test(
        serde_json::from_str(SERVING).unwrap(),
        Arc::new(ScriptedLoader {
            responses: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }),
        Some(vec!["bsc".to_string()]),
    );
    let error = RuntimeServerApp::from_env_map_with_core_dependencies(
        runtime_vars(),
        transport,
        || 777,
        core_dependencies(),
        HashMap::from([
            ("bsc".to_string(), "EVM".to_string()),
            ("ethereum".to_string(), "EVM".to_string()),
        ]),
        RuntimeMode::Development,
        Arc::new(ProviderRankTracker::new()),
        Some(owner),
        providers,
        metrics.clone(),
    )
    .await
    .err()
    .expect("a chain with no provider config has to fail the startup report");
    assert!(
        error.contains("missing provider config"),
        "the failure has to be the one this test is about: {error}"
    );

    let after_construction = calls.load(std::sync::atomic::Ordering::SeqCst);
    settle().await;
    tokio::time::advance(std::time::Duration::from_secs(600)).await;
    settle().await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        after_construction,
        "a construction that failed owns nothing, so nothing may keep probing"
    );
}

/// A dropped `JoinHandle` detaches in tokio, so the loops used to keep probing
/// providers after the process stopped serving. The abort has to be explicit.
#[tokio::test(start_paused = true)]
async fn dropping_the_app_stops_the_loops_from_probing() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = CountingTransport {
        calls: calls.clone(),
    };
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let app = app_with_every_background_loop(transport, &metrics).await;

    settle().await;
    tokio::time::advance(std::time::Duration::from_secs(151)).await;
    settle().await;
    let while_running = calls.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        while_running > 0,
        "the loops have to be probing before their silence proves anything"
    );
    let handles = app.background_abort_handles();
    assert!(
        handles.iter().all(|handle| !handle.is_finished()),
        "the loops are mid-interval, not finished"
    );

    drop(app);
    settle().await;
    assert!(
        handles.iter().all(tokio::task::AbortHandle::is_finished),
        "dropping the app has to have finished every loop it owned"
    );

    tokio::time::advance(std::time::Duration::from_secs(600)).await;
    settle().await;
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        while_running,
        "no provider may be probed after the app that owns the loop is gone"
    );
}

/// The refresh loop has to record into the registry the HTTP surface renders.
///
/// It previously recorded into a registry the owner built for itself, so
/// `pillar_provider_config_refresh_total` never appeared on `/metrics` and a
/// bucket that had been failing for hours was invisible to alerting.
#[tokio::test(start_paused = true)]
async fn refresh_outcomes_reach_the_registry_the_app_renders() {
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let owner = RemoteProviderConfigOwner::with_loader_for_test(
        serde_json::from_str(SERVING).unwrap(),
        Arc::new(ScriptedLoader {
            responses: Arc::new(tokio::sync::Mutex::new(vec![
                Ok(REPLACEMENT.to_string()),
                Ok(UNSIGNABLE.to_string()),
                Err(pillar_config::ConfigError::Json(
                    "bucket unreachable".to_string(),
                )),
            ])),
        }),
        Some(vec!["bsc".to_string()]),
    );

    let mut owner = Some(owner);
    // The same handoff the composition root performs: the roster is settled,
    // so the refresh loop may start against it.
    let providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(SERVING).unwrap(),
            Some(&["bsc".to_string()]),
        )
        .unwrap(),
        &["bsc".to_string()],
        Some("bsc"),
        metrics.clone(),
    )
    .await
    .unwrap();
    let app = RuntimeServerApp::from_env_map_with_core_dependencies(
        runtime_vars(),
        AlwaysOkTransport,
        || 777,
        core_dependencies(),
        HashMap::from([("bsc".to_string(), "EVM".to_string())]),
        RuntimeMode::Development,
        Arc::new(ProviderRankTracker::new()),
        owner,
        providers,
        metrics.clone(),
    )
    .await
    .unwrap();

    // Whatever the composition root was handed is what `/metrics` serves.
    let app_metrics = app.metrics().expect("runtime app exposes its registry");
    assert!(
        Arc::ptr_eq(&app_metrics, &metrics),
        "the app must render the registry it was constructed with"
    );

    // A usable snapshot lands.
    tick_one_refresh().await;
    let text = rendered(&app_metrics).await;
    assert!(
        text.contains(r#"pillar_provider_config_refresh_total{result="ok"}"#),
        "{text}"
    );

    // One that could never sign is refused, and says so under its own label.
    tick_one_refresh().await;
    let text = rendered(&app_metrics).await;
    assert!(
        text.contains(r#"pillar_provider_config_refresh_total{result="rejected"}"#),
        "{text}"
    );

    // A failed read is a third, distinct outcome.
    tick_one_refresh().await;
    let text = rendered(&app_metrics).await;
    assert!(
        text.contains(r#"pillar_provider_config_refresh_total{result="error"}"#),
        "{text}"
    );
}

/// A refresh cannot widen what the process advertises.
///
/// Signing capability is assembled once at startup - wallets, signer backends,
/// chain types, contract tables. A refresh that named a new chain would put it
/// on `/available-chains` while nothing could sign for it, so the chain set is
/// a ceiling and the roster only ever shrinks below it. What *does* land is a
/// URI change for a chain that was already assembled.
#[tokio::test(start_paused = true)]
async fn a_refresh_cannot_add_a_chain_the_process_has_no_signer_for() {
    const ADDS_A_CHAIN: &str = r#"{"bsc":{"uris":["https://bsc-rpc-9.example"],"quorum":1},"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1}}"#;

    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let owner = RemoteProviderConfigOwner::with_loader_for_test(
        serde_json::from_str(SERVING).unwrap(),
        Arc::new(ScriptedLoader {
            responses: Arc::new(tokio::sync::Mutex::new(vec![Ok(ADDS_A_CHAIN.to_string())])),
        }),
        Some(vec!["bsc".to_string()]),
    );
    let mut owner = Some(owner);
    let providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(SERVING).unwrap(),
            Some(&["bsc".to_string()]),
        )
        .unwrap(),
        &["bsc".to_string()],
        Some("bsc"),
        metrics.clone(),
    )
    .await
    .unwrap();
    let app = RuntimeServerApp::from_env_map_with_core_dependencies(
        runtime_vars(),
        AlwaysOkTransport,
        || 777,
        core_dependencies(),
        HashMap::from([("bsc".to_string(), "EVM".to_string())]),
        RuntimeMode::Development,
        Arc::new(ProviderRankTracker::new()),
        owner,
        providers,
        metrics.clone(),
    )
    .await
    .unwrap();

    assert_eq!(app.get_available_chain_names(), vec!["bsc".to_string()]);

    tick_one_refresh().await;

    let text = rendered(&metrics).await;
    assert!(
        text.contains(r#"pillar_provider_config_refresh_total{result="ok"}"#),
        "the refresh is admitted - the extra chain is dropped, not a reason to \
         refuse a usable configuration: {text}"
    );
    assert_eq!(
        app.get_available_chain_names(),
        vec!["bsc".to_string()],
        "a chain with no signer must never be advertised"
    );
    assert_eq!(
        app.get_provider_health()
            .await
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec!["bsc"],
        "and it must not be probed either"
    );
}

/// A refresh that no longer carries a chain this process was started for is
/// refused, and the chain keeps being served.
///
/// The read is restricted by the same roster as the startup load, so the file
/// fails `StaticProviderConfig`'s missing-chain check and the previous
/// configuration stays active. Upstream does the same - `fetchConfig` runs
/// `checkForMissingChainNames` on every poll
/// (`packages/dynamic-config/src/providerConfig/index.ts:129-134`) and the
/// polled caller keeps the stale value (`polled/index.ts:42-63`) - and it is
/// the conservative behaviour for a DVN: the set of chains it will attest for
/// changes only when an operator changes the roster and restarts, which is also
/// the only way the signer set behind it can change.
#[tokio::test(start_paused = true)]
async fn a_refresh_that_removes_a_chain_is_refused_and_the_chain_keeps_serving() {
    const TWO_CHAINS: &str = r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1},"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1}}"#;
    const DROPS_ETHEREUM: &str = r#"{"bsc":{"uris":["https://bsc-rpc-9.example"],"quorum":1}}"#;

    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let chains = ["bsc".to_string(), "ethereum".to_string()];
    let owner = RemoteProviderConfigOwner::with_loader_for_test(
        serde_json::from_str(TWO_CHAINS).unwrap(),
        Arc::new(ScriptedLoader {
            responses: Arc::new(tokio::sync::Mutex::new(vec![
                Ok(DROPS_ETHEREUM.to_string()),
            ])),
        }),
        Some(chains.to_vec()),
    );
    let mut owner = Some(owner);
    let providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(TWO_CHAINS).unwrap(),
            Some(&chains),
        )
        .unwrap(),
        &chains,
        Some("bsc,ethereum"),
        metrics.clone(),
    )
    .await
    .unwrap();

    let mut vars = runtime_vars();
    vars.insert(
        pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
        "bsc,ethereum".to_string(),
    );
    vars.insert(LZ_PROVIDER_CONFIG.to_string(), TWO_CHAINS.to_string());
    let app = RuntimeServerApp::from_env_map_with_core_dependencies(
        vars,
        AlwaysOkTransport,
        || 777,
        core_dependencies(),
        HashMap::from([
            ("bsc".to_string(), "EVM".to_string()),
            ("ethereum".to_string(), "EVM".to_string()),
        ]),
        RuntimeMode::Development,
        Arc::new(ProviderRankTracker::new()),
        owner,
        providers.clone(),
        metrics.clone(),
    )
    .await
    .unwrap();

    tick_one_refresh().await;

    let text = rendered(&metrics).await;
    assert!(
        text.contains(r#"pillar_provider_config_refresh_total{result="error"}"#),
        "a file missing a required chain must fail the read, countably: {text}"
    );
    assert_eq!(
        app.get_available_chain_names(),
        vec!["bsc".to_string(), "ethereum".to_string()],
        "the previous configuration keeps serving, both chains included"
    );
    assert_eq!(
        providers.load().generation(),
        0,
        "nothing was published, so the URI change carried in the same file is \
         not applied either - that is the cost of the conservative policy"
    );
}

/// Publishes a new generation the first time the health probe touches the
/// network, i.e. while `/ready` is between its two reads of provider state.
/// Also fails the Ethereum endpoint, so the two generations disagree about
/// readiness and the answer says which one produced it.
#[derive(Clone)]
struct RefreshesDuringProbeTransport {
    armed: Arc<std::sync::atomic::AtomicBool>,
    serving: crate::provider_snapshot::ProviderSnapshotHandle,
    next: Arc<str>,
    fail_urls_containing: Arc<str>,
}

impl RefreshesDuringProbeTransport {
    fn publish_once(&self) {
        if !self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let candidate = self
            .serving
            .candidate(serde_json::from_str(self.next.as_ref()).unwrap());
        self.serving.publish(candidate);
    }

    fn answer(&self, url: &str) -> Result<Value, String> {
        self.publish_once();
        if url.contains(self.fail_urls_containing.as_ref()) {
            return Err("endpoint down".to_string());
        }
        Ok(json!({"result": "0x38"}))
    }
}

#[async_trait]
impl JsonRpcTransport for RefreshesDuringProbeTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        self.answer(&url)
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.answer(&url)
    }
}

/// `/ready` reads provider state twice - the health snapshot, then the chain
/// roster to ask whether any advertised chain is healthy - so it has to pin a
/// generation the way a sign request does. Without the pin a refresh landing
/// between those reads answers from one generation's health and another's chain
/// set, describing a combination that never served.
///
/// The two generations are built to disagree: generation 0 serves `bsc` (up)
/// and `ethereum` (down), so it is ready; generation 1 serves only `ethereum`,
/// so it is not. A `/ready` call that starts on generation 0 must answer for
/// generation 0.
#[tokio::test]
async fn readiness_answers_from_one_generation_when_a_refresh_lands_mid_probe() {
    const TWO_CHAINS: &str = r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1},"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1}}"#;
    const DROPS_BSC: &str = r#"{"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1}}"#;

    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let chains = ["bsc".to_string(), "ethereum".to_string()];
    let mut owner = None;
    let providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(TWO_CHAINS).unwrap(),
            Some(&chains),
        )
        .unwrap(),
        &chains,
        Some("bsc,ethereum"),
        metrics.clone(),
    )
    .await
    .unwrap();

    let transport = RefreshesDuringProbeTransport {
        armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        serving: providers.clone(),
        next: Arc::from(DROPS_BSC),
        fail_urls_containing: Arc::from("eth-rpc"),
    };

    // A clock the test moves, so the startup-warmed value can be aged out and
    // readiness has to probe.
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let now = clock.clone();

    let mut vars = runtime_vars();
    vars.insert(
        pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
        "bsc,ethereum".to_string(),
    );
    vars.insert(LZ_PROVIDER_CONFIG.to_string(), TWO_CHAINS.to_string());
    let app = RuntimeServerApp::from_env_map_with_core_dependencies(
        vars,
        transport.clone(),
        move || now.load(std::sync::atomic::Ordering::SeqCst),
        core_dependencies(),
        HashMap::from([
            ("bsc".to_string(), "EVM".to_string()),
            ("ethereum".to_string(), "EVM".to_string()),
        ]),
        RuntimeMode::Development,
        Arc::new(ProviderRankTracker::new()),
        owner,
        providers.clone(),
        metrics.clone(),
    )
    .await
    .unwrap();

    clock.store(
        pillar_core::PROVIDER_HEALTH_CACHE_STALE_MS + 1,
        std::sync::atomic::Ordering::SeqCst,
    );
    transport
        .armed
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let readiness = app.readiness().await;

    // The refresh did land - the next caller sees the narrowed roster.
    assert_eq!(providers.generation(), 1);
    assert_eq!(
        providers.load().available_chain_names(),
        ["ethereum".to_string()]
    );

    // ...and the answer just given was computed entirely from generation 0,
    // which served a healthy bsc.
    assert_eq!(
        readiness,
        pillar_api::ReadinessStatus::Ready,
        "readiness must be decided from the generation it started on"
    );
}

/// A health probe that straddles a refresh must not write its observations into
/// the process-wide provider rank.
///
/// The rank key is the URL with headers stripped, so an operator rotating the
/// credentials on an endpoint would otherwise have the failures observed under
/// the old ones recorded against the fixed one, and `plan_dispatch` would keep
/// excluding it until the entry aged out - failing requests closed for a chain
/// whose quorum then cannot be met, minutes after the configuration was fixed.
///
/// Drives the startup seed, which runs the same gate as the reprobe loop.
#[tokio::test]
async fn a_health_probe_straddling_a_refresh_does_not_rank_the_replaced_endpoints() {
    const SERVING_ONE: &str = r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#;
    const ROTATED: &str = r#"{"bsc":{"uris":["https://bsc-rpc-rotated.example"],"quorum":1}}"#;

    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let chains = ["bsc".to_string()];
    let mut owner = None;
    let providers = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            serde_json::from_str(SERVING_ONE).unwrap(),
            Some(&chains),
        )
        .unwrap(),
        &chains,
        Some("bsc"),
        metrics.clone(),
    )
    .await
    .unwrap();

    // Fails every endpoint - so a recorded observation would be Unhealthy - and
    // publishes the rotated configuration while the startup probe is running.
    let transport = RefreshesDuringProbeTransport {
        armed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        serving: providers.clone(),
        next: Arc::from(ROTATED),
        fail_urls_containing: Arc::from("bsc-rpc"),
    };

    let rank_tracker = Arc::new(ProviderRankTracker::new());
    let mut vars = runtime_vars();
    vars.insert(
        pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
        "bsc".to_string(),
    );
    vars.insert(LZ_PROVIDER_CONFIG.to_string(), SERVING_ONE.to_string());
    let _app = RuntimeServerApp::from_env_map_with_core_dependencies(
        vars,
        transport,
        || 777,
        core_dependencies(),
        HashMap::from([("bsc".to_string(), "EVM".to_string())]),
        RuntimeMode::Development,
        rank_tracker.clone(),
        owner,
        providers.clone(),
        metrics.clone(),
    )
    .await
    .unwrap();

    // The refresh did land under the probe.
    assert_eq!(providers.generation(), 1);

    // Nothing observed under the replaced configuration was recorded, so the
    // rotated endpoint starts unranked - which dispatch reads as Normal and
    // tries, instead of excluding it on evidence about different credentials.
    assert_eq!(
        rank_tracker.rank_of("bsc", "https://bsc-rpc.example").await,
        crate::provider_health::ProviderRank::Normal
    );
    assert_eq!(
        rank_tracker
            .rank_of("bsc", "https://bsc-rpc-rotated.example")
            .await,
        crate::provider_health::ProviderRank::Normal
    );
}
