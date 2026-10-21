use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

async fn bsc_app(
    transport: DelayedTransport,
    clock: Arc<AtomicU64>,
) -> RuntimeServerApp<DelayedTransport> {
    RuntimeServerApp::from_env_map(
        HashMap::from([
            (SERVER_PORT.to_string(), "3000".to_string()),
            (
                pillar_config::PILLAR_API_AUTH_TOKENS.to_string(),
                "test-token-0123456789abcdef0123456789".to_string(),
            ),
            (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
            (LZ_ENV.to_string(), "mainnet".to_string()),
            (
                pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
                "bsc".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                providers_json(r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#),
            ),
            (
                LZ_QUORUM_STRATEGY_CONFIG.to_string(),
                strategy_json(r#"{"bsc":{"uris":["https://bsc-rpc.example"],"quorum":1}}"#),
            ),
        ]),
        transport,
        move || clock.load(Ordering::SeqCst),
    )
    .await
    .unwrap()
}

/// Round 3 M-14: a caller that disconnects mid-request drops the handler future. That
/// must not cancel the probe round or leave the report uncached, or every reconnect
/// starts another fan-out to the providers the signing path shares.
#[tokio::test(start_paused = true)]
async fn round3_m14_cancelled_report_requests_cannot_restart_probe_rounds() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let app = bsc_app(
        DelayedTransport {
            calls: calls.clone(),
            delay: std::time::Duration::from_millis(500),
            response: Ok(json!({"result": "0x38"})),
        },
        clock.clone(),
    )
    .await;
    // Production startup probes and warms the cache; this test-only constructor does not.
    app.get_provider_health().await.unwrap();
    let probes = || calls.lock().unwrap().len();
    let after_startup = probes();
    let disconnect_early = || {
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            app.get_provider_health_report(),
        )
    };

    for _ in 0..5 {
        let _ = disconnect_early().await;
    }
    assert_eq!(
        probes(),
        after_startup,
        "within the TTL the startup observation is served"
    );

    let refreshed_at = 1_000 + pillar_core::PROVIDER_HEALTH_CACHE_TTL_MS + 1;
    clock.store(refreshed_at, Ordering::SeqCst);
    for _ in 0..5 {
        let _ = disconnect_early().await;
    }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(
        probes(),
        after_startup + 1,
        "five abandoned requests past the TTL share one refresh round"
    );

    let report = app.get_provider_health_report().await.unwrap();
    assert_eq!(
        report["bsc"]["checkedAtUnixMs"], refreshed_at,
        "the round started for an abandoned request still completes and is served"
    );
    assert_eq!(report["bsc"]["healthy"], true);
    assert_eq!(probes(), after_startup + 1);
}

/// Answers `eth_chainId` after 2 s for the first request and 1 s for later ones, so two
/// overlapping rounds finish in the opposite order to the one they started in.
#[derive(Clone)]
struct FirstRequestSlowest {
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl JsonRpcTransport for FirstRequestSlowest {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        let seconds = if self.requests.fetch_add(1, Ordering::SeqCst) == 0 {
            2
        } else {
            1
        };
        tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
        Ok(json!({"result": "0x38"}))
    }

    async fn get_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }
}

/// The refresh and rank loops probe independently. An older round finishing last must not
/// replace the newer report, and a report is only served for the generation it observed.
#[tokio::test(start_paused = true)]
async fn round3_m14_retained_report_keeps_the_newest_round_of_the_serving_generation() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                1,
            ),
        )]),
        None,
    )
    .unwrap();
    let clock = Arc::new(AtomicU64::new(0));
    let source = RpcProviderHealthSource::from_getter(
        &getter,
        FirstRequestSlowest {
            requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        },
        {
            let clock = clock.clone();
            move || clock.fetch_add(1, Ordering::SeqCst)
        },
    );
    let generation = pillar_core::ProviderHealthSource::configuration_generation(&source);

    let (older, newer) = tokio::join!(
        source.get_provider_health_report(),
        source.get_provider_health_report()
    );
    let older_checked_at = older.unwrap()["bsc"].checked_at_unix_ms;
    let newer_checked_at = newer.unwrap()["bsc"].checked_at_unix_ms;
    assert!(older_checked_at < newer_checked_at);

    let retained = source.retained_report(generation, 10).await.unwrap();
    assert_eq!(retained["bsc"].checked_at_unix_ms, newer_checked_at);
    assert!(source.retained_report(generation + 1, 10).await.is_none());
    assert!(source
        .retained_report(generation, 10 + pillar_core::PROVIDER_HEALTH_CACHE_STALE_MS)
        .await
        .is_none());
}
