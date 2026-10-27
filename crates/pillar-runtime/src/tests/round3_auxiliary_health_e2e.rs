use super::*;

/// Answers by URL prefix, the same for GET and POST, and fails every other URL.
#[derive(Clone)]
struct RouteTransport {
    routes: Arc<Vec<(&'static str, Result<Value, String>)>>,
}

impl RouteTransport {
    fn new(routes: Vec<(&'static str, Result<Value, String>)>) -> Self {
        Self {
            routes: Arc::new(routes),
        }
    }

    fn answer(&self, url: &str) -> Result<Value, String> {
        self.routes
            .iter()
            .find(|(prefix, _)| url.starts_with(prefix))
            .map(|(_, response)| response.clone())
            .unwrap_or_else(|| Err(format!("unexpected request {url}")))
    }
}

#[async_trait]
impl JsonRpcTransport for RouteTransport {
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

const APTOS_WITH_INDEXER: &str = "https://aptos-rpc.example/v1?event-indexer=https%3A%2F%2Fevent-indexer.example%2Fgraphql&event-indexer-api-key=event-token";
const TRON_WITH_WEB: &str =
    "https://tron-rpc.example/jsonrpc?tron-web-url=https%3A%2F%2Ftron-web.example";

async fn report(
    chain: &str,
    chain_type: &str,
    uri: &str,
    transport: RouteTransport,
) -> serde_json::Value {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(uri.to_string())], 1),
        )]),
        Some(&[chain.to_string()]),
    )
    .unwrap();
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1,
        HashMap::from([(chain.to_string(), chain_type.to_string())]),
    );
    serde_json::to_value(source.get_provider_health_report().await.unwrap()).unwrap()
}

fn entries(report: &Value, chain: &str) -> Vec<Value> {
    report[chain]["providers"].as_array().unwrap().clone()
}

/// Round 3 L-04: the indexer and TronWeb endpoints are probed for operators but never
/// read by signing. Their outage is reported as a diagnostic and does not make the
/// chain - or a pod advertising only that chain - unhealthy.
#[tokio::test]
async fn round3_l04_auxiliary_outage_is_a_diagnostic_not_chain_health() {
    for (chain, chain_type, uri, transport) in [
        (
            "aptos",
            "APTOS",
            APTOS_WITH_INDEXER,
            RouteTransport::new(vec![
                ("https://aptos-rpc.example/", Ok(json!({"chain_id": 1}))),
                (
                    "https://event-indexer.example/",
                    Err("HTTP 503".to_string()),
                ),
            ]),
        ),
        (
            "tron",
            "TRON",
            TRON_WITH_WEB,
            RouteTransport::new(vec![
                ("https://tron-rpc.example/", Ok(json!({"result": "0x10"}))),
                ("https://tron-web.example/", Err("HTTP 503".to_string())),
            ]),
        ),
    ] {
        let report = report(chain, chain_type, uri, transport).await;
        assert_eq!(report[chain]["healthy"], true, "{chain}: {report}");
        let entries = entries(&report, chain);
        assert_eq!(entries.len(), 2, "{chain}");
        let auxiliary = entries
            .iter()
            .find(|entry| entry["healthy"] == false)
            .unwrap_or_else(|| panic!("{chain}: the outage stays visible"));
        assert_eq!(auxiliary["diagnostic"], true, "{chain}: {auxiliary}");
        let primary = entries
            .iter()
            .find(|entry| entry["healthy"] == true)
            .unwrap();
        assert!(primary.get("diagnostic").is_none(), "{chain}: {primary}");
    }
}

/// Excluding the auxiliary endpoints must not hide the endpoint signing does read.
#[tokio::test]
async fn round3_l04_primary_outage_still_fails_the_chain_whatever_the_indexer_says() {
    for (chain, chain_type, uri, transport) in [
        (
            "aptos",
            "APTOS",
            APTOS_WITH_INDEXER,
            RouteTransport::new(vec![
                ("https://aptos-rpc.example/", Err("HTTP 503".to_string())),
                (
                    "https://event-indexer.example/",
                    Ok(json!({"data": {"events": [{"transaction_version": 7}]}})),
                ),
            ]),
        ),
        (
            "tron",
            "TRON",
            TRON_WITH_WEB,
            RouteTransport::new(vec![
                ("https://tron-rpc.example/", Err("HTTP 503".to_string())),
                (
                    "https://tron-web.example/",
                    Ok(json!({"block_header": {"raw_data": {"number": 16}}})),
                ),
            ]),
        ),
    ] {
        let report = report(chain, chain_type, uri, transport).await;
        assert_eq!(report[chain]["healthy"], false, "{chain}: {report}");
    }
}

#[tokio::test]
async fn round3_l04_initia_event_indexer_failure_is_diagnostic() {
    let report = report(
        "initia",
        "INITIA",
        "https://initia-rpc.example/lcd?event-indexer=https%3A%2F%2Finitia-indexer.example%2Fgraphql",
        RouteTransport::new(vec![
            (
                "https://initia-rpc.example/",
                Ok(json!({"block": {"header": {"height": "9"}}})),
            ),
            ("https://initia-indexer.example/", Err("HTTP 503".to_string())),
        ]),
    )
    .await;
    assert_eq!(report["initia"]["healthy"], true);
    let indexer = entries(&report, "initia")
        .into_iter()
        .find(|entry| entry["diagnostic"] == true)
        .unwrap();
    assert_eq!(indexer["diagnostic"], true);
}

/// A saturated JSON parser - shared with signing - must leave the Initia indexer entry
/// unattempted, as every other probe does, not fail the whole health round.
#[tokio::test]
async fn round3_l04_initia_indexer_admission_does_not_fail_the_health_round() {
    let report = report(
        "initia",
        "INITIA",
        "https://initia-rpc.example/lcd?event-indexer=https%3A%2F%2Finitia-indexer.example%2Fgraphql",
        RouteTransport::new(vec![
            (
                "https://initia-rpc.example/",
                Ok(json!({"block": {"header": {"height": "9"}}})),
            ),
            (
                "https://initia-indexer.example/",
                Err("Provider JSON parser capacity exhausted".to_string()),
            ),
        ]),
    )
    .await;
    assert_eq!(report["initia"]["healthy"], true, "{report}");
    let indexer = entries(&report, "initia")
        .into_iter()
        .find(|entry| entry["diagnostic"] == true)
        .unwrap();
    assert_eq!(
        indexer["response"]["observation"], "not_attempted",
        "{indexer}"
    );
}

async fn aptos_runtime_app(transport: RouteTransport) -> RuntimeServerApp<RouteTransport> {
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
                "aptos".to_string(),
            ),
            (
                LZ_PROVIDER_CONFIG.to_string(),
                providers_json(format!(
                    r#"{{"aptos":{{"uris":["{APTOS_WITH_INDEXER}"],"quorum":1}}}}"#
                )),
            ),
            (
                LZ_QUORUM_STRATEGY_CONFIG.to_string(),
                strategy_json(format!(
                    r#"{{"aptos":{{"uris":["{APTOS_WITH_INDEXER}"],"quorum":1}}}}"#
                )),
            ),
        ]),
        transport,
        || 1,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn round3_l04_aptos_readiness_ignores_indexer_but_not_primary_failure() {
    let indexer_down = aptos_runtime_app(RouteTransport::new(vec![
        ("https://aptos-rpc.example/", Ok(json!({"chain_id": 1}))),
        (
            "https://event-indexer.example/",
            Err("HTTP 503".to_string()),
        ),
    ]))
    .await;
    assert_eq!(
        indexer_down.readiness().await,
        pillar_api::ReadinessStatus::Ready
    );

    let primary_down = aptos_runtime_app(RouteTransport::new(vec![
        ("https://aptos-rpc.example/", Err("HTTP 503".to_string())),
        (
            "https://event-indexer.example/",
            Ok(json!({"data": {"events": [{"transaction_version": 7}]}})),
        ),
    ]))
    .await;
    assert_eq!(
        primary_down.readiness().await,
        pillar_api::ReadinessStatus::NotReady
    );
}

#[tokio::test]
async fn stalled_chain_does_not_withdraw_an_observable_healthy_chain() {
    use pillar_core::execution::{BudgetLimits, ExecutionResources, FairBudget};
    #[derive(Clone)]
    struct Transport;
    #[async_trait]
    impl JsonRpcTransport for Transport {
        async fn post_json(
            &self,
            url: String,
            _: HashMap<String, String>,
            _: Value,
        ) -> Result<Value, String> {
            if url.contains("slow") {
                return futures::future::pending().await;
            }
            Ok(json!({"result": 100}))
        }
        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            Err("unexpected GET".into())
        }
    }
    let getter = StaticProviderConfig::new(
        IndexMap::from([
            (
                "slow".into(),
                ProviderConfig::with_distinct_entities(
                    vec![
                        ProviderUri::Uri("https://slow-a".into()),
                        ProviderUri::Uri("https://slow-b".into()),
                    ],
                    1,
                ),
            ),
            (
                "healthy".into(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://healthy".into())],
                    1,
                ),
            ),
        ]),
        None,
    )
    .unwrap();
    let budget = || {
        FairBudget::new(
            vec!["background".into()],
            BudgetLimits {
                active: 2,
                per_lane: 2,
                waiting: 8,
                per_lane_waiting: 8,
                wait: std::time::Duration::from_millis(50),
            },
        )
        .unwrap()
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        Transport,
        || 1,
        HashMap::from([
            ("slow".into(), "SOLANA".into()),
            ("healthy".into(), "SOLANA".into()),
        ]),
    )
    .with_execution_resources(Arc::new(ExecutionResources {
        signing: budget(),
        rpc: budget(),
        kms: budget(),
        parser: budget(),
    }));
    let report = source.get_provider_health_report().await.unwrap();
    assert!(report["healthy"].healthy);
    assert!(report["healthy"].providers[0].observed);
    assert!(!report["slow"].healthy);
    super::round1_artifact(
        "health-chain-fairness",
        serde_json::to_value(&report).unwrap(),
    );
}
