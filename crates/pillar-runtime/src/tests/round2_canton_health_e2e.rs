//! Round 2 M-08: Canton's ledger is probed at startup through the production composition,
//! so a working ledger serves readiness and its sender read, and a failing one fails closed.
use super::*;
use tower::ServiceExt;

const LEDGER: &str = "https://ledger.example";
const TOKEN_URL: &str = "https://idp.example/token";
const OAUTH: &str = "&token-url=https://idp.example/token&client-id=pillar";
#[derive(Clone, Copy, Debug, PartialEq)]
enum Ledger {
    Healthy,
    EndOffsetUnavailable,
    TokenRefused,
    TokenOnlyOnce,
    OffsetNotNumeric,
}

#[derive(Clone)]
struct CantonWire {
    ledger: Ledger,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl JsonRpcTransport for CantonWire {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(format!("POST {url}"));
        if url != format!("{LEDGER}/v2/updates/update-by-id") {
            return Err(format!("unexpected POST {url}"));
        }
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer tok-1")
        );
        assert_eq!(body["updateId"], "1220abcd");
        Ok(json!({"update": {"Transaction": {"value": {
            "updateId": "1220abcd",
            "offset": 42,
            "recordTime": "t",
            "events": [{"CreatedEvent": {"createArgument": {"sender": "Erin::1220"}}}],
        }}}}))
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(format!("GET {url}"));
        if url != format!("{LEDGER}/v2/state/ledger-end") {
            return Err(format!("unexpected GET {url}"));
        }
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer tok-1")
        );
        match self.ledger {
            Ledger::EndOffsetUnavailable => {
                Err("Provider returned HTTP 503 Service Unavailable".to_string())
            }
            Ledger::OffsetNotNumeric => Ok(json!({"offset": "42"})),
            Ledger::Healthy | Ledger::TokenRefused | Ledger::TokenOnlyOnce => {
                Ok(json!({"offset": 42}))
            }
        }
    }

    async fn post_form(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: String,
    ) -> Result<(u16, String), String> {
        let mut calls = self.calls.lock().unwrap();
        let form_count = calls
            .iter()
            .filter(|call| call.starts_with("FORM "))
            .count();
        calls.push(format!("FORM {url}"));
        drop(calls);
        assert_eq!(url, TOKEN_URL);
        Ok(match self.ledger {
            Ledger::TokenRefused => (401, r#"{"error":"invalid_client"}"#.to_string()),
            Ledger::TokenOnlyOnce if form_count > 0 => {
                (503, r#"{"error":"temporarily_unavailable"}"#.to_string())
            }
            _ => (
                200,
                r#"{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}"#.to_string(),
            ),
        })
    }
}

fn ledger_uri(oauth: &str) -> String {
    format!(
        "{LEDGER}/?admin-api=admin:5002&act-as=P1::1220&wallet-url=https://wallet.example{oauth}"
    )
}

struct Outcome {
    http_ready: u16,
    provider_health: Value,
    report: Value,
    rank: String,
    sender: Result<String, String>,
    calls: Vec<String>,
}

async fn canton_only(ledger: Ledger, oauth: &str) -> Outcome {
    let uri = ledger_uri(oauth);
    let fixture = json!({"canton": {"uris": [uri], "quorum": 1}}).to_string();
    let mut providers: Value = serde_json::from_str(&providers_json(&fixture)).unwrap();
    providers["entities"]
        .as_array_mut()
        .unwrap()
        .push(json!("canton-sequencer"));
    providers["chains"]["canton"]["sequencer"] = json!([{
        "uri": "https://sequencer.example/?sequencer-validators=0x027bf07ae10c208725dd53e49e8d12bf23fad3e49684ef08ea61be56b2dfbc75a6&sequencer-quorum=1",
        "headers": {"authorization": "Bearer sequencer"},
        "category": "internal",
        "entity": "canton-sequencer",
    }]);
    let chains = ["canton".to_string()];
    let metrics = Arc::new(tokio::sync::Mutex::new(PillarMetrics::new()));
    let mut owner = None;
    let snapshot = crate::server_app::serving_provider_snapshot(
        &mut owner,
        &pillar_config::StaticProviderConfig::new(
            pillar_config::provider_validation::provider_configs_from_v2(
                &providers.to_string(),
                &strategy_json(&fixture),
            )
            .unwrap(),
            Some(&chains),
        )
        .unwrap(),
        &chains,
        Some("canton"),
        metrics.clone(),
    )
    .await
    .unwrap();
    let wire = CantonWire {
        ledger,
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    let mut vars = runtime_vars();
    vars.extend([
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(),
            "canton".to_string(),
        ),
        (LZ_PROVIDER_CONFIG.to_string(), providers.to_string()),
        (LZ_QUORUM_STRATEGY_CONFIG.to_string(), strategy_json(&fixture)),
        (
            pillar_config::LZ_WALLETS.to_string(),
            config_wallet_json("wallet-a", "CANTON", "secret-a"),
        ),
        (
            pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(),
            r#"{"wallet-a-CANTON":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/60'/0'/0/0"}}"#.to_string(),
        ),
    ]);
    if !oauth.is_empty() {
        vars.insert(
            "CANTON_CLIENT_SECRET".to_string(),
            "not-a-secret".to_string(),
        );
    }
    let canton_ledger_auth = CantonLedgerAuth::from_env_map("mainnet", &vars);
    let rank_tracker = Arc::new(ProviderRankTracker::new());
    let app = RuntimeServerApp::from_env_map_with_core_dependencies(
        vars,
        wire.clone(),
        || 1,
        canton_ledger_auth.clone(),
        core_dependencies(),
        pillar_config::static_chain_type_by_chain_name(&chains).unwrap(),
        RuntimeMode::Development,
        rank_tracker.clone(),
        owner,
        snapshot.clone(),
        metrics,
    )
    .await
    .unwrap();
    let report = pillar_api::ServerApp::get_provider_health_report(&app)
        .await
        .unwrap();
    let provider_health = serde_json::to_value(app.get_provider_health().await.unwrap()).unwrap();
    let rank = format!("{:?}", rank_tracker.rank_of("canton", &uri).await);
    let http_ready = pillar_api::router(app, "round2-canton")
        .oneshot(
            axum::http::Request::builder()
                .uri("/ready")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
        .as_u16();
    // The sender read shares the tracker the startup probe seeded.
    let sender = RuntimeRpcValidationChecks::from_getter(&snapshot, wire.clone())
        .with_canton_ledger_auth(canton_ledger_auth)
        .with_rank_tracker(rank_tracker)
        .source_transaction_from_address("canton", "1220abcd")
        .await
        .map_err(|error| error.to_string());
    let calls = wire.calls.lock().unwrap().clone();
    Outcome {
        http_ready,
        provider_health,
        report,
        rank,
        sender,
        calls,
    }
}

#[tokio::test]
async fn round2_m08_canton_ledger_is_probed_and_fails_closed() {
    let mut observations = Vec::new();
    for (label, ledger, oauth) in [
        ("healthy", Ledger::Healthy, OAUTH),
        ("health-token-cache-shared", Ledger::TokenOnlyOnce, OAUTH),
        ("ledger-end-503", Ledger::EndOffsetUnavailable, OAUTH),
        ("token-401", Ledger::TokenRefused, OAUTH),
        ("offset-not-numeric", Ledger::OffsetNotNumeric, OAUTH),
        ("oauth-not-configured", Ledger::Healthy, ""),
    ] {
        let outcome = canton_only(ledger, oauth).await;
        let entries = &outcome.report["canton"]["providers"];
        observations.push(json!({
            "case": label,
            "http_ready": outcome.http_ready,
            "provider_health": outcome.provider_health,
            "report_entries": entries,
            "seeded_rank": outcome.rank,
            "sender": format!("{:?}", outcome.sender),
            "wire": outcome.calls,
        }));
        let reported = entries[0]["response"].to_string();
        assert!(
            !reported.contains("No provider health probe is registered"),
            "{label}: {reported}"
        );
        assert!(
            !outcome.report.to_string().contains("not-a-secret"),
            "{label}"
        );
        if matches!(label, "healthy" | "health-token-cache-shared") {
            assert_eq!(outcome.http_ready, 200, "{label}");
            assert_eq!(outcome.provider_health, json!({"canton": true}), "{label}");
            assert_eq!(entries[0]["response"], 42, "{label}");
            assert_eq!(outcome.rank, "Normal", "{label}");
            assert_eq!(outcome.sender, Ok("Erin::1220".to_string()), "{label}");
            assert!(outcome
                .calls
                .iter()
                .any(|call| call == &format!("GET {LEDGER}/v2/state/ledger-end")));
            if label == "health-token-cache-shared" {
                assert_eq!(
                    outcome
                        .calls
                        .iter()
                        .filter(|call| call.starts_with("FORM "))
                        .count(),
                    1,
                    "{label}: health and sender must share the token cache"
                );
            }
        } else {
            assert_eq!(outcome.http_ready, 503, "{label}");
            assert_eq!(outcome.provider_health, json!({"canton": false}), "{label}");
            assert_eq!(outcome.rank, "Unhealthy", "{label}");
            assert!(
                outcome
                    .sender
                    .as_ref()
                    .is_err_and(|error| error.contains("Not enough healthy providers")),
                "{label}: {:?}",
                outcome.sender
            );
            assert!(
                !outcome
                    .calls
                    .iter()
                    .any(|call| call.ends_with("/v2/updates/update-by-id")),
                "{label}: the ledger was read for a sender after it was found unhealthy"
            );
        }
    }
    audit_round_artifact(
        "round2",
        "m08-canton-ledger-health",
        json!({ "cases": observations }),
    );
}

/// A Canton probe that cannot authenticate leaves the rest of the report intact.
#[tokio::test]
async fn round2_m08_canton_failure_does_not_fail_other_chains() {
    #[derive(Clone)]
    struct Mixed(CantonWire);
    #[async_trait]
    impl JsonRpcTransport for Mixed {
        async fn post_json(
            &self,
            url: String,
            headers: HashMap<String, String>,
            body: Value,
        ) -> Result<Value, String> {
            if url.starts_with("https://eth-rpc.example") {
                return Ok(json!({"result": "0x1"}));
            }
            self.0.post_json(url, headers, body).await
        }
        async fn get_json(
            &self,
            url: String,
            headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            self.0.get_json(url, headers).await
        }
    }
    let chains = ["ethereum".to_string(), "canton".to_string()];
    let getter = StaticProviderConfig::new(
        IndexMap::from([
            (
                "ethereum".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri("https://eth-rpc.example".to_string())],
                    1,
                ),
            ),
            (
                "canton".to_string(),
                ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(ledger_uri(""))], 1)
                    .with_sequencer(vec![ProviderUri::Uri(
                        "https://sequencer.example/?sequencer-validators=0x027bf07ae10c208725dd53e49e8d12bf23fad3e49684ef08ea61be56b2dfbc75a6&sequencer-quorum=1".to_string(),
                    )]),
            ),
        ]),
        Some(&chains),
    )
    .unwrap();
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        Mixed(CantonWire {
            ledger: Ledger::Healthy,
            calls: Arc::new(Mutex::new(Vec::new())),
        }),
        || 1,
        pillar_config::static_chain_type_by_chain_name(&chains).unwrap(),
    )
    .with_canton_ledger_auth(CantonLedgerAuth::for_environment("mainnet", None));
    let report = source.get_provider_health_report().await.unwrap();
    assert!(report["ethereum"].healthy);
    assert!(!report["canton"].healthy);
    assert!(report["canton"].providers[0]
        .response
        .to_string()
        .contains("OAuth2"));
}
