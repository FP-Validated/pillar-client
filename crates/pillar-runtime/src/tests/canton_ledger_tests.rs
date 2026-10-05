//! The Canton ledger read behind the extra-context sender, against the published
//! `@layerzerolabs/common-canton` 1.2.66 source (`provider.ts` `parseCantonChainUri` and
//! `createTokenProvider`, `auth/client-credentials-token-provider.ts`,
//! `client/canton-client.ts:844-862,1206-1232`) and `RpcCantonSdk.getFromAddress`
//! (`rpc-sdk/src/canton/index.ts:86-111,343-360`). Synthetic: no upstream run, no ledger,
//! no identity provider; every token and secret here is a non-secret fixture.
use super::*;
use crate::layerzero_runtime::{
    canton_ledger_parties, parse_canton_chain_uri, CantonChainUri, CantonClientCredentials,
    CantonLedgerAuth, CantonOAuth2Config, CantonTokenProvider,
};

const SEQUENCER: &str = "https://sequencer.example";

type LedgerCall = (String, HashMap<String, String>, Value);

#[derive(Clone, Default)]
struct Ledger {
    /// `(url, headers, body)` of every POST.
    calls: Arc<Mutex<Vec<LedgerCall>>>,
    /// Answer per (base URL, party); a missing entry is a transport error.
    answers: Arc<HashMap<(String, String), Value>>,
    /// `(url, body)` of every form POST, and the answers given to them in order.
    form_calls: Arc<Mutex<Vec<(String, String)>>>,
    form_answers: Arc<Mutex<Vec<(u16, String)>>>,
}

#[async_trait]
impl JsonRpcTransport for Ledger {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers, body.clone()));
        let party = body["updateFormat"]["includeTransactions"]["eventFormat"]["filtersByParty"]
            .as_object()
            .and_then(|filters| filters.keys().next().cloned())
            .unwrap_or_default();
        let base = url.trim_end_matches("/v2/updates/update-by-id").to_string();
        self.answers
            .get(&(base, party))
            .cloned()
            .ok_or_else(|| format!("no ledger answer for {url}"))
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }

    async fn post_form(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: String,
    ) -> Result<(u16, String), String> {
        self.form_calls.lock().unwrap().push((url, body));
        let mut answers = self.form_answers.lock().unwrap();
        if answers.is_empty() {
            return Err("no token answer".to_string());
        }
        Ok(answers.remove(0))
    }
}

struct FixedToken(&'static str);

#[async_trait]
impl CantonTokenProvider for FixedToken {
    async fn get_token(&self) -> Result<String, AppCoreError> {
        Ok(self.0.to_string())
    }
}

const OAUTH_QUERY: &str = "&token-url=https://idp.example/token&client-id=pillar-test\
     &scope=daml_ledger_api&audience=https://ledger.example";
const TOKEN_ANSWER: &str = r#"{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}"#;

fn ledger_uri(base: &str, parties: &str) -> String {
    format!(
        "{base}/?admin-api=admin.example:5002&act-as={parties}&wallet-url=https://wallet.example"
    )
}

fn checks<T: JsonRpcTransport>(
    ledger: T,
    rpc: Vec<ProviderUri>,
    quorum: u64,
) -> RuntimeRpcValidationChecks<T> {
    let sequencer = ProviderUri::UriWithHeaders {
        uri: SEQUENCER.to_string(),
        headers: HashMap::from([("authorization".to_string(), "Bearer sequencer".to_string())]),
    };
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "canton".to_string(),
            ProviderConfig::with_distinct_entities(rpc, quorum).with_sequencer(vec![sequencer]),
        )]),
        Some(&["canton".to_string()]),
    )
    .unwrap();
    RuntimeRpcValidationChecks::from_getter(&ProviderSnapshotHandle::from_getter(&getter), ledger)
}

fn transaction(events: Value, record_time: &str) -> Value {
    json!({"update": {"Transaction": {"value": {
        "updateId": "1220abcd",
        "offset": 42,
        "recordTime": record_time,
        "events": events,
    }}}})
}

fn test_bearer(_: &str, _: &CantonChainUri) -> Result<Arc<dyn CantonTokenProvider>, AppCoreError> {
    Ok(Arc::new(FixedToken("test-bearer")))
}

#[test]
fn canton_chain_uri_is_parsed_like_common_canton() {
    let uri = parse_canton_chain_uri(
        "https://ledger.example:5975/?admin-api=a:1&user-id=u&act-as=P1::1220,%20P2::1220%20,&\
         wallet-url=https://w&token-url=https://t&client-id=c&client-secret=s&scope=x&audience=y&keep=a+b",
    )
    .unwrap();
    assert_eq!(uri.json_api_url, "https://ledger.example:5975/?keep=a+b");
    assert_eq!(uri.act_as, ["P1::1220", "P2::1220"]);

    let bare =
        parse_canton_chain_uri("https://ledger.example/json/?admin-api=a&wallet-url=w").unwrap();
    assert_eq!(bare.json_api_url, "https://ledger.example/json");
    assert!(bare.act_as.is_empty());

    for (uri, error) in [
        (
            "https://ledger.example/?admin-api=&wallet-url=w",
            "Canton provider URI missing required \"admin-api\" query parameter",
        ),
        (
            "https://ledger.example/?admin-api=a",
            "Canton provider URI missing required \"wallet-url\" query parameter",
        ),
        ("not a url", "Invalid URL"),
    ] {
        assert_eq!(parse_canton_chain_uri(uri).unwrap_err(), error, "{uri}");
    }
}

#[tokio::test]
async fn canton_sender_is_read_like_common_canton() {
    let events = json!([
        {"ArchivedEvent": {"contractId": "00a"}},
        {"CreatedEvent": {"createArgument": {"sender": ""}}},
        {"ExercisedEvent": {"choiceArgument": {"sender": "Alice::1220"}},
         "CreatedEvent": {"createArgument": {"sender": "Bob::1220"}}},
        {"CreatedEvent": {"createArgument": {"sender": "Carol::1220"}}},
    ]);
    let answers = HashMap::from([
        (
            ("https://a.example".to_string(), "P1::1220".to_string()),
            transaction(events.clone(), "t1"),
        ),
        (
            ("https://b.example".to_string(), "P1::1220".to_string()),
            transaction(events, "t1"),
        ),
    ]);
    let ledger = Ledger {
        answers: Arc::new(answers),
        ..Ledger::default()
    };
    let rpc = vec![
        ProviderUri::UriWithHeaders {
            uri: ledger_uri("https://a.example", "P1::1220"),
            headers: HashMap::from([("x-config".to_string(), "not for the ledger".to_string())]),
        },
        ProviderUri::Uri(ledger_uri("https://b.example", "P1::1220")),
    ];
    let checks = checks(ledger.clone(), rpc, 2);
    let from = checks
        .canton_transaction_from_address(&["P1::1220".to_string()], "1220abcd", test_bearer)
        .await
        .unwrap();
    assert_eq!(from, "Alice::1220");

    let expected_body = json!({
        "updateId": "1220abcd",
        "updateFormat": {"includeTransactions": {
            "eventFormat": {
                "filtersByParty": {"P1::1220": {"cumulative": [{"identifierFilter": {
                    "WildcardFilter": {"value": {"includeCreatedEventBlob": false}},
                }}]}},
                "verbose": false,
            },
            "transactionShape": "TRANSACTION_SHAPE_LEDGER_EFFECTS",
        }},
    });
    let calls = ledger.calls.lock().unwrap().clone();
    let mut urls: Vec<_> = calls.iter().map(|(url, _, _)| url.as_str()).collect();
    urls.sort();
    assert_eq!(
        urls,
        [
            "https://a.example/v2/updates/update-by-id",
            "https://b.example/v2/updates/update-by-id"
        ]
    );
    for (_, headers, body) in &calls {
        assert_eq!(
            headers,
            &HashMap::from([(
                "Authorization".to_string(),
                "Bearer test-bearer".to_string()
            )])
        );
        assert_eq!(body, &expected_body);
    }
}

#[tokio::test]
async fn canton_reads_fall_back_party_by_party() {
    let base = "https://a.example";
    let answers = HashMap::from([
        (
            (base.to_string(), "P1::1220".to_string()),
            json!({"update": {"OffsetCheckpoint": {}}}),
        ),
        (
            (base.to_string(), "P2::1220".to_string()),
            transaction(
                json!([{"CreatedEvent": {"createArgument": {"sender": "Dave::1220"}}}]),
                "t",
            ),
        ),
    ]);
    let ledger = Ledger {
        answers: Arc::new(answers),
        ..Ledger::default()
    };
    let checks = checks(
        ledger,
        vec![ProviderUri::Uri(ledger_uri(base, "P1::1220,P2::1220"))],
        1,
    );
    let parties = ["P1::1220".to_string(), "P2::1220".to_string()];
    assert_eq!(
        checks
            .canton_transaction_from_address(&parties, "1220abcd", test_bearer)
            .await
            .unwrap(),
        "Dave::1220"
    );
    let error = checks
        .canton_transaction_from_address(&parties[..1], "1220abcd", test_bearer)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("transaction-from for chain canton"),
        "{error}"
    );
}

#[tokio::test]
async fn canton_sender_edge_cases_and_quorum() {
    let base = "https://a.example";
    let read = |events: Value, record_times: [&str; 2]| {
        let answers = HashMap::from([
            (
                (base.to_string(), "P1::1220".to_string()),
                transaction(events.clone(), record_times[0]),
            ),
            (
                ("https://b.example".to_string(), "P1::1220".to_string()),
                transaction(events, record_times[1]),
            ),
        ]);
        let ledger = Ledger {
            answers: Arc::new(answers),
            ..Ledger::default()
        };
        let rpc = vec![
            ProviderUri::Uri(ledger_uri(base, "P1::1220")),
            ProviderUri::Uri(ledger_uri("https://b.example", "P1::1220")),
        ];
        async move {
            checks(ledger, rpc, 2)
                .canton_transaction_from_address(&["P1::1220".to_string()], "1220abcd", test_bearer)
                .await
        }
    };
    // Upstream answers `''` when no event names a truthy sender.
    assert_eq!(
        read(
            json!([{"CreatedEvent": {"createArgument": {"sender": 0}}}]),
            ["t", "t"]
        )
        .await
        .unwrap(),
        ""
    );
    assert_eq!(read(Value::Null, ["t", "t"]).await.unwrap(), "");
    // Stricter: upstream would return a truthy non-string sender as is.
    assert!(read(
        json!([{"ExercisedEvent": {"choiceArgument": {"sender": 7}}}]),
        ["t", "t"]
    )
    .await
    .is_err());
    // Providers that disagree on the projected recordTime do not make a quorum of two.
    assert!(read(json!([]), ["t1", "t2"]).await.is_err());
}

#[tokio::test]
async fn canton_ledger_read_refuses_without_a_token_or_with_an_unusable_base() {
    let ledger = Ledger::default();
    let config_checks = checks(
        ledger.clone(),
        vec![ProviderUri::Uri(ledger_uri(
            "https://a.example",
            "P1::1220",
        ))],
        1,
    );
    let error = config_checks
        .source_transaction_from_address("canton", "1220abcd")
        .await
        .unwrap_err();
    // Production auth with no OAuth2 configuration refuses, before any request.
    assert_eq!(
        error.to_string(),
        "Canton provider requires OAuth2 credentials (token-url, client-id, client-secret in \
         URI or CANTON_CLIENT_SECRET)"
    );
    // Stricter: a base that keeps a fragment would move the path out of the URL path.
    let fragment = checks(
        ledger.clone(),
        vec![ProviderUri::Uri(format!(
            "{}#frag",
            ledger_uri("https://a.example", "P1::1220")
        ))],
        1,
    );
    assert!(fragment
        .canton_transaction_from_address(&["P1::1220".to_string()], "1220abcd", test_bearer)
        .await
        .is_err());
    assert!(ledger.calls.lock().unwrap().is_empty());
    let config = ProviderConfig::with_distinct_entities(
        vec![ProviderUri::Uri(ledger_uri("https://a.example", ""))],
        1,
    );
    assert!(canton_ledger_parties(&config).is_empty());
}

fn oauth_credentials(ledger: &Ledger, valid: &str) -> CantonClientCredentials<Ledger> {
    ledger
        .form_answers
        .lock()
        .unwrap()
        .extend([(200, valid.to_string()), (200, valid.to_string())]);
    CantonClientCredentials::new(
        CantonOAuth2Config {
            token_url: "https://idp.example/token".to_string(),
            client_id: "pillar-test".to_string(),
            client_secret: zeroize::Zeroizing::new("not-a-secret".to_string()),
            scope: Some("daml_ledger_api".to_string()),
            audience: Some("https://ledger.example".to_string()),
        },
        ledger.clone(),
    )
}

#[tokio::test(start_paused = true)]
async fn canton_oauth2_token_is_requested_and_cached_like_common_canton() {
    let ledger = Ledger::default();
    let tokens = oauth_credentials(&ledger, TOKEN_ANSWER);
    assert_eq!(tokens.get_token().await.unwrap(), "tok-1");
    assert_eq!(tokens.get_token().await.unwrap(), "tok-1");
    assert_eq!(
        ledger.form_calls.lock().unwrap().clone(),
        [(
            "https://idp.example/token".to_string(),
            "grant_type=client_credentials&client_id=pillar-test&client_secret=not-a-secret\
             &scope=daml_ledger_api&audience=https%3A%2F%2Fledger.example"
                .to_string()
        )]
    );
    // Dropped `expires_in - 60` seconds after acquisition.
    tokio::time::advance(std::time::Duration::from_secs(3539)).await;
    tokens.get_token().await.unwrap();
    assert_eq!(ledger.form_calls.lock().unwrap().len(), 1);
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    tokens.get_token().await.unwrap();
    assert_eq!(ledger.form_calls.lock().unwrap().len(), 2);

    // A lifetime within the 60 s buffer is used once and not kept.
    let short = Ledger::default();
    let tokens = oauth_credentials(&short, r#"{"access_token":"tok-2","expires_in":30}"#);
    tokens.get_token().await.unwrap();
    tokens.get_token().await.unwrap();
    assert_eq!(short.form_calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn canton_oauth2_failures_are_not_cached() {
    let ledger = Ledger::default();
    ledger.form_answers.lock().unwrap().extend([
        (401, "denied".to_string()),
        (200, r#"{"token_type":"Bearer"}"#.to_string()),
        (200, TOKEN_ANSWER.to_string()),
    ]);
    let tokens = CantonClientCredentials::new(
        CantonOAuth2Config {
            token_url: "https://idp.example/token".to_string(),
            client_id: "pillar-test".to_string(),
            client_secret: zeroize::Zeroizing::new("not-a-secret".to_string()),
            scope: None,
            audience: None,
        },
        ledger.clone(),
    );
    assert_eq!(
        tokens.get_token().await.unwrap_err().to_string(),
        "Client credentials token request failed: 401 Unauthorized — denied"
    );
    // Stricter: upstream would send the ledger request with no token.
    assert!(tokens.get_token().await.is_err());
    assert_eq!(tokens.get_token().await.unwrap(), "tok-1");
    let calls = ledger.form_calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].1,
        "grant_type=client_credentials&client_id=pillar-test&client_secret=not-a-secret"
    );
}

#[test]
fn canton_token_provider_is_chosen_like_create_token_provider() {
    let ledger = Ledger::default();
    let base = ledger_uri("https://a.example", "P1::1220");
    let without_secret = format!("{base}{OAUTH_QUERY}");
    let uri = parse_canton_chain_uri(&without_secret).unwrap();
    let required = "Canton provider requires OAuth2 credentials (token-url, client-id, \
                    client-secret in URI or CANTON_CLIENT_SECRET)";
    let refusal = |auth: &CantonLedgerAuth, raw: &str| {
        auth.token_provider(raw, &parse_canton_chain_uri(raw).unwrap(), &ledger)
            .err()
            .map(|error| error.to_string())
    };
    assert_eq!(
        refusal(
            &CantonLedgerAuth::for_environment("mainnet", None),
            &without_secret
        )
        .as_deref(),
        Some(required)
    );
    assert_eq!(
        refusal(
            &CantonLedgerAuth::for_environment("mainnet", Some(String::new())),
            &without_secret
        )
        .as_deref(),
        Some(required)
    );
    // `searchParams.get` keeps an empty `client-secret`, so the environment is not consulted.
    let empty_secret = format!("{without_secret}&client-secret=");
    assert_eq!(
        refusal(
            &CantonLedgerAuth::for_environment("testnet", Some("not-a-secret".to_string())),
            &empty_secret
        )
        .as_deref(),
        Some(required)
    );
    // Sandbox and localnet would self-sign an admin JWT upstream; never enabled here.
    for environment in ["sandbox", "localnet"] {
        let auth = CantonLedgerAuth::for_environment(environment, Some("not-a-secret".to_string()));
        assert_eq!(
            refusal(
                &auth,
                &format!("{without_secret}&client-secret=not-a-secret")
            )
            .as_deref(),
            Some("Canton sandbox/localnet ledger auth (a self-signed admin JWT) is not enabled")
        );
    }
    let auth = CantonLedgerAuth::for_environment("mainnet", Some("not-a-secret".to_string()));
    let first = auth.token_provider(&without_secret, &uri, &ledger).unwrap();
    let again = auth.token_provider(&without_secret, &uri, &ledger).unwrap();
    assert!(
        Arc::ptr_eq(&first, &again),
        "one token provider per rpc entry"
    );
    assert!(
        ledger.form_calls.lock().unwrap().is_empty(),
        "built lazily, no request yet"
    );

    let with_secret =
        parse_canton_chain_uri(&format!("{without_secret}&client-secret=not-a-secret")).unwrap();
    assert!(!format!("{with_secret:?}{auth:?}").contains("not-a-secret"));
}

#[tokio::test]
async fn canton_sender_is_read_with_an_oauth2_token_through_the_production_path() {
    let base = "https://a.example";
    let answers = HashMap::from([(
        (base.to_string(), "P1::1220".to_string()),
        transaction(
            json!([{"CreatedEvent": {"createArgument": {"sender": "Erin::1220"}}}]),
            "t",
        ),
    )]);
    let ledger = Ledger {
        answers: Arc::new(answers),
        ..Ledger::default()
    };
    ledger
        .form_answers
        .lock()
        .unwrap()
        .push((200, TOKEN_ANSWER.to_string()));
    let rpc = vec![ProviderUri::Uri(format!(
        "{}{OAUTH_QUERY}",
        ledger_uri(base, "P1::1220")
    ))];
    let checks = checks(ledger.clone(), rpc, 1).with_canton_ledger_auth(
        CantonLedgerAuth::for_environment("mainnet", Some("not-a-secret".to_string())),
    );
    for _ in 0..2 {
        assert_eq!(
            checks
                .source_transaction_from_address("canton", "1220abcd")
                .await
                .unwrap(),
            "Erin::1220"
        );
    }
    assert_eq!(ledger.form_calls.lock().unwrap().len(), 1, "token reused");
    let calls = ledger.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    for (url, headers, _) in calls {
        assert_eq!(url, "https://a.example/v2/updates/update-by-id");
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer tok-1")
        );
    }
}

/// The real JSON Ledger API behind a synthetic identity provider: every token request is
/// answered locally, every ledger request goes to the network and is recorded.
#[derive(Clone)]
struct LiveLedger {
    inner: ReqwestJsonRpcTransport,
    log: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl JsonRpcTransport for LiveLedger {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let result = self
            .inner
            .post_json(url.clone(), headers.clone(), body.clone())
            .await;
        self.log.lock().unwrap().push(json!({
            "url": url,
            "authorization": headers.get("Authorization"),
            "request": body,
            "response": result.as_ref().ok(),
            "error": result.as_ref().err(),
        }));
        result
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected GET {url}"))
    }

    async fn post_form(
        &self,
        url: String,
        _: HashMap<String, String>,
        _: String,
    ) -> Result<(u16, String), String> {
        self.log.lock().unwrap().push(json!({"tokenUrl": url}));
        Ok((200, LIVE_TOKEN_ANSWER.to_string()))
    }
}

const LIVE_TOKEN_ANSWER: &str =
    r#"{"access_token":"synthetic-live-token","token_type":"Bearer","expires_in":3600}"#;

/// E2E against an unauthenticated, operator-scoped test Canton ledger, reached through a
/// port-forward. `PILLAR_CANTON_LIVE_CASES` is `[{"updateId": .., "sender": ..}]`, recorded when
/// the probe contracts were submitted; the artifact holds every ledger exchange.
#[tokio::test]
#[ignore = "Requires a scoped test Canton ledger (PILLAR_CANTON_LIVE_*)"]
async fn canton_sender_is_read_from_a_live_ledger_through_the_production_path() {
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    let base = env("PILLAR_CANTON_LIVE_JSON_API");
    let party = env("PILLAR_CANTON_LIVE_PARTY");
    let cases: Vec<Value> = serde_json::from_str(&env("PILLAR_CANTON_LIVE_CASES")).unwrap();
    let artifact = std::path::PathBuf::from(env("PILLAR_CANTON_LIVE_ARTIFACT"));
    assert!(!artifact.exists(), "artifacts are never overwritten");
    let ledger = LiveLedger {
        inner: ReqwestJsonRpcTransport::new().unwrap(),
        log: Arc::default(),
    };
    let rpc = vec![ProviderUri::Uri(format!(
        "{}{OAUTH_QUERY}",
        ledger_uri(base.trim_end_matches('/'), &party)
    ))];
    let checks = checks(ledger.clone(), rpc, 1).with_canton_ledger_auth(
        CantonLedgerAuth::for_environment("testnet", Some("not-a-secret".to_string())),
    );
    let mut outcomes = Vec::new();
    for case in &cases {
        let update_id = case["updateId"].as_str().unwrap();
        let result = checks
            .source_transaction_from_address("canton", update_id)
            .await;
        outcomes.push(json!({
            "updateId": update_id,
            "expected": case["sender"],
            "sender": result.as_ref().ok(),
            "error": result.as_ref().err().map(ToString::to_string),
        }));
    }
    let unknown = checks
        .source_transaction_from_address(
            "canton",
            "1220ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        .await;
    let record = json!({
        "jsonApi": base,
        "party": party,
        "outcomes": outcomes,
        "unknownUpdate": unknown.as_ref().err().map(ToString::to_string),
        "exchanges": ledger.log.lock().unwrap().clone(),
    });
    std::fs::write(&artifact, serde_json::to_vec_pretty(&record).unwrap()).unwrap();

    assert!(!cases.is_empty());
    for outcome in &outcomes {
        assert_eq!(outcome["sender"], outcome["expected"], "{outcome}");
    }
    assert!(unknown.is_err(), "{unknown:?}");
    let exchanges = ledger.log.lock().unwrap().clone();
    assert_eq!(
        exchanges
            .iter()
            .filter(|e| e.get("tokenUrl").is_some())
            .count(),
        1,
        "one cached synthetic token"
    );
    for exchange in exchanges.iter().filter(|e| e.get("url").is_some()) {
        assert_eq!(exchange["authorization"], "Bearer synthetic-live-token");
    }
}
