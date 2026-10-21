use super::*;

const LEDGER_URL: &str = "https://ledger.example";
const SEQUENCER_URL: &str = "https://sequencer.example:8443/base/?sequencer-validators=0x04382c3efc88473874f6a6f2ada544e6457e6776cec7c18ac774ba27ab39cb9518b1b80981213287b59438fbceecfc05393722f901220a1f29bb47ccf7ccbe99a9,0x027bf07ae10c208725dd53e49e8d12bf23fad3e49684ef08ea61be56b2dfbc75a6,0x04566ad9ab43cc7f4f8a53f75116fefb7c0d4f4f0d6b497bec6304914c4bffb9b94e1d4bb5b743af3e086691b819b670644ec76764b3c10b37f3b9d11a974d4500&sequencer-quorum=2";
const SEQUENCER_SCAN_PREFIX: &str = "https://sequencer.example:8443/scan";
const IDP_URL: &str = "https://idp.example/token";
const POLICY_URL: &str = "https://policy.example/verify";
const TX_HASH: &str = "1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SENDER: &str = "Erin::1220";
const ETH_ENDPOINT: &str = "0x1a44076050125825900e736c501f859c50fE728c";
const ETH_RECEIVE_ULN: &str = "0xc02Ab410f0734EFa3F14628780e6e695156024C2";
const ETH_RECEIVE_VIEW: &str = "0xcc0de82D7d520d8d5897d23cf961867Bc16Fd346";
const TOKEN: &str = r#"{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}"#;
const SHORT_TOKEN: &str = r#"{"access_token":"tok-1","token_type":"Bearer","expires_in":60}"#;
const CANTON_HTTP_CONFIRMATION_FIXTURE: &str =
    include_str!("../../tests/gasolina_parity/canton_http_confirmations.json");

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenResponse {
    Available,
    Unauthorized,
    UnauthorizedAfterProbe,
}

#[derive(Clone)]
struct CantonHttpWire {
    token_response: TokenResponse,
    token_statuses: Arc<Mutex<Vec<u16>>>,
    calls: RecordedJsonCalls,
    policy_calls: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl JsonRpcTransport for CantonHttpWire {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers.clone(), body.clone()));
        if url == POLICY_URL {
            assert_eq!(
                headers.get("Authorization").map(String::as_str),
                Some("Bearer policy-token")
            );
            self.policy_calls.lock().unwrap().push(body);
            return Ok(Value::Bool(true));
        }
        if url == format!("{LEDGER_URL}/v2/updates/update-by-id") {
            assert_eq!(
                headers.get("Authorization").map(String::as_str),
                Some("Bearer tok-1")
            );
            assert_eq!(body["updateId"], TX_HASH);
            return Ok(json!({"update":{"Transaction":{"value":{
                "updateId":TX_HASH,
                "offset":42,
                "recordTime":"2026-10-21T00:00:00Z",
                "events":[{"CreatedEvent":{"createArgument":{"sender":SENDER}}}]
            }}}}));
        }
        if url == "https://eth-rpc.example" {
            return match body["method"].as_str().unwrap_or_default() {
                "eth_chainId" => Ok(json!({"result":"0x1"})),
                "eth_blockNumber" => Ok(json!({"result":"0x64"})),
                "eth_getBlockByNumber" => {
                    Ok(json!({"result":{"number":"0x64","timestamp":"0x6b49d200"}}))
                }
                "eth_call" => {
                    let data = body["params"][0]["data"].as_str().unwrap_or_default();
                    let to = body["params"][0]["to"].as_str().unwrap_or_default();
                    let selector = &data[..data.len().min(10)];
                    let expected = match selector {
                        "0x402f8468" => ETH_ENDPOINT,
                        "0x43ea4fa9" | "0x3c782a52" => ETH_RECEIVE_ULN,
                        "0x27d12cd9" => ETH_RECEIVE_VIEW,
                        other => {
                            return Err(format!(
                                "unstubbed Ethereum eth_call selector {other}: {body}"
                            ))
                        }
                    };
                    if !to.eq_ignore_ascii_case(expected) {
                        return Err(format!(
                            "Ethereum eth_call {selector} target {to}, expected {expected}"
                        ));
                    }
                    match selector {
                        "0x402f8468" => Ok(
                            json!({"result":format!("0x{:0>64}{:0>64}", ETH_RECEIVE_ULN[2..].to_lowercase(), "1")}),
                        ),
                        "0x43ea4fa9" => Ok(json!({"result":format!("0x{:0>64}", "1")})),
                        "0x3c782a52" => Ok(json!({"result":format!("0x{}", "0".repeat(128))})),
                        "0x27d12cd9" => Ok(json!({"result":format!("0x{:0>64}", "0")})),
                        _ => unreachable!(),
                    }
                }
                method => Err(format!("unstubbed Ethereum RPC method {method}: {body}")),
            };
        }
        Err(format!("unstubbed JSON POST {url}: {body}"))
    }

    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((url.clone(), headers.clone(), json!({"method":"GET"})));
        if url == format!("{LEDGER_URL}/v2/state/ledger-end") {
            if self.token_response != TokenResponse::Unauthorized {
                assert_eq!(
                    headers.get("Authorization").map(String::as_str),
                    Some("Bearer tok-1")
                );
                return Ok(json!({"offset":42}));
            }
            return Err("ledger probe unexpectedly sent a token after OAuth refusal".into());
        }
        let exchange = canton_http_confirmation_exchanges()
            .into_iter()
            .find(|exchange| url == exchange["url"].as_str().unwrap());
        if let Some(exchange) = exchange {
            assert_eq!(exchange["method"], "GET");
            assert_eq!(exchange["status"], 200);
            assert_eq!(
                headers,
                serde_json::from_value::<HashMap<String, String>>(exchange["headers"].clone())
                    .unwrap(),
                "Canton sequencer authorization must match the recorded exchange"
            );
            return Ok(exchange["response"].clone());
        }
        if url.starts_with(SEQUENCER_SCAN_PREFIX) {
            return Err(format!("unstubbed Canton sequencer URL {url}"));
        }
        Err(format!("unstubbed GET {url}"))
    }

    async fn post_form(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: String,
    ) -> Result<(u16, String), String> {
        let attempt = self.token_statuses.lock().unwrap().len();
        let (status, response) = match (self.token_response, attempt) {
            (TokenResponse::Available, 0) => (200, TOKEN.to_string()),
            (TokenResponse::Available, _) => (
                503,
                "token endpoint unavailable after first call".to_string(),
            ),
            (TokenResponse::Unauthorized, _) => (401, "unauthorized".to_string()),
            (TokenResponse::UnauthorizedAfterProbe, 0) => (200, SHORT_TOKEN.to_string()),
            (TokenResponse::UnauthorizedAfterProbe, _) => (401, "unauthorized".to_string()),
        };
        assert_eq!(url, IDP_URL);
        assert!(headers.is_empty());
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=pillar"));
        assert!(body.contains("client_secret=not-a-secret"));
        self.token_statuses.lock().unwrap().push(status);
        Ok((status, response))
    }
}

fn canton_http_env(chains: &[&str]) -> HashMap<String, String> {
    let ledger_uri = format!(
        "{LEDGER_URL}/?admin-api=admin:5002&act-as=Erin::1220&wallet-url=https://wallet.example&token-url={IDP_URL}&client-id=pillar&scope=daml_ledger_api"
    );
    let canton_provider = json!({"canton":{"uris":[ledger_uri],"quorum":1}}).to_string();
    let mut provider: Value = serde_json::from_str(&providers_json(&canton_provider)).unwrap();
    provider["entities"]
        .as_array_mut()
        .unwrap()
        .push(json!("canton-sequencer"));
    provider["chains"]["canton"]["sequencer"] = json!([{
        "uri":SEQUENCER_URL,
        "headers":{"authorization":"Bearer parity"},
        "category":"internal",
        "entity":"canton-sequencer"
    }]);
    if chains.contains(&"ethereum") {
        let ethereum =
            json!({"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1}}).to_string();
        let mut all: Value = serde_json::from_str(&providers_json(&ethereum)).unwrap();
        for (chain, entry) in provider["chains"].as_object().unwrap() {
            all["chains"][chain] = entry.clone();
        }
        let mut entities = provider["entities"].as_array().unwrap().clone();
        entities.extend(all["entities"].as_array().unwrap().iter().cloned());
        all["entities"] = Value::Array(entities);
        provider = all;
    }
    let strategies = if chains.contains(&"ethereum") {
        json!({"canton":{"uris":[ledger_uri],"quorum":1},"ethereum":{"uris":["https://eth-rpc.example"],"quorum":1}}).to_string()
    } else {
        canton_provider
    };
    let wallet_canton = config_wallet_json("wallet-canton", "CANTON", "secret-canton");
    let wallet_evm = config_wallet_json("wallet-evm", "EVM", "secret-evm");
    HashMap::from([
        (pillar_config::PILLAR_API_AUTH_TOKENS.to_string(), "test-token-0123456789abcdef0123456789".to_string()),
        (SERVER_PORT.to_string(), "3000".to_string()),
        (LZ_PROVIDER_CONFIG_TYPE.to_string(), "LOCAL".to_string()),
        (LZ_ENV.to_string(), "mainnet".to_string()),
        (LZ_PROVIDER_CONFIG.to_string(), provider.to_string()),
        (LZ_QUORUM_STRATEGY_CONFIG.to_string(), strategy_json(&strategies)),
        (pillar_config::LZ_AVAILABLE_CHAIN_NAMES.to_string(), chains.join(",")),
        (pillar_config::LZ_DEBUG_MODE.to_string(), "true".to_string()),
        (pillar_config::EXTRA_CONTEXT_REQUEST_URL.to_string(), POLICY_URL.to_string()),
        (pillar_config::EXTRA_CONTEXT_REQUEST_AUTH_TOKEN.to_string(), "policy-token".to_string()),
        (SIGNER_TYPE.to_string(), "LOCAL_MNEMONIC".to_string()),
        (pillar_config::LZ_WALLETS.to_string(), format!("[{},{}]", &wallet_canton[1..wallet_canton.len()-1], &wallet_evm[1..wallet_evm.len()-1])),
        (pillar_config::LZ_WALLET_MNEMONIC_MAPPING.to_string(), r#"{"wallet-canton-CANTON":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/501'/0'/0'"},"wallet-evm-EVM":{"mnemonic":"test test test test test test test test test test test junk","path":"m/44'/60'/0/0/0"}}"#.to_string()),
        ("CANTON_CLIENT_SECRET".to_string(), "not-a-secret".to_string()),
    ])
}
fn canton_http_confirmation_exchanges() -> Vec<Value> {
    let fixture: Value = serde_json::from_str(CANTON_HTTP_CONFIRMATION_FIXTURE).unwrap();
    fixture["exchanges"].as_array().unwrap().clone()
}

async fn assembled_app(
    token_response: TokenResponse,
    chains: &[&str],
) -> (RuntimeServerApp<CantonHttpWire>, CantonHttpWire) {
    let wire = CantonHttpWire {
        token_response,
        token_statuses: Arc::new(Mutex::new(Vec::new())),
        calls: Arc::new(Mutex::new(Vec::new())),
        policy_calls: Arc::new(Mutex::new(Vec::new())),
    };
    let app = RuntimeServerApp::from_env_map_with_runtime_core(
        canton_http_env(chains),
        wire.clone(),
        || 1_800_000_000_000,
    )
    .await
    .expect("production runtime assembly");
    (app, wire)
}

struct CantonHttp {
    address: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl CantonHttp {
    async fn open(app: RuntimeServerApp<CantonHttpWire>) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, pillar_api::router(app, "round2-canton-http"))
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            stop: Some(stop),
            task,
        }
    }
    async fn ready(&self) -> u16 {
        reqwest::Client::new()
            .get(format!("http://{}/ready", self.address))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
    async fn sign(&self, request: &PillarApiRequestV2) -> (u16, Value) {
        let response = reqwest::Client::new()
            .post(format!("http://{}/v2/resolve-and-sign", self.address))
            .bearer_auth("test-token-0123456789abcdef0123456789")
            .json(request)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.json().await.unwrap();
        (status, body)
    }
    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        (&mut self.task).await.unwrap();
    }
}
impl Drop for CantonHttp {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn canton_request() -> PillarApiRequestV2 {
    let mut request = request_v2();
    request.src_tx_hash = TX_HASH.to_string();
    request.lz_message_id = LzMessageId {
        pathway_id: PathwayId {
            src_chain_name: "canton".to_string(),
            dst_chain_name: "ethereum".to_string(),
            extra: IndexMap::from([
                ("srcEid".to_string(), json!(30_567)),
                ("dstEid".to_string(), json!(30_101)),
                (
                    "sender".to_string(),
                    json!(format!("0x{}", "c4".repeat(32))),
                ),
                (
                    "receiver".to_string(),
                    json!(format!("0x{}", "e7".repeat(20))),
                ),
            ]),
        },
        nonce: 7,
        uln_send_version: json!("V302"),
    };
    request.signing_context = SigningContext::Message {
        expiration: 1_800_001_800,
        skip_v_id: None,
        dvn_address: Some("0x4444444444444444444444444444444444444444".to_string()),
        block_confirmation: 1,
    };
    request.message_hash =
        "0xd4fd4e189132273036449fc9e11198c739161b4c0116a9a2dccdfa1c492006f1".to_string();
    request
}

#[tokio::test]
async fn round2_canton_http_sign_uses_one_shared_oauth_token() {
    let (app, wire) = assembled_app(TokenResponse::Available, &["canton", "ethereum"]).await;
    let initial_ledger_probe = {
        let calls = wire.calls.lock().unwrap();
        calls.iter().any(|(url, _, body)| {
            url == &format!("{LEDGER_URL}/v2/state/ledger-end") && body["method"] == "GET"
        })
    };
    assert!(initial_ledger_probe, "Canton must be probed before signing");
    assert_eq!(wire.token_statuses.lock().unwrap().len(), 1);
    let http = CantonHttp::open(app).await;
    assert_eq!(http.ready().await, 200);
    let (status, envelope) = http.sign(&canton_request()).await;
    assert_eq!(status, 200, "{envelope}");
    let response: pillar_core::PillarApiResponse =
        serde_json::from_value(envelope["body"].clone()).unwrap();
    assert_eq!(response.signatures.len(), 1);
    // The IdP rejects later requests to expose duplicate token caches.
    assert_eq!(
        wire.token_statuses.lock().unwrap().len(),
        1,
        "health and sender must share the cached token"
    );
    let (ledger_update_by_id, source_exchanges, policy_from, oauth_form_requests) = {
        let calls = wire.calls.lock().unwrap();
        let ledger_update_by_id = calls.iter().any(|(url, _, body)| {
            url == &format!("{LEDGER_URL}/v2/updates/update-by-id") && body["updateId"] == TX_HASH
        });
        let expected_urls = [
            "https://sequencer.example:8443/scan?type=events&emitter=0xc35194c1ae9936954bea5931c720168c376ede8af156fcc37993a2fbfdc647ac&transactionHash=1220bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&names=EndpointV2_PacketSentEvent".to_string(),
            "https://sequencer.example:8443/scan?type=events&emitter=0xc35194c1ae9936954bea5931c720168c376ede8af156fcc37993a2fbfdc647ac&from=900&to=901".to_string(),
            "https://sequencer.example:8443/scan?type=requests&id=req-900".to_string(),
        ];
        let source_exchanges = expected_urls.iter().all(|expected_url| {
            calls.iter().any(|(url, headers, body)| {
                url == expected_url
                    && headers.get("authorization").map(String::as_str) == Some("Bearer parity")
                    && body["method"] == "GET"
            })
        });
        let policy = wire.policy_calls.lock().unwrap();
        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0]["from"], SENDER);
        let statuses = wire.token_statuses.lock().unwrap();
        assert_eq!(statuses[0], 200);
        (
            ledger_update_by_id,
            source_exchanges,
            policy[0]["from"].clone(),
            statuses.len(),
        )
    };
    assert!(ledger_update_by_id);
    assert!(
        source_exchanges,
        "source resolution and confirmation exchanges must be exact"
    );
    audit_round_artifact(
        "round2-completion",
        "canton-http-shared-auth",
        json!({
            "route":"POST /v2/resolve-and-sign",
            "ready":200,
            "sign":status,
            "signatures":response.signatures.len(),
            "oauthFormRequests":oauth_form_requests,
            "ledgerEndBeforeSigning":initial_ledger_probe,
            "ledgerUpdateById":ledger_update_by_id,
            "policyFrom":policy_from,
            "tokenExpiresIn":3600
        }),
    );
    http.close().await;
}

#[tokio::test]
async fn round2_canton_http_auth_failure_is_fail_closed_and_readiness_is_chain_scoped() {
    let (app, canton_only_wire) = assembled_app(TokenResponse::Unauthorized, &["canton"]).await;
    let canton_only = CantonHttp::open(app).await;
    assert_eq!(canton_only.ready().await, 503);
    assert_eq!(canton_only_wire.token_statuses.lock().unwrap()[0], 401);
    canton_only.close().await;

    let (app, mixed_wire) =
        assembled_app(TokenResponse::Unauthorized, &["canton", "ethereum"]).await;
    let mixed = CantonHttp::open(app).await;
    assert_eq!(
        mixed.ready().await,
        200,
        "healthy Ethereum keeps a mixed-chain service ready"
    );
    let (status, envelope) = mixed.sign(&canton_request()).await;
    assert_eq!(
        status, 500,
        "unhealthy Canton must fail the sign request: {envelope}"
    );
    assert!(envelope["body"]["signatures"]
        .as_array()
        .is_none_or(Vec::is_empty));
    let policy_call_count = {
        let policy_calls = mixed_wire.policy_calls.lock().unwrap();
        assert!(policy_calls.is_empty());
        policy_calls.len()
    };
    let update_by_id_calls = {
        let calls = mixed_wire.calls.lock().unwrap();
        calls
            .iter()
            .filter(|(url, _, _)| url.ends_with("/v2/updates/update-by-id"))
            .count()
    };
    assert_eq!(update_by_id_calls, 0);
    let (initial_oauth_status, oauth_form_requests) = {
        let statuses = mixed_wire.token_statuses.lock().unwrap();
        (statuses[0], statuses.len())
    };
    assert_eq!(initial_oauth_status, 401);
    assert_eq!(oauth_form_requests, 1);
    let mixed_ethereum_healthy = {
        let calls = mixed_wire.calls.lock().unwrap();
        calls.iter().any(|(url, _, body)| {
            url == "https://eth-rpc.example" && body["method"] == "eth_chainId"
        })
    };
    audit_round_artifact(
        "round2-completion",
        "canton-http-auth-failure",
        json!({
            "route":"POST /v2/resolve-and-sign",
            "cantonOnlyReady":503,
            "mixedChainReady":200,
            "signStatus":status,
            "signatures":0,
            "policyCalls":policy_call_count,
            "updateByIdCalls":update_by_id_calls,
            "initialOAuthStatus":initial_oauth_status,
            "mixedEthereumHealthy":mixed_ethereum_healthy
        }),
    );
    mixed.close().await;
}

#[tokio::test]
async fn round2_canton_http_sender_oauth_refusal_after_a_healthy_probe_never_signs() {
    let (app, wire) = assembled_app(
        TokenResponse::UnauthorizedAfterProbe,
        &["canton", "ethereum"],
    )
    .await;
    let initial_ledger_probe = {
        let calls = wire.calls.lock().unwrap();
        calls.iter().any(|(url, _, body)| {
            url == &format!("{LEDGER_URL}/v2/state/ledger-end") && body["method"] == "GET"
        })
    };
    assert!(initial_ledger_probe);
    assert_eq!(wire.token_statuses.lock().unwrap().as_slice(), [200]);
    let http = CantonHttp::open(app).await;
    assert_eq!(http.ready().await, 200);
    let (status, envelope) = http.sign(&canton_request()).await;
    assert_eq!(status, 500, "{envelope}");
    assert!(envelope["body"]["signatures"]
        .as_array()
        .is_none_or(Vec::is_empty));
    let oauth_statuses = wire.token_statuses.lock().unwrap().clone();
    assert_eq!(oauth_statuses, [200, 401]);
    let policy_call_count = {
        let policy_calls = wire.policy_calls.lock().unwrap();
        assert!(policy_calls.is_empty());
        policy_calls.len()
    };
    let ledger_updates = {
        let calls = wire.calls.lock().unwrap();
        calls
            .iter()
            .filter(|(url, _, _)| url.ends_with("/v2/updates/update-by-id"))
            .count()
    };
    assert_eq!(ledger_updates, 0);
    audit_round_artifact(
        "round2-completion",
        "canton-http-sender-oauth-refusal",
        json!({
            "route":"POST /v2/resolve-and-sign",
            "initialLedgerEndProbe":initial_ledger_probe,
            "initialTokenExpiresIn":60,
            "oauthStatuses":oauth_statuses,
            "signStatus":status,
            "signatures":0,
            "policyCalls":policy_call_count,
            "ledgerUpdateByIdCalls":ledger_updates
        }),
    );
    http.close().await;
}
