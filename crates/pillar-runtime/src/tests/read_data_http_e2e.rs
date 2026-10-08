use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug)]
enum HttpBehavior {
    Chain(ReadChain),
    Revert,
    RevertEmpty,
    RevertUpperData,
    RevertDifferentData,
    RevertMalformed,
    RevertWrongType,
    StandardRevert,
    MisleadingError,
    MethodNotFoundRevertMessage,
    TimeoutRevertMessage,
    MissingCodeRevertMessage,
    StringCodeRevertMessage,
    NullCodeRevertMessage,
    Timeout,
    Disconnect,
}

#[derive(Clone)]
struct HttpFixtureState {
    receipt: Value,
    chains_by_path: HashMap<String, ReadChain>,
    behaviors_by_path: HashMap<String, HttpBehavior>,
    wire_requests: Arc<parking_lot::Mutex<Vec<CapturedHttpRequest>>>,
    failures: Arc<parking_lot::Mutex<Vec<String>>>,
}

struct CapturedHttpRequest {
    path: String,
    headers: HashMap<String, String>,
    body: Value,
}

struct HttpRequest {
    path: String,
    headers: HashMap<String, String>,
    body: Value,
}

#[derive(Debug)]
struct CaseResult {
    status: u16,
    body: Value,
    raw_body: String,
    response_headers: HashMap<String, String>,
    wire_requests: Vec<Value>,
    signed: bool,
    signatures: Vec<Signature>,
    sign_stage_observation_count: u64,
    read_call_count: usize,
    read_code_count: usize,
    pinned_provider_pairs: bool,
}
#[derive(Clone, Debug, serde::Serialize)]
struct StageObservation {
    stage: String,
    src_chain: String,
    dst_chain: String,
    status: String,
    count: u64,
}

fn parse_stage_observations(rendered: &str) -> Vec<StageObservation> {
    const METRIC_PREFIX: &str = "pillar_sign_stage_duration_seconds_count";
    rendered
        .lines()
        .filter(|line| line.starts_with(METRIC_PREFIX))
        .map(|line| {
            let labels_and_count = line
                .strip_prefix(METRIC_PREFIX)
                .expect("matching stage metric prefix");
            let labels_and_count = labels_and_count
                .strip_prefix('{')
                .expect("matching stage metric must have labels");
            let (labels, count) = labels_and_count
                .split_once("} ")
                .expect("matching stage metric must have labels and a numeric count");
            let count = count
                .parse()
                .expect("matching stage metric count must be an unsigned number");
            let mut stage = None;
            let mut src_chain = None;
            let mut dst_chain = None;
            let mut status = None;
            for label in labels.split(',') {
                let (name, value) = label
                    .split_once('=')
                    .expect("matching stage metric label must contain a value");
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .expect("matching stage metric label value must be quoted");
                match name {
                    "stage" => assert!(
                        stage.replace(value.to_owned()).is_none(),
                        "duplicate stage label"
                    ),
                    "src_chain" => assert!(
                        src_chain.replace(value.to_owned()).is_none(),
                        "duplicate src_chain label"
                    ),
                    "dst_chain" => assert!(
                        dst_chain.replace(value.to_owned()).is_none(),
                        "duplicate dst_chain label"
                    ),
                    "status" => assert!(
                        status.replace(value.to_owned()).is_none(),
                        "duplicate status label"
                    ),
                    _ => panic!("unexpected matching stage metric label {name:?}"),
                }
            }
            StageObservation {
                stage: stage.expect("matching stage metric is missing stage label"),
                src_chain: src_chain.expect("matching stage metric is missing src_chain label"),
                dst_chain: dst_chain.expect("matching stage metric is missing dst_chain label"),
                status: status.expect("matching stage metric is missing status label"),
                count,
            }
        })
        .collect()
}

fn stage_observation_count(
    observations: &[StageObservation],
    stage: &str,
    src_chain: &str,
    dst_chain: &str,
    status: &str,
) -> u64 {
    observations
        .iter()
        .find(|observation| {
            observation.stage == stage
                && observation.src_chain == src_chain
                && observation.dst_chain == dst_chain
                && observation.status == status
        })
        .map_or(0, |observation| observation.count)
}

fn http_provider_env(
    ethereum_url: &str,
    bsc_urls: &[String],
    quorum: usize,
) -> HashMap<String, String> {
    let mut env = read_vertical_env_map();
    let provider_config = json!({
        "ethereum": {"uris": [ethereum_url], "quorum": 1},
        "bsc": {"uris": bsc_urls.iter().map(|uri| json!({"uri": uri, "headers": {"x-read-provider": uri}})).collect::<Vec<_>>(), "quorum": quorum},
    })
    .to_string();
    env.insert(
        LZ_PROVIDER_CONFIG.to_string(),
        providers_json(provider_config.clone()),
    );
    env.insert(
        LZ_QUORUM_STRATEGY_CONFIG.to_string(),
        strategy_json(provider_config),
    );
    env
}

async fn read_http_request(stream: TcpStream) -> Result<(TcpStream, HttpRequest), String> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .map_err(|error| error.to_string())?;
    let mut request_line_parts = request_line.split_whitespace();
    let method = request_line_parts.next().unwrap_or_default();
    let path = request_line_parts.next().unwrap_or_default();
    if method != "POST" || path.is_empty() {
        return Err(format!("unexpected HTTP request line {request_line:?}"));
    }

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|error| error.to_string())?;
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed HTTP header {line:?}"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
    }

    let content_length = headers
        .get("content-length")
        .ok_or_else(|| "JSON-RPC POST omitted Content-Length".to_string())?
        .parse::<usize>()
        .map_err(|error| format!("invalid Content-Length: {error}"))?;
    let mut body_bytes = vec![0; content_length];
    reader
        .read_exact(&mut body_bytes)
        .await
        .map_err(|error| error.to_string())?;
    let body = serde_json::from_slice(&body_bytes).map_err(|error| error.to_string())?;
    Ok((
        reader.into_inner(),
        HttpRequest {
            path: path.to_string(),
            headers,
            body,
        },
    ))
}

async fn respond_json(stream: &mut TcpStream, body: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&body)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())
}

async fn serve_one(stream: TcpStream, state: &HttpFixtureState) -> Result<(), String> {
    let (mut stream, request) = read_http_request(stream).await?;
    state.wire_requests.lock().push(CapturedHttpRequest {
        path: request.path.clone(),
        headers: request.headers.clone(),
        body: request.body.clone(),
    });
    if request.body["method"] == "eth_call" && request.body["params"][0]["to"] == READ_TARGET {
        let error = match state.behaviors_by_path.get(&request.path) {
            Some(HttpBehavior::Revert) => {
                Some(json!({"code": 3, "message": "VM execution error", "data": "0xabcd"}))
            }
            Some(HttpBehavior::RevertEmpty) => {
                Some(json!({"code": 3, "message": "execution reverted", "data": "0x"}))
            }
            Some(HttpBehavior::RevertUpperData) => {
                Some(json!({"code": 3, "message": "execution reverted", "data": "0xABCD"}))
            }
            Some(HttpBehavior::RevertDifferentData) => {
                Some(json!({"code": 3, "message": "execution reverted", "data": "0xabce"}))
            }
            Some(HttpBehavior::RevertMalformed) => {
                Some(json!({"code": 3, "message": "execution reverted", "data": "0x0"}))
            }
            Some(HttpBehavior::RevertWrongType) => {
                Some(json!({"code": 3, "message": "execution reverted", "data": 7}))
            }
            Some(HttpBehavior::StandardRevert) => {
                Some(json!({"code": -32000, "message": "execution reverted"}))
            }
            Some(HttpBehavior::MisleadingError) => Some(
                json!({"code": -32000, "message": "upstream timeout: execution reverted is unavailable"}),
            ),
            Some(HttpBehavior::MethodNotFoundRevertMessage) => {
                Some(json!({"code": -32601, "message": "execution reverted"}))
            }
            Some(HttpBehavior::TimeoutRevertMessage) => {
                Some(json!({"code": -32002, "message": "execution reverted"}))
            }
            Some(HttpBehavior::MissingCodeRevertMessage) => {
                Some(json!({"message": "execution reverted"}))
            }
            Some(HttpBehavior::StringCodeRevertMessage) => {
                Some(json!({"code": "-32000", "message": "execution reverted"}))
            }
            Some(HttpBehavior::NullCodeRevertMessage) => {
                Some(json!({"code": null, "message": "execution reverted"}))
            }
            Some(HttpBehavior::Timeout) => {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                return Ok(());
            }
            Some(HttpBehavior::Disconnect) => return Ok(()),
            _ => None,
        };
        if let Some(error) = error {
            return respond_json(
                &mut stream,
                &json!({"jsonrpc": "2.0", "id": request.body["id"], "error": error}),
            )
            .await;
        }
    }
    let chain = state
        .chains_by_path
        .get(&request.path)
        .copied()
        .ok_or_else(|| format!("unconfigured provider path {}", request.path))?;
    let url = format!("http://fixture{}", request.path);
    let provider = ReadVerticalTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        receipt: state.receipt.clone(),
        chain,
    };
    let response = match provider
        .post_json(url, request.headers, request.body.clone())
        .await
    {
        Ok(response) => response,
        Err(error) => {
            state.failures.lock().push(error.clone());
            json!({
                "jsonrpc": "2.0",
                "id": request.body["id"],
                "error": {"code": -32000, "message": error},
            })
        }
    };
    respond_json(&mut stream, &response).await
}

async fn serve_http_fixture(
    listener: TcpListener,
    state: HttpFixtureState,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return;
            },
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        connections.spawn(async move {
                            if let Err(error) = serve_one(stream, &state).await {
                                state.failures.lock().push(error);
                            }
                        });
                    }
                    Err(error) => state.failures.lock().push(error.to_string()),
                }
            }
        }
    }
}
fn is_read_target_request(request: &CapturedHttpRequest) -> bool {
    request.path.starts_with("/bsc-rpc-")
        && match request.body["method"].as_str() {
            Some("eth_call") => request.body["params"][0]["to"] == READ_TARGET,
            Some("eth_getCode") => request.body["params"][0] == READ_TARGET,
            _ => false,
        }
}

async fn run_full_consumer_case(
    behaviors: &[HttpBehavior],
    quorum: usize,
    same_entity: bool,
) -> (CaseResult, Vec<StageObservation>) {
    let bsc_chains = behaviors
        .iter()
        .map(|behavior| match behavior {
            HttpBehavior::Chain(chain) => *chain,
            _ => ReadChain::EmptyCallCodeZero,
        })
        .collect::<Vec<_>>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local JSON-RPC endpoint");
    let address = listener.local_addr().expect("local JSON-RPC address");
    let ethereum_path = "/eth-rpc";
    let ethereum_url = format!("http://{address}{ethereum_path}");
    let bsc_paths = (0..bsc_chains.len())
        .map(|index| format!("/bsc-rpc-{}", (b'a' + index as u8) as char))
        .collect::<Vec<_>>();
    let bsc_urls = bsc_paths
        .iter()
        .map(|path| format!("http://{address}{path}"))
        .collect::<Vec<_>>();

    let wire_requests = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let failures = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let chains_by_path = std::iter::once((ethereum_path.to_string(), ReadChain::Stable))
        .chain(bsc_paths.iter().cloned().zip(bsc_chains.iter().copied()))
        .collect();
    let state = HttpFixtureState {
        receipt: read_vertical_receipt(ReadMarker::BlockNumber),
        chains_by_path,
        behaviors_by_path: bsc_paths
            .iter()
            .cloned()
            .zip(behaviors.iter().copied())
            .collect(),
        wire_requests: wire_requests.clone(),
        failures: failures.clone(),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_http_fixture(listener, state, shutdown_rx));

    let transport = ReqwestJsonRpcTransport::new().expect("production Reqwest transport");
    let mut variables = http_provider_env(&ethereum_url, &bsc_urls, quorum);
    if same_entity {
        let mut providers: Value = serde_json::from_str(&variables[LZ_PROVIDER_CONFIG]).unwrap();
        providers["chains"]["bsc"]["rpc"][1]["entity"] = json!("bsc-0");
        variables.insert(LZ_PROVIDER_CONFIG.to_string(), providers.to_string());
    }
    let app = RuntimeServerApp::from_env_map_with_runtime_core(variables, transport, || {
        1_767_323_045_000
    })
    .await
    .unwrap_or_else(|error| panic!("production READ HTTP app did not assemble: {error}"));
    let metrics = app.metrics().expect("production metrics registry");
    let inbound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound_address = inbound.local_addr().unwrap();
    let router = pillar_api::router(app, "read-domain-e2e");
    let api = tokio::spawn(async move { axum::serve(inbound, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{inbound_address}/v2/resolve-and-sign"))
        .bearer_auth("test-token-0123456789abcdef0123456789")
        .json(&read_vertical_request(ReadMarker::BlockNumber))
        .send()
        .await
        .expect("actual inbound HTTP response");
    let status = response.status().as_u16();
    let response_headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_string()))
        .collect();
    let raw_body = response.text().await.expect("raw HTTP response body");
    let body: Value = serde_json::from_str(&raw_body).expect("HTTP JSON envelope");
    let rendered = metrics
        .lock()
        .await
        .render_prometheus("mainnet", "read-domain-e2e");
    let stages = parse_stage_observations(&rendered);
    api.abort();
    let _ = api.await;
    let _ = shutdown_tx.send(());
    server.await.expect("local JSON-RPC server joined");

    let requests = wire_requests.lock();
    let bsc_read_calls = requests
        .iter()
        .filter(|request| is_read_target_request(request) && request.body["method"] == "eth_call")
        .count();
    let bsc_read_code_calls = requests
        .iter()
        .filter(|request| {
            is_read_target_request(request) && request.body["method"] == "eth_getCode"
        })
        .count();
    let mut complete_provider_pairs = 0;
    let mut pinned_provider_pairs = true;
    for (index, path) in bsc_paths.iter().enumerate() {
        let mut provider_requests = requests
            .iter()
            .filter(|request| request.path == *path && is_read_target_request(request))
            .collect::<Vec<_>>();
        if provider_requests.is_empty() || provider_requests.len() == 1 {
            continue;
        }
        provider_requests.sort_by_key(|request| request.body["method"] == "eth_getCode");
        if provider_requests.len() != 2 {
            pinned_provider_pairs = false;
            continue;
        }
        complete_provider_pairs += 1;
        pinned_provider_pairs &= provider_requests[0].headers.len()
            == provider_requests[1].headers.len()
            && provider_requests[0].headers.iter().all(|(name, value)| {
                name == "content-length" || provider_requests[1].headers.get(name) == Some(value)
            })
            && provider_requests[0].headers.get("x-read-provider") == Some(&bsc_urls[index])
            && provider_requests[0].body["params"][1] == provider_requests[1].body["params"][1]
            && provider_requests[0].body["params"][1]["blockHash"] == BLOCK_A
            && provider_requests[0].body["params"][1]["requireCanonical"] == true
            && provider_requests
                .iter()
                .map(|request| request.body["method"].as_str().unwrap_or_default())
                .collect::<HashSet<_>>()
                == HashSet::from(["eth_call", "eth_getCode"]);
    }
    pinned_provider_pairs &= complete_provider_pairs >= quorum;
    let failures = failures.lock().clone();
    assert!(failures.is_empty(), "HTTP fixture failures: {failures:?}");

    let signatures: Vec<Signature> = body["body"]
        .get("signatures")
        .map(|value| serde_json::from_value(value.clone()).unwrap())
        .unwrap_or_default();
    let signed = !signatures.is_empty();
    (
        CaseResult {
            status,
            body,
            wire_requests: requests.iter().map(|request| json!({"path": request.path, "headers": request.headers, "body": request.body})).collect(),
            raw_body,
            response_headers,
            signed,
            signatures,
            sign_stage_observation_count: stage_observation_count(
                &stages, "sign", "ethereum", "ethereum", "ok",
            ),
            read_call_count: bsc_read_calls,
            read_code_count: bsc_read_code_calls,
            pinned_provider_pairs,
        },
        stages,
    )
}

#[tokio::test]
async fn sign_stage_metric_observations_are_not_series_cardinality() {
    let metrics =
        std::sync::Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new()));
    let observer = pillar_metrics::PillarMetricsStageObserver::new(metrics.clone());
    for _ in 0..2 {
        pillar_core::SignStageObserver::observe_stage(
            &observer,
            "sign",
            "ethereum",
            "bsc",
            pillar_core::SignStageStatus::Success,
            0.01,
        )
        .await;
    }
    for (stage, src_chain, status) in [
        ("sign", "ethereum", pillar_core::SignStageStatus::Failure),
        ("sign", "optimism", pillar_core::SignStageStatus::Success),
        (
            "validate",
            "ethereum",
            pillar_core::SignStageStatus::Success,
        ),
    ] {
        pillar_core::SignStageObserver::observe_stage(
            &observer, stage, src_chain, "bsc", status, 0.02,
        )
        .await;
    }
    let rendered = metrics.lock().await.render_prometheus("mainnet", "test");
    let observations = parse_stage_observations(&rendered);
    assert_eq!(
        stage_observation_count(&observations, "sign", "ethereum", "bsc", "ok"),
        2
    );
    assert_eq!(
        stage_observation_count(&observations, "sign", "ethereum", "bsc", "error"),
        1
    );
    assert_eq!(
        stage_observation_count(&observations, "sign", "optimism", "bsc", "ok"),
        1
    );
    assert_eq!(
        stage_observation_count(&observations, "validate", "ethereum", "bsc", "ok"),
        1
    );
    assert_eq!(
        stage_observation_count(&observations, "sign", "ethereum", "missing", "ok"),
        0
    );
    for malformed_sample in [
        "pillar_sign_stage_duration_seconds_count{stage=\"sign\",src_chain=\"ethereum\",dst_chain=\"bsc\",status=\"ok\"} not-a-number",
        "pillar_sign_stage_duration_seconds_count{stage=\"sign\",src_chain=\"ethereum\",dst_chain=\"bsc\"} 1",
    ] {
        let malformed_rendered = format!("{rendered}\n{malformed_sample}\n");
        assert!(
            std::panic::catch_unwind(|| parse_stage_observations(&malformed_rendered)).is_err(),
            "matching metric rows must reject malformed count or labels: {malformed_sample}"
        );
    }
}

#[tokio::test]
async fn reqwest_http_full_consumer_enforces_read_data_and_provider_quorum() {
    use HttpBehavior::*;
    let good = Chain(ReadChain::EmptyCallCodeZero);
    let no_code = Chain(ReadChain::EmptyCallCodeEmptyCode);
    let malformed = Chain(ReadChain::MalformedCodeOdd);
    let cases = [
        ("empty_call_with_0x00_code", vec![good; 2], 200, false),
        (
            "empty_call_with_0x6000_code",
            vec![Chain(ReadChain::EmptyCallCodeNonzero); 2],
            200,
            false,
        ),
        (
            "singleton_no_code_two_good",
            vec![no_code, good, good],
            200,
            false,
        ),
        (
            "singleton_revert_two_good",
            vec![Revert, good, good],
            200,
            false,
        ),
        (
            "singleton_malformed_two_good",
            vec![malformed, good, good],
            200,
            false,
        ),
        (
            "singleton_timeout_two_good",
            vec![Timeout, good, good],
            200,
            false,
        ),
        (
            "singleton_transport_two_good",
            vec![Disconnect, good, good],
            200,
            false,
        ),
        (
            "method_not_found_revert_message_negative_q2",
            vec![MethodNotFoundRevertMessage; 2],
            500,
            false,
        ),
        (
            "method_not_found_revert_message_singleton_two_good",
            vec![MethodNotFoundRevertMessage, good, good],
            200,
            false,
        ),
        (
            "timeout_code_revert_message_negative_q2",
            vec![TimeoutRevertMessage; 2],
            500,
            false,
        ),
        (
            "timeout_code_revert_message_singleton_two_good",
            vec![TimeoutRevertMessage, good, good],
            200,
            false,
        ),
        (
            "missing_code_revert_message_negative_q2",
            vec![MissingCodeRevertMessage; 2],
            500,
            false,
        ),
        (
            "missing_code_revert_message_singleton_two_good",
            vec![MissingCodeRevertMessage, good, good],
            200,
            false,
        ),
        (
            "string_code_revert_message_negative_q2",
            vec![StringCodeRevertMessage; 2],
            500,
            false,
        ),
        (
            "string_code_revert_message_singleton_two_good",
            vec![StringCodeRevertMessage, good, good],
            200,
            false,
        ),
        (
            "null_code_revert_message_negative_q2",
            vec![NullCodeRevertMessage; 2],
            500,
            false,
        ),
        (
            "null_code_revert_message_singleton_two_good",
            vec![NullCodeRevertMessage, good, good],
            200,
            false,
        ),
        (
            "no_code_negative_q2",
            vec![no_code, no_code, good],
            400,
            false,
        ),
        (
            "revert_negative_q2",
            vec![Revert, RevertUpperData, good],
            400,
            false,
        ),
        (
            "standard_revert_negative_q2",
            vec![StandardRevert; 2],
            400,
            false,
        ),
        (
            "absent_empty_revert_equal",
            vec![StandardRevert, RevertEmpty],
            400,
            false,
        ),
        (
            "timeout_singleton_no_code",
            vec![Timeout, no_code],
            500,
            false,
        ),
        (
            "timeout_singleton_revert",
            vec![Timeout, Revert],
            500,
            false,
        ),
        (
            "same_entity_two_uri_no_code",
            vec![no_code, no_code, malformed],
            500,
            true,
        ),
        (
            "same_entity_two_uri_revert",
            vec![Revert, Revert, malformed],
            500,
            true,
        ),
        (
            "positive_q2_negative_q2_ambiguous",
            vec![good, good, no_code, no_code],
            500,
            false,
        ),
        (
            "positive_q2_revert_q2_ambiguous",
            vec![good, good, Revert, Revert],
            500,
            false,
        ),
        (
            "different_revert_data",
            vec![Revert, RevertDifferentData],
            500,
            false,
        ),
        (
            "malformed_revert_data_not_absent",
            vec![RevertMalformed, StandardRevert],
            500,
            false,
        ),
        (
            "wrong_type_revert_data_not_absent",
            vec![RevertWrongType, StandardRevert],
            500,
            false,
        ),
        (
            "arbitrary_revert_substring",
            vec![MisleadingError; 2],
            500,
            false,
        ),
        (
            "malformed_call_odd_hex",
            vec![Chain(ReadChain::MalformedCallOdd); 2],
            500,
            false,
        ),
        ("malformed_code_odd_hex", vec![malformed; 2], 500, false),
    ];
    let mut evidence = Vec::new();
    let mut baseline = None;
    let mut status_mismatches = Vec::new();
    for (name, providers, expected_status, same_entity) in cases {
        let (result, stages) = run_full_consumer_case(&providers, 2, same_entity).await;
        println!(
            "{}",
            json!({"case": name, "status": result.status, "body": result.body, "stages": stages})
        );
        evidence.push(
            json!({"name": name, "providers": format!("{providers:?}"), "same_entity": same_entity,
            "status": result.status, "expected_status": expected_status, "body": result.body, "signed": result.signed,
            "raw_body": result.raw_body, "response_headers": result.response_headers,
            "wire_requests": result.wire_requests,
            "sign_stage_observation_count": result.sign_stage_observation_count, "stage_observations": stages,
            "same_provider_headers_and_pin": result.pinned_provider_pairs,
            "read_call_count": result.read_call_count, "read_code_count": result.read_code_count}),
        );
        if result.status != expected_status {
            status_mismatches.push(format!(
                "{name}: expected {expected_status}, got {}",
                result.status
            ));
            continue;
        }
        let expected_signed = expected_status == 200;
        assert_eq!(result.signed, expected_signed, "{name}: {result:?}");
        assert_eq!(
            result.sign_stage_observation_count,
            u64::from(expected_signed),
            "{name}"
        );
        if expected_signed {
            let baseline = baseline.get_or_insert_with(|| result.signatures.clone());
            assert_eq!(&result.signatures, baseline, "{name}");
            assert!(result.pinned_provider_pairs, "{name}");
            assert!(result.body.get("code").is_none(), "{name}");
            assert!(result.body.get("retryable").is_none(), "{name}");
            assert_eq!(result.body["statusCode"], 200);
            assert_eq!(
                result
                    .body
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<HashSet<_>>(),
                HashSet::from(["statusCode", "body"])
            );
        } else {
            assert!(stages.iter().all(|stage| stage.stage != "sign"), "{name}");
            assert_eq!(result.body["statusCode"], expected_status, "{name}");
            assert!(result.body["body"].is_string(), "{name}");
            let keys = result
                .body
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>();
            if expected_status == 400 {
                assert_eq!(result.body["code"], "UNRESOLVABLE_COMMAND", "{name}");
                assert_eq!(result.body["retryable"], false, "{name}");
                assert_eq!(
                    keys,
                    HashSet::from(["statusCode", "body", "code", "retryable"])
                );
                let reason = if providers
                    .iter()
                    .any(|provider| matches!(provider, Chain(ReadChain::EmptyCallCodeEmptyCode)))
                {
                    "ReadV1002 command is unresolvable: target has no code at the pinned block"
                } else {
                    "ReadV1002 command is unresolvable: execution reverted at the pinned block"
                };
                assert_eq!(result.body["body"], reason, "{name}");
            } else {
                assert_eq!(keys, HashSet::from(["statusCode", "body"]), "{name}");
            }
        }
    }
    let artifact = json!({"schema_version": 3, "transport": "ReqwestJsonRpcTransport",
        "consumer": "RuntimeServerApp<ReqwestJsonRpcTransport>", "inbound": "POST /v2/resolve-and-sign",
        "request": read_vertical_request(ReadMarker::BlockNumber), "receipt": read_vertical_receipt(ReadMarker::BlockNumber),
        "block": {"blockHash": BLOCK_A, "requireCanonical": true}, "cases": evidence});
    if let Some(output_dir) = std::env::var_os("READ_DOMAIN_ARTIFACT_DIR") {
        let output_dir = std::path::PathBuf::from(output_dir);
        assert!(output_dir.is_absolute());
        std::fs::create_dir_all(&output_dir).unwrap();
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_dir.join("http-results.json"))
            .expect("new, immutable evidence file");
        serde_json::to_writer_pretty(file, &artifact).unwrap();
    }
    println!("{artifact}");
    assert!(
        status_mismatches.is_empty(),
        "{}",
        status_mismatches.join("; ")
    );
}
