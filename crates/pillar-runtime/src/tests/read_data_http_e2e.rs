use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Clone)]
struct HttpFixtureState {
    receipt: Value,
    chains_by_path: HashMap<String, ReadChain>,
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
    signed: bool,
    signatures: Vec<Signature>,
    signer_stage_count: usize,
    read_call_count: usize,
    read_code_count: usize,
    pinned_provider_pairs: bool,
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
    loop {
        tokio::select! {
            _ = &mut shutdown => return,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        if let Err(error) = serve_one(stream, &state).await {
                            state.failures.lock().push(error);
                        }
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
    bsc_chains: &[ReadChain],
    quorum: usize,
) -> (CaseResult, Vec<String>) {
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
        wire_requests: wire_requests.clone(),
        failures: failures.clone(),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_http_fixture(listener, state, shutdown_rx));

    let transport = ReqwestJsonRpcTransport::new().expect("production Reqwest transport");
    let app = RuntimeServerApp::from_env_map_with_runtime_core(
        http_provider_env(&ethereum_url, &bsc_urls, quorum),
        transport,
        || 1_767_323_045_000,
    )
    .await
    .unwrap_or_else(|error| panic!("production READ HTTP app did not assemble: {error}"));
    let response = app
        .sign_request_v2(read_vertical_request(ReadMarker::BlockNumber))
        .await;
    let stages = stages_of(&app).await;
    drop(app);
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

    let (signed, signatures) = match response {
        Ok(response) => (!response.signatures.is_empty(), response.signatures),
        Err(_) => (false, Vec::new()),
    };
    (
        CaseResult {
            signed,
            signatures,
            signer_stage_count: stages
                .iter()
                .filter(|stage| stage.as_str() == "sign")
                .count(),
            read_call_count: bsc_read_calls,
            read_code_count: bsc_read_code_calls,
            pinned_provider_pairs,
        },
        stages,
    )
}

#[tokio::test]
async fn reqwest_http_full_consumer_enforces_read_data_and_provider_quorum() {
    let (mock_app, _) =
        read_vertical_app(ReadChain::EmptyCallCodeZero, ReadMarker::BlockNumber).await;
    let baseline = mock_app
        .sign_request_v2(read_vertical_request(ReadMarker::BlockNumber))
        .await
        .expect("normal empty return with nonempty code signs")
        .signatures;
    drop(mock_app);
    let cases = [
        (
            "empty_call_with_0x00_code",
            vec![ReadChain::EmptyCallCodeZero; 2],
            true,
        ),
        (
            "empty_call_with_0x6000_code",
            vec![ReadChain::EmptyCallCodeNonzero; 2],
            true,
        ),
        (
            "malformed_call_odd_hex",
            vec![ReadChain::MalformedCallOdd; 2],
            false,
        ),
        (
            "malformed_code_odd_hex",
            vec![ReadChain::MalformedCodeOdd; 2],
            false,
        ),
        (
            "one_bad_two_good_quorum_2",
            vec![
                ReadChain::OneProviderMalformedCode,
                ReadChain::EmptyCallCodeZero,
                ReadChain::EmptyCallCodeZero,
            ],
            true,
        ),
        (
            "cross_provider_partial_observations",
            vec![
                ReadChain::EmptyCallCodeEmptyCode,
                ReadChain::EmptyCallCodeZero,
                ReadChain::EmptyCallCodeEmptyCode,
            ],
            false,
        ),
    ];
    let mut evidence = Vec::new();
    for (name, providers, expected_signed) in cases {
        let (result, stages) = run_full_consumer_case(&providers, 2).await;
        assert_eq!(result.signed, expected_signed, "{name}: {result:?}");
        assert_eq!(
            result.signer_stage_count,
            usize::from(expected_signed),
            "{name}"
        );
        assert!(result.read_call_count >= 2, "{name}");
        if expected_signed {
            assert_eq!(result.signatures, baseline, "{name}");
            assert!(result.pinned_provider_pairs, "{name}");
        } else {
            assert!(stages.iter().all(|stage| stage != "sign"), "{name}");
        }
        if name == "malformed_call_odd_hex" {
            assert_eq!(result.read_code_count, 0);
        } else {
            assert!(result.read_code_count >= 2, "{name}");
        }
        evidence.push(json!({"name": name, "signed": result.signed,
            "signer_stage_count": result.signer_stage_count,
            "signature_matches_baseline": expected_signed.then(|| result.signatures == baseline),
            "same_provider_headers_and_pin": result.pinned_provider_pairs,
            "read_call_count": result.read_call_count, "read_code_count": result.read_code_count}));
    }
    let artifact = json!({"schema_version": 1, "transport": "ReqwestJsonRpcTransport",
        "consumer": "RuntimeServerApp<ReqwestJsonRpcTransport>",
        "block": {"blockHash": BLOCK_A, "requireCanonical": true}, "cases": evidence});
    let output_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../audit/review-80e0ad21-20261008/read-data");
    std::fs::create_dir_all(&output_dir).expect("create READ E2E evidence directory");
    std::fs::write(
        output_dir.join("reqwest-read-full-consumer.json"),
        serde_json::to_vec_pretty(&artifact).expect("encode READ E2E evidence"),
    )
    .expect("retain READ E2E evidence");
    println!("{artifact}");
}
