use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}
struct DropSignal(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

fn transport_fixture(name: &str) -> Value {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/transport");
    path.push(name);
    serde_json::from_slice(&std::fs::read(path).expect("transport fixture exists"))
        .expect("transport fixture parses")
}

fn recorded_response(method: &str, path: &str, request_body: &[u8]) -> Vec<u8> {
    if method == "GET" {
        if let Some(depth) = path
            .strip_prefix("/ton-depth/")
            .and_then(|depth| depth.parse::<usize>().ok())
        {
            return ton_depth_payload(depth);
        }
    }
    if method == "GET" {
        if path.contains("deep-source") {
            return ton_trace_payload(254);
        }
        if path.contains("duplicate-source") {
            return ton_trace_payload_with_duplicate(8);
        }
        if path.contains("too-many-source") {
            return ton_star_trace_payload(513);
        }
        if path.contains("large-metadata-star-source") {
            return ton_star_trace_payload_with_large_ignored_metadata(
                512,
                4 * 1024 * 1024 - 100 * 1024,
            );
        }
        if path.contains("noise-source") {
            return ton_trace_payload_with_nested_noise(200, 500);
        }
        if path.contains("omitted-leaf-events") {
            return serde_json::to_vec(&serde_json::json!({"events":[{"trace":{"tx_hash":"leaf"},"transactions":{"leaf":{"hash":"leaf","mc_block_seqno":1,"in_msg":null}}}]})).unwrap();
        }
        if path.contains("omitted-leaf-legacy") {
            return if path.starts_with("/api/v3/transactionTrace") {
                serde_json::to_vec(&serde_json::json!({"transaction":{"hash":"leaf","mc_block_seqno":1,"in_msg":null}})).unwrap()
            } else {
                b"{\"events\":[]}".to_vec()
            };
        }
        if path.contains("malformed-topology-source") {
            return serde_json::to_vec(&serde_json::json!({"events":[{"trace":{"tx_hash":"bad","children":null},"transactions":{"bad":{"in_msg":null}}}]})).expect("malformed-topology fixture serializes");
        }
        if path.contains("malformed-json-source") {
            return b"{\"events\":[".to_vec();
        }
    }
    let rpc_method = serde_json::from_slice::<Value>(request_body)
        .ok()
        .and_then(|body| body["method"].as_str().map(str::to_string));
    let fixture_name = match (method, path, rpc_method.as_deref()) {
        ("POST", "/solana", Some("getTransaction")) => {
            "source_replay/solana-getTransaction-jsonParsed.response.json"
        }
        ("POST", "/tron", Some("eth_getTransactionReceipt")) => {
            "source_replay/tron-eth_getTransactionReceipt.response.json"
        }
        ("GET", p, _) if p.starts_with("/api/v3/events?tx_hash=") => {
            "source_replay/ton-v3-events.response.json"
        }
        _ => panic!("unrecorded Pillar request: {method} {path} {rpc_method:?}"),
    };
    let mut response_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    response_path.push("tests/gasolina_parity");
    response_path.push(fixture_name);
    std::fs::read(response_path).expect("recorded response body exists")
}
fn ton_depth_payload(total_depth: usize) -> Vec<u8> {
    assert!(total_depth >= 2);
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/gasolina_parity/source_replay/ton-v3-events.response.json");
    let mut bytes = std::fs::read(path).expect("TON source replay exists");
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes.pop();
    }
    assert_eq!(bytes.pop(), Some(b'}'));
    bytes.extend_from_slice(b",\"depth_probe\":");
    bytes.extend(std::iter::repeat_n(b'[', total_depth - 1));
    bytes.extend_from_slice(b"null");
    bytes.extend(std::iter::repeat_n(b']', total_depth - 1));
    bytes.push(b'}');
    bytes
}

fn ton_trace_payload(nodes: usize) -> Vec<u8> {
    ton_trace_payload_variant(nodes, false)
}

fn ton_trace_payload_with_duplicate(nodes: usize) -> Vec<u8> {
    ton_trace_payload_variant(nodes, true)
}

fn ton_trace_payload_variant(nodes: usize, duplicate: bool) -> Vec<u8> {
    assert!(nodes > 0);
    let mut json = String::from("{\"events\":[{\"trace\":");
    for index in 0..nodes - 1 {
        let tx_index = if duplicate && index == 1 { 0 } else { index };
        json.push_str(&format!("{{\"tx_hash\":\"tx{tx_index}\",\"children\":["));
    }
    json.push_str(&format!(
        "{{\"tx_hash\":\"tx{}\",\"children\":[]}}",
        nodes - 1
    ));
    for _ in 1..nodes {
        json.push_str("]}");
    }
    json.push_str(",\"transactions\":{");
    for index in 0..nodes {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&format!("\"tx{index}\":{{\"in_msg\":null}}"));
    }
    json.push_str("}}]}");
    json.into_bytes()
}

fn ton_trace_payload_with_nested_noise(nodes: usize, depth: usize) -> Vec<u8> {
    let mut json = String::from_utf8(ton_trace_payload(nodes)).expect("synthetic trace is UTF-8");
    let needle = r#""tx0":{"in_msg":null}"#;
    let start = json.find(needle).expect("first transaction exists");
    let mut nested = String::with_capacity(depth * 2 + 4);
    nested.extend(std::iter::repeat_n('[', depth));
    nested.push_str("null");
    nested.extend(std::iter::repeat_n(']', depth));
    json.replace_range(
        start..start + needle.len(),
        &format!("\"tx0\":{{\"in_msg\":null,\"ignored_noise\":{nested}}}"),
    );
    json.into_bytes()
}
fn ton_star_trace_payload(nodes: usize) -> Vec<u8> {
    assert!(nodes > 0);
    let mut json = String::from("{\"events\":[{\"trace\":{\"tx_hash\":\"tx0\",\"children\":[");
    for index in 1..nodes {
        if index > 1 {
            json.push(',');
        }
        json.push_str(&format!("{{\"tx_hash\":\"tx{index}\",\"children\":[]}}"));
    }
    json.push_str(" ]},\"transactions\":{");
    for index in 0..nodes {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&format!("\"tx{index}\":{{\"in_msg\":null}}"));
    }
    json.push_str("}}]}");
    json.into_bytes()
}
fn ton_star_trace_payload_with_large_ignored_metadata(
    nodes: usize,
    payload_bytes: usize,
) -> Vec<u8> {
    assert!(nodes > 0);
    let mut json = String::with_capacity(payload_bytes + nodes * 80 + 256);
    json.push_str("{\"events\":[{\"trace\":{\"tx_hash\":\"tx0\",\"children\":[");
    for index in 1..nodes {
        if index > 1 {
            json.push(',');
        }
        json.push_str(&format!("{{\"tx_hash\":\"tx{index}\",\"children\":[]}}"));
    }
    json.push_str(" ]},\"transactions\":{");
    for index in 0..nodes {
        if index > 0 {
            json.push(',');
        }
        if index == 0 {
            json.push_str("\"tx0\":{\"in_msg\":null,\"ignored_metadata\":\"");
            json.extend(std::iter::repeat_n('x', payload_bytes));
            json.push_str("\"}");
        } else {
            json.push_str(&format!("\"tx{index}\":{{\"in_msg\":null}}"));
        }
    }
    json.push_str("}}]}");
    json.into_bytes()
}

fn json_max_depth(bytes: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut maximum = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == 92 {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                maximum = maximum.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    maximum
}

async fn read_request(stream: tokio::net::TcpStream) -> CapturedRequest {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    stream.read_line(&mut line).await.expect("request line");
    let mut parts = line.split_whitespace();
    let method = parts.next().expect("request method").to_string();
    let path = parts.next().expect("request path").to_string();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        stream.read_line(&mut line).await.expect("request header");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let body_len = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; body_len];
    stream.read_exact(&mut body).await.expect("request body");
    let response_body = recorded_response(&method, &path, &body);
    let response_header = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response_body.len()
    );
    stream
        .get_mut()
        .write_all(response_header.as_bytes())
        .await
        .expect("response headers");
    stream
        .get_mut()
        .write_all(&response_body)
        .await
        .expect("recorded response body");
    CapturedRequest {
        method,
        path,
        headers,
        body,
    }
}

fn upstream_request(fixture: &Value, family: &str, method: &str) -> Value {
    fixture["requests"]
        .as_array()
        .expect("captured requests")
        .iter()
        .find(|request| {
            request["family"] == family
                && request["method"] == "POST"
                && serde_json::from_str::<Value>(request["bodyUtf8"].as_str().unwrap_or_default())
                    .ok()
                    .and_then(|body| body["method"].as_str().map(str::to_string))
                    .as_deref()
                    == Some(method)
        })
        .cloned()
        .expect("SDK request recorded")
}

fn normalize_rpc_id(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        object.remove("id");
    }
}

#[tokio::test]
async fn real_reqwest_source_calls_capture_solana_tron_and_ton_wire_shapes() {
    let fixture = transport_fixture("upstream_requests.json");
    let solana_upstream = upstream_request(&fixture, "solana", "getTransaction");
    let tron_upstream = upstream_request(&fixture, "tron", "eth_getTransactionReceipt");
    let ton_upstream = fixture["requests"]
        .as_array()
        .expect("captured requests")
        .iter()
        .find(|request| request["family"] == "ton" && request["method"] == "GET")
        .cloned()
        .expect("TON SDK GET recorded");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let server = tokio::spawn(async move {
        let mut captured = Vec::new();
        for _ in 0..3 {
            let (stream, _) = listener.accept().await.expect("accept request");
            captured.push(read_request(stream).await);
        }
        captured
    });

    let transport = ReqwestJsonRpcTransport::new().expect("production reqwest transport");
    let base = format!("http://{address}");

    let mut solana_body: Value = serde_json::from_str(
        solana_upstream["bodyUtf8"]
            .as_str()
            .expect("captured Solana body"),
    )
    .expect("captured Solana JSON");
    // Pillar builds this body in packet_resolver.rs:140-153, including its v1 cap.
    solana_body["params"][1]["maxSupportedTransactionVersion"] = json!(1);
    solana_body["id"] = json!(1);
    transport
        .post_json(format!("{base}/solana"), HashMap::new(), solana_body)
        .await
        .expect("recorded Solana response");

    let mut tron_body: Value = serde_json::from_str(
        tron_upstream["bodyUtf8"]
            .as_str()
            .expect("captured TRON body"),
    )
    .expect("captured TRON JSON");
    tron_body["id"] = json!(1);
    transport
        .post_json(format!("{base}/tron"), HashMap::new(), tron_body)
        .await
        .expect("recorded TRON response");

    let ton_url = format!("{base}{}", ton_upstream["pathAndQuery"].as_str().unwrap());
    transport
        .get_ton_json(ton_url, HashMap::new())
        .await
        .expect("recorded TON response");

    let captured = server.await.expect("loopback server task");
    assert_eq!(captured.len(), 3);
    for (index, (ours, upstream)) in [
        (&captured[0], &solana_upstream),
        (&captured[1], &tron_upstream),
        (&captured[2], &ton_upstream),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(ours.method, upstream["method"], "request {index} method");
        assert_eq!(
            ours.path, upstream["pathAndQuery"],
            "request {index} path+query"
        );
        if ours.method == "POST" {
            assert_eq!(
                ours.headers.get("content-type").map(String::as_str),
                upstream["headers"]["content-type"].as_str(),
                "request {index} content-type",
            );
            let mut actual: Value = serde_json::from_slice(&ours.body).expect("Pillar JSON body");
            let mut expected: Value =
                serde_json::from_str(upstream["bodyUtf8"].as_str().expect("upstream body"))
                    .expect("upstream JSON body");
            normalize_rpc_id(&mut actual);
            normalize_rpc_id(&mut expected);
            if index == 0 {
                // Intentional difference: Pillar opts into transaction version 1.
                expected["params"][1]["maxSupportedTransactionVersion"] = json!(1);
            }
            assert_eq!(actual, expected, "request {index} JSON-RPC semantics");
        } else {
            assert!(ours.body.is_empty(), "TON GET has no body");
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn ton_depth_limit_and_trace_traversal_are_worker_safe_over_http() {
    if std::env::var_os("PILLAR_TON_ISOLATED_CHILD").is_none() {
        let executable = std::env::current_exe().expect("current test executable");
        let mut time_command = std::process::Command::new("/usr/bin/time");
        if cfg!(target_os = "macos") {
            time_command.arg("-l");
        } else {
            time_command.args(["-f", "%M maximum resident set size"]);
        }
        let mut child = time_command
            .arg(executable)
            .args(["--exact", "tests::transport_wire_tests::ton_depth_limit_and_trace_traversal_are_worker_safe_over_http", "--nocapture"])
            .env("PILLAR_TON_ISOLATED_CHILD", "1")
            .env("RUST_MIN_STACK", "2097152")
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn isolated TON lifecycle test");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
        loop {
            if child.try_wait().expect("child process status").is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("isolated TON lifecycle child exceeded 45s timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let output = child
            .wait_with_output()
            .expect("collect child resource report");
        let time_report = String::from_utf8_lossy(&output.stderr);
        let reported_peak_rss = time_report
            .lines()
            .find(|line| line.contains("maximum resident set size"))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|number| number.parse::<u64>().ok())
            .expect("time reports maximum resident set size");
        let peak_rss_bytes = if cfg!(target_os = "macos") {
            reported_peak_rss
        } else {
            reported_peak_rss * 1024
        };
        let rss_budget_bytes = 512 * 1024 * 1024u64;
        println!(
            "ton-child-resource-evidence: {}",
            serde_json::json!({
                "peak_rss_bytes": peak_rss_bytes,
                "rss_budget_bytes": rss_budget_bytes,
                "rss_within_budget": peak_rss_bytes <= rss_budget_bytes,
                "rss_limit_enforced_by_os": false,
                "resource_source": if cfg!(target_os = "macos") {
                    "/usr/bin/time -l (bytes)"
                } else {
                    "/usr/bin/time -f '%M maximum resident set size' (KiB converted to bytes)"
                },
                "reported_peak_rss": reported_peak_rss,
                "reported_peak_rss_unit": if cfg!(target_os = "macos") { "bytes" } else { "KiB" }
            })
        );
        assert!(
            peak_rss_bytes <= rss_budget_bytes,
            "isolated TON child exceeded RSS budget: {peak_rss_bytes}"
        );
        assert!(
            output.status.success(),
            "isolated TON child exited with {}: {time_report}",
            output.status
        );
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let server = tokio::spawn(async move {
        for path in [
            "/ton-depth/266",
            "/ton-depth/512",
            "/ton-depth/513",
            "/api/v3/events?tx_hash=deep-source",
            "/api/v3/events?tx_hash=duplicate-source",
            "/api/v3/traces?tx_hash=duplicate-source",
            "/api/v3/transactionTrace?hash=duplicate-source",
            "/api/v3/events?tx_hash=too-many-source",
            "/api/v3/traces?tx_hash=too-many-source",
            "/api/v3/transactionTrace?hash=too-many-source",
            "/api/v3/events?tx_hash=large-metadata-star-source",
            "/api/v3/events?tx_hash=omitted-leaf-events",
            "/api/v3/events?tx_hash=omitted-leaf-legacy",
            "/api/v3/traces?tx_hash=omitted-leaf-legacy",
            "/api/v3/transactionTrace?hash=omitted-leaf-legacy",
            "/api/v3/events?tx_hash=malformed-topology-source",
            "/api/v3/traces?tx_hash=malformed-topology-source",
            "/api/v3/transactionTrace?hash=malformed-topology-source",
            "/api/v3/events?tx_hash=malformed-json-source",
            "/api/v3/events?tx_hash=noise-source",
            "/api/v3/events?tx_hash=follow-up",
        ] {
            let (stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                    .await
                    .expect("loopback accept timeout")
                    .expect("accept request");
            let request = read_request(stream).await;
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, path);
        }
    });

    let transport = ReqwestJsonRpcTransport::new().expect("production reqwest transport");
    let base = format!("http://{address}");
    let caller = tokio::spawn(async move {
        let mut accepted_depths = Vec::new();
        for depth in [266, 512] {
            assert_eq!(json_max_depth(&ton_depth_payload(depth)), depth);
            let value = transport
                .get_ton_json(format!("{base}/ton-depth/{depth}"), HashMap::new())
                .await
                .expect("depth at or below TON bound parses");
            assert!(value.get("depth_probe").is_some());
            accepted_depths.push(depth);
            drop(value);
        }

        let over_limit_depth = json_max_depth(&ton_depth_payload(513));
        assert_eq!(
            over_limit_depth, 513,
            "rejection input is actually depth 513"
        );
        let rejected = transport
            .get_ton_json(format!("{base}/ton-depth/513"), HashMap::new())
            .await;
        let depth_513_rejected = rejected.is_err();
        assert!(depth_513_rejected, "depth-513 JSON must be rejected");

        let deep_trace_json = ton_trace_payload(254);
        let deep_trace_json_depth = json_max_depth(&deep_trace_json);
        assert!(
            deep_trace_json_depth <= 512,
            "synthetic trace fits the JSON nesting guard"
        );
        assert!(
            deep_trace_json.len() <= 4 * 1024 * 1024,
            "synthetic trace fits the HTTP byte cap"
        );
        let trace = crate::provider_health::rpc_scope("ton", async {
            crate::layerzero_runtime::fetch_ton_transaction_trace(
                &transport,
                &format!("{base}/api/v3"),
                &HashMap::new(),
                "deep-source",
            )
            .await
        })
        .await
        .expect("actual HTTP source trace fetch succeeds")
        .expect("deep synthetic source trace is present");
        let fingerprinted =
            crate::layerzero_runtime::ton_trace_quorum_fingerprint(&trace).is_some();
        assert!(fingerprinted);
        let no_packet_events = crate::layerzero_runtime::decode_ton_packet_sent_events(
            &trace,
            &HashSet::new(),
            &HashMap::new(),
        )
        .is_empty();
        assert!(no_packet_events);
        let serialized_trace =
            serde_json::to_vec(&trace).expect("bounded projected trace serializes");
        let projected_json_depth = json_max_depth(&serialized_trace);
        assert!(
            projected_json_depth <= 512,
            "composed output depth is bounded: {projected_json_depth}"
        );

        let providers = pillar_config::ProviderConfig::with_distinct_entities(
            ["ton-a", "ton-b", "ton-c", "ton-d"]
                .into_iter()
                .map(|name| pillar_config::ProviderUri::Uri(format!("https://{name}.invalid")))
                .collect(),
            2,
        );
        let quorum =
            crate::provider_health::required_provider_quorum(&providers, "ton lifecycle").unwrap();
        use futures::FutureExt;
        type QuorumResult = (
            usize,
            Result<Option<(String, Value)>, crate::provider_health::RpcError>,
        );
        let requests: futures::stream::FuturesUnordered<
            futures::future::BoxFuture<'static, QuorumResult>,
        > = futures::stream::FuturesUnordered::new();
        let fingerprint = crate::layerzero_runtime::ton_trace_quorum_fingerprint(&trace).unwrap();
        requests.push(
            futures::future::ready((0, Ok(Some((fingerprint.clone(), trace.clone()))))).boxed(),
        );
        requests.push(futures::future::ready((1, Ok(Some((fingerprint, trace))))).boxed());
        requests.push(
            futures::future::ready((
                2,
                Err(crate::provider_health::RpcError::Remote(
                    "x".repeat(1024 * 1024),
                )),
            ))
            .boxed(),
        );
        let loser_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loser_signal = DropSignal(loser_dropped.clone());
        requests.push(
            async move {
                let _signal = loser_signal;
                std::future::pending::<QuorumResult>().await
            }
            .boxed(),
        );
        let selected = crate::provider_health::resolve_provider_quorum(
            requests,
            4,
            quorum,
            "TON lifecycle early return",
        )
        .await
        .expect("matching two-provider TON quorum returns before loser");
        assert!(
            loser_dropped.load(std::sync::atomic::Ordering::SeqCst),
            "losing provider future is dropped"
        );
        let loser_disposed = loser_dropped.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            loser_disposed,
            "error response and losing future are disposed"
        );
        let selected_depth = json_max_depth(&serde_json::to_vec(&selected).unwrap());
        assert!(
            selected_depth <= 512,
            "quorum clone remains bounded: {selected_depth}"
        );

        let cancel_providers = pillar_config::ProviderConfig::with_distinct_entities(
            ["ton-cancel-a", "ton-cancel-b"]
                .into_iter()
                .map(|name| pillar_config::ProviderUri::Uri(format!("https://{name}.invalid")))
                .collect(),
            2,
        );
        let cancel_quorum =
            crate::provider_health::required_provider_quorum(&cancel_providers, "ton cancellation")
                .unwrap();
        let canceled_dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let canceled_signal = DropSignal(canceled_dropped.clone());
        let canceled_trace = selected.clone();
        let canceled_requests: futures::stream::FuturesUnordered<
            futures::future::BoxFuture<'static, QuorumResult>,
        > = futures::stream::FuturesUnordered::new();
        canceled_requests.push(
            async move {
                let _trace = canceled_trace;
                let _signal = canceled_signal;
                std::future::pending::<QuorumResult>().await
            }
            .boxed(),
        );
        let canceled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            crate::provider_health::resolve_provider_quorum(
                canceled_requests,
                2,
                cancel_quorum,
                "TON cancellation",
            ),
        )
        .await
        .is_err();
        assert!(canceled, "quorum resolver future was canceled by deadline");
        assert!(
            canceled_dropped.load(std::sync::atomic::Ordering::SeqCst),
            "canceled trace owner is dropped"
        );

        let duplicate_rejected = crate::layerzero_runtime::fetch_ton_transaction_trace(
            &transport,
            &format!("{base}/api/v3"),
            &HashMap::new(),
            "duplicate-source",
        )
        .await
        .expect("duplicate hash trace refusals are provider responses")
        .is_none();
        let excessive_nodes_rejected = crate::layerzero_runtime::fetch_ton_transaction_trace(
            &transport,
            &format!("{base}/api/v3"),
            &HashMap::new(),
            "too-many-source",
        )
        .await
        .expect("513-node trace refusals are provider responses")
        .is_none();
        let expanded_bytes_payload =
            ton_star_trace_payload_with_large_ignored_metadata(512, 4 * 1024 * 1024 - 100 * 1024);
        let expanded_response_bytes = expanded_bytes_payload.len();
        assert!(
            expanded_response_bytes < 4 * 1024 * 1024,
            "512-node star response fits the transport byte cap"
        );
        drop(expanded_bytes_payload);
        let expanded_star = crate::layerzero_runtime::fetch_ton_transaction_trace(
            &transport,
            &format!("{base}/api/v3"),
            &HashMap::new(),
            "large-metadata-star-source",
        )
        .await
        .expect("under-cap 512-node star is a normal response")
        .expect("512-node star remains accepted");
        assert_eq!(expanded_star["children"].as_array().unwrap().len(), 511);
        assert!(crate::layerzero_runtime::ton_trace_quorum_fingerprint(&expanded_star).is_some());
        let expanded_star_accepted = true;
        crate::provider_health::drop_json_value_safely(expanded_star);
        for source_hash in ["omitted-leaf-events", "omitted-leaf-legacy"] {
            let canonical_leaf = crate::layerzero_runtime::fetch_ton_transaction_trace(
                &transport,
                &format!("{base}/api/v3"),
                &HashMap::new(),
                source_hash,
            )
            .await
            .unwrap()
            .expect("omitted leaf children remain usable over HTTP");
            assert!(canonical_leaf["children"].as_array().unwrap().is_empty());
            assert_eq!(
                crate::layerzero_runtime::ton_trace_quorum_fingerprint(&canonical_leaf).as_deref(),
                Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            );
        }
        let malformed_topology_rejected = crate::layerzero_runtime::fetch_ton_transaction_trace(
            &transport,
            &format!("{base}/api/v3"),
            &HashMap::new(),
            "malformed-topology-source",
        )
        .await
        .expect("malformed topology refusals are provider responses")
        .is_none();
        let malformed_json_rejected = transport
            .get_ton_json(
                format!("{base}/api/v3/events?tx_hash=malformed-json-source"),
                HashMap::new(),
            )
            .await
            .is_err();
        let noise_payload = ton_trace_payload_with_nested_noise(200, 500);
        let input_depth = json_max_depth(&noise_payload);
        assert_eq!(input_depth, 505, "M-01 input reproducer has depth 505");
        let projected = crate::layerzero_runtime::fetch_ton_transaction_trace(
            &transport,
            &format!("{base}/api/v3"),
            &HashMap::new(),
            "noise-source",
        )
        .await
        .expect("noise subtree is omitted by projection")
        .expect("depth-505 source response accepted");
        let projected_depth = json_max_depth(&serde_json::to_vec(&projected).unwrap());
        assert!(
            projected_depth <= 512,
            "projected consumer output depth is bounded"
        );
        assert!(
            projected_depth < input_depth,
            "projection removes the 500-level unconsumed subtree"
        );
        crate::provider_health::drop_json_value_safely(projected);
        let normal_trace = crate::layerzero_runtime::fetch_ton_transaction_trace(
            &transport,
            &format!("{base}/api/v3"),
            &HashMap::new(),
            "follow-up",
        )
        .await
        .expect("normal request follows rejected/canceled responses")
        .expect("normal recorded trace remains usable after failure cases");
        assert_eq!(
            crate::layerzero_runtime::ton_trace_quorum_fingerprint(&normal_trace).as_deref(),
            Some("cf0ca115fcea8450f50122d6d54c24b390c2d1869ccbcbc43860e156857d1ed1")
        );
        let normal_followup = true;
        drop(selected);
        (
            accepted_depths,
            over_limit_depth,
            depth_513_rejected,
            deep_trace_json.len(),
            deep_trace_json_depth,
            fingerprinted,
            no_packet_events,
            projected_json_depth,
            selected_depth,
            canceled,
            duplicate_rejected,
            excessive_nodes_rejected,
            expanded_star_accepted,
            loser_disposed,
            malformed_topology_rejected,
            malformed_json_rejected,
            input_depth,
            projected_depth,
            normal_followup,
            expanded_response_bytes,
        )
    });
    let (
        accepted_depths,
        rejected_depth,
        depth_513_rejected,
        deep_trace_bytes,
        deep_trace_depth,
        fingerprinted,
        no_packet_events,
        projected_json_depth,
        selected_depth,
        canceled,
        duplicate_rejected,
        excessive_nodes_rejected,
        expanded_star_accepted,
        loser_disposed,
        malformed_topology_rejected,
        malformed_json_rejected,
        input_depth,
        projected_depth,
        normal_followup,
        expanded_response_bytes,
    ) = tokio::time::timeout(std::time::Duration::from_secs(10), caller)
        .await
        .expect("TON caller task timeout")
        .expect("TON worker task completes without stack overflow");
    server.await.expect("loopback server task completes");

    let mut fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fixture_path.push("tests/gasolina_parity/source_replay/ton-v3-events.response.json");
    let fixture_bytes = std::fs::read(fixture_path).expect("recorded TON fixture exists");
    use sha2::{Digest, Sha256};
    let fixture_sha256 = hex::encode(Sha256::digest(&fixture_bytes));
    println!(
        "{}",
        serde_json::json!({
            "test": "ton_depth_limit_and_trace_traversal_are_worker_safe_over_http",
            "evidence_kind": "recorded_fixture_identity_plus_synthetic_http_depth_probes_and_source_trace",
            "recorded_fixture": "ton-v3-events.response.json",
            "recorded_fixture_bytes": fixture_bytes.len(),
            "recorded_fixture_sha256": fixture_sha256,
            "raw266_depth_fixture_found": false,
            "synthetic_http_depths_parsed_and_dropped": accepted_depths,
            "synthetic_http_rejection_input_json_depth": rejected_depth,
            "synthetic_http_depth_513_rejected": depth_513_rejected,
            "depth_unit": "JSON containers for response depth; trace nodes for trace node count",
            "runtime_worker_stack_bytes": 2097152,
            "child_virtual_memory_limit_bytes": null,
            "child_peak_rss_budget_bytes": 536870912,
             "child_wall_timeout_seconds": 45,
            "child_peak_rss_observed_by_time": true,
            "synthetic_source_trace_nodes_via_fetch": 254,
            "expanded_projection_source_response_bytes": expanded_response_bytes,
            "expanded_projection_budget_bytes": 4194304,
            "synthetic_source_trace_response_bytes": deep_trace_bytes,
            "synthetic_source_trace_input_json_depth": deep_trace_depth,
            "synthetic_source_trace_output_json_depth": projected_json_depth,
            "synthetic_source_trace_fingerprinted": fingerprinted,
            "synthetic_source_trace_packet_events_empty": no_packet_events,
            "duplicate_hash_rejected": duplicate_rejected,
            "512_node_star_under_cap_accepted": expanded_star_accepted,
            "malformed_topology_rejected": malformed_topology_rejected,
            "malformed_json_rejected": malformed_json_rejected,
            "nested_noise_input_depth_505": input_depth,
            "nested_noise_output_depth": projected_depth,
            "early_quorum_return_clone_depth": selected_depth,
            "513_node_star_rejected": excessive_nodes_rejected,
            "canceled_quorum_future_dropped_trace": canceled,
            "error_disposal_and_pending_loser_drop": loser_disposed,
            "normal_recorded_trace_followup_survives": normal_followup,
            "source_trace_tree_dropped": true,
            "worker_task_joined": true,
            "server_task_joined": true
        })
    );
}
