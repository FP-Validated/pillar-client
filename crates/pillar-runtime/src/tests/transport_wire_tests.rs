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
    if method == "GET" && path == "/api/v3/events?tx_hash=deep-source" {
        return ton_trace_payload(250);
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
    assert!(nodes > 0);
    let mut json = String::from("{\"events\":[{\"trace\":");
    for index in 0..nodes - 1 {
        json.push_str(&format!("{{\"tx_hash\":\"tx{index}\",\"children\":["));
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

        let deep_trace_json = ton_trace_payload(250);
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
        drop(trace);
        (
            accepted_depths,
            over_limit_depth,
            depth_513_rejected,
            deep_trace_json.len(),
            deep_trace_json_depth,
            fingerprinted,
            no_packet_events,
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
            "synthetic_source_trace_nodes_via_fetch": 250,
            "synthetic_source_trace_response_bytes": deep_trace_bytes,
            "synthetic_source_trace_json_depth": deep_trace_depth,
            "synthetic_source_trace_fingerprinted": fingerprinted,
            "synthetic_source_trace_packet_events_empty": no_packet_events,
            "source_trace_tree_dropped": true,
            "worker_task_joined": true,
            "server_task_joined": true
        })
    );
}
