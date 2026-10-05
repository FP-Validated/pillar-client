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
        .get_json(ton_url, HashMap::new())
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
