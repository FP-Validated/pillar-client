use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[derive(Debug)]
struct CapturedMoveRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    status: u16,
}

fn aptos_wire_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gasolina_parity/transport/upstream_aptos_transport.json");
    serde_json::from_slice(&std::fs::read(path).expect("upstream Aptos wire fixture exists"))
        .expect("upstream Aptos wire fixture parses")
}

fn aptos_source_response(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gasolina_parity/transport/source_replay/aptos")
        .join(name);
    std::fs::read(path).expect("recorded Aptos response exists")
}

fn move_response(path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    if path == "/view" {
        let request: Value = serde_json::from_slice(body).expect("Pillar view request is JSON");
        let function = request["function"].as_str().expect("view function");
        // Recorded mainnet response for the APT OFT receiver; the v14 capture predates this read.
        let response = if function.ends_with("::endpoint::get_effective_receive_library") {
            b"[\"0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9\",true]"
                .to_vec()
        } else if function.ends_with("::endpoint_view::get_receive_msglib") {
            aptos_source_response("004-mainnet-bridge-get_receive_msglib-101.response.body")
        } else if function.ends_with("::endpoint_view::get_config") {
            aptos_source_response(
                "008-mainnet-bridge-get_config-u64-string-u8-number.response.body",
            )
        } else if function.ends_with("::endpoint_view::inbound_nonce") {
            aptos_source_response("011-mainnet-bridge-inbound_nonce-101.response.body")
        } else if function.ends_with("::msglib::get_verification_confirmations") {
            aptos_source_response(
                "016-mainnet-uln301-get_verification_confirmations-synthetic.response.body",
            )
        } else if function.ends_with("::uln_301::verifiable") {
            aptos_source_response("015-mainnet-uln301-verifiable-synthetic.response.body")
        } else if function.ends_with("::endpoint::get_config") {
            let chain = request["arguments"][0].as_str().unwrap_or_default();
            if chain == "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa" {
                aptos_source_response("010-mainnet-v302-get_config-u32-numbers.response.body")
            } else {
                aptos_source_response("movement-v302-get-config.response.body")
            }
        } else if function.ends_with("::uln_302::verifiable") {
            b"[0]".to_vec()
        } else {
            panic!("unrecorded Pillar Move view: {function}");
        };
        return (200, response);
    }
    if path.contains("/resource/") {
        return (
            200,
            aptos_source_response("003-mainnet-bridge-channels.response.body"),
        );
    }
    if path.starts_with("/tables/") {
        let request: Value =
            serde_json::from_slice(body).expect("Pillar table item request is JSON");
        if request["key_type"] == "u64" {
            return (
                404,
                aptos_source_response(
                    "013-mainnet-bridge-payload_hashs-74756-absent.response.body",
                ),
            );
        }
        return (
            200,
            aptos_source_response("012-mainnet-bridge-channel-remote-101.response.body"),
        );
    }
    panic!("unrecorded Pillar Aptos HTTP request: {path}");
}

async fn serve_one(stream: tokio::net::TcpStream) -> CapturedMoveRequest {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    stream.read_line(&mut line).await.expect("request line");
    let mut parts = line.split_whitespace();
    let method = parts.next().expect("HTTP method").to_string();
    let path = parts.next().expect("HTTP path").to_string();
    let mut headers = HashMap::new();
    loop {
        line.clear();
        stream.read_line(&mut line).await.expect("request header");
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.expect("request body");
    let (status, response_body) = move_response(&path, &body);
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let response_header = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
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
        .expect("response body");
    CapturedMoveRequest {
        method,
        path,
        headers,
        body,
        status,
    }
}

fn upstream_request_for_observation<'a>(fixture: &'a Value, observation: &Value) -> &'a Value {
    let function = observation["function"].as_str().expect("upstream function");
    fixture["requests"]
        .as_array()
        .expect("upstream HTTP requests")
        .iter()
        .find(|request| {
            request["decodedFunction"] == function && request["pathAndQuery"] == "/v1/view"
        })
        .expect("upstream BCS request for view observation")
}

fn typed_semantic_value(value: &Value, move_type: &str) -> String {
    match move_type {
        "u8" | "u16" | "u32" | "u64" | "u128" | "u256" => value
            .as_str()
            .map(str::to_string)
            .or_else(|| value.as_u64().map(|number| number.to_string()))
            .expect("integer Move argument"),
        "address" | "vector<u8>" => value
            .as_str()
            .expect("string Move argument")
            .to_ascii_lowercase(),
        other => panic!("unexpected Move argument type {other}"),
    }
}

fn assert_view_semantics(fixture: &Value, captured: &[CapturedMoveRequest], function_suffix: &str) {
    let observations = fixture["viewObservations"]
        .as_array()
        .expect("upstream typed view observations");
    let actual = captured
        .iter()
        .filter(|request| request.method == "POST" && request.path == "/view")
        .map(|request| {
            assert_eq!(
                request.headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            serde_json::from_slice::<Value>(&request.body).expect("Pillar view JSON")
        })
        .find(|request| {
            request["function"]
                .as_str()
                .unwrap_or_default()
                .ends_with(function_suffix)
        })
        .unwrap_or_else(|| panic!("Pillar view ending in {function_suffix} was not captured"));
    let function = actual["function"].as_str().expect("Pillar function");
    let arguments = actual["arguments"].as_array().expect("Pillar arguments");
    let observation = observations
        .iter()
        .find(|candidate| {
            candidate["function"] == function
                && candidate["functionArguments"]
                    .as_array()
                    .is_some_and(|upstream_args| {
                        let types = candidate["functionArgumentTypes"]
                            .as_array()
                            .expect("upstream argument types");
                        upstream_args.len() == arguments.len()
                            && arguments.len() == types.len()
                            && upstream_args.iter().zip(arguments).zip(types).all(
                                |((expected, actual), ty)| {
                                    let move_type = ty.as_str().expect("Move type");
                                    typed_semantic_value(expected, move_type)
                                        == typed_semantic_value(actual, move_type)
                                },
                            )
                    })
        })
        .unwrap_or_else(|| {
            panic!("Pillar call {function} has no typed-semantic upstream match: {actual}")
        });
    let upstream_args = observation["functionArguments"]
        .as_array()
        .expect("upstream arguments");
    let types = observation["functionArgumentTypes"]
        .as_array()
        .expect("upstream argument types");
    for ((expected, actual), ty) in upstream_args.iter().zip(arguments).zip(types) {
        match ty.as_str().expect("Move argument type") {
            "u8" | "u16" | "u32" => assert!(
                actual.is_number(),
                "Pillar JSON Move integer should be numeric: {actual}"
            ),
            "u64" | "u128" | "u256" => assert!(
                actual.is_string(),
                "Pillar JSON large Move integer should be a decimal string: {actual}"
            ),
            _ => {}
        }
        assert_eq!(
            typed_semantic_value(expected, ty.as_str().unwrap()),
            typed_semantic_value(actual, ty.as_str().unwrap())
        );
    }
    let upstream = upstream_request_for_observation(fixture, observation);
    assert_eq!(upstream["method"], "POST");
    assert_eq!(upstream["pathAndQuery"], "/v1/view");
    let upstream_route = upstream["pathAndQuery"].as_str().unwrap();
    let actual_http = captured
        .iter()
        .find(|request| {
            request.method == "POST"
                && request.path == upstream_route.strip_prefix("/v1").unwrap_or(upstream_route)
                && serde_json::from_slice::<Value>(&request.body)
                    .ok()
                    .is_some_and(|body| body["function"] == function)
        })
        .expect("Pillar HTTP view route");
    assert_eq!(actual_http.method, upstream["method"]);
    assert_eq!(
        upstream["headers"]["content-type"],
        "application/x.aptos.view_function+bcs"
    );
    let upstream_hex = upstream["bodyHex"].as_str().expect("upstream BCS body");
    assert!(
        !upstream_hex.is_empty(),
        "upstream captured real BCS request bytes"
    );
}

fn configured_event(
    chain: &str,
    version: &str,
    src_eid: u64,
    dst_eid: u64,
    sender: &str,
    receiver: &str,
) -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.src_chain_name = "ethereum".to_string();
    event.lz_message_id.pathway_id.dst_chain_name = chain.to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("srcEid".to_string(), Value::from(src_eid));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(dst_eid));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("sender".to_string(), Value::from(sender));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("receiver".to_string(), Value::from(receiver));
    event.lz_message_id.nonce = 74_756;
    event.lz_message_id.uln_send_version = Value::from(version);
    event.message = format!("0x{}", "c0ffee".repeat(11));
    event.extra.insert(
        "guid".to_string(),
        Value::from(format!("0x{}", "5a".repeat(32))),
    );
    event
}

#[allow(clippy::too_many_arguments)]
async fn run_production_move_validation(
    fixture: &Value,
    chain: &str,
    version: &str,
    src_eid: u64,
    dst_eid: u64,
    sender: &str,
    receiver: &str,
    requests: usize,
) -> Vec<CapturedMoveRequest> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind");
    let address = listener.local_addr().expect("loopback address");
    let server = tokio::spawn(async move {
        let mut captured = Vec::with_capacity(requests);
        for _ in 0..requests {
            let (stream, _) = listener.accept().await.expect("accept Pillar request");
            captured.push(serve_one(stream).await);
        }
        captured
    });

    let chain_names = vec!["aptos".to_string(), "movement".to_string()];
    let getter = StaticProviderConfig::new(
        IndexMap::from([
            (
                "aptos".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("http://{address}"))],
                    1,
                ),
            ),
            (
                "movement".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("http://{address}"))],
                    1,
                ),
            ),
        ]),
        Some(&chain_names),
    )
    .expect("local Move provider config");
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReqwestJsonRpcTransport::new().expect("production reqwest transport"),
        "mainnet",
        &chain_names,
    )
    .expect("production validator config");
    let event = configured_event(chain, version, src_eid, dst_eid, sender, receiver);
    checks
        .validate_payload_not_signed(&event, Some(&format!("0x{}", "33".repeat(32))), chain)
        .await
        .unwrap_or_else(|error| panic!("production {chain} {version} validator failed: {error}"));
    // Fewer Pillar requests than upstream's capture must fail, not leave accept() waiting.
    let captured = tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap_or_else(|_| {
            panic!("{chain} {version}: Pillar sent fewer than {requests} Move requests")
        })
        .expect("loopback server task");
    assert_eq!(captured.len(), requests);
    let _ = fixture;
    captured
}

fn upstream_data_request_count(fixture: &Value) -> usize {
    fixture["requests"]
        .as_array()
        .expect("upstream requests")
        .iter()
        .filter(|request| {
            let path = request["pathAndQuery"].as_str().expect("upstream route");
            path != "/v1" && !path.contains("/module/")
        })
        .count()
}

// The v14 capture is below `App.validatePayloadSigned`, so it has no receive-library observation to compare.
fn assert_receive_library_lookup_leads(
    fixture: &Value,
    captured: &[CapturedMoveRequest],
    receiver: &str,
    src_eid: u64,
) {
    let upstream_endpoint = fixture["viewObservations"]
        .as_array()
        .expect("upstream typed view observations")
        .iter()
        .filter_map(|observation| observation["function"].as_str())
        .find_map(|function| function.strip_suffix("::endpoint::get_config"))
        .expect("upstream EndpointV2 get_config observation");
    let first = captured.first().expect("Pillar Move requests");
    assert_eq!(
        (first.method.as_str(), first.path.as_str()),
        ("POST", "/view")
    );
    let request: Value = serde_json::from_slice(&first.body).expect("Pillar view JSON");
    assert_eq!(
        request["function"],
        format!("{upstream_endpoint}::endpoint::get_effective_receive_library")
    );
    assert_eq!(
        request["arguments"],
        serde_json::json!([receiver.to_ascii_lowercase(), src_eid])
    );
}

#[tokio::test]
async fn production_reqwest_aptos_v301_and_v302_move_views_match_upstream_wire_semantics() {
    let fixture = aptos_wire_fixture();
    let aptos_sender = "0x50002cdfe7ccb0c41f519c6eb0653158d11cd907";
    let aptos_receiver = "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa";

    let v301 = run_production_move_validation(
        &fixture,
        "aptos",
        "V301",
        101,
        108,
        aptos_sender,
        aptos_receiver,
        8,
    )
    .await;
    for suffix in [
        "::get_receive_msglib",
        "::get_config",
        "::get_verification_confirmations",
        "::verifiable",
        "::inbound_nonce",
    ] {
        assert_view_semantics(&fixture, &v301, suffix);
    }
    let upstream_tables = fixture["requests"].as_array().expect("upstream requests");
    let upstream_channels = upstream_tables
        .iter()
        .find(|request| request["matchedRecording"] == "003-mainnet-bridge-channels")
        .expect("upstream Channels resource request");
    let upstream_channel_path = upstream_channels["pathAndQuery"]
        .as_str()
        .expect("upstream resource route");
    let actual_channels = v301
        .iter()
        .find(|request| {
            request.path
                == upstream_channel_path
                    .strip_prefix("/v1")
                    .unwrap_or(upstream_channel_path)
        })
        .expect("Pillar Channels resource request");
    assert_eq!(actual_channels.method, upstream_channels["method"]);
    assert_eq!(
        actual_channels.status,
        upstream_channels["status"].as_u64().unwrap() as u16
    );
    for marker in [
        "012-mainnet-bridge-channel-remote-101",
        "013-mainnet-bridge-payload_hashs-74756-absent",
    ] {
        let upstream = upstream_tables
            .iter()
            .find(|request| request["matchedRecording"] == marker)
            .expect("upstream table request");
        let actual = v301
            .iter()
            .find(|request| {
                let upstream_path = upstream["pathAndQuery"].as_str().expect("upstream route");
                request.path == upstream_path.strip_prefix("/v1").unwrap_or(upstream_path)
            })
            .unwrap_or_else(|| panic!("Pillar table call missing: {marker}"));
        assert_eq!(actual.method, upstream["method"]);
        assert_eq!(actual.status, upstream["status"].as_u64().unwrap() as u16);
        assert_eq!(
            serde_json::from_slice::<Value>(&actual.body).unwrap(),
            serde_json::from_str::<Value>(upstream["bodyUtf8"].as_str().unwrap()).unwrap()
        );
    }

    let aptos_v302 = run_production_move_validation(
        &fixture,
        "aptos",
        "V302",
        30_101,
        108,
        aptos_sender,
        aptos_receiver,
        4,
    )
    .await;
    assert_receive_library_lookup_leads(&fixture, &aptos_v302, aptos_receiver, 30_101);
    for suffix in [
        "::get_config",
        "::get_verification_confirmations",
        "::verifiable",
    ] {
        assert_view_semantics(&fixture, &aptos_v302, suffix);
    }

    let movement_sender = format!("0x{}", "22".repeat(32));
    let movement_receiver = movement_sender.clone();
    let movement_v302 = run_production_move_validation(
        &fixture,
        "movement",
        "V302",
        30_101,
        40_161,
        &movement_sender,
        &movement_receiver,
        4,
    )
    .await;
    assert_receive_library_lookup_leads(&fixture, &movement_v302, &movement_receiver, 30_101);
    for suffix in [
        "::get_config",
        "::get_verification_confirmations",
        "::verifiable",
    ] {
        assert_view_semantics(&fixture, &movement_v302, suffix);
    }
    assert_eq!(
        v301.len() + aptos_v302.len() + movement_v302.len(),
        upstream_data_request_count(&fixture) + 2,
        "Pillar data requests must equal upstream's plus the two V302 receive-library lookups"
    );
}
