//! Round 2 M-09: unsupported READ codec versions and empty commands are refused
//! before any READ-target RPC or signing; a normal V1 command remains signable.
use super::*;
use tower::ServiceExt;

fn receipt_for(command: &str) -> Value {
    let encoded_payload = format!(
        "01{nonce:016x}{src_eid:08x}{sender:0>64}{dst_eid:08x}{receiver:0>64}{guid}{message}",
        nonce = 7,
        src_eid = 30_101,
        sender = "1111111111111111111111111111111111111111",
        dst_eid = u32::MAX,
        receiver = "2222222222222222222222222222222222222222",
        guid = "bb".repeat(32),
        message = command.strip_prefix("0x").unwrap(),
    );
    let data = format!(
        "0x{}",
        abi_encode_packet_sent(
            &encoded_payload,
            "1234",
            &ethereum_contract("ReadLib1002")[2..].to_lowercase()
        )
    );
    json!({"result": {
        "transactionHash": PACKET_SENT_TX_HASH,
        "blockHash": format!("0x{}", "ab".repeat(32)),
        "blockNumber": "0x60",
        "status": "0x1",
        "logs": [{
            "transactionHash": PACKET_SENT_TX_HASH,
            "blockHash": format!("0x{}", "ab".repeat(32)),
            "blockNumber": "0x60",
            "removed": false,
            "address": ethereum_contract("EndpointV2").to_lowercase(),
            "logIndex": "0x0",
            "topics": [pillar_layerzero::ENDPOINT_V2_PACKET_SENT_TOPIC],
            "data": data,
        }]
    }})
}

fn with_hex_at(command: &str, at: usize, replacement: &str) -> String {
    let mut out = command.to_string();
    out.replace_range(at..at + replacement.len(), replacement);
    out
}

#[tokio::test]
async fn round2_m09_read_codec_versions_and_empty_commands_are_guarded_before_rpc_and_signing() {
    let v1 = evm_read_command_with_block_marker();
    // A V1 map-only compute on bsc at the request's block, so only its version differs.
    let compute = format!(
        "01000100{eid:08x}01{block:016x}{confirmations:04x}{to}",
        eid = 30_102,
        block = 0x40,
        confirmations = 12,
        to = "22".repeat(20),
    );
    let with_compute = format!("{v1}{compute}");
    let zero_no_compute = format!("{}0000", &v1[..10]);
    let compute_only = format!("{zero_no_compute}{compute}");
    let two_requests = evm_read_command_with_repeated_block_markers(2);
    let second_request_start = v1.len();
    let empty_command = Some("READ command must contain at least one request");
    let cases = [
        (
            "command",
            with_hex_at(&v1, 2, "0002"),
            Some("Unsupported READ command version: 2"),
        ),
        (
            "request",
            with_hex_at(&v1, 14, "02"),
            Some("Unsupported READ request version: 2"),
        ),
        (
            "request-after-first",
            with_hex_at(&two_requests, second_request_start, "02"),
            Some("Unsupported READ request version: 2"),
        ),
        (
            "compute",
            with_hex_at(&with_compute, with_compute.len() - compute.len(), "02"),
            Some("Unsupported READ compute version: 2"),
        ),
        ("zero-count", zero_no_compute, empty_command),
        ("compute-only", compute_only, empty_command),
        ("valid-v1", v1.clone(), None),
    ];
    for (field, command, refusal) in cases {
        let encoded_command = command.strip_prefix("0x").unwrap_or(&command);
        let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
        let transport = ReadVerticalTransport {
            calls: calls.clone(),
            receipt: receipt_for(&command),
            chain: ReadChain::Stable,
        };
        let app = RuntimeServerApp::from_env_map_with_runtime_core(
            read_vertical_env_map(),
            transport,
            || 1_767_323_045_000,
        )
        .await
        .unwrap();
        let startup_calls = calls.lock().unwrap().len();
        let metrics = app.metrics().expect("production metrics registry");
        let mut request = read_vertical_request(ReadMarker::BlockNumber);
        request.message_hash = format!(
            "0x{}",
            hex::encode(<sha3::Keccak256 as sha3::Digest>::digest(
                hex::decode(encoded_command).unwrap()
            ))
        );
        let response = pillar_api::router(app, "round2-read-version")
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v2/resolve-and-sign")
                    .header("content-type", "application/json")
                    .header(
                        "authorization",
                        "Bearer test-token-0123456789abcdef0123456789",
                    )
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&request).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let request_calls = calls
            .lock()
            .unwrap()
            .iter()
            .skip(startup_calls)
            .map(|(url, _, body)| {
                format!(
                    "{} {}",
                    if url.contains("bsc-rpc") {
                        "bsc"
                    } else {
                        "ethereum"
                    },
                    body["method"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>();
        let rendered = metrics
            .lock()
            .await
            .render_prometheus("mainnet", "round2-read-version");
        let signed = rendered.lines().any(|line| {
            line.starts_with("pillar_sign_stage_duration_seconds_count")
                && line.contains("stage=\"sign\"")
        });
        audit_round_artifact(
            "round2",
            &format!("m09-read-{field}"),
            json!({
                "command": command,
                "http_status": status,
                "body": body,
                "request_rpc_calls": request_calls,
                "sign_stage_observed": signed,
                "expected_refusal": refusal,
            }),
        );
        let Some(refusal) = refusal else {
            let signatures = body["body"]["signatures"]
                .as_array()
                .expect("successful V1 response signatures");
            assert_eq!(status, 200, "{field}: {body}");
            assert!(!signatures.is_empty(), "{field}: V1 was not signed");
            assert!(signed, "{field}: signer stage did not run");
            assert!(request_calls.contains(&"ethereum eth_getTransactionReceipt".to_string()));
            assert!(request_calls.iter().any(|call| call.starts_with("bsc ")));
            continue;
        };
        assert_eq!(status, 400, "{field}: {body}");
        assert_eq!(body["body"], refusal, "{field}: refused for another reason");
        assert_eq!(
            request_calls,
            ["ethereum eth_getTransactionReceipt"],
            "{field}: only the source receipt may be read before refusal"
        );
        assert!(!signed, "{field}: the signer stage ran");
    }
}
