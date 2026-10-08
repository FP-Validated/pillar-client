use super::*;

#[derive(Clone)]
struct ReadConcurrencyTransport {
    active: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl JsonRpcTransport for ReadConcurrencyTransport {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        use std::sync::atomic::Ordering;

        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        eth_call_result("0x1234")
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}

async fn serve_local_read_rpc(
    code_response: Value,
) -> (String, tokio::task::JoinHandle<Vec<Value>>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .expect("localhost RPC accept timed out")
                    .unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let mut content_length = 0;
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some((key, value)) = line.split_once(':') {
                    if key.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse::<usize>().unwrap();
                    }
                }
            }
            let mut body = vec![0; content_length];
            stream.read_exact(&mut body).await.unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let response = if request["method"] == "eth_call" {
                json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": "0x",
                })
            } else {
                let mut response = code_response.clone();
                response["jsonrpc"] = json!("2.0");
                response["id"] = request["id"].clone();
                response
            };
            let response = serde_json::to_vec(&response).unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            stream
                .get_mut()
                .write_all(headers.as_bytes())
                .await
                .unwrap();
            stream.get_mut().write_all(&response).await.unwrap();
            requests.push(request);
        }
        requests
    });
    (format!("http://{address}"), task)
}

async fn run_reqwest_read_code_case(
    code_responses: Vec<Value>,
    quorum: u64,
) -> (
    Result<String, AppCoreError>,
    Vec<tokio::task::JoinHandle<Vec<Value>>>,
) {
    let mut uris = Vec::new();
    let mut servers = Vec::new();
    for code_response in code_responses {
        let (uri, server) = serve_local_read_rpc(code_response).await;
        uris.push(ProviderUri::Uri(uri));
        servers.push(server);
    }
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(uris, quorum),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let resolver = RuntimeEvmReadPayloadResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReqwestJsonRpcTransport::new().unwrap(),
        HashMap::from([(30_102, "bsc".to_string())]),
    );
    let mut sent_event = read_command_sent_event(evm_read_command_with_block_marker());
    sent_event.read_block_pins = bsc_read_block_pins();
    let result = resolver
        .resolve_payload(
            &sent_event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await;
    (result, servers)
}

async fn collect_local_read_rpc_requests(
    servers: Vec<tokio::task::JoinHandle<Vec<Value>>>,
) -> Vec<Value> {
    let mut requests = Vec::new();
    for server in servers {
        requests.extend(
            tokio::time::timeout(std::time::Duration::from_secs(12), server)
                .await
                .expect("localhost RPC server join timed out")
                .unwrap(),
        );
    }
    requests
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_caps_process_wide_rpc_concurrency() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let resolver = RuntimeEvmReadPayloadResolver::new_with_rpc_limit(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReadConcurrencyTransport {
            active: active.clone(),
            peak: peak.clone(),
        },
        HashMap::from([(30_102, "bsc".to_string())]),
        2,
    );

    resolver
        .resolve_payload(
            &LzSentEvent {
                lz_message_id: LzMessageId {
                    pathway_id: PathwayId {
                        src_chain_name: "ethereum".to_string(),
                        dst_chain_name: "bsc".to_string(),
                        extra: IndexMap::new(),
                    },
                    nonce: 1,
                    uln_send_version: Value::from("ReadV1002"),
                },
                message: evm_read_command_with_repeated_block_markers(8),
                tx_hash: "0xtx".to_string(),
                source_evidence: None,
                read_block_pins: bsc_read_block_pins(),
                extra: IndexMap::new(),
            },
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_calls_request_block_marker() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver =
        runtime_evm_read_payload_resolver(vec![eth_call_result("0x1234")], calls.clone());
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 1,
            uln_send_version: Value::from("ReadV1002"),
        },
        message: evm_read_command_with_block_marker(),
        tx_hash: "0xtx".to_string(),
        source_evidence: None,
        read_block_pins: bsc_read_block_pins(),
        extra: IndexMap::new(),
    };
    let resolved = resolver
        .resolve_payload(
            &sent_event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(resolved, "0x1234");
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://bsc-rpc.example");
    assert_eq!(calls[0].2["method"], "eth_call");
    assert_eq!(
        calls[0].2["params"][0]["to"],
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(calls[0].2["params"][0]["data"], "0xdeadbeef");
    assert_eq!(calls[0].2["params"][1], pinned_block(BSC_BLOCK_64_HASH));
}

/// Without a pin for the marker's block the resolver refuses outright. A
/// number-tagged fallback here is exactly the read that can come from a block
/// readiness never looked at, so not even one RPC may be issued.
#[tokio::test]
async fn runtime_evm_read_payload_resolver_refuses_a_block_readiness_did_not_pin() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver =
        runtime_evm_read_payload_resolver(vec![eth_call_result("0x1234")], calls.clone());
    let mut pins = bsc_read_block_pins();
    pins.retain(|pin| pin.block_number != 64);
    let sent_event = LzSentEvent {
        read_block_pins: pins,
        ..read_command_sent_event(evm_read_command_with_block_marker())
    };

    let error = resolver
        .resolve_payload(
            &sent_event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "No validated block identity for chainName bsc block 64; refusing an unpinned read"
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_requires_exact_result_quorum() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = runtime_evm_read_payload_resolver_with_providers(
        vec![
            eth_call_result("0xforged"),
            eth_call_result("0x1234"),
            eth_call_result("0x1234"),
        ],
        calls.clone(),
        vec![
            "https://forged.example".to_string(),
            "https://honest-a.example".to_string(),
            "https://honest-b.example".to_string(),
        ],
        2,
    );
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 1,
            uln_send_version: Value::from("ReadV1002"),
        },
        message: evm_read_command_with_block_marker(),
        tx_hash: "0xtx".to_string(),
        source_evidence: None,
        read_block_pins: bsc_read_block_pins(),
        extra: IndexMap::new(),
    };

    let resolved = resolver
        .resolve_payload(
            &sent_event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(resolved, "0x1234");
    assert_eq!(calls.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_fails_without_exact_result_quorum() {
    let resolver = runtime_evm_read_payload_resolver_with_providers(
        vec![eth_call_result("0xaaaa"), eth_call_result("0xbbbb")],
        Arc::new(Mutex::new(Vec::new())),
        vec![
            "https://rpc-a.example".to_string(),
            "https://rpc-b.example".to_string(),
        ],
        2,
    );
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 1,
            uln_send_version: Value::from("ReadV1002"),
        },
        message: evm_read_command_with_block_marker(),
        tx_hash: "0xtx".to_string(),
        source_evidence: None,
        read_block_pins: bsc_read_block_pins(),
        extra: IndexMap::new(),
    };

    let error = resolver
        .resolve_payload(
            &sent_event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("No ReadV1002 eth_call quorum"));
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_uses_resolved_timestamp_marker() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver =
        runtime_evm_read_payload_resolver(vec![eth_call_result("0xabcd")], calls.clone());
    let sent_event = LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 1,
            uln_send_version: Value::from("ReadV1002"),
        },
        message: evm_read_command_with_timestamp_marker(),
        tx_hash: "0xtx".to_string(),
        source_evidence: None,
        read_block_pins: bsc_read_block_pins(),
        extra: IndexMap::new(),
    };
    let resolved = resolver
        .resolve_payload(
            &sent_event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: vec![ResolvedTimestampTimeMarker {
                    chain_name: "bsc".to_string(),
                    is_block_number: false,
                    timestamp: 1_700_000_000,
                    block_number: 64,
                    block_confirmation: 12,
                }],
            },
        )
        .await
        .unwrap();

    assert_eq!(resolved, "0xabcd");
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].2["params"][1], pinned_block(BSC_BLOCK_64_HASH));
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_applies_only_map_compute() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = runtime_evm_read_payload_resolver(
        vec![eth_call_result("0xaaaa"), abi_bytes_result("0xbbcc")],
        calls.clone(),
    );
    let resolved = resolver
        .resolve_payload(
            &LzSentEvent {
                lz_message_id: LzMessageId {
                    pathway_id: PathwayId {
                        src_chain_name: "ethereum".to_string(),
                        dst_chain_name: "bsc".to_string(),
                        extra: IndexMap::new(),
                    },
                    nonce: 1,
                    uln_send_version: Value::from("ReadV1002"),
                },
                message: evm_read_command_with_compute_setting(0),
                tx_hash: "0xtx".to_string(),
                source_evidence: None,
                read_block_pins: bsc_read_block_pins(),
                extra: IndexMap::new(),
            },
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(resolved, "0xbbcc");
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].2["params"][1], pinned_block(BSC_BLOCK_64_HASH));
    assert_eq!(
        calls[1].2["params"][0]["to"],
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(calls[1].2["params"][1], pinned_block(BSC_BLOCK_65_HASH));
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_applies_only_reduce_compute() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = runtime_evm_read_payload_resolver(
        vec![eth_call_result("0xaaaa"), abi_bytes_result("0xccdd")],
        calls.clone(),
    );
    let resolved = resolver
        .resolve_payload(
            &LzSentEvent {
                lz_message_id: LzMessageId {
                    pathway_id: PathwayId {
                        src_chain_name: "ethereum".to_string(),
                        dst_chain_name: "bsc".to_string(),
                        extra: IndexMap::new(),
                    },
                    nonce: 1,
                    uln_send_version: Value::from("ReadV1002"),
                },
                message: evm_read_command_with_compute_setting(1),
                tx_hash: "0xtx".to_string(),
                source_evidence: None,
                read_block_pins: bsc_read_block_pins(),
                extra: IndexMap::new(),
            },
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(resolved, "0xccdd");
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        calls[1].2["params"][0]["to"],
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(calls[1].2["params"][1], pinned_block(BSC_BLOCK_65_HASH));
}

#[tokio::test]
async fn runtime_evm_read_payload_resolver_applies_map_reduce_compute() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let resolver = runtime_evm_read_payload_resolver(
        vec![
            eth_call_result("0xaaaa"),
            abi_bytes_result("0xbbcc"),
            abi_bytes_result("0xddee"),
        ],
        calls.clone(),
    );
    let resolved = resolver
        .resolve_payload(
            &LzSentEvent {
                lz_message_id: LzMessageId {
                    pathway_id: PathwayId {
                        src_chain_name: "ethereum".to_string(),
                        dst_chain_name: "bsc".to_string(),
                        extra: IndexMap::new(),
                    },
                    nonce: 1,
                    uln_send_version: Value::from("ReadV1002"),
                },
                message: evm_read_command_with_compute_setting(2),
                tx_hash: "0xtx".to_string(),
                source_evidence: None,
                read_block_pins: bsc_read_block_pins(),
                extra: IndexMap::new(),
            },
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
        .unwrap();

    assert_eq!(resolved, "0xddee");
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].2["params"][1], pinned_block(BSC_BLOCK_65_HASH));
    assert_eq!(calls[2].2["params"][1], pinned_block(BSC_BLOCK_65_HASH));
}

#[tokio::test]
async fn reqwest_read_empty_call_smoke_covers_code_and_pinned_quorum() {
    let (no_code, no_code_servers) =
        run_reqwest_read_code_case(vec![json!({ "result": "0x" })], 1).await;
    assert!(matches!(no_code, Err(AppCoreError::UnresolvableCommand(_))));
    let no_code_requests = collect_local_read_rpc_requests(no_code_servers).await;
    assert_eq!(no_code_requests.len(), 2);

    let (deployed_empty, deployed_servers) =
        run_reqwest_read_code_case(vec![json!({ "result": "0x6000" })], 1).await;
    assert_eq!(deployed_empty.unwrap(), "0x");
    let deployed_requests = collect_local_read_rpc_requests(deployed_servers).await;
    assert_eq!(deployed_requests.len(), 2);

    let (pin_rejected, pin_servers) = run_reqwest_read_code_case(
        vec![json!({
            "error": {
                "code": -32000,
                "message": "block no longer canonical for requireCanonical",
            }
        })],
        1,
    )
    .await;
    assert!(matches!(pin_rejected, Err(AppCoreError::Internal(_))));
    let pin_requests = collect_local_read_rpc_requests(pin_servers).await;
    assert_eq!(pin_requests.len(), 2);

    let (one_paired_vote, paired_servers) = run_reqwest_read_code_case(
        vec![
            json!({ "result": "0x6000" }),
            json!({
                "error": {
                    "code": -32000,
                    "message": "code observation unavailable",
                }
            }),
        ],
        2,
    )
    .await;
    assert!(matches!(one_paired_vote, Err(AppCoreError::Internal(_))));
    let paired_requests = collect_local_read_rpc_requests(paired_servers).await;
    assert_eq!(paired_requests.len(), 4);

    for request in no_code_requests
        .iter()
        .chain(deployed_requests.iter())
        .chain(pin_requests.iter())
        .chain(paired_requests.iter())
    {
        assert_eq!(request["params"][1], pinned_block(BSC_BLOCK_64_HASH));
    }
    for requests in [
        no_code_requests.as_slice(),
        deployed_requests.as_slice(),
        pin_requests.as_slice(),
    ] {
        assert_eq!(requests[0]["method"], "eth_call");
        assert_eq!(requests[1]["method"], "eth_getCode");
        assert_eq!(
            requests[0]["params"][0]["to"],
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(
            requests[1]["params"][0],
            "0x1111111111111111111111111111111111111111"
        );
    }
    for requests in paired_requests.as_chunks::<2>().0 {
        assert_eq!(requests[0]["method"], "eth_call");
        assert_eq!(requests[1]["method"], "eth_getCode");
    }
    println!(
        "READ_EMPTY0X_HTTP_SMOKE {}",
        json!({
            "cases": {
                "no_code": {
                    "asserted_outcome": "UnresolvableCommand",
                    "rpc_trace": no_code_requests,
                },
                "deployed_empty_return": {
                    "asserted_outcome": "accepted_as_0x",
                    "rpc_trace": deployed_requests,
                },
                "canonical_pin_rejection": {
                    "asserted_outcome": "rejected",
                    "rpc_trace": pin_requests,
                },
                "two_provider_quorum_one_valid_pair": {
                    "asserted_outcome": "rejected_no_quorum",
                    "rpc_trace_by_provider": paired_requests
                        .as_chunks::<2>().0.iter()
                        .map(|requests| requests.to_vec())
                        .collect::<Vec<_>>(),
                },
            },
        })
    );
}
