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

#[tokio::test]
async fn runtime_evm_read_payload_resolver_caps_process_wide_rpc_concurrency() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                quorum: Some(1),
            },
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
    assert_eq!(calls[0].2["params"][1], "0x40");
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
    assert_eq!(calls[0].2["params"][1], "0x40");
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
    assert_eq!(calls[0].2["params"][1], "0x40");
    assert_eq!(
        calls[1].2["params"][0]["to"],
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(calls[1].2["params"][1], "0x41");
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
    assert_eq!(calls[1].2["params"][1], "0x41");
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
    assert_eq!(calls[1].2["params"][1], "0x41");
    assert_eq!(calls[2].2["params"][1], "0x41");
}
