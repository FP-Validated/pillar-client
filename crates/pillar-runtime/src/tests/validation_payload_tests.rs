use super::*;

fn policy_message_context() -> SigningContext {
    SigningContext::Message {
        expiration: 1_700_000_000,
        skip_v_id: None,
        dvn_address: None,
        block_confirmation: 12,
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_payload() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            // The endpoint is asked which library the receiver receives on
            // before anything is read from a library.
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, true)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            Some("0x3333333333333333333333333333333333333333"),
            "bsc",
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0].0, "https://bsc-rpc.example");
    assert_eq!(calls[0].2["method"], "eth_call");
    assert_eq!(calls[0].2["params"][0]["to"], TEST_ENDPOINT_V2);
    assert_eq!(
        calls[1].2["params"][0]["to"],
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(
        calls[2].2["params"][0]["to"],
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(
        calls[3].2["params"][0]["to"],
        "0x2222222222222222222222222222222222222223"
    );
    assert_eq!(calls[3].2["params"][1], "latest");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_hash_lookup_signed_payload() {
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, true)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(true, 64)),
            eth_call_result(&abi_word(0)),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let err = checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            Some("0x3333333333333333333333333333333333333333"),
            "bsc",
        )
        .await
        .unwrap_err();

    assert!(matches!(err, AppCoreError::BadRequest(_)));
    assert!(err
        .to_string()
        .starts_with("Payload already signed for message {"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_verifiable_verified_payload() {
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, true)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(2)),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let err = checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            Some("0x3333333333333333333333333333333333333333"),
            "bsc",
        )
        .await
        .unwrap_err();

    assert!(matches!(err, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_starknet_payload() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://starknet.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({"result": ["0x0"]}))])),
        },
    )
    .with_starknet_uln_302("0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38");
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "starknet".to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(30_500));

    checks
        .validate_payload_not_signed(
            &event,
            Some("0x3333333333333333333333333333333333333333"),
            "starknet",
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2["method"], "starknet_call");
    assert_eq!(
        calls[0].2["params"][0]["contract_address"],
        "0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_signed_starknet_payload() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://starknet.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({"result": ["0x1"]}))])),
        },
    )
    .with_starknet_uln_302("0x0727f40349719ac76861a51a0b3d3e07be1577fff137bb81a5dc32e5a5c61d38");
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "starknet".to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(30_500));

    let error = checks
        .validate_payload_not_signed(
            &event,
            Some("0x3333333333333333333333333333333333333333"),
            "starknet",
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)));
    assert!(error.to_string().starts_with("Payload already signed"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_move_payloads() {
    for chain_name in ["aptos", "movement"] {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    1,
                ),
            )]),
            Some(&[chain_name.to_string()]),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(vec![
                    Ok(json!([
                        "0x4444444444444444444444444444444444444444444444444444444444444444"
                    ])),
                    Ok(json!(["0x0000000000000002"])),
                    Ok(json!([0])),
                    Ok(json!([1])),
                ])),
            },
        )
        .with_move_payload_contracts(
            HashMap::from([(chain_name.to_string(), "0xendpoint".to_string())]),
            HashMap::from([(chain_name.to_string(), "0xuln302".to_string())]),
            HashMap::from([(chain_name.to_string(), "0xviews".to_string())]),
        );
        let mut event = payload_signed_sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = chain_name.to_string();

        checks
            .validate_payload_not_signed(&event, Some("0xdvn"), chain_name)
            .await
            .unwrap();
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[0].2["function"],
            "0xendpoint::endpoint::get_effective_receive_library"
        );
        assert_eq!(calls[1].2["function"], "0xendpoint::endpoint::get_config");
        assert_eq!(calls[2].2["function"], "0xviews::uln_302::verifiable");
        assert_eq!(
            calls[3].2["function"],
            "0xuln302::msglib::get_verification_confirmations"
        );
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_initia_payload() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://initia.example/".to_string())],
                1,
            ),
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![
                Ok(json!({"data": "[\"0x0000000000000003\"]"})),
                Ok(json!({"data": "[\"0x0000000000000002\"]"})),
                Ok(json!({"data": "[0]"})),
                Ok(json!({"data": "[0]"})),
            ])),
        },
    )
    .with_move_payload_contracts(
        HashMap::from([("initia".to_string(), "0x33".to_string())]),
        HashMap::from([("initia".to_string(), "0x11".to_string())]),
        HashMap::from([("initia".to_string(), "0x22".to_string())]),
    );
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "initia".to_string();

    checks
        .validate_payload_not_signed(&event, Some("0x3333"), "initia")
        .await
        .unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    assert!(calls[0]
        .0
        .ends_with("endpoint/view_functions/get_effective_receive_library"));
    assert_eq!(calls[0].2["args"].as_array().unwrap().len(), 2);
    assert_eq!(
        calls[1].0,
        "https://initia.example/initia/move/v1/accounts/0x33/modules/endpoint/view_functions/get_config"
    );
    assert_eq!(calls[1].2["args"].as_array().unwrap().len(), 4);
    assert_eq!(
        calls[2].0,
        "https://initia.example/initia/move/v1/accounts/0x22/modules/uln_302/view_functions/verifiable"
    );
    assert_eq!(calls[2].2["type_args"], json!([]));
    assert_eq!(calls[2].2["args"].as_array().unwrap().len(), 2);
    assert_eq!(
        calls[3].0,
        "https://initia.example/initia/move/v1/accounts/0x11/modules/msglib/view_functions/get_verification_confirmations"
    );
    assert_eq!(calls[3].2["args"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_confirmed_move_payload() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://movement.example/".to_string())],
                1,
            ),
        )]),
        Some(&["movement".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(json!([
                    "0x4444444444444444444444444444444444444444444444444444444444444444"
                ])),
                Ok(json!(["0x0000000000000002"])),
                Ok(json!([0])),
                Ok(json!([2])),
                Ok(json!([2])),
            ])),
        },
    )
    .with_move_payload_contracts(
        HashMap::from([("movement".to_string(), "0xendpoint".to_string())]),
        HashMap::from([("movement".to_string(), "0xuln302".to_string())]),
        HashMap::from([("movement".to_string(), "0xviews".to_string())]),
    );
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "movement".to_string();

    let error = checks
        .validate_payload_not_signed(&event, Some("0xdvn"), "movement")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_never_falls_back_to_evm_for_native_payloads() {
    for chain_name in ["stellar", "canton"] {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                    1,
                ),
            )]),
            Some(&[chain_name.to_string()]),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(vec![])),
            },
        );
        let mut event = payload_signed_sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = chain_name.to_string();

        let error = checks
            .validate_payload_not_signed(&event, Some("0x3333"), chain_name)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, AppCoreError::Internal(message)
                if message.contains("No Stellar payload-signed contracts configured")
                    || message == "Missing \"sequencer\" provider config for chain: canton"),
            "{chain_name}: {error}"
        );
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_never_falls_back_to_evm_for_unconfigured_sui() {
    // Sui and IOTA have a chain-native path, but a validator built without the
    // Sui contract table must fail closed rather than use the EVM lookup.
    for chain_name in ["sui", "iotal1"] {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                    1,
                ),
            )]),
            Some(&[chain_name.to_string()]),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(vec![])),
            },
        );
        let mut event = payload_signed_sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = chain_name.to_string();

        let error = checks
            .validate_payload_not_signed(&event, Some("0x3333"), chain_name)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("No Sui LayerZero contracts configured"),
            "{chain_name}: {error}"
        );
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_never_falls_back_to_evm_for_unconfigured_ton() {
    // TON has a chain-native path, but a validator built without the TON ULN
    // contracts must still fail closed instead of using the EVM lookup.
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://ton.example".to_string())],
                1,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![])),
        },
    );
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "ton".to_string();

    let error = checks
        .validate_payload_not_signed(&event, Some("0x3333"), "ton")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("No TON LayerZero contracts configured"),
        "{error}"
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_skips_legacy_payload_without_guid() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(vec![], calls.clone());
    let mut sent_event = payload_signed_sent_event();
    sent_event.extra.clear();

    checks
        .validate_payload_not_signed(
            &sent_event,
            Some("0x3333333333333333333333333333333333333333"),
            "bsc",
        )
        .await
        .unwrap();

    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_skips_extra_context_when_unconfigured() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_extra_context_checks(
        RuntimeExtraContextConfig::default(),
        vec![],
        calls.clone(),
    );

    checks
        .validate_extra_context(&payload_signed_sent_event(), &policy_message_context())
        .await
        .unwrap();

    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_read_signing_context_controls_local_policy_verdict() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local policy and RPC server");
    let address = listener.local_addr().expect("local test server address");
    let policy_server = tokio::spawn(async move {
        let mut policy_verdicts = Vec::with_capacity(2);
        for _ in 0..4 {
            let (stream, _) =
                tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                    .await
                    .expect("local policy/RPC request timed out")
                    .expect("accept local policy/RPC request");
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream
                .read_line(&mut line)
                .await
                .expect("read request line");
            let mut content_length = 0usize;
            loop {
                line.clear();
                stream
                    .read_line(&mut line)
                    .await
                    .expect("read request headers");
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().expect("valid content length");
                    }
                }
            }
            let mut body = vec![0; content_length];
            stream
                .read_exact(&mut body)
                .await
                .expect("read request body");
            let request: Value = serde_json::from_slice(&body).expect("JSON request body");
            let response = if request.get("method").is_some() {
                json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {
                        "hash": "0xtx",
                        "from": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                        "to": "0x2222222222222222222222222222222222222222",
                        "input": "0xdeadbeef",
                    },
                })
            } else {
                let context = &request["signingContext"];
                let markers = &context["resolvedTimestampTimeMarkers"];
                let allowed = request["from"] == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
                    && context["protocolType"] == "READ"
                    && context.get("skipVId").is_none()
                    && context.get("dvnAddress").is_none()
                    && context["expiration"] == 1_700_000_001
                    && markers.as_array().is_some_and(|markers| {
                        markers.len() == 1
                            && markers[0]["blockConfirmation"] == 4
                            && markers[0]["isBlockNumber"] == true
                            && markers[0]["chainName"] == "ethereum"
                            && markers[0]["blockNumber"] == 99
                            && markers[0]["timestamp"] == 1_700_000_000
                    });
                policy_verdicts.push(allowed);
                json!(allowed)
            };
            let response = serde_json::to_vec(&response).expect("serialize local response");
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            stream
                .get_mut()
                .write_all(headers.as_bytes())
                .await
                .expect("write response headers");
            stream
                .get_mut()
                .write_all(&response)
                .await
                .expect("write response body");
        }
        policy_verdicts
    });

    let provider_url = format!("http://{address}");
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig::with_distinct_entities(vec![ProviderUri::Uri(provider_url.clone())], 1),
        )]),
        Some(&["ethereum".to_string()]),
    )
    .expect("local source RPC provider config");
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReqwestJsonRpcTransport::new().expect("production reqwest transport"),
    )
    .with_extra_context(RuntimeExtraContextConfig {
        request_url: Some(format!("{provider_url}/verify")),
        request_auth_token: None,
        aws_lambda_name: None,
    });
    let event = payload_signed_sent_event();
    let valid_context = SigningContext::Read {
        expiration: 1_700_000_001,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: vec![ResolvedTimestampTimeMarker {
            block_confirmation: 4,
            is_block_number: true,
            chain_name: "ethereum".to_string(),
            block_number: 99,
            timestamp: 1_700_000_000,
        }],
    };

    let allowed = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        checks.validate_extra_context(&event, &valid_context),
    )
    .await
    .expect("valid READ policy validation timed out");
    assert!(
        allowed.is_ok(),
        "valid READ context was rejected: {allowed:?}"
    );

    let mut altered_context = valid_context.clone();
    if let SigningContext::Read {
        resolved_timestamp_time_markers,
        ..
    } = &mut altered_context
    {
        resolved_timestamp_time_markers[0].timestamp += 1;
    }
    let denied = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        checks.validate_extra_context(&event, &altered_context),
    )
    .await
    .expect("altered READ policy validation timed out");
    assert!(matches!(denied, Err(AppCoreError::BadRequest(_))));

    let verdicts = tokio::time::timeout(std::time::Duration::from_secs(10), policy_server)
        .await
        .expect("local policy server timed out")
        .expect("local policy server task failed");
    assert_eq!(verdicts, vec![true, false]);
    println!(
        "{}",
        json!({
            "event": "read_signing_context_policy_consumer_e2e",
            "transport": "ReqwestJsonRpcTransport",
            "validation_path": "RuntimeRpcValidationChecks.validate_extra_context",
            "observations": [
                { "case": "valid_marker", "policy_verdict": "allow", "validation": "accepted" },
                { "case": "changed_marker_timestamp", "policy_verdict": "deny", "validation": "rejected" },
            ],
        })
    );
}
#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_false_extra_context_response() {
    let checks = runtime_rpc_extra_context_checks(
        RuntimeExtraContextConfig {
            request_url: Some("https://policy.example/extra".to_string()),
            request_auth_token: None,
            aws_lambda_name: None,
        },
        vec![
            transaction_result("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
            Ok(Value::Bool(false)),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let err = checks
        .validate_extra_context(&payload_signed_sent_event(), &policy_message_context())
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .starts_with("Extra context validation failed:"));
    assert!(matches!(err, AppCoreError::BadRequest(_)));
}
#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_non_boolean_extra_context_responses() {
    let responses = [
        (json!("false"), "string"),
        (json!("true"), "string"),
        (json!({}), "object"),
        (json!([]), "array"),
        (json!({ "allow": false }), "object"),
        (json!(0), "number"),
        (json!(1), "number"),
        (Value::Null, "null"),
    ];

    for (policy_response, received_type) in responses {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let checks = runtime_rpc_extra_context_checks(
            RuntimeExtraContextConfig {
                request_url: Some("https://policy.example/extra".to_string()),
                request_auth_token: None,
                aws_lambda_name: None,
            },
            vec![
                transaction_result("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
                Ok(policy_response),
            ],
            calls.clone(),
        );

        let err = checks
            .validate_extra_context(&payload_signed_sent_event(), &policy_message_context())
            .await
            .unwrap_err();

        assert!(matches!(err, AppCoreError::BadRequest(_)));
        assert!(err.to_string().contains(received_type));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2, "policy response was not requested");
        assert_eq!(calls[1].0, "https://policy.example/extra");
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_false_lambda_body() {
    let checks = runtime_rpc_extra_context_checks(
        RuntimeExtraContextConfig {
            request_url: None,
            request_auth_token: None,
            aws_lambda_name: Some("policy-lambda".to_string()),
        },
        vec![transaction_result(
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        )],
        Arc::new(Mutex::new(Vec::new())),
    )
    .with_extra_context_lambda_client(Arc::new(RecordingLambdaClient {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "body": false }))])),
    }));

    let err = checks
        .validate_extra_context(&payload_signed_sent_event(), &policy_message_context())
        .await
        .unwrap_err();

    assert!(err
        .to_string()
        .starts_with("Extra context validation failed:"));
    assert!(matches!(err, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_sends_the_typed_signing_context_to_the_policy_lambda() {
    let lambda_calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_extra_context_checks(
        RuntimeExtraContextConfig {
            request_url: None,
            request_auth_token: None,
            aws_lambda_name: Some("policy-lambda".to_string()),
        },
        vec![transaction_result(
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        )],
        Arc::new(Mutex::new(Vec::new())),
    )
    .with_extra_context_lambda_client(Arc::new(RecordingLambdaClient {
        calls: lambda_calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "body": true }))])),
    }));

    checks
        .validate_extra_context(&payload_signed_sent_event(), &policy_message_context())
        .await
        .expect("the policy Lambda allowed the request");

    let calls = lambda_calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    let (function_name, payload) = &calls[0];
    assert_eq!(function_name, "policy-lambda");
    assert_eq!(
        payload["signingContext"],
        serde_json::to_value(policy_message_context()).unwrap()
    );
    assert_eq!(
        payload["from"],
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    );
    assert!(payload["sentEvent"].is_object(), "{payload}");
}
#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_unsafe_lambda_responses() {
    let responses = [
        (Ok(json!({ "statusCode": 403, "body": "false" })), false),
        (
            Err("Lambda invocation reported a function error".to_string()),
            true,
        ),
    ];

    for (lambda_response, is_invocation_error) in responses {
        let rpc_calls = Arc::new(Mutex::new(Vec::new()));
        let lambda_calls = Arc::new(Mutex::new(Vec::new()));
        let checks = runtime_rpc_extra_context_checks(
            RuntimeExtraContextConfig {
                request_url: None,
                request_auth_token: None,
                aws_lambda_name: Some("policy-lambda".to_string()),
            },
            vec![transaction_result(
                "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            )],
            rpc_calls.clone(),
        )
        .with_extra_context_lambda_client(Arc::new(RecordingLambdaClient {
            calls: lambda_calls.clone(),
            responses: Arc::new(Mutex::new(vec![lambda_response])),
        }));

        let err = checks
            .validate_extra_context(&payload_signed_sent_event(), &policy_message_context())
            .await
            .unwrap_err();

        if is_invocation_error {
            assert!(matches!(&err, AppCoreError::Internal(_)));
        } else {
            assert!(matches!(&err, AppCoreError::BadRequest(_)));
            assert!(err.to_string().contains("statusCode"));
        }
        assert_eq!(rpc_calls.lock().unwrap().len(), 1);
        assert_eq!(lambda_calls.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_solana_payload() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_solana_payload_checks(
        vec![get_multiple_accounts_result([
            None,
            None,
            None,
            Some(solana_receive_config_account_bytes(5)),
            None,
        ])],
        calls.clone(),
    );

    checks
        .validate_payload_not_signed(
            &payload_signed_solana_sent_event(),
            Some("4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF"),
            "solana",
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "https://solana-rpc.example");
    assert_eq!(calls[0].2["method"], "getMultipleAccounts");
    let pubkeys = calls[0].2["params"][0].as_array().unwrap();
    assert_eq!(pubkeys.len(), 5);
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_already_signed_solana_payload() {
    let checks = runtime_rpc_solana_payload_checks(
        vec![get_multiple_accounts_result([
            None,
            None,
            None,
            Some(solana_receive_config_account_bytes(1)),
            Some(solana_confirmations_account_bytes(Some(1))),
        ])],
        Arc::new(Mutex::new(Vec::new())),
    );

    let err = checks
        .validate_payload_not_signed(
            &payload_signed_solana_sent_event(),
            Some("4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF"),
            "solana",
        )
        .await
        .unwrap_err();

    assert!(matches!(err, AppCoreError::BadRequest(_)));
    assert!(err
        .to_string()
        .starts_with("Payload already signed for message {"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_already_delivered_solana_payload() {
    let checks = runtime_rpc_solana_payload_checks(
        vec![get_multiple_accounts_result([
            Some(solana_nonce_account_bytes(7)),
            None,
            None,
            Some(solana_receive_config_account_bytes(5)),
            None,
        ])],
        Arc::new(Mutex::new(Vec::new())),
    );

    let err = checks
        .validate_payload_not_signed(
            &payload_signed_solana_sent_event(),
            Some("4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF"),
            "solana",
        )
        .await
        .unwrap_err();

    // Already delivered (inboundNonce >= packet nonce) counts as "already
    // signed" the same way TypeScript's `isVerified` does.
    assert!(err
        .to_string()
        .starts_with("Payload already signed for message {"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_solana_transaction_from_address() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![solana_transaction_result(
            "6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA",
        )])),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    );

    let from = checks
        .source_transaction_from_address("solana", "5signaturebase58")
        .await
        .unwrap();

    // Solana returns the fee payer (accountKeys[0].pubkey) verbatim in base58,
    // not lowercased hex like EVM. Only the Solana branch can parse this
    // getTransaction shape (the EVM branch reads result.from, absent here),
    // so a successful extraction proves the branch dispatched on chain type.
    // Matches TS RpcSolanaSdk.getFromAddress.
    assert_eq!(from, "6td1W4vFnQsKKunmKprARgpMEtYdVBnZ2FVcpqxKxaoA");
    // This path keeps its default commitment, but it must opt into v1 like the
    // resolver and readiness reads: `getTransaction` answers -32015 for a newer
    // transaction than the requested ceiling, so a 0 here blinds fee-payer
    // observation to every v1 source transaction.
    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].2,
        json!({
            "method": "getTransaction",
            "params": [
                "5signaturebase58",
                {
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 1,
                },
            ],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_move_transaction_from_address() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://movement.example/".to_string())],
                1,
            ),
        )]),
        Some(&["movement".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "hash": "0xtx",
                "sender": "0xABCDEF",
                "events": []
            }))])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("movement", "0xtx")
            .await
            .unwrap(),
        "0xabcdef"
    );
    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].0,
        "https://movement.example/transactions/by_hash/0xtx"
    );
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

/// A ULNv2 send names its ledger version; upstream's `getTransactionByHashOrVersion`
/// reads it with `BigInt`, so leading zeros do not reach the URL.
#[tokio::test]
async fn runtime_rpc_validation_checks_reads_aptos_sender_by_ledger_version() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "aptos".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://aptos.example/v1".to_string())],
                1,
            ),
        )]),
        Some(&["aptos".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "version": "26629",
                "sender": "0xABCDEF",
                "events": []
            }))])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("aptos", "026629")
            .await
            .unwrap(),
        "0xabcdef"
    );
    assert_eq!(
        calls.lock().unwrap()[0].0,
        "https://aptos.example/v1/transactions/by_version/26629"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_derives_initia_sender_from_public_key() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://initia.example/".to_string())],
                1,
            ),
        )]),
        Some(&["initia".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "tx_response": {
                    "txhash": "ABC",
                    "tx": {"auth_info": {"signer_infos": [{"public_key": {
                        "@type": "/cosmos.crypto.secp256k1.PubKey",
                        "key": "Anm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeY"
                    }}]}},
                    "events": []
                }
            }))])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("initia", "ABC")
            .await
            .unwrap(),
        "init1w508d6qejxtdg4y5r3zarvary0c5xw7k5thfy6"
    );
    assert_eq!(
        calls.lock().unwrap()[0].0,
        "https://initia.example/cosmos/tx/v1beta1/txs/ABC"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_sui_and_iota_transaction_from_address() {
    for chain_name in ["sui", "iotal1"] {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                    1,
                ),
            )]),
            Some(&[chain_name.to_string()]),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let response = if chain_name == "sui" {
            json!({"data":{"transaction":{"digest":"0xtx","sender":{"address":"0x1234"},"transactionBcs":"AQI=","effects":{"checkpoint":{"sequenceNumber":"42"},"status":"SUCCESS"}}}})
        } else {
            json!({"result":{"digest":"0xtx","checkpoint":"42","transaction":{"data":{"sender":"0x1234","transaction":{"kind":"ProgrammableTransaction"}}},"effects":{"status":{"status":"success"}}}})
        };
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(vec![Ok(response)])),
            },
        );

        assert_eq!(
            checks
                .source_transaction_from_address(chain_name, "0xtx")
                .await
                .unwrap(),
            "0x1234"
        );
        let calls = calls.lock().unwrap();
        if chain_name == "sui" {
            assert!(calls[0].2["query"]
                .as_str()
                .unwrap()
                .contains("transaction(digest: $digest)"));
            assert_eq!(calls[0].2["variables"]["digest"], "0xtx");
        } else {
            assert_eq!(calls[0].2["method"], "iota_getTransactionBlock");
            assert_eq!(
                calls[0].2["params"],
                json!(["0xtx", {"showInput": true, "showEffects": true}])
            );
        }
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_failed_sui_transaction_sender() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sui".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://sui.example".to_string())],
                1,
            ),
        )]),
        Some(&["sui".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": {
                    "digest": "0xtx",
                    "checkpoint": "42",
                    "transaction": {"data": {
                        "sender": "0x1234",
                        "transaction": {"kind": "ProgrammableTransaction"}
                    }},
                    "effects": {"status": {"status": "failure"}}
                }
            }))])),
        },
    );

    let error = checks
        .source_transaction_from_address("sui", "0xtx")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_starknet_transaction_from_address() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "starknet".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://starknet.example".to_string())],
                1,
            ),
        )]),
        Some(&["starknet".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": {
                    "transaction_hash": "0xtx",
                    "sender_address": "0x1234",
                    "calldata": [],
                    "nonce": "0x1",
                    "version": "0x3",
                    "type": "INVOKE"
                }
            }))])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("starknet", "0xtx")
            .await
            .unwrap(),
        "0x1234"
    );
    assert_eq!(
        calls.lock().unwrap()[0].2["method"],
        "starknet_getTransactionByHash"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_ton_transaction_from_address() {
    let provider_uri =
        "https://ton-v2.example?api-key=secret&v3-endpoint=https%3A%2F%2Fton-v3.example";
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(provider_uri.to_string())],
                1,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "transaction": {
                    "mc_block_seqno": 42,
                    "in_msg": {
                        "destination": format!("0:{}", "11".repeat(32)),
                        "hash": "tx-hash",
                        "message_content": {
                            "body": pillar_layerzero::ton_boc_to_base64(&ton_core::cell::TonCell::empty().clone()).unwrap()
                        }
                    }
                },
                "children": []
            }))])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("ton", "0xtx")
            .await
            .unwrap(),
        format!("0x{}", "11".repeat(32))
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].0, "https://ton-v3.example/events?tx_hash=0xtx");
    assert_eq!(calls[0].1["X-API-Key"], "secret");
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn ton_sender_extra_context_uses_projection_quorum_for_seqno_disagreement() {
    let uris = [
        "https://ton-a.example?v3-endpoint=https%3A%2F%2Fton-a.example%2Fv3",
        "https://ton-b.example?v3-endpoint=https%3A%2F%2Fton-b.example%2Fv3",
        "https://ton-c.example?v3-endpoint=https%3A%2F%2Fton-c.example%2Fv3",
    ];
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                uris.into_iter()
                    .map(|uri| ProviderUri::Uri(uri.to_string()))
                    .collect(),
                2,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let body = pillar_layerzero::ton_boc_to_base64(ton_core::cell::TonCell::empty()).unwrap();
    let trace = |seqno| {
        json!({
            "transaction": {
                "mc_block_seqno": seqno,
                "in_msg": {
                    "destination": format!("0:{}", "11".repeat(32)),
                    "source": "0:2222222222222222222222222222222222222222222222222222222222222222",
                    "hash": "tx-hash",
                    "message_content": { "body": body }
                }
            },
            "children": []
        })
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(trace(42)),
                Ok(trace(42)),
                Ok(trace(43)),
            ])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("ton", "0xtx")
            .await
            .unwrap(),
        format!("0x{}", "11".repeat(32))
    );
}

#[tokio::test]
async fn ton_sender_extra_context_excludes_missing_in_msg_provider_vote() {
    let uris = [
        "https://ton-a.example?v3-endpoint=https%3A%2F%2Fton-a.example%2Fv3",
        "https://ton-b.example?v3-endpoint=https%3A%2F%2Fton-b.example%2Fv3",
        "https://ton-c.example?v3-endpoint=https%3A%2F%2Fton-c.example%2Fv3",
    ];
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ton".to_string(),
            ProviderConfig::with_distinct_entities(
                uris.into_iter()
                    .map(|uri| ProviderUri::Uri(uri.to_string()))
                    .collect(),
                2,
            ),
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let body = pillar_layerzero::ton_boc_to_base64(ton_core::cell::TonCell::empty()).unwrap();
    let trace = |seqno, missing_child| {
        let mut value = json!({
            "transaction": {
                "mc_block_seqno": seqno,
                "in_msg": {
                    "destination": format!("0:{}", "11".repeat(32)),
                    "source": "0:2222222222222222222222222222222222222222222222222222222222222222",
                    "hash": "tx-hash",
                    "message_content": { "body": body }
                }
            },
            "children": []
        });
        if missing_child {
            value["children"] = json!([{ "transaction": {}, "children": [] }]);
        }
        value
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(trace(42, false)),
                Ok(trace(43, false)),
                Ok(trace(42, true)),
            ])),
        },
    );

    let error = checks
        .source_transaction_from_address("ton", "0xtx")
        .await
        .expect_err("missing in_msg loses its vote, leaving no two-provider quorum");
    assert!(
        matches!(error, AppCoreError::Internal(_)),
        "expected no-quorum failure after the malformed provider is excluded: {error:?}"
    );
}
#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_stellar_transaction_from_address() {
    use base64::Engine;

    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://stellar.example".to_string())],
                1,
            ),
        )]),
        Some(&["stellar".to_string()]),
    )
    .unwrap();
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&2_i32.to_be_bytes());
    envelope.extend_from_slice(&0_i32.to_be_bytes());
    envelope.extend_from_slice(&[0x22; 32]);
    let envelope_xdr = base64::engine::general_purpose::STANDARD.encode(envelope);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": {
                    "status": "SUCCESS",
                    "ledger": 42,
                    "envelopeXdr": envelope_xdr
                }
            }))])),
        },
    );

    assert_eq!(
        checks
            .source_transaction_from_address("stellar", "0xtx")
            .await
            .unwrap(),
        "GARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCFRVX"
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0].2["method"], "getTransaction");
    assert_eq!(calls[0].2["params"], json!({"hash": "0xtx"}));
}

/// Companion to the timestamp exhaustiveness test, for the `_ => generic EVM` arm at
/// `validation_extra_context.rs:144`. That arm calls `observe_transaction_from`, which
/// issues `eth_getTransactionByHash`. A non-EVM chain reaching it would have its source
/// address read with Ethereum semantics, and because every arm there ends in `.ok()`,
/// the failure would arrive as a missing quorum observation rather than an error naming
/// the real cause.
#[tokio::test]
async fn no_non_evm_chain_falls_through_to_the_evm_transaction_from_default() {
    for chain_name in &super::validation_timestamp_tests::non_evm_chain_roster() {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.clone(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    1,
                ),
            )]),
            Some(std::slice::from_ref(chain_name)),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(vec![Ok(json!({})); 32])),
        };
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            transport,
        );

        let _ = checks
            .source_transaction_from_address(chain_name, "0xtx")
            .await;

        for (_, _, body) in calls.lock().unwrap().iter() {
            assert_ne!(
                body["method"], "eth_getTransactionByHash",
                "{chain_name} is a non-EVM chain but reached the EVM transaction-from \
                 default, so its source address would be read with Ethereum semantics"
            );
        }
    }
}

/// The fourth dispatch site: `validation_payload.rs`. Its EVM fallback begins with a
/// receive-contract lookup (`validation_payload.rs:78-86`) that names EVM in its error,
/// and the harness configures none - so reaching the EVM path is observable as that
/// exact error, without needing the path to issue an RPC at all.
///
/// This is the check that decides whether a payload has already been signed, so a
/// non-EVM chain answered through the EVM receive contracts would be asking the wrong
/// contract whether this DVN already verified the packet.
#[tokio::test]
async fn no_non_evm_chain_falls_through_to_the_evm_payload_check() {
    let event = payload_signed_sent_event();
    assert!(
        event.extra.contains_key("guid"),
        "the fixture must carry a guid, or validation_payload.rs:12-14 returns Ok before \
         any chain dispatch and this test proves nothing"
    );

    for chain_name in &super::validation_timestamp_tests::non_evm_chain_roster() {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.clone(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    1,
                ),
            )]),
            Some(std::slice::from_ref(chain_name)),
        )
        .unwrap();
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(vec![Ok(json!({})); 32])),
            },
        );
        let mut event = payload_signed_sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = chain_name.clone();

        let outcome = checks
            .validate_payload_not_signed(
                &event,
                Some("0x3333333333333333333333333333333333333333"),
                chain_name,
            )
            .await;

        if let Err(error) = outcome {
            assert!(
                !error
                    .to_string()
                    .contains("No EVM LayerZero receive contracts"),
                "{chain_name} is a non-EVM chain but reached the EVM payload check, so \
                 whether this DVN already signed would be read from EVM receive contracts"
            );
        }
    }
}
