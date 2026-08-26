use super::*;

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
            "0x3333333333333333333333333333333333333333",
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
            "0x3333333333333333333333333333333333333333",
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
            "0x3333333333333333333333333333333333333333",
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
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://starknet.example".to_string())],
                quorum: Some(1),
            },
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
            "0x3333333333333333333333333333333333333333",
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
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://starknet.example".to_string())],
                quorum: Some(1),
            },
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
            "0x3333333333333333333333333333333333333333",
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
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!("https://{chain_name}.example/"))],
                    quorum: Some(1),
                },
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
            .validate_payload_not_signed(&event, "0xdvn", chain_name)
            .await
            .unwrap();
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0, format!("https://{chain_name}.example/view"));
        assert_eq!(calls[0].2["function"], "0xendpoint::endpoint::get_config");
        assert_eq!(calls[1].2["function"], "0xviews::uln_302::verifiable");
        assert_eq!(
            calls[2].2["function"],
            "0xuln302::msglib::get_verification_confirmations"
        );
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_initia_payload() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://initia.example/".to_string())],
                quorum: Some(1),
            },
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
        .validate_payload_not_signed(&event, "0x3333", "initia")
        .await
        .unwrap();
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].0,
        "https://initia.example/initia/move/v1/accounts/0x33/modules/endpoint/view_functions/get_config"
    );
    assert_eq!(calls[0].2["args"].as_array().unwrap().len(), 4);
    assert_eq!(
        calls[1].0,
        "https://initia.example/initia/move/v1/accounts/0x22/modules/uln_302/view_functions/verifiable"
    );
    assert_eq!(calls[1].2["type_args"], json!([]));
    assert_eq!(calls[1].2["args"].as_array().unwrap().len(), 2);
    assert_eq!(
        calls[2].0,
        "https://initia.example/initia/move/v1/accounts/0x11/modules/msglib/view_functions/get_verification_confirmations"
    );
    assert_eq!(calls[2].2["args"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_confirmed_move_payload() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://movement.example/".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["movement".to_string()]),
    )
    .unwrap();
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![
                Ok(json!(["0x0000000000000002"])),
                Ok(json!([0])),
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
        .validate_payload_not_signed(&event, "0xdvn", "movement")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_never_falls_back_to_evm_for_native_payloads() {
    for chain_name in ["stellar"] {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                    quorum: Some(1),
                },
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
            .validate_payload_not_signed(&event, "0x3333", chain_name)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Chain-native payload-signed validation is unavailable"),
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
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                    quorum: Some(1),
                },
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
            .validate_payload_not_signed(&event, "0x3333", chain_name)
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
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://ton.example".to_string())],
                quorum: Some(1),
            },
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
        .validate_payload_not_signed(&event, "0x3333", "ton")
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
            "0x3333333333333333333333333333333333333333",
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
        .validate_extra_context(&payload_signed_sent_event())
        .await
        .unwrap();

    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn runtime_rpc_validation_checks_posts_ts_compatible_extra_context() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_extra_context_checks(
        RuntimeExtraContextConfig {
            request_url: Some("https://policy.example/extra".to_string()),
            request_auth_token: Some("secret-token".to_string()),
            aws_lambda_name: None,
        },
        vec![
            transaction_result("0xABCDEFabcdefABCDEFabcdefABCDEFabcdefabcd"),
            Ok(Value::Bool(true)),
        ],
        calls.clone(),
    );

    checks
        .validate_extra_context(&payload_signed_sent_event())
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "https://eth-rpc.example");
    assert_eq!(
        calls[0].2,
        json!({
            "method": "eth_getTransactionByHash",
            "params": ["0xtx"],
            "id": 1,
            "jsonrpc": "2.0",
        })
    );
    assert_eq!(calls[1].0, "https://policy.example/extra");
    assert_eq!(
        calls[1].1.get("Authorization"),
        Some(&"Bearer secret-token".to_string())
    );
    assert_eq!(
        calls[1].2["from"],
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    );
    assert_eq!(calls[1].2["sentEvent"]["onChainEvent"]["txHash"], "0xtx");
    assert_eq!(
        calls[1].2["sentEvent"]["onChainEvent"]["chainName"],
        "ethereum"
    );
    assert!(calls[1].2["sentEvent"].get("txHash").is_none());
    assert_eq!(calls[1].2["sentEvent"]["lzMessageId"]["nonce"], 7);
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
        .validate_extra_context(&payload_signed_sent_event())
        .await
        .unwrap_err();

    assert_eq!(err.to_string(), "Extra context validation failed");
    assert!(matches!(err, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_invokes_ts_compatible_extra_context_lambda() {
    let rpc_calls = Arc::new(Mutex::new(Vec::new()));
    let lambda_calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_extra_context_checks(
        RuntimeExtraContextConfig {
            request_url: None,
            request_auth_token: None,
            aws_lambda_name: Some("policy-lambda".to_string()),
        },
        vec![transaction_result(
            "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefabcd",
        )],
        rpc_calls.clone(),
    )
    .with_extra_context_lambda_client(Arc::new(RecordingLambdaClient {
        calls: lambda_calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({ "body": true }))])),
    }));

    checks
        .validate_extra_context(&payload_signed_sent_event())
        .await
        .unwrap();

    assert_eq!(rpc_calls.lock().unwrap().len(), 1);
    let lambda_calls = lambda_calls.lock().unwrap();
    assert_eq!(lambda_calls.len(), 1);
    assert_eq!(lambda_calls[0].0, "policy-lambda");
    assert_eq!(
        lambda_calls[0].1["from"],
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    );
    assert_eq!(
        lambda_calls[0].1["sentEvent"]["onChainEvent"]["txHash"],
        "0xtx"
    );
    assert!(lambda_calls[0].1["sentEvent"].get("txHash").is_none());
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
        .validate_extra_context(&payload_signed_sent_event())
        .await
        .unwrap_err();

    assert_eq!(err.to_string(), "Extra context validation failed");
    assert!(matches!(err, AppCoreError::BadRequest(_)));
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
            "4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF",
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
            "4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF",
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
            "4gnov6q1KFcjtwBjepBmQtuf5R4ho4XVkrytY8hk4CTF",
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
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://solana-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    let transport = RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
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
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_move_transaction_from_address() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "movement".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://movement.example/".to_string())],
                quorum: Some(1),
            },
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

#[tokio::test]
async fn runtime_rpc_validation_checks_derives_initia_sender_from_public_key() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "initia".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://initia.example/".to_string())],
                quorum: Some(1),
            },
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
    for (chain_name, method) in [
        ("sui", "sui_getTransactionBlock"),
        ("iotal1", "iota_getTransactionBlock"),
    ] {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                    quorum: Some(1),
                },
            )]),
            Some(&[chain_name.to_string()]),
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let checks = RuntimeRpcValidationChecks::from_getter(
            &ProviderSnapshotHandle::from_getter(&getter),
            RecordingTransport {
                calls: calls.clone(),
                responses: Arc::new(Mutex::new(vec![Ok(json!({
                    "result": {
                        "digest": "0xtx",
                        "checkpoint": "42",
                        "transaction": {"data": {
                            "sender": "0x1234",
                            "transaction": {"kind": "ProgrammableTransaction"}
                        }},
                        "effects": {"status": {"status": "success"}}
                    }
                }))])),
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
        assert_eq!(calls[0].2["method"], method);
        assert_eq!(
            calls[0].2["params"],
            json!(["0xtx", {"showInput": true, "showEffects": true}])
        );
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_failed_sui_transaction_sender() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "sui".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://sui.example".to_string())],
                quorum: Some(1),
            },
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
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://starknet.example".to_string())],
                quorum: Some(1),
            },
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
            ProviderConfig {
                uris: vec![ProviderUri::Uri(provider_uri.to_string())],
                quorum: Some(1),
            },
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
                        "message_content": {"body": "body"}
                    }
                }
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
    assert_eq!(calls[0].0, "https://ton-v3.example/traces/0xtx");
    assert_eq!(calls[0].1["X-API-Key"], "secret");
    assert_eq!(calls[0].2, json!({"method": "GET"}));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_resolves_stellar_transaction_from_address() {
    use base64::Engine;

    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "stellar".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://stellar.example".to_string())],
                quorum: Some(1),
            },
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
