use super::*;

fn record(name: &str, value: Value) {
    super::round1_artifact(name, value);
}

fn recorded_solana_request() -> LzMessageId {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/upstream-stage3-events.json"
    ))
    .unwrap();
    let event = &fixture["events"]["solana"]["event"];
    LzMessageId {
        pathway_id: serde_json::from_value(event["pathway"].clone()).unwrap(),
        nonce: event["nonce"].as_u64().unwrap(),
        uln_send_version: event["ulnSendVersion"].clone(),
    }
}

async fn resolve_solana_with_untrusted_large_instruction() -> Result<LzSentEvent, AppCoreError> {
    let mut response: Value = serde_json::from_str(include_str!(
        "../../tests/gasolina_parity/source_replay/solana-getTransaction-jsonParsed.response.json"
    ))
    .unwrap();
    let tx_hash = response
        .pointer("/result/transaction/signatures/0")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let instructions = response["result"]["meta"]["innerInstructions"][0]["instructions"]
        .as_array_mut()
        .unwrap();
    instructions.insert(
        0,
        json!({
            "programId": "untrusted-program",
            "data": "z".repeat(1_000_000)
        }),
    );
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "solana".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://solana.example".to_string())],
                1,
            ),
        )]),
        Some(&["solana".to_string()]),
    )
    .unwrap();
    EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(response)])),
        },
        runtime_evm_layerzero_config("mainnet", &["solana".to_string(), "bsc".to_string()])
            .unwrap()
            .packet_sent_resolver_config,
    )
    .get_lz_sent_event(&tx_hash, &recorded_solana_request())
    .await
}

#[tokio::test]
async fn round1_solana_untrusted_large_instruction_does_not_mask_trusted_packet() {
    if std::env::var_os("PILLAR_ROUND1_M04_CHILD").is_some() {
        let result = resolve_solana_with_untrusted_large_instruction().await;
        record(
            "solana-untrusted-large-instruction-child",
            json!({"result": format!("{result:?}")}),
        );
        assert_eq!(result.unwrap().lz_message_id.nonce, 3826);
        return;
    }
    let started = std::time::Instant::now();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "round1_solana_untrusted_large_instruction_does_not_mask_trusted_packet",
            "--nocapture",
        ])
        .env("PILLAR_ROUND1_M04_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = started + std::time::Duration::from_secs(8);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    record(
        "solana-untrusted-large-instruction-cost-bound",
        json!({
            "completed": status.is_some(),
            "success": status.as_ref().is_some_and(std::process::ExitStatus::success),
            "elapsed_ms": started.elapsed().as_millis()
        }),
    );
    assert!(
        status.is_some_and(|status| status.success()),
        "untrusted 1 MB base58 payload must be skipped before decode"
    );
}

#[tokio::test]
async fn round1_ton_confirmation_arithmetic_rejects_negative_head_and_clamps_behind_head() {
    async fn check(current: i64) -> Result<Vec<pillar_core::ReadBlockPin>, AppCoreError> {
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                "ton".to_string(),
                ProviderConfig::with_distinct_entities(
                    vec![ProviderUri::Uri(
                        "https://ton.example/v2?v3-endpoint=https://ton.example/v3".to_string(),
                    )],
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
                calls,
                responses: Arc::new(Mutex::new(vec![Ok(json!({"last": {"seqno": current}}))])),
            },
        );
        let mut sent_event = readiness_sent_event();
        sent_event.lz_message_id.pathway_id.src_chain_name = "ton".to_string();
        sent_event
            .extra
            .insert("blockNumber".to_string(), json!(20));
        checks
            .validate_readiness(
                &sent_event,
                &SigningContext::Message {
                    expiration: 0,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 0,
                },
            )
            .await
    }

    let negative = check(-1).await;
    let behind = check(10).await;
    record(
        "ton-confirmation-arithmetic",
        json!({"negative_head": format!("{negative:?}"), "head_behind": format!("{behind:?}")}),
    );
    assert!(negative.is_err());
    behind.unwrap();
}
