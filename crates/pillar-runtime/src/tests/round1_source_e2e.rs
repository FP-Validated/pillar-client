use super::*;

fn record(name: &str, value: Value) {
    super::round1_artifact(name, value);
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
