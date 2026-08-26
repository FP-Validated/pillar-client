use super::*;

#[tokio::test]
async fn destination_router_rejects_unsupported_non_evm_destination() {
    let recorder = Arc::new(Recorder::default());
    let router = Arc::new(
        DestinationUlnPayloadBuilderRouter::new(
            recorder.clone(),
            recorder.clone(),
            recorder.clone(),
        )
        .with_unsupported_non_evm_destinations(vec!["solana".to_string()]),
    );
    let builders = build_hash_call_data_builders(
        router.clone(),
        router.clone(),
        router,
        recorder.clone(),
        "mainnet",
    );
    let mut event = sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "solana".to_string();

    let err = builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &event,
            &SigningContext::Message {
                expiration: 2,
                skip_v_id: Some(true),
                dvn_address: Some("0xdvn".to_string()),
                block_confirmation: 1,
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Unsupported LayerZero destination chain type for solana"
    );
    assert!(recorder.calls.lock().await.is_empty());
}

#[test]
fn non_evm_vector_corpus_records_upstream_source_metadata() {
    let corpus: Value = serde_json::from_str(UPSTREAM_NON_EVM_LAYERZERO_VECTORS).unwrap();

    assert_eq!(corpus["schemaVersion"], 1);
    assert!(corpus["source"]["package"]
        .as_str()
        .is_some_and(|package| !package.is_empty()));
    assert!(corpus["source"]["packageVersion"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));
    assert_eq!(corpus["source"]["files"].as_array().unwrap().len(), 7);

    let vectors = corpus["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for vector in vectors {
        assert!(vector["todo"].as_str().unwrap().starts_with("Todo "));
        assert!(!vector["chainNames"].as_array().unwrap().is_empty());
        assert!(!vector["upstreamBehavior"].as_object().unwrap().is_empty());
        let current_rust_behavior = vector["currentRustBehavior"].as_str().unwrap();
        assert!(current_rust_behavior.contains("supported"));
        assert!(!current_rust_behavior.contains("unsupported"));
        if vector["id"] == "solana-uln-v3-execute-transaction-digest" {
            assert_eq!(
                vector["sourceBackedProvenance"]["observable"],
                "matches hashCallData, dvnHashCallData.dvnCallData, and dvnCallData.ulnCallData exactly"
            );
        }
        assert!(!vector["missingBuilderBehavior"]
            .as_str()
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn destination_router_rejects_each_upstream_non_evm_gap_chain() {
    let recorder = Arc::new(Recorder::default());
    let router = Arc::new(
        DestinationUlnPayloadBuilderRouter::new(
            recorder.clone(),
            recorder.clone(),
            recorder.clone(),
        )
        .with_unsupported_non_evm_destinations(
            UPSTREAM_NON_EVM_GAP_CHAINS
                .iter()
                .copied()
                .map(str::to_string),
        ),
    );
    let builders = build_hash_call_data_builders(
        router.clone(),
        router.clone(),
        router,
        recorder.clone(),
        "mainnet",
    );

    for chain_name in UPSTREAM_NON_EVM_GAP_CHAINS {
        let mut event = sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = (*chain_name).to_string();
        let err = builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &event,
                &SigningContext::Message {
                    expiration: 2,
                    skip_v_id: Some(true),
                    dvn_address: Some("0xdvn".to_string()),
                    block_confirmation: 1,
                },
            )
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!("Unsupported LayerZero destination chain type for {chain_name}")
        );
    }
    assert!(recorder.calls.lock().await.is_empty());
}

#[test]
fn upstream_non_evm_vectors_mark_only_real_gaps_as_unsupported() {
    let corpus: Value = serde_json::from_str(UPSTREAM_NON_EVM_LAYERZERO_VECTORS).unwrap();
    let unsupported_vectors = corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|vector| {
            vector["currentRustBehavior"]
                .as_str()
                .unwrap()
                .contains("unsupported")
        })
        .map(|vector| vector["id"].as_str().unwrap())
        .collect::<Vec<_>>()
        .join(", ");

    assert_eq!(unsupported_vectors, "");
    assert_eq!(UPSTREAM_NON_EVM_GAP_CHAINS, ["tron"]);
}

#[tokio::test]
async fn destination_router_uses_aptos_builder_for_aptos_destination() {
    let default = Arc::new(Recorder::default());
    let aptos = Arc::new(aptos_payload_builder());
    let router = Arc::new(
        DestinationUlnPayloadBuilderRouter::new(default.clone(), default.clone(), default.clone())
            .with_chain_builder("aptos", aptos.clone(), aptos.clone(), aptos),
    );
    let builders = build_hash_call_data_builders(
        router.clone(),
        router.clone(),
        router,
        default.clone(),
        "mainnet",
    );

    let result = builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &aptos_sent_event(),
            &SigningContext::Message {
                expiration: 1_712_345_678,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 20,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert!(default.calls.lock().await.is_empty());
}
