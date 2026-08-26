use super::*;

#[tokio::test]
async fn initia_and_movement_vectors_use_move_hash_verify_like_upstream() {
    let default = Arc::new(Recorder::default());
    let move_builder = Arc::new(AptosUlnPayloadBuilder::new(HashMap::from([
        (
            "initia".to_string(),
            AptosReceiveContracts {
                v1_oracle: "0x1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                v1_uln_301: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                uln_302: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        ),
        (
            "movement".to_string(),
            AptosReceiveContracts {
                v1_oracle: "0x4444444444444444444444444444444444444444444444444444444444444444"
                    .to_string(),
                v1_uln_301: "0x5555555555555555555555555555555555555555555555555555555555555555"
                    .to_string(),
                uln_302: "0x6666666666666666666666666666666666666666666666666666666666666666"
                    .to_string(),
            },
        ),
    ])));
    let router = MOVE_CHAIN_NAMES.iter().copied().fold(
        DestinationUlnPayloadBuilderRouter::new(default.clone(), default.clone(), default.clone()),
        |router, chain_name| {
            router.with_chain_builder(
                chain_name,
                move_builder.clone(),
                move_builder.clone(),
                move_builder.clone(),
            )
        },
    );
    let router = Arc::new(router);
    let builders = build_hash_call_data_builders(
        router.clone(),
        router.clone(),
        router,
        default.clone(),
        "mainnet",
    );

    for chain_name in MOVE_CHAIN_NAMES {
        let mut event = aptos_sent_event();
        event.lz_message_id.pathway_id.dst_chain_name = (*chain_name).to_string();
        let result = builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &event,
                &SigningContext::Message {
                    expiration: 1_712_345_678,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 20,
                },
            )
            .await
            .unwrap();

        assert_eq!(result.details["ulnCallData"]["methodName"], "hashPropose");
        assert_eq!(result.details["dvnCallData"]["vid"], "108");
        assert_ne!(result.hash_call_data, "0xv3");
    }
    assert!(default.calls.lock().await.is_empty());
}
