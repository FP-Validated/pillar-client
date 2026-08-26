use super::*;

fn sui_like_sent_event(dst_chain_name: &str, dst_eid: u64) -> LzSentEvent {
    let mut event = evm_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = dst_chain_name.to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(dst_eid));
    event.message = "0xdeadbeef".to_string();
    event.extra.insert(
        "guid".to_string(),
        Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );
    event
}

fn sui_payload_builder() -> SuiUlnPayloadBuilder {
    SuiUlnPayloadBuilder::new(HashMap::from([
        (
            "sui".to_string(),
            SuiReceiveContracts {
                uln_302_package:
                    "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0".to_string(),
            },
        ),
        (
            "iotal1".to_string(),
            SuiReceiveContracts {
                uln_302_package:
                    "0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e".to_string(),
            },
        ),
    ]))
}

#[tokio::test]
async fn sui_iotamove_builder_matches_upstream_v302_hash_verify_vectors() {
    let builder = sui_payload_builder();
    let cases = [
        (
            "sui",
            39_000_u64,
            "0xa3a435b92460100101237390814fd76b78120635c4cc0f3e2836ed5bfb4d0d54",
            "3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0",
        ),
        (
            "iotal1",
            39_200_u64,
            "0x62c93905a668edcc42c971b69ff87e1bd4af96f1c5fdad3f0d2c68e4db0b0211",
            "042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e",
        ),
    ];

    for (chain_name, dst_eid, expected_hash, expected_target) in cases {
        let result = builder
            .build_uln_v3_verify_payload(
                &sui_like_sent_event(chain_name, dst_eid),
                64,
                1_900_000_000,
                (dst_eid % 30_000).to_string(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            result.hash_call_data,
            expected_hash.trim_start_matches("0x")
        );
        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            expected_target
        );
        assert_eq!(
            result.details["ulnCallData"]["proof"]["payloadHash"],
            "0x08eed9e984b654cded42042a70953b0e5c143f47cb44b60296d86f5345656887"
        );
    }
}

#[tokio::test]
async fn sui_iotamove_builder_preserves_upstream_non_v302_rejections() {
    let builder = sui_payload_builder();
    let sent_event = sui_like_sent_event("sui", 39_000);

    let v2_err = builder
        .build_uln_v2_verify_payload(&sent_event, 64, 1_900_000_000, "9000".to_string())
        .await
        .unwrap_err();
    assert_eq!(v2_err.to_string(), "SUI only supports ULN V302");

    let read_err = builder
        .build_uln_read_v1_verify_payload(
            &sent_event,
            "0xresolved".to_string(),
            1_900_000_000,
            "9000".to_string(),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(read_err.to_string(), "SUI only supports ULN V302");
}
