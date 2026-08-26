use super::*;

const SOLANA_DVN_PDA: &str = "HtEYV4xB4wvsj5fgTkcfuChYpvGYzgzwvNhgDZQNh7wW";

#[tokio::test]
async fn solana_vector_rejects_missing_dvn_pda_like_upstream() {
    let builder = SolanaUlnPayloadBuilder;
    let err = builder
        .build_uln_v3_verify_payload(
            &solana_sent_event(),
            64,
            1_900_000_000,
            "168".to_string(),
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Solana: DVN Address is required for verify payload"
    );
}

#[tokio::test]
async fn solana_vector_builds_execute_transaction_digest_like_upstream() {
    let builder = SolanaUlnPayloadBuilder;
    let result = builder
        .build_uln_v3_verify_payload(
            &solana_sent_event(),
            64,
            1_900_000_000,
            "168".to_string(),
            Some(SOLANA_DVN_PDA),
        )
        .await
        .unwrap();
    let uln_call_data = result.details["dvnCallData"]["ulnCallData"]
        .as_str()
        .unwrap();
    let dvn_call_data = result.details["dvnHashCallData"]["dvnCallData"]
        .as_str()
        .unwrap();
    let corpus: Value = serde_json::from_str(UPSTREAM_NON_EVM_LAYERZERO_VECTORS).unwrap();
    let solana_vector = corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == "solana-uln-v3-execute-transaction-digest")
        .unwrap();
    let expected = &solana_vector["sourceBackedExpected"];

    assert_eq!(
        result.hash_call_data,
        expected["hashCallData"].as_str().unwrap()
    );
    assert!(!result.hash_call_data.starts_with("0x"));
    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "7a4WjyR8VZ7yZz5XJAKm39BUGn5iT9CKcv2pmG9tdXVH"
    );
    assert_eq!(result.details["dvnCallData"]["vid"], "168");
    assert_eq!(
        uln_call_data,
        expected["dvnCallDataUlnCallData"].as_str().unwrap()
    );
    assert!(!uln_call_data.starts_with("0x"));
    assert_eq!(
        dvn_call_data,
        expected["dvnHashCallDataDvnCallData"].as_str().unwrap()
    );
    assert!(!dvn_call_data.starts_with("0x"));
    assert_eq!(result.details["ulnCallData"]["methodName"], "verify");
}

fn solana_sent_event() -> LzSentEvent {
    let mut event = evm_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "solana".to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(30_168_u64));
    event
}
