use super::*;

const FIXTURE: &str = include_str!("../../../tests/gasolina_parity/non_evm_destination.json");
const SENDER: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const RECEIVER: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const GUID: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const MESSAGE: &str = "0xc0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee";
const DVN_ADDRESS: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";

fn fixture_event(dst_eid: u64, src_eid: u64) -> LzSentEvent {
    let mut event = super::matrix::matrix_sent_event("ton", dst_eid);
    event.lz_message_id.nonce = 4242;
    event.message = MESSAGE.to_string();
    event.extra.insert("guid".to_string(), Value::from(GUID));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("srcEid".to_string(), Value::from(src_eid));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("sender".to_string(), Value::from(SENDER));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("receiver".to_string(), Value::from(RECEIVER));
    event
}

fn transport(response: Option<Value>) -> RecordingTransport {
    RecordingTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        responses: Arc::new(Mutex::new(response.into_iter().map(Ok).collect())),
    }
}

#[tokio::test]
async fn ton_v302_without_dvn_address_matches_upstream_error_without_rpc() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    for row in fixture["rows"].as_array().unwrap().iter().filter(|row| {
        row["family"] == "ton"
            && (row["environment"] == "mainnet" || row["environment"] == "sandbox")
    }) {
        let environment = row["environment"].as_str().unwrap();
        let dst_eid = row["dstEidV2"].as_u64().unwrap();
        let src_eid = row["srcEidV2"].as_u64().unwrap();
        let transport = transport(None);
        let calls = transport.calls.clone();
        let builders = super::matrix::runtime_ton_hash_builders_for(environment, transport);
        let error = builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &fixture_event(dst_eid, src_eid),
                &SigningContext::Message {
                    expiration: 1_760_000_000,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 15,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            row["arms"]["V302"]["error"].as_str().unwrap()
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "missing DVN address must fail before RPC"
        );
    }
}

#[tokio::test]
async fn ton_v302_not_deployed_destination_matches_upstream_vectors() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/gasolina_parity/ton_v302_destination.json"
    ))
    .unwrap();
    let mut environments: Vec<&str> = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| vector["environment"].as_str().unwrap())
        .collect();
    environments.sort_unstable();
    assert_eq!(environments, ["mainnet", "sandbox"]);
    for vector in fixture["vectors"].as_array().unwrap() {
        let environment = vector["environment"].as_str().unwrap();
        let transport = transport(Some(json!({"result":{"state":"uninitialized","data":""}})));
        let calls = transport.calls.clone();
        let builders = super::matrix::runtime_ton_hash_builders_for(environment, transport);
        let result = builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &fixture_event(
                    vector["dstEid"].as_u64().unwrap(),
                    vector["srcEid"].as_u64().unwrap(),
                ),
                &SigningContext::Message {
                    expiration: 1_760_000_000,
                    skip_v_id: None,
                    dvn_address: Some(DVN_ADDRESS.to_string()),
                    block_confirmation: 15,
                },
            )
            .await
            .unwrap();
        // Upstream's SDK returns bare hex and its App signs `hexToBytes` of it; the bytes are what matter.
        assert_eq!(
            result.hash_call_data,
            format!("0x{}", vector["built"]["hashCallData"].as_str().unwrap())
        );
        assert_eq!(
            result.details["dvnCallData"]["targetContract"],
            vector["built"]["targetContract"]
        );
        assert_eq!(
            result.details["dvnCallData"]["ulnCallData"],
            vector["built"]["ulnCallDataBoc"]
        );
        assert_eq!(
            result.details["dvnHashCallData"]["dvnCallData"],
            vector["built"]["dvnCallDataBoc"]
        );
        assert_eq!(
            result.details["ulnCallData"]["proof"]["lookupHash"],
            vector["built"]["packetHash"]
        );
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            let (_, _, request) = &calls[0];
            assert_eq!(request["method"], "getAddressInformation");
            assert_eq!(request["params"]["address"], DVN_ADDRESS);
        }
        assert_eq!(
            vector["implementationBranch"]["name"],
            "not-deployed/not-a-proxy"
        );
        let missing = &vector["missingDvnAddress"];
        assert_eq!(missing["providerGetStateCalls"], 0);
        assert!(missing["stackFrames"][0]
            .as_str()
            .unwrap()
            .starts_with("at parseTonAddress "));
        let error = builders[ULN_VERSION_V302]
            .build_dvn_hash_call_data(
                &fixture_event(
                    vector["dstEid"].as_u64().unwrap(),
                    vector["srcEid"].as_u64().unwrap(),
                ),
                &SigningContext::Message {
                    expiration: 1_760_000_000,
                    skip_v_id: None,
                    dvn_address: None,
                    block_confirmation: 15,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), missing["message"]);
        assert_eq!(
            calls.lock().unwrap().len(),
            1,
            "missing DVN address must fail before RPC"
        );
    }
}
