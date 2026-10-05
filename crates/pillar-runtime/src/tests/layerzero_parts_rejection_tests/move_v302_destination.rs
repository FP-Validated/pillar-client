use super::*;
use std::sync::Mutex;

const APTOS_RECEIVER: &str = "0xf22bede237a07e121b56d91a491eb7bcdfd1f5907926a9e58338f964a01b17fa";
const MOVEMENT_RECEIVER: &str =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
const DVN: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const ULN_302: &str = "0xc33752e0220faf79e45385dd73fb28d681dcd9f1569a1480725507c1f3c3aba9";

#[derive(Clone)]
struct MoveScript {
    state: Value,
    confirmations: Value,
    required: u64,
    calls: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl JsonRpcTransport for MoveScript {
    async fn post_json(
        &self,
        url: String,
        _: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push(body.clone());
        if !url.ends_with("/view") {
            return Err(format!("unexpected Move request: {url}"));
        }
        let function = body["function"].as_str().unwrap_or_default();
        if function.ends_with("::endpoint::get_effective_receive_library") {
            Ok(json!([format!("0x{}", "44".repeat(32))]))
        } else if function.ends_with("::endpoint::get_config") {
            Ok(json!([format!(
                "0x{:016x}0001{}00000000",
                self.required,
                &DVN[2..]
            )]))
        } else if function.ends_with("::uln_302::verifiable") {
            Ok(self.state.clone())
        } else if function.ends_with("::msglib::get_verification_confirmations") {
            Ok(self.confirmations.clone())
        } else {
            Err(format!("unexpected Move view: {function}"))
        }
    }

    async fn get_json(&self, url: String, _: HashMap<String, String>) -> Result<Value, String> {
        Err(format!("unexpected Move GET: {url}"))
    }
}

fn v302_event(chain: &str) -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.src_chain_name = "ethereum".to_string();
    event.lz_message_id.pathway_id.dst_chain_name = chain.to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("srcEid".to_string(), Value::from(30_101));
    event.lz_message_id.pathway_id.extra.insert(
        "dstEid".to_string(),
        Value::from(if chain == "aptos" { 30_108 } else { 30_325 }),
    );
    event.lz_message_id.pathway_id.extra.insert(
        "sender".to_string(),
        Value::from(format!("0x{}", "11".repeat(20))),
    );
    event.lz_message_id.pathway_id.extra.insert(
        "receiver".to_string(),
        Value::from(if chain == "aptos" {
            APTOS_RECEIVER
        } else {
            MOVEMENT_RECEIVER
        }),
    );
    event.lz_message_id.uln_send_version = Value::from("V302");
    event.lz_message_id.nonce = 74_756;
    event.message = format!("0x{}", "c0ffee".repeat(11));
    event.extra.insert(
        "guid".to_string(),
        Value::from(format!("0x{}", "5a".repeat(32))),
    );
    event
}

fn move_checks(
    chain: &str,
    state: Value,
    confirmations: Value,
    required: u64,
) -> (
    RuntimeRpcValidationChecks<MoveScript>,
    Arc<Mutex<Vec<Value>>>,
) {
    let names = vec![
        "ethereum".to_string(),
        "aptos".to_string(),
        "movement".to_string(),
    ];
    let provider_names = vec![chain.to_string()];
    let uris = vec![
        ProviderUri::Uri("https://move-a.example/v1".to_string()),
        ProviderUri::Uri("https://move-b.example/v1".to_string()),
    ];
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            chain.to_string(),
            ProviderConfig::with_distinct_entities(uris, 2),
        )]),
        Some(&provider_names),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        MoveScript {
            state,
            confirmations,
            required,
            calls: calls.clone(),
        },
        "mainnet",
        &names,
    )
    .unwrap();
    (checks, calls)
}

#[tokio::test]
async fn move_v302_verifiable_enum_matches_upstream_value_by_value() {
    for value in 0..=4 {
        let (checks, calls) = move_checks("aptos", json!([value]), json!(["1"]), 2);
        let result = checks
            .validate_payload_not_signed(&v302_event("aptos"), Some(DVN), "aptos")
            .await;
        assert_eq!(result.is_err(), value == 2, "state {value}: {result:?}");
        let library = calls
            .lock()
            .unwrap()
            .iter()
            .find(|body| {
                body["function"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("::endpoint::get_effective_receive_library"))
            })
            .unwrap()
            .clone();
        assert_eq!(library["arguments"], json!([APTOS_RECEIVER, 30_101]));
        let config = calls
            .lock()
            .unwrap()
            .iter()
            .find(|body| {
                body["function"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("::endpoint::get_config"))
            })
            .unwrap()
            .clone();
        assert_eq!(
            config["arguments"],
            json!([APTOS_RECEIVER, ULN_302, 30_101, 3])
        );
    }
}

#[tokio::test]
async fn move_v302_invalid_verifiable_values_fail_the_two_provider_quorum() {
    for state in [
        json!([5]),
        json!([-1]),
        json!(["bad"]),
        json!([true]),
        json!([null]),
        json!([]),
    ] {
        let (checks, _) = move_checks("aptos", state.clone(), json!(["0"]), 2);
        let err = checks
            .validate_payload_not_signed(&v302_event("aptos"), Some(DVN), "aptos")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("quorum"),
            "invalid state {state}: {err}"
        );
    }
}

#[tokio::test]
async fn move_v302_confirmation_decode_matches_upstream_empty_and_invalid_behavior() {
    // Upstream `length > 0 && Number(x[0]) >= required`: an empty vector is unsigned.
    let (checks, _) = move_checks("movement", json!([0]), json!([]), 2);
    assert!(checks
        .validate_payload_not_signed(&v302_event("movement"), Some(DVN), "movement")
        .await
        .is_ok());
    for confirmations in [
        json!(["not-u64"]),
        json!([true]),
        json!([null]),
        json!([-1]),
    ] {
        let (checks, _) = move_checks("movement", json!([0]), confirmations.clone(), 2);
        let err = checks
            .validate_payload_not_signed(&v302_event("movement"), Some(DVN), "movement")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("quorum"),
            "invalid confirmations {confirmations}: {err}"
        );
    }
    let (checks, calls) = move_checks("movement", json!([0]), json!(["2"]), 2);
    let err = checks
        .validate_payload_not_signed(&v302_event("movement"), Some(DVN), "movement")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("already signed"),
        "confirmation threshold must refuse: {err}"
    );
    let config = calls
        .lock()
        .unwrap()
        .iter()
        .find(|body| {
            body["function"]
                .as_str()
                .is_some_and(|f| f.ends_with("::endpoint::get_config"))
        })
        .unwrap()
        .clone();
    assert_eq!(
        config["arguments"],
        json!([MOVEMENT_RECEIVER, ULN_302, 30_101, 3])
    );
}

#[tokio::test]
async fn move_v302_empty_confirmations_do_not_sign_even_when_zero_are_required() {
    for state in [0, 1] {
        let (checks, _) = move_checks("movement", json!([state]), json!([]), 0);
        assert!(
            checks
                .validate_payload_not_signed(&v302_event("movement"), Some(DVN), "movement")
                .await
                .is_ok(),
            "state {state}"
        );
    }
    let (checks, _) = move_checks("movement", json!([2]), json!([]), 0);
    assert!(checks
        .validate_payload_not_signed(&v302_event("movement"), Some(DVN), "movement")
        .await
        .is_err());
}

#[tokio::test]
async fn move_v302_pads_only_the_receive_library_lookup_receiver() {
    for receiver in ["0xabc", "abc"] {
        let (checks, calls) = move_checks("aptos", json!([0]), json!(["1"]), 2);
        let mut event = v302_event("aptos");
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("receiver".to_string(), Value::from(receiver));
        checks
            .validate_payload_not_signed(&event, Some(DVN), "aptos")
            .await
            .unwrap();

        let calls = calls.lock().unwrap();
        let lookup = calls
            .iter()
            .find(|body| {
                body["function"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("::endpoint::get_effective_receive_library"))
            })
            .unwrap();
        assert_eq!(
            lookup["arguments"],
            json!([format!("0x{}0abc", "0".repeat(60)), 30_101])
        );
        let config = calls
            .iter()
            .find(|body| {
                body["function"]
                    .as_str()
                    .is_some_and(|f| f.ends_with("::endpoint::get_config"))
            })
            .unwrap();
        assert_eq!(config["arguments"], json!([receiver, ULN_302, 30_101, 3]));
    }
}
