use super::*;

/// A Sui address in the fixture's ULN receive config.
const VERIFIER: &str = "0x0c12321ebe562b8fb8a74e6d29f144ea199a8f31a4cea3a417ce72477f6dfebb";
const SUI_RECEIVER: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const SIMULATION_CAPTURE: &str =
    include_str!("../../tests/gasolina_parity/transport/sui-mainnet-graphql-shared-version.json");

fn sui_sent_event(dst_chain_name: &str, dst_eid: u64) -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = dst_chain_name.to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(dst_eid));
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("receiver".to_string(), Value::from(SUI_RECEIVER));
    event
}

/// `getNormalizedMoveFunction`: every payload-signed view takes its objects by
/// immutable reference, which is what the live mainnet response shows.
fn normalized_immutable(parameters: usize) -> Result<Value, String> {
    let params = (0..parameters)
        .map(|_| json!({"repr":"&uln_302::Uln302"}))
        .collect::<Vec<_>>();
    Ok(json!({"data":{"package":{"module":{"function":{"parameters":params}}}}}))
}

fn shared_object(initial_shared_version: u64) -> Result<Value, String> {
    Ok(
        json!({"data":{"object":{"asMoveObject":{"owner":{"__typename":"Shared","initialSharedVersion":initial_shared_version.to_string()}}}}}),
    )
}

fn dev_inspect_bytes(bytes: Vec<u8>) -> Result<Value, String> {
    use base64::Engine;
    Ok(
        json!({"data":{"simulateTransaction":{"effects":{"status":"SUCCESS"},"outputs":[{"returnValues":[{"value":{"bcs":base64::engine::general_purpose::STANDARD.encode(bytes)}}]}]}}}),
    )
}

fn dev_inspect_three_commands(bytes: Vec<u8>) -> Result<Value, String> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    Ok(
        json!({"data":{"simulateTransaction":{"effects":{"status":"SUCCESS"},"outputs":[{"returnValues":[{"value":{"bcs":"AA=="}}]},{"returnValues":[{"value":{"bcs":"AA=="}}]},{"returnValues":[{"value":{"bcs":encoded}}]}]}}}),
    )
}

fn dev_inspect_abort(sub_status: i64) -> Result<Value, String> {
    Ok(
        json!({"data":{"simulateTransaction":{"effects":{"status":"FAILURE","executionError":{"abortCode":sub_status,"message":"MoveAbort"}},"outputs":[]}}}),
    )
}
fn iota_responses(channel: &str, state: u8, required: u64) -> Vec<Result<Value, String>> {
    let normalized = |parameters| {
        Ok(
            json!({"result":{"parameters":(0..parameters).map(|_| json!({"Reference":{"Struct":{"module":"uln_302","name":"Uln302"}}})).collect::<Vec<_>>()}}),
        )
    };
    let shared = |version| {
        Ok(json!({"result":[{"data":{"owner":{"Shared":{"initial_shared_version":version}}}}]}))
    };
    let inspect =
        |bytes: Vec<u8>| Ok(json!({"result":{"results":[{"returnValues":[[bytes,"u8"]]}]}}));
    let mut responses = vec![normalized(2), shared(8), inspect(address_bytes(channel))];
    for _ in 0..4 {
        responses.push(normalized(6));
        responses.push(shared(635_685_319));
    }
    responses.push(inspect(vec![state]));
    responses.push(normalized(4));
    responses.push(shared(635_685_319));
    let confirmation_results = json!([
        {"returnValues":[[[0],"bytes32"]]},
        {"returnValues":[[[0],"bytes32"]]},
        {"returnValues":[[0u64.to_le_bytes().to_vec(),"u64"]]},
    ]);
    responses.push(Ok(json!({"result":{"results":confirmation_results}})));
    responses.push(normalized(3));
    responses.push(shared(635_685_319));
    responses.push(inspect(uln_config_bytes(required)));
    responses
}
fn uln_config_bytes(confirmations: u64) -> Vec<u8> {
    let mut bytes = confirmations.to_le_bytes().to_vec();
    bytes.push(0); // no required DVNs
    bytes.push(0); // no optional DVNs
    bytes.push(0); // threshold
    bytes
}

fn address_bytes(hex_value: &str) -> Vec<u8> {
    hex::decode(hex_value.trim_start_matches("0x")).unwrap()
}

/// The provider call order for one observation:
/// normalized(endpoint) -> multiGet(endpoint) -> devInspect(messaging channel)
/// -> [normalized+multiGet] x4 for the `verifiable` objects -> devInspect
/// -> normalized+multiGet(verification) -> devInspect(get_confirmations)
/// -> normalized+multiGet(uln) -> devInspect(effective config)
#[allow(clippy::too_many_arguments)]
fn sui_responses(
    channel: &str,
    state: u8,
    confirmations: Option<Result<Value, String>>,
    required: u64,
) -> Vec<Result<Value, String>> {
    let mut responses = vec![
        normalized_immutable(2),
        shared_object(8),
        dev_inspect_bytes(address_bytes(channel)),
    ];
    for _ in 0..4 {
        responses.push(normalized_immutable(6));
        responses.push(shared_object(635_685_319));
    }
    responses.push(dev_inspect_bytes(vec![state]));
    responses.push(normalized_immutable(4));
    responses.push(shared_object(635_685_319));
    responses.push(
        confirmations.unwrap_or_else(|| dev_inspect_three_commands(0u64.to_le_bytes().to_vec())),
    );
    responses.push(normalized_immutable(3));
    responses.push(shared_object(635_685_319));
    responses.push(dev_inspect_bytes(uln_config_bytes(required)));
    responses
}

fn sui_checks(
    chain_name: &str,
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            chain_name.to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri(format!("https://{chain_name}.example"))],
                1,
            ),
        )]),
        Some(&[chain_name.to_string()]),
    )
    .unwrap();
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls,
            responses: Arc::new(Mutex::new(responses)),
        },
        "mainnet",
        &[chain_name.to_string()],
    )
    .unwrap();
    // The Sui branch must never fall through to the EVM receive-contract lookup.
    checks.with_evm_receive_contracts(HashMap::new())
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_sui_payload() {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    // state 0 (VERIFYING) and 3 of 15 confirmations.
    let mut responses = sui_responses(SUI_RECEIVER, 0, None, 15);
    responses[14] = dev_inspect_three_commands(3u64.to_le_bytes().to_vec());
    let checks = sui_checks("sui", responses, calls.clone());

    checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .expect("an unverified Sui packet must pass without an EVM contract lookup");

    let calls = calls.lock().unwrap();
    assert!(calls[0].2["query"]
        .as_str()
        .unwrap()
        .contains("package(address: $package)"));
    assert_eq!(calls[0].2["variables"]["module"], "endpoint_v2");
    assert_eq!(calls[0].2["variables"]["function"], "get_messaging_channel");
    assert!(calls[1].2["query"]
        .as_str()
        .unwrap()
        .contains("object(address: $address)"));
    let object_id = calls[1].2["variables"]["address"].as_str().unwrap();
    assert!(
        object_id.starts_with("0x") && object_id.len() == 66,
        "{object_id}"
    );
    assert!(calls[2].2["query"]
        .as_str()
        .unwrap()
        .contains("simulateTransaction(transaction: $transaction"));
    assert_eq!(
        calls[2].2["variables"]["transaction"]["sender"],
        "0x1234567890123456789012345678901234567890123456789012345678901234"
    );
    assert_eq!(calls[1].2["query"], "query($address: SuiAddress!) { object(address: $address) { asMoveObject { owner { __typename ... on Shared { initialSharedVersion } } } } }");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_verified_sui_payload() {
    let checks = sui_checks(
        "sui",
        // state 2 = VERIFIED signs the payload on its own.
        sui_responses(SUI_RECEIVER, 2, None, 15),
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(error
        .to_string()
        .starts_with("Payload already signed for message {"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_verifiable_sui_payload() {
    // Sui is stricter than TON: VERIFIABLE(1) is not signed.
    let checks = sui_checks(
        "sui",
        sui_responses(SUI_RECEIVER, 1, None, 15),
        Arc::new(Mutex::new(Vec::new())),
    );

    checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .expect("VERIFIABLE is not VERIFIED on Sui");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_sui_payload_at_required_confirmations() {
    let mut responses = sui_responses(SUI_RECEIVER, 0, None, 15);
    responses[14] = dev_inspect_three_commands(15u64.to_le_bytes().to_vec());
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::BadRequest(_)),
        "confirmations >= required means this DVN already signed: {error}"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_treat_missing_sui_confirmations_as_zero() {
    // `EConfirmationsNotFound` (sub_status 1) is "nothing recorded", not a
    // failure, so with a non-zero requirement the payload is unsigned.
    let responses = sui_responses(SUI_RECEIVER, 0, Some(dev_inspect_abort(1)), 15);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .expect("an EConfirmationsNotFound abort means zero confirmations");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_other_sui_aborts() {
    // Any other abort code is not the "no confirmations" case and must not be
    // read as zero.
    let responses = sui_responses(SUI_RECEIVER, 0, Some(dev_inspect_abort(7)), 15);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)), "{error}");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_string_sui_abort_code() {
    let response = Ok(
        json!({"data":{"simulateTransaction":{"effects":{"status":"FAILURE","executionError":{"abortCode":"7","message":"MoveAbort"}},"outputs":[]}}}),
    );
    let responses = sui_responses(SUI_RECEIVER, 0, Some(response), 15);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));
    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)), "{error}");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_when_sui_confirmations_are_zero_and_required_is_zero(
) {
    // A pathway requiring zero confirmations is satisfied by zero, which is the
    // upstream `>=` semantics; assert we follow it rather than special-casing.
    let responses = sui_responses(SUI_RECEIVER, 0, Some(dev_inspect_abort(1)), 0);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_use_iota_rpc_namespace() {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = sui_checks("iotal1", iota_responses(SUI_RECEIVER, 0, 15), calls.clone());

    checks
        .validate_payload_not_signed(&sui_sent_event("iotal1", 30_423), Some(VERIFIER), "iotal1")
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    for call in calls.iter() {
        let method = call.2["method"].as_str().unwrap();
        assert!(
            method.starts_with("iota_"),
            "IOTA must use its own namespace: {method}"
        );
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reject_non_v302_sui_payload() {
    let mut event = sui_sent_event("sui", 30_350);
    event.lz_message_id.uln_send_version = Value::from("V301");
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = sui_checks("sui", Vec::new(), calls.clone());

    let error = checks
        .validate_payload_not_signed(&event, Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(calls.lock().unwrap().is_empty(), "gated before any RPC");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_non_shared_sui_object() {
    // The encoder only supports shared inputs; an owned object must fail rather
    // than be guessed at.
    let mut responses = sui_responses(SUI_RECEIVER, 0, None, 15);
    responses[1] =
        Ok(json!({"data":{"object":{"asMoveObject":{"owner":{"__typename":"AddressOwner"}}}}}));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = sui_checks("sui", responses, calls.clone());

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)), "{error}");
    let queries: Vec<String> = calls
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, body)| body["query"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(queries.len(), 2, "stopped at the owner read: {queries:?}");
    assert!(queries
        .iter()
        .all(|query| !query.contains("simulateTransaction")));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_sui_transport_failure() {
    let checks = sui_checks(
        "sui",
        vec![Err("boom".to_string())],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)), "{error}");
}

/// Reverse-traced from the real `uln_302::verify` transaction
/// `9h6eebgREowC5pso9myMcuDspMyMF3idaA1zHNVgQ5Cq` on Sui mainnet: a delivered
/// Ethereum(30101) -> Sui(30378) message at nonce 16. Replaying that
/// transaction's own packet header through `uln_302_views::verifiable` on the
/// messaging channel that `endpoint_v2::get_messaging_channel` resolves for its
/// receiver answered state `2` (`VERIFIED`), while nonce 100 answered `0`.
///
/// Reproduce with a `sui_devInspectTransactionBlock` of that view call on any
/// public Sui mainnet fullnode; the constants below pin its inputs.
const LIVE_SUI_SRC_EID: u64 = 30_101;
const LIVE_SUI_SENDER: &str = "0x000000000000000000000000e24a3dc889621612422a64e6388927901608b91d";
const LIVE_SUI_DST_EID: u64 = 30_378;
const LIVE_SUI_RECEIVER: &str =
    "0xa356ca2010fcdf44d6cecfcecf18b73c32188d361e39dff3a96ac8de0dec7b1b";
const LIVE_SUI_NONCE: u64 = 16;
const LIVE_SUI_PACKET_HEADER: &str = "01000000000000001000007595000000000000000000000000e24a3dc889621612422a64e6388927901608b91d000076aaa356ca2010fcdf44d6cecfcecf18b73c32188d361e39dff3a96ac8de0dec7b1b";

fn live_sui_sent_event() -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "sui".to_string();
    event.lz_message_id.nonce = LIVE_SUI_NONCE;
    let extra = &mut event.lz_message_id.pathway_id.extra;
    extra.insert("srcEid".to_string(), Value::from(LIVE_SUI_SRC_EID));
    extra.insert("dstEid".to_string(), Value::from(LIVE_SUI_DST_EID));
    extra.insert("sender".to_string(), Value::from(LIVE_SUI_SENDER));
    extra.insert("receiver".to_string(), Value::from(LIVE_SUI_RECEIVER));
    event
}

/// The load-bearing assertion is the recorded request: the validator has to put
/// the real delivered packet header on the wire. Checking only the `2 ->
/// BadRequest` mapping would pass for any packet at all.
#[tokio::test]
async fn runtime_rpc_validation_checks_send_the_live_sui_header_and_reject_its_verified_state() {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let mut responses = sui_responses(LIVE_SUI_RECEIVER, 2, None, 1);
    responses[1] = Ok(
        json!({"data":{"object":{"asMoveObject":{"owner":{"__typename":"Shared","initialSharedVersion":"635685314"}}}}}),
    );
    let checks = sui_checks("sui", responses, calls.clone());

    let error = checks
        .validate_payload_not_signed(&live_sui_sent_event(), Some(VERIFIER), "sui")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");

    let recorded = calls.lock().unwrap();
    let capture: Value = serde_json::from_str(SIMULATION_CAPTURE).unwrap();
    let captured =
        &capture["correct_version"]["variables"]["transaction"]["kind"]["programmableTransaction"];
    let generated = recorded
        .iter()
        .find(|(_, _, body)| {
            body["query"].as_str().is_some_and(|query| {
                query.contains("simulateTransaction(transaction: $transaction")
            }) && body["variables"]["transaction"]["kind"]["programmableTransaction"]["commands"][0]
                ["moveCall"]["function"]
                == "get_messaging_channel"
        })
        .expect("production code generated get_messaging_channel simulation");
    let programmable = &generated.2["variables"]["transaction"]["kind"]["programmableTransaction"];
    assert_eq!(programmable["inputs"], captured["inputs"]);
    assert_eq!(programmable["commands"], captured["commands"]);

    let header = hex::decode(LIVE_SUI_PACKET_HEADER).unwrap();
    let carried = recorded.iter().any(|(_, _, body)| {
        body["query"]
            .as_str()
            .is_some_and(|query| query.contains("simulateTransaction(transaction: $transaction"))
            && body["variables"]["transaction"]["kind"]["programmableTransaction"]["inputs"]
                .as_array()
                .is_some_and(|inputs| {
                    inputs.iter().any(|input| {
                        input["kind"] == "PURE"
                            && input["pure"]
                                .as_str()
                                .and_then(|encoded| base64_decode(encoded).ok())
                                .is_some_and(|bytes| contains_subslice(&bytes, &header))
                    })
                })
    });
    assert!(
        carried,
        "no devInspect request carried the live packet header"
    );
}

fn base64_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(value)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
