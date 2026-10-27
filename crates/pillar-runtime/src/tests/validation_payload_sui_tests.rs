use super::*;

/// A Sui address in the fixture's ULN receive config.
pub(super) const VERIFIER: &str =
    "0x0c12321ebe562b8fb8a74e6d29f144ea199a8f31a4cea3a417ce72477f6dfebb";
pub(super) const SUI_RECEIVER: &str =
    "0x1111111111111111111111111111111111111111111111111111111111111111";
const SIMULATION_CAPTURE: &str =
    include_str!("../../tests/gasolina_parity/transport/sui-mainnet-graphql-shared-version.json");

pub(super) fn sui_sent_event(dst_chain_name: &str, dst_eid: u64) -> LzSentEvent {
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

/// The live Sui mainnet `ExecutionError` shape (`tests/onchain_provenance/move_abort_origin.json`).
fn dev_inspect_abort_in(
    code: i64,
    package: &str,
    module: &str,
    function: &str,
) -> Result<Value, String> {
    Ok(
        json!({"data":{"simulateTransaction":{"effects":{"status":"FAILURE","executionError":{"abortCode":code.to_string(),"message":"MoveAbort","module":{"name":module,"package":{"address":package}},"function":{"name":function}}},"outputs":[]}}}),
    )
}

const SUI_ULN_302: &str = "0x3ce7457bed48ad23ee5d611dd3172ae4fbd0a22ea0e846782a7af224d905dbb0";
const SUI_UTILS: &str = "0x00245ba36f7a1cc643a2b037450dff1e4399e18069c6545fb5fcaaf37d39d7dc";

fn dev_inspect_abort(code: i64) -> Result<Value, String> {
    dev_inspect_abort_in(code, SUI_ULN_302, "receive_uln", "get_confirmations")
}
pub(super) fn iota_responses(
    channel: &str,
    state: u8,
    required: u64,
) -> Vec<Result<Value, String>> {
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
    let mut responses = vec![
        normalized(2),
        shared(8),
        inspect(address_bytes(channel)),
        normalized(6),
        Ok(
            json!({"result": (0..3).map(|_| json!({"data":{"owner":{"Shared":{"initial_shared_version":635_685_319}}}})).collect::<Vec<_>>()}),
        ),
        inspect(vec![state]),
        normalized(4),
    ];
    let confirmation_results = json!([
        {"returnValues":[[[0],"bytes32"]]},
        {"returnValues":[[[0],"bytes32"]]},
        {"returnValues":[[0u64.to_le_bytes().to_vec(),"u64"]]},
    ]);
    responses.push(Ok(json!({"result":{"results":confirmation_results}})));
    responses.push(normalized(3));
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

#[allow(clippy::too_many_arguments)]
pub(super) fn sui_responses(
    channel: &str,
    state: u8,
    confirmations: Option<Result<Value, String>>,
    required: u64,
) -> Vec<Result<Value, String>> {
    let mut responses = vec![
        normalized_immutable(2),
        shared_object(8),
        dev_inspect_bytes(address_bytes(channel)),
        normalized_immutable(6),
        Ok(
            json!({"data": (0..3).map(|index| (format!("o{index}"), json!({"asMoveObject":{"owner":{"__typename":"Shared","initialSharedVersion":"635685319"}}}))).collect::<serde_json::Map<_, _>>()}),
        ),
        dev_inspect_bytes(vec![state]),
        normalized_immutable(4),
    ];
    responses.push(
        confirmations.unwrap_or_else(|| dev_inspect_three_commands(0u64.to_le_bytes().to_vec())),
    );
    responses.push(normalized_immutable(3));
    responses.push(dev_inspect_bytes(uln_config_bytes(required)));
    responses
}

pub(super) fn sui_checks(
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
    responses[7] = dev_inspect_three_commands(3u64.to_le_bytes().to_vec());
    let checks = sui_checks("sui", responses, calls.clone());

    checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
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
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
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
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
        .await
        .expect("VERIFIABLE is not VERIFIED on Sui");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_sui_payload_at_required_confirmations() {
    let mut responses = sui_responses(SUI_RECEIVER, 0, None, 15);
    responses[7] = dev_inspect_three_commands(15u64.to_le_bytes().to_vec());
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::BadRequest(_)),
        "confirmations >= required means this DVN already signed: {error}"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_treat_missing_sui_confirmations_as_unsigned() {
    // `EConfirmationsNotFound` (sub_status 1) is "nothing recorded", not a
    // failure, so the payload is unsigned.
    let responses = sui_responses(SUI_RECEIVER, 0, Some(dev_inspect_abort(1)), 15);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
        .await
        .expect("an EConfirmationsNotFound abort means no confirmation");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_other_sui_aborts() {
    // Any other abort code is not the "no confirmations" case and must not be
    // read as zero.
    let responses = sui_responses(SUI_RECEIVER, 0, Some(dev_inspect_abort(7)), 15);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));

    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)), "{error}");
}

/// Code 1 from anywhere but `receive_uln::get_confirmations` - `bytes32::from_bytes` on a
/// wrong-length hash, another package, or no reported site - is not "no record".
#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_code_1_from_another_function() {
    let elsewhere = [
        dev_inspect_abort_in(1, SUI_UTILS, "bytes32", "from_bytes"),
        dev_inspect_abort_in(1, SUI_UTILS, "receive_uln", "get_confirmations"),
        dev_inspect_abort_in(1, SUI_ULN_302, "receive_uln", "verify"),
        Ok(
            json!({"data":{"simulateTransaction":{"effects":{"status":"FAILURE","executionError":{"abortCode":"1","message":"MoveAbort"}},"outputs":[]}}}),
        ),
    ];
    for response in elsewhere {
        let site = format!("{response:?}");
        let responses = sui_responses(SUI_RECEIVER, 0, Some(response), 15);
        let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));
        let error = checks
            .validate_payload_not_signed(
                &sui_sent_event("sui", 30_350),
                Some(VERIFIER),
                "sui",
                None,
            )
            .await
            .expect_err(&site);
        assert!(
            matches!(error, AppCoreError::Internal(_)),
            "{site}: {error}"
        );
    }
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_string_sui_abort_code() {
    let response = dev_inspect_abort_in(7, SUI_ULN_302, "receive_uln", "get_confirmations");
    let responses = sui_responses(SUI_RECEIVER, 0, Some(response), 15);
    let checks = sui_checks("sui", responses, Arc::new(Mutex::new(Vec::new())));
    let error = checks
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)), "{error}");
}

/// `receive_uln::verified` is false without a record and `count >= required` with one,
/// so on a zero-requirement pathway a missing record is unsigned and a stored 0 is
/// signed. Upstream reads the abort as 0 and refuses both; this follows the chain.
/// `get_confirmations` keys its record by `keccak256(packetHeader)`, and `from_bytes`
/// aborts with the same code 1 on any other length, so the raw 81-byte header would read
/// as "no record" for every packet.
#[tokio::test]
async fn m21_sui_and_iota_missing_confirmations_are_unsigned_even_when_zero_are_required() {
    use sha3::{Digest, Keccak256};

    let event = sui_sent_event("sui", 30_350);
    let header = hex::decode(
        pillar_layerzero::compute_lz_packet_v1_proof_from_event(&event)
            .unwrap()
            .packet_header
            .trim_start_matches("0x"),
    )
    .unwrap();
    let mut header_hash_input = vec![32u8];
    header_hash_input.extend_from_slice(&Keccak256::digest(&header));
    let mut observations = Vec::new();
    for (label, confirmations, signed) in [
        ("required-0-missing-record", dev_inspect_abort(1), false),
        (
            "required-0-stored-0",
            dev_inspect_three_commands(0u64.to_le_bytes().to_vec()),
            true,
        ),
        (
            "required-0-stored-1",
            dev_inspect_three_commands(1u64.to_le_bytes().to_vec()),
            true,
        ),
    ] {
        let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
        let responses = sui_responses(SUI_RECEIVER, 0, Some(confirmations), 0);
        let checks = sui_checks("sui", responses, calls.clone());
        let result = checks
            .validate_payload_not_signed(&event, Some(VERIFIER), "sui", None)
            .await;
        let confirmation_inputs = calls
            .lock()
            .unwrap()
            .iter()
            .find_map(|(_, _, body)| {
                let programmable =
                    &body["variables"]["transaction"]["kind"]["programmableTransaction"];
                (programmable["commands"][2]["moveCall"]["function"] == "get_confirmations")
                    .then(|| programmable["inputs"].clone())
            })
            .expect("get_confirmations was simulated");
        let header_hash_sent = base64_decode(confirmation_inputs[2]["pure"].as_str().unwrap())
            .unwrap()
            == header_hash_input;
        observations.push(json!({
            "chain": "sui",
            "case": label,
            "get_confirmations_header_input_is_keccak": header_hash_sent,
            "result": format!("{result:?}"),
        }));
        assert!(
            header_hash_sent,
            "{label}: get_confirmations must take keccak256(header)"
        );
        match (signed, result) {
            (false, result) => {
                result.unwrap_or_else(|error| panic!("{label}: {error}"));
            }
            (true, Ok(_)) => panic!("{label}: a stored record at the requirement is signed"),
            (true, Err(error)) => assert!(
                error.to_string().starts_with("Payload already signed"),
                "{label}: {error}"
            ),
        }
    }
    // IOTA JSON-RPC reports the abort as `result.error`, as `dev_inspect_return` parses it.
    let mut missing = iota_responses(SUI_RECEIVER, 0, 0);
    missing[7] = Ok(json!({"result": {
        "error": "MoveAbort: Move Runtime Abort. Location: 0x042e3bb837e5528e495124542495b9df5016acd011d89838ae529db5a814499e::receive_uln::get_confirmations (function index 10) at offset 22, Abort Code: 1; at command index: 2",
        "results": [],
    }}));
    let iota = sui_checks("iotal1", missing, Arc::new(Mutex::new(Vec::new())))
        .validate_payload_not_signed(
            &sui_sent_event("iotal1", 30_423),
            Some(VERIFIER),
            "iotal1",
            None,
        )
        .await;
    observations.push(json!({"chain": "iotal1", "case": "required-0-missing-record", "result": format!("{iota:?}")}));
    audit_round_artifact(
        "h02-m21",
        "m21-sui-iota-zero-confirmations",
        json!({ "cases": observations }),
    );
    iota.expect("iotal1: a missing record on a zero-requirement pathway is unsigned");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_use_iota_rpc_namespace() {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = sui_checks("iotal1", iota_responses(SUI_RECEIVER, 0, 15), calls.clone());

    checks
        .validate_payload_not_signed(
            &sui_sent_event("iotal1", 30_423),
            Some(VERIFIER),
            "iotal1",
            None,
        )
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
        .validate_payload_not_signed(&event, Some(VERIFIER), "sui", None)
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
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
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
        .validate_payload_not_signed(&sui_sent_event("sui", 30_350), Some(VERIFIER), "sui", None)
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
        .validate_payload_not_signed(&live_sui_sent_event(), Some(VERIFIER), "sui", None)
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

#[tokio::test]
async fn slow_sui_entity_cannot_occupy_the_entire_destination_lane() {
    use pillar_core::execution::{BudgetLimits, ExecutionResources, FairBudget, RequestContext};
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Clone)]
    struct Transport {
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    #[async_trait]
    impl JsonRpcTransport for Transport {
        async fn post_json(
            &self,
            url: String,
            _: HashMap<String, String>,
            body: Value,
        ) -> Result<Value, String> {
            if url.contains("slow") {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(active, Ordering::SeqCst);
                let _active = Active(self.active.clone());
                return futures::future::pending().await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            if body.pointer("/variables/function").is_some() {
                return normalized_immutable(6);
            }
            if body.pointer("/variables/address").is_some() {
                return shared_object(8);
            }
            if body.pointer("/variables/a0").is_some() {
                return Ok(
                    json!({"data": (0..3).map(|index| (format!("o{index}"), json!({"asMoveObject":{"owner":{"__typename":"Shared","initialSharedVersion":"9"}}}))).collect::<serde_json::Map<_, _>>()}),
                );
            }
            let function = body
                .pointer("/variables/transaction/kind/programmableTransaction/commands")
                .and_then(Value::as_array)
                .and_then(|calls| calls.last())
                .and_then(|call| call.pointer("/moveCall/function"))
                .and_then(Value::as_str);
            match function {
                Some("get_messaging_channel") => dev_inspect_bytes(address_bytes(SUI_RECEIVER)),
                Some("verifiable") => dev_inspect_bytes(vec![0]),
                Some("get_confirmations") => {
                    dev_inspect_three_commands(0u64.to_le_bytes().to_vec())
                }
                Some("get_effective_receive_uln_config") => dev_inspect_bytes(uln_config_bytes(15)),
                _ => Err(format!("unexpected Sui request {body}")),
            }
        }
        async fn get_json(&self, _: String, _: HashMap<String, String>) -> Result<Value, String> {
            Err("unexpected GET".into())
        }
    }
    let transport = Transport {
        active: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    };
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "sui".to_string(),
            ProviderConfig::with_distinct_entities(
                ["slow", "healthy-a", "healthy-b"]
                    .map(|name| ProviderUri::Uri(format!("https://{name}.example")))
                    .to_vec(),
                2,
            ),
        )]),
        Some(&["sui".to_string()]),
    )
    .unwrap();
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport.clone(),
        "mainnet",
        &["sui".to_string()],
    )
    .unwrap();
    let budget = || {
        FairBudget::new(
            vec!["sui".to_string()],
            BudgetLimits {
                active: 8,
                per_lane: 8,
                waiting: 32,
                per_lane_waiting: 32,
                wait: std::time::Duration::from_secs(2),
            },
        )
        .unwrap()
    };
    let resources = Arc::new(ExecutionResources {
        signing: budget(),
        rpc: budget(),
        kms: budget(),
        parser: budget(),
    });
    let results = futures::future::join_all((0..8).map(|_| {
        let mut context = RequestContext::new(std::time::Duration::from_secs(5));
        context.resources = Some(resources.clone());
        context.source_chain = Some(Arc::from("ethereum"));
        let checks = &checks;
        async move {
            context
                .scope(checks.validate_payload_not_signed(
                    &sui_sent_event("sui", 30_350),
                    Some(VERIFIER),
                    "sui",
                    None,
                ))
                .await
        }
    }))
    .await;
    assert!(
        results.iter().all(|result| *result == Ok(Some(15))),
        "{results:?}"
    );
    assert!(transport.peak.load(Ordering::SeqCst) <= 2);
    assert_eq!(transport.active.load(Ordering::SeqCst), 0);
}
