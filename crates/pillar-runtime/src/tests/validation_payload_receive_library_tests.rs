use super::*;

/// The endpoint reports a non-default `ReceiveUln301` for this receiver, so the
/// payload-signed check has to read ULN301 - not the ULN302 that `dstEid`
/// alone implies.
///
/// TS: `apps/gasolina/src/app/app.ts:619-621` resolves the receive version
/// through `endpointV2Sdk.getUlnReceiveVersion`, i.e.
/// `packages/sdks/lz-v2-sdk/src/endpoint/evm/endpointV2.ts:82-118`, not through
/// the `dstEid` derivation the *signing target* uses
/// (`apps/gasolina/src/app/sdks/gasolinaSdk/evm/index.ts:137-145`).
///
/// The assertions are on which contract each call went to, because the outcome
/// alone can be reached by accident: a scripted response decoded by the wrong
/// decoder can still land on `Signed`.
#[tokio::test]
async fn payload_signed_reads_the_receive_library_the_endpoint_reports() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            // getReceiveLibrary(receiver, srcEid) -> (ReceiveUln301, isDefault=false)
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_301, false)),
            // isValidReceiveLibrary(receiver, srcEid, lib) -> true
            eth_call_result(&abi_word(1)),
            // getUlnConfig on ULN301
            eth_call_result(&abi_word(64)),
            // hashLookup on ULN301 -> already confirmed by this DVN
            eth_call_result(&abi_bool_uint64(true, 64)),
            // verifiable on ULN301View
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    let error = checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            "0x3333333333333333333333333333333333333333",
            "bsc",
        )
        .await
        .expect_err("the DVN has already attested on the library the OApp uses");
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(
        error.to_string().contains("Payload already signed"),
        "{error}"
    );

    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].2["params"][0]["to"], TEST_ENDPOINT_V2,
        "the receive library has to be read from the destination endpoint"
    );
    assert_eq!(
        calls[2].2["params"][0]["to"], TEST_RECEIVE_ULN_301,
        "the config has to come from the library the endpoint reported"
    );
    assert_eq!(
        calls[3].2["params"][0]["to"], TEST_RECEIVE_ULN_301,
        "the attestation has to be looked up on the reported library"
    );
}

/// The default library is trusted without the extra round trip, exactly as
/// upstream skips `isValidReceiveLibrary` when `isDefault` is set
/// (TS: `endpoint/evm/endpointV2.ts:91-102`).
#[tokio::test]
async fn payload_signed_trusts_a_default_library_without_revalidating_it() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, true)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            "0x3333333333333333333333333333333333333333",
            "bsc",
        )
        .await
        .unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 4, "a default library needs no revalidation");
    assert_eq!(calls[0].2["params"][0]["to"], TEST_ENDPOINT_V2);
    assert_eq!(calls[1].2["params"][0]["to"], TEST_RECEIVE_ULN_302);
}

/// An address that is none of the three known message libraries.
///
/// Upstream throws `Cannot get ULN Version from Address`
/// (TS: `endpoint/evm/decoders/index.ts:86-88`). Falling back to the `dstEid`
/// derivation would read a contract the OApp does not receive on, so a payload
/// already attested on the real library would look unsigned.
#[tokio::test]
async fn payload_signed_refuses_an_unrecognised_receive_library() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_address_bool(
                "0x00000000000000000000000000000000deadbeef",
                true,
            )),
            // Present only to prove they are never reached.
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    let error = checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            "0x3333333333333333333333333333333333333333",
            "bsc",
        )
        .await
        .expect_err("an unvalidatable library must not be signed over");
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(
        error.to_string().contains("cannot validate"),
        "the refusal has to name the cause: {error}"
    );

    let calls = calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "no library was resolved, so no library may be read"
    );
}

/// A non-default library the endpoint itself rejects.
///
/// TS: `endpoint/evm/endpointV2.ts:97-101` raises `Invalid ULN version for
/// lib`. The address is a *recognised* library here, so only the
/// `isValidReceiveLibrary` answer can produce the refusal - a fallback to the
/// derivation would sail through, since the derivation picks ULN302 anyway.
#[tokio::test]
async fn payload_signed_refuses_a_library_the_endpoint_calls_invalid() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, false)),
            eth_call_result(&abi_word(0)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    let error = checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            "0x3333333333333333333333333333333333333333",
            "bsc",
        )
        .await
        .expect_err("the endpoint rejected the override, so it cannot be trusted");
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");

    let calls = calls.lock().unwrap();
    assert_eq!(
        calls.len(),
        2,
        "resolution stops at the rejected override: {:?}",
        calls
            .iter()
            .map(|call| &call.2["params"][0]["to"])
            .collect::<Vec<_>>()
    );
}

/// A V2 message addressed to a V1 endpoint reads `getReceiveLibraryAddress`,
/// which takes no source eid, instead of assuming ULN301 from the eid range.
///
/// TS: `endpoint/evm/endpointV1.ts:86-110`.
#[tokio::test]
async fn payload_signed_resolves_a_v1_endpoint_destination_on_chain() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_word_address(TEST_RECEIVE_ULN_301)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(true, 64)),
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    let mut event = payload_signed_sent_event();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(102));

    let error = checks
        .validate_payload_not_signed(&event, "0x3333333333333333333333333333333333333333", "bsc")
        .await
        .expect_err("the DVN has already attested on the resolved library");
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(
        error.to_string().contains("Payload already signed"),
        "{error}"
    );

    let calls = calls.lock().unwrap();
    assert_eq!(
        calls[0].2["params"][0]["to"], TEST_ENDPOINT_V1,
        "a V1 destination is asked on the V1 endpoint"
    );
    assert_eq!(calls[1].2["params"][0]["to"], TEST_RECEIVE_ULN_301);
}

/// Two providers, both concluding "not signed", but from different libraries.
///
/// The verdicts coincide, so agreeing on the verdict alone would let a
/// provider that misreports the receiver's configuration pick which contract
/// the DVN trusts. The library is therefore part of what the quorum agrees on,
/// the same shape as the TON branch agreeing on storage
/// (`runtime_rpc_validation_checks_require_ton_providers_to_agree_on_storage`).
///
/// Both providers are asserted to have asked the endpoint. Without that, this
/// test passes under a derivation fallback too - the scripted responses would
/// simply be consumed by the wrong decoders and still diverge, so the error
/// alone proves nothing about *why* the quorum failed.
#[tokio::test]
async fn payload_signed_requires_providers_to_agree_on_the_receive_library() {
    let first = "https://bsc-a.example".to_string();
    let second = "https://bsc-b.example".to_string();
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri(first.clone()),
                    ProviderUri::Uri(second.clone()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    // Identical shapes: both non-default, both revalidated, both unsigned.
    // Only the library differs.
    let provider_responses = |library: &str| {
        vec![
            eth_call_result(&abi_address_bool(library, false)),
            eth_call_result(&abi_word(1)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(0)),
        ]
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = PerUrlPayloadTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(HashMap::from([
            (first.clone(), provider_responses(TEST_RECEIVE_ULN_302)),
            (second.clone(), provider_responses(TEST_RECEIVE_ULN_301)),
        ]))),
    };
    let checks = RuntimeRpcValidationChecks::from_getter(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
    )
    .with_evm_receive_contracts(HashMap::from([(
        "bsc".to_string(),
        test_receive_contracts(),
    )]));

    let error = checks
        .validate_payload_not_signed(
            &payload_signed_sent_event(),
            "0x3333333333333333333333333333333333333333",
            "bsc",
        )
        .await
        .expect_err("providers disagreeing on the library must not reach quorum");
    assert!(
        matches!(error, AppCoreError::Internal(_)),
        "an ambiguous library is a quorum failure, not a verdict: {error}"
    );

    let calls = calls.lock().unwrap();
    for url in [&first, &second] {
        assert_eq!(
            calls
                .iter()
                .find(|(called_url, _)| called_url == url)
                .map(|(_, body)| body["params"][0]["to"].clone()),
            Some(Value::from(TEST_ENDPOINT_V2)),
            "{url} has to resolve the library itself"
        );
    }
}

/// The shape the packet resolver actually produces.
///
/// `decode_lz_packet_v1` reads the receiver as `bytes32`
/// (`crates/pillar-layerzero/src/packet.rs`), and `packet_resolver` puts that
/// verbatim into `pathway.extra.receiver` - it has to, because the packet
/// header this service signs over is built from the padded form. Every other
/// test here uses a 20-byte fixture receiver, so none of them touch this.
///
/// Before the narrowing, the *pre-existing* `getUlnConfig` call rejected it
/// with `invalid address length: 32`, which the observation swallowed into
/// `Missing`: the EVM payload-signed check never ran against a real packet and
/// reported "validation unavailable" instead. Both the endpoint reads and that
/// config call are asserted here, because they share the one narrowed value.
#[tokio::test]
async fn payload_signed_accepts_the_bytes32_receiver_the_resolver_produces() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![
            eth_call_result(&abi_address_bool(TEST_RECEIVE_ULN_302, true)),
            eth_call_result(&abi_word(64)),
            eth_call_result(&abi_bool_uint64(false, 0)),
            eth_call_result(&abi_word(0)),
        ],
        calls.clone(),
    );

    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.extra.insert(
        "receiver".to_string(),
        Value::from("0x0000000000000000000000002222222222222222222222222222222222222222"),
    );

    checks
        .validate_payload_not_signed(&event, "0x3333333333333333333333333333333333333333", "bsc")
        .await
        .expect("a bytes32 receiver is what the resolver hands over");

    let calls = calls.lock().unwrap();
    let expected_oapp = "2222222222222222222222222222222222222222";
    assert_eq!(calls[0].2["params"][0]["to"], TEST_ENDPOINT_V2);
    assert!(
        calls[0].2["params"][0]["data"]
            .as_str()
            .unwrap()
            .contains(expected_oapp),
        "getReceiveLibrary carries the narrowed address: {}",
        calls[0].2["params"][0]["data"]
    );
    assert!(
        calls[1].2["params"][0]["data"]
            .as_str()
            .unwrap()
            .contains(expected_oapp),
        "the pre-existing getUlnConfig call carries it too: {}",
        calls[1].2["params"][0]["data"]
    );
}

/// A 32-byte receiver whose leading bytes are not zero is not an EVM address.
///
/// Upstream would silently keep the low 20 bytes
/// (`packages/static-config/src/index.ts:723-727`). Attesting for a truncated
/// address is attesting for a different OApp than the packet names, so this
/// refuses. Deliberate divergence, recorded in SECURITY.md.
#[tokio::test]
async fn payload_signed_refuses_a_receiver_that_is_not_a_padded_evm_address() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let checks = runtime_rpc_payload_checks(
        vec![eth_call_result(&abi_address_bool(
            TEST_RECEIVE_ULN_302,
            true,
        ))],
        calls.clone(),
    );

    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.extra.insert(
        "receiver".to_string(),
        Value::from("0x9999999999999999999900002222222222222222222222222222222222222222"),
    );

    let error = checks
        .validate_payload_not_signed(&event, "0x3333333333333333333333333333333333333333", "bsc")
        .await
        .expect_err("truncating this would attest for a different OApp");
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(error.to_string().contains("not an EVM address"), "{error}");
    assert!(
        calls.lock().unwrap().is_empty(),
        "nothing is dialled for an address that cannot be formed"
    );
}

type QueuedEthCallsByUrl = Arc<Mutex<HashMap<String, Vec<Result<Value, String>>>>>;

#[derive(Clone)]
struct PerUrlPayloadTransport {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    responses: QueuedEthCallsByUrl,
}

#[async_trait]
impl JsonRpcTransport for PerUrlPayloadTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        self.calls.lock().unwrap().push((url.clone(), body));
        let mut responses = self.responses.lock().unwrap();
        let queue = responses
            .get_mut(&url)
            .unwrap_or_else(|| panic!("no responses queued for {url}"));
        queue.remove(0)
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("unexpected GET".to_string())
    }
}
