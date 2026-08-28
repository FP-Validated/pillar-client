use super::*;

/// Storage BOCs produced by
/// `pillar_layerzero` `other_non_evm::ton::payload_signed::tests::runtime_storage_fixtures_are_stable`,
/// which is the authoritative builder for these class cells. If the class
/// encoding ever changes, that test fails there and the decodes below fail here.
///
/// `UlnConnection` storage: attestation from DVN `0xaa..aa` for nonce 7, and a
/// receive config that lists that DVN.
const ATTESTED_CONNECTION: &str = "te6cckECCAEAAaEAA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgcHAQRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAgMHAnNVbG5SZWN2Q2ZnAV7UV/AX/YYDAcDk/8AcHk/9McL//////////////////gAAAAEAAAAAAAAAAAAgBAcBQ6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAFAECqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgFDoBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVUAYApwAAAABBdHRlc3SBXtiXv//////////////////////////////////////93d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3dwAAAAAAAAABgAA42yTPA==";
/// `UlnConnection` storage whose `hashLookups` dictionary is empty.
const EMPTY_CONNECTION: &str = "te6cckECBQEAAQEAA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgQEAQRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAgQEAnNVbG5SZWN2Q2ZnAV7UV/AX/YYDAcDk/8AcHk/9McL//////////////////gAAAAEAAAAAAAAAAAAgAwQAQKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqAACEskBt";
/// `UlnConnection` storage with an attestation from `0xaa..aa` whose receive
/// config only lists `0xbb..bb`.
const FOREIGN_DVN_CONNECTION: &str = "te6cckECCAEAAaEAA+djb25uZWN0aW9uk/8k/9gV7gl7Y17iADm/8m/9m/+m/////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgcHAQRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAgMHAnNVbG5SZWN2Q2ZnAV7UV/AX/YYDAcDk/8AcHk/9McL//////////////////gAAAAEAAAAAAAAAAAAgBAcBQ6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAFAEC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7uwFDoBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVUAYApwAAAABBdHRlc3SBXtiXv//////////////////////////////////////93d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3dwAAAAAAAAABgAAhwJfzA==";
/// `Uln` storage whose `defaultUlnReceiveConfig` has empty, non-null DVN lists.
const ULN_STORAGE: &str = "te6cckEBBAEAhAADcwAAAAAAAAB1bG6T/xRXtRfuT/2b/yb/2b/5BntBrtBvv//////////////8AAAAAAAAAAAAAAAAAAIDAQICc1VsblJlY3ZDZmcBXtRX8Bf9hgMBwOT/wBweT/0xwv/////////////////+AAAAAQAAAAAAAAAAACADAwMAAwMDAACgWnrC";

/// A DVN in the fixture's receive config.
const CONFIGURED_VERIFIER: &str =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn ton_sent_event() -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "ton".to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(30_343));
    event.lz_message_id.pathway_id.extra.insert(
        "receiver".to_string(),
        Value::from("0:2222222222222222222222222222222222222222222222222222222222222222"),
    );
    event
}

fn address_information(storage_base64: &str) -> Result<Value, String> {
    Ok(json!({ "result": { "state": "active", "data": storage_base64 } }))
}

fn committable_view(state: u64) -> Result<Value, String> {
    Ok(json!({
        "result": { "exit_code": 0, "stack": [["num", format!("0x{state:x}")]] }
    }))
}

/// The validator reads the connection storage, then the ULN storage, then calls
/// `committableView`.
fn ton_checks(
    responses: Vec<Result<Value, String>>,
    calls: RecordedJsonCalls,
) -> RuntimeRpcValidationChecks<RecordingTransport> {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "ton".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://ton.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls,
            responses: Arc::new(Mutex::new(responses)),
        },
        "mainnet",
        &["ton".to_string()],
    )
    .unwrap();
    // The TON branch must never fall through to the EVM receive-contract
    // lookup, so deliberately leave the EVM contract map empty.
    checks.with_evm_receive_contracts(HashMap::new())
}

/// Observed by invoking `committableView` on the real mainnet `UlnConnection`
/// `0:168B0D4BC86F5F148DDC86AEE8D8A9AF61D75C82E8C4509A14C8C0377DA8AD79` with
/// **its own** on-chain arguments: the `lz::Packet` and `UlnRecvCfg` cells were
/// extracted from that contract's inbound `MdObj` message (opcode
/// `0xf9d37b80`) for the Ethereum(30101) -> TON(30343) pathway at nonce 2095,
/// its `firstUnexecutedNonce`. Raw state `0x2` is `VERIFIED`, so a signing
/// request for that packet must be refused.
///
/// The same contract answers `0x3` for the already-executed nonce 2094, which
/// is how we know these are genuine per-nonce reads and not a constant.
fn live_verified_pending_response() -> Result<Value, String> {
    Ok(json!({
        "result": {
            "@type": "smc.runResult",
            "gas_used": 3559,
            "exit_code": 0,
            "stack": [["num", "0x2"]]
        }
    }))
}

/// The pathway of the real delivered message, so the validator builds the real
/// packet rather than a synthetic one. The field values are owned by
/// `pillar_layerzero`'s
/// `other_non_evm::ton::payload_signed::tests::rebuilds_the_live_mainnet_inbound_packet_byte_for_byte`,
/// which proves this pathway reproduces `LIVE_PACKET_BOC` byte for byte.
fn live_ton_sent_event() -> LzSentEvent {
    let mut event = payload_signed_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "ton".to_string();
    event.lz_message_id.nonce = 2095;
    event.message =
        "0x00030000000000000000000000000000000000000016542ba463000000000000000000000000000000000000000000000000"
            .to_string();
    let extra = &mut event.lz_message_id.pathway_id.extra;
    extra.insert("srcEid".to_string(), Value::from(30_101));
    extra.insert("dstEid".to_string(), Value::from(30_343));
    extra.insert(
        "sender".to_string(),
        Value::from("0x1f748c76de468e9d11bd340fa9d5cbadf315dfb0"),
    );
    extra.insert(
        "receiver".to_string(),
        Value::from("0x1ddf580052174ed1dd0d66c35bfdc1a5fcc69af4f4ae36154b13dcfc6c14a35f"),
    );
    event.extra.insert(
        "guid".to_string(),
        Value::from("0xb017e830f88f78a02579795cc188eb417860be607e91924003f56c8674e408fe"),
    );
    event
}

/// End-to-end lock on the live TON read: the validator must put the real
/// nonce and the real `lz::Packet` BOC on the wire, and the state that the
/// deployed contract actually answered for them must refuse the signature.
///
/// Asserting the recorded request is the point. Without it this would only
/// re-check the `0x2 -> BadRequest` mapping and any packet at all would pass.
#[tokio::test]
async fn runtime_rpc_validation_checks_send_the_live_packet_and_reject_its_verified_state() {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            live_verified_pending_response(),
        ],
        calls.clone(),
    );

    let error = checks
        .validate_payload_not_signed(&live_ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
    assert!(error
        .to_string()
        .starts_with("Payload already signed for message {"));

    let recorded = calls.lock().unwrap();
    let get_method = recorded
        .iter()
        .find_map(|(_, _, body)| (body["method"] == "runGetMethod").then_some(body))
        .expect("committableView must be invoked");
    let params = &get_method["params"];
    assert_eq!(params["method"], "committableView");
    let stack = params["stack"].as_array().expect("stack array");
    assert_eq!(stack[0][1], Value::from("2095"), "real nonce on the wire");
    assert_eq!(
        stack[1][1],
        Value::from(pillar_layerzero::LIVE_TON_PACKET_BOC),
        "the packet argument must be the real delivered packet"
    );
    assert_eq!(stack[1][0], Value::from("tvm.Cell"));
    assert_eq!(stack[2][0], Value::from("tvm.Cell"));
}

/// The verbatim toncenter response observed when `committableView` was invoked
/// on the real mainnet `UlnConnection`
/// `0:168B0D4BC86F5F148DDC86AEE8D8A9AF61D75C82E8C4509A14C8C0377DA8AD79` with
/// arguments this crate built (nonce 1, an `lz::Packet` BOC and the `Uln`'s
/// `defaultUlnReceiveConfig` BOC). Raw state `0x3` is "VERIFIED (executed)", so
/// the request must be refused as already signed.
fn live_committable_view_response() -> Result<Value, String> {
    Ok(json!({
        "result": {
            "@type": "smc.runResult",
            "gas_used": 1904,
            "exit_code": 0,
            "stack": [["num", "0x3"]]
        }
    }))
}

/// The verbatim response for a `UlnConnection` address that is derived
/// correctly but never deployed (an unused pathway): the get-method cannot run.
fn live_uninitialized_contract_response() -> Result<Value, String> {
    Ok(json!({
        "result": {
            "@type": "smc.runResult",
            "gas_used": 0,
            "exit_code": -13,
            "stack": [["num", "0x1"]]
        }
    }))
}

#[tokio::test]
async fn runtime_rpc_validation_checks_reject_live_executed_ton_state() {
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            live_committable_view_response(),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)), "{error}");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fail_closed_on_live_uninitialized_connection() {
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            live_uninitialized_contract_response(),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::Internal(_)),
        "an aborted get-method must never read as unsigned: {error}"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_unsigned_ton_payload() {
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            committable_view(0), // VERIFYING
        ],
        calls.clone(),
    );

    checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .expect("an unverified TON packet must pass without an EVM contract lookup");

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].0, "https://ton.example");
    assert_eq!(calls[0].2["method"], "getAddressInformation");
    assert_eq!(calls[1].2["method"], "getAddressInformation");
    // The two storage reads target different contracts: UlnConnection, then Uln.
    assert_ne!(
        calls[0].2["params"]["address"],
        calls[1].2["params"]["address"]
    );
    assert_eq!(calls[2].2["method"], "runGetMethod");
    assert_eq!(calls[2].2["params"]["method"], "committableView");
    // `committableView` is called on the UlnConnection contract.
    assert_eq!(
        calls[2].2["params"]["address"],
        calls[0].2["params"]["address"]
    );
    let stack = calls[2].2["params"]["stack"].as_array().unwrap();
    assert_eq!(stack.len(), 3);
    assert_eq!(stack[0][0], "num");
    assert_eq!(stack[0][1], "7", "nonce is serialized as a decimal num");
    assert_eq!(stack[1][0], "tvm.Cell");
    assert_eq!(stack[2][0], "tvm.Cell");
    // The third argument is the ULN's defaultUlnReceiveConfig, not the packet.
    assert_ne!(stack[1][1], stack[2][1]);
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_committable_ton_payload() {
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            committable_view(1), // VERIFIABLE
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();

    assert!(matches!(error, AppCoreError::BadRequest(_)));
    assert!(error
        .to_string()
        .starts_with("Payload already signed for message {"));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_executed_ton_payload() {
    // Raw state 3 is "VERIFIED (executed)" upstream, which still counts as
    // signed.
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            committable_view(3),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_ton_config_error_state() {
    // Raw state 4 maps back to VERIFYING upstream, so it is not signed.
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            committable_view(4),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .expect("a config-error state is VERIFYING, not signed");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_rejects_ton_payload_for_an_unconfigured_dvn() {
    // The nonce has an attestation but this DVN is not in the destination
    // receive config, so TON could never accept its proof; upstream reports it
    // as already signed to make the request a no-op.
    let checks = ton_checks(
        vec![
            address_information(FOREIGN_DVN_CONNECTION),
            address_information(ULN_STORAGE),
            committable_view(0),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::BadRequest(_)));
}

#[tokio::test]
async fn runtime_rpc_validation_checks_accepts_ton_payload_attested_for_another_packet() {
    // The attestation exists for this nonce and DVN, but hashes a different
    // packet, so this packet is still unsigned.
    let checks = ton_checks(
        vec![
            address_information(ATTESTED_CONNECTION),
            address_information(ULN_STORAGE),
            committable_view(0),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .expect("an attestation for a different packet hash is not this packet's signature");
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fails_closed_on_unreadable_ton_storage() {
    let checks = ton_checks(
        vec![Err("boom".to_string())],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::Internal(_)),
        "unreadable storage must fail closed, not pass: {error}"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_fails_closed_on_aborted_committable_view() {
    let checks = ton_checks(
        vec![
            address_information(EMPTY_CONNECTION),
            address_information(ULN_STORAGE),
            Ok(json!({ "result": { "exit_code": 11, "stack": [] } })),
        ],
        Arc::new(Mutex::new(Vec::new())),
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(matches!(error, AppCoreError::Internal(_)));
}

/// A transport that answers per provider URL, so a two-provider quorum is
/// deterministic regardless of dispatch order.
type QueuedResponsesByUrl = Arc<Mutex<HashMap<String, Vec<Result<Value, String>>>>>;

#[derive(Clone)]
struct PerUrlTransport {
    responses: QueuedResponsesByUrl,
}

#[async_trait]
impl JsonRpcTransport for PerUrlTransport {
    async fn post_json(
        &self,
        url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
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

#[tokio::test]
async fn runtime_rpc_validation_checks_require_ton_providers_to_agree_on_storage() {
    // Both providers derive "not signed", but from different `UlnConnection`
    // storage. Upstream agrees providers on the storage cell itself, so this
    // must not reach quorum.
    let first = "https://ton-a.example".to_string();
    let second = "https://ton-b.example".to_string();
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "ton".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri(first.clone()),
                    ProviderUri::Uri(second.clone()),
                ],
                quorum: Some(2),
            },
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let transport = PerUrlTransport {
        responses: Arc::new(Mutex::new(HashMap::from([
            (
                first,
                vec![
                    address_information(EMPTY_CONNECTION),
                    address_information(ULN_STORAGE),
                    committable_view(0),
                ],
            ),
            (
                second,
                vec![
                    address_information(ATTESTED_CONNECTION),
                    address_information(ULN_STORAGE),
                    committable_view(0),
                ],
            ),
        ]))),
    };
    let checks = runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "mainnet",
        &["ton".to_string()],
    )
    .unwrap();

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();
    assert!(
        matches!(error, AppCoreError::Internal(_)),
        "divergent storage must fail the quorum: {error}"
    );
}

#[tokio::test]
async fn runtime_rpc_validation_checks_skips_ton_payload_without_guid() {
    let mut event = ton_sent_event();
    event.extra.shift_remove("guid");
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let checks = ton_checks(Vec::new(), calls.clone());

    checks
        .validate_payload_not_signed(&event, CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap();
    assert!(calls.lock().unwrap().is_empty(), "V1 messages are skipped");
}

/// `getAddressInformation` for a contract that exists but holds no storage.
/// Upstream's `tonContractStateQuorumFn` folds this into the string `'0'`,
/// which is a value providers can agree on - not the absence of an answer.
fn inactive_address_information() -> Result<Value, String> {
    Ok(json!({ "result": { "state": "uninitialized", "data": "" } }))
}

fn ton_quorum_checks(
    providers: Vec<(&str, Vec<Result<Value, String>>)>,
    quorum: u64,
) -> RuntimeRpcValidationChecks<PerUrlTransport> {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "ton".to_string(),
            ProviderConfig {
                uris: providers
                    .iter()
                    .map(|(url, _)| ProviderUri::Uri((*url).to_string()))
                    .collect(),
                quorum: Some(quorum),
            },
        )]),
        Some(&["ton".to_string()]),
    )
    .unwrap();
    let transport = PerUrlTransport {
        responses: Arc::new(Mutex::new(
            providers
                .into_iter()
                .map(|(url, queue)| (url.to_string(), queue))
                .collect::<HashMap<_, _>>(),
        )),
    };
    runtime_rpc_validation_checks_from_evm_config(
        &ProviderSnapshotHandle::from_getter(&getter),
        transport,
        "mainnet",
        &["ton".to_string()],
    )
    .unwrap()
}

/// Upstream buckets a non-active contract as `'0'` and lets providers agree on
/// it; `fetchQuorumedStorageCell` then throws on the agreed state. Two
/// providers that both see an uninitialized contract have therefore agreed
/// about the chain, and the refusal is a determined verdict.
#[tokio::test]
async fn ton_quorum_lets_providers_agree_that_the_contract_is_not_active() {
    let checks = ton_quorum_checks(
        vec![
            (
                "https://ton-a.example",
                vec![inactive_address_information()],
            ),
            (
                "https://ton-b.example",
                vec![inactive_address_information()],
            ),
        ],
        2,
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();

    // The determined-state refusal, not the no-quorum one.
    assert_eq!(
        format!("{error}"),
        "Payload-signed validation unavailable for chain ton",
        "agreeing that the contract is not active is a verdict, not a failure to answer"
    );
}

/// The mirror of the case above, and the reason the two must not share a
/// bucket. Upstream's provider rejects when it cannot answer, so a dead
/// provider never reaches the quorum function at all. Folding "no answer" into
/// the same value as "not active" would let two dead providers manufacture
/// agreement about a chain neither of them read.
#[tokio::test]
async fn ton_quorum_refuses_to_let_dead_providers_agree() {
    let checks = ton_quorum_checks(
        vec![
            (
                "https://ton-a.example",
                vec![Err("connection refused".to_string())],
            ),
            (
                "https://ton-b.example",
                vec![Err("connection refused".to_string())],
            ),
        ],
        2,
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();

    let rendered = format!("{error}");
    assert!(
        rendered.contains("0 distinct successful responses, 2 errors"),
        "two providers that never answered must be counted as errors, not as an \
         agreeing majority: {rendered}"
    );
}

/// The behavioural consequence. A provider that cannot answer must not be able
/// to outvote one that can: with a quorum of one, the single healthy provider
/// decides the request. While transport failures voted, its answer was one
/// candidate among two and the request was refused for ambiguity.
#[tokio::test(start_paused = true)]
async fn ton_quorum_lets_one_healthy_provider_outweigh_a_dead_one() {
    let checks = ton_quorum_checks(
        vec![
            (
                "https://ton-dead.example",
                vec![Err("connection refused".to_string())],
            ),
            (
                "https://ton-live.example",
                vec![
                    address_information(EMPTY_CONNECTION),
                    address_information(ULN_STORAGE),
                    committable_view(0),
                ],
            ),
        ],
        1,
    );

    checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .expect("the one provider that answered says the payload is unsigned");
}

/// The mixed case the two buckets exist for: one provider reads the chain and
/// reports a non-active contract, two others never answer.
///
/// Upstream has one `'0'` against a quorum of two and two rejected promises, so
/// it cannot reach quorum and the request fails as incomplete. Sharing a bucket
/// would instead give three "missing" votes, clear the quorum, and report a
/// verdict about a chain only one provider actually read.
#[tokio::test]
async fn ton_quorum_does_not_mix_a_read_contract_with_providers_that_never_answered() {
    let checks = ton_quorum_checks(
        vec![
            (
                "https://ton-a.example",
                vec![inactive_address_information()],
            ),
            (
                "https://ton-b.example",
                vec![Err("connection refused".to_string())],
            ),
            (
                "https://ton-c.example",
                vec![Err("connection refused".to_string())],
            ),
        ],
        2,
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();

    let rendered = format!("{error}");
    assert!(
        rendered.contains("1 distinct successful responses, 2 errors"),
        "one provider read the chain and two did not; they must not add up to a \
         quorum: {rendered}"
    );
}

/// The other direction of the mixed case: the readers are the majority.
///
/// Two providers agree the contract is not active and one never answered.
/// Upstream reaches its quorum of two on `'0'` and throws on the agreed state,
/// so the verdict is determined and the straggler is irrelevant. The failing
/// provider must neither block that quorum nor be counted into it.
#[tokio::test]
async fn ton_quorum_reaches_a_verdict_when_the_readers_outnumber_the_failures() {
    let checks = ton_quorum_checks(
        vec![
            (
                "https://ton-a.example",
                vec![inactive_address_information()],
            ),
            (
                "https://ton-b.example",
                vec![Err("connection refused".to_string())],
            ),
            (
                "https://ton-c.example",
                vec![inactive_address_information()],
            ),
        ],
        2,
    );

    let error = checks
        .validate_payload_not_signed(&ton_sent_event(), CONFIGURED_VERIFIER, "ton")
        .await
        .unwrap_err();

    assert_eq!(
        format!("{error}"),
        "Payload-signed validation unavailable for chain ton",
        "two providers read the same non-active contract, so the verdict is determined \
         rather than an incomplete response set"
    );
}
