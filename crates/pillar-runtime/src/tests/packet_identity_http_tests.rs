use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

struct CountingSigner(Arc<AtomicUsize>);

#[async_trait]
impl SignerGetter for CountingSigner {
    async fn pillar_sign(
        &self,
        dst_chain_name: &str,
        wallet_name: &str,
        data_hex: &str,
    ) -> Result<Signature, AppCoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        FixedSigner
            .pillar_sign(dst_chain_name, wallet_name, data_hex)
            .await
    }
}

/// Real EVM resolver over a one-response fake transport, behind the real router.
fn router_over_receipt(
    responses: Vec<Result<Value, String>>,
) -> (axum::Router, Arc<AtomicUsize>, RecordedJsonCalls) {
    router_over_receipt_with(evm_packet_sent_resolver_config("V302"), responses)
}

fn router_over_receipt_with(
    config: EvmPacketSentResolverConfig,
    responses: Vec<Result<Value, String>>,
) -> (axum::Router, Arc<AtomicUsize>, RecordedJsonCalls) {
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let calls: RecordedJsonCalls = Arc::new(Mutex::new(Vec::new()));
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: calls.clone(),
            responses: Arc::new(Mutex::new(responses)),
        },
        config,
    );
    let mut app = core_api_app();
    app.core.sent_event_resolver = Arc::new(resolver);
    for version in ["V2", "V301"] {
        app.core
            .hash_call_data_builders
            .insert(version.to_string(), Arc::new(FixedBuilder));
    }
    app.core.signer_getter = Arc::new(CountingSigner(signer_calls.clone()));
    let app = app.with_public_sign_routes(true);
    (
        pillar_api::router(app, "packet-identity"),
        signer_calls,
        calls,
    )
}

struct FailingResolver(String);

#[async_trait]
impl SentEventResolver for FailingResolver {
    async fn get_lz_sent_event(
        &self,
        _src_tx_hash: &str,
        _lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        Err(AppCoreError::Internal(self.0.clone()))
    }
}

fn router_over_failing_resolver(message: String) -> (axum::Router, Arc<AtomicUsize>) {
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let mut app = core_api_app();
    app.core.sent_event_resolver = Arc::new(FailingResolver(message));
    app.core.signer_getter = Arc::new(CountingSigner(signer_calls.clone()));
    let app = app.with_public_sign_routes(true);
    (pillar_api::router(app, "packet-identity"), signer_calls)
}

fn sign_http(request: &LzMessageId) -> Request<Body> {
    let input = PillarApiRequestV2 {
        lz_message_id: request.clone(),
        ..request_v2()
    };
    Request::builder()
        .method("POST")
        .uri("/v2/resolve-and-sign")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&input).unwrap()))
        .unwrap()
}

async fn post(router: axum::Router, request: &LzMessageId) -> (StatusCode, Value) {
    let response = router.oneshot(sign_http(request)).await.unwrap();
    let status = response.status();
    let body =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    (status, body)
}

#[tokio::test]
async fn matching_trusted_event_signs_through_http() {
    let (router, signer_calls, _) = router_over_receipt(vec![Ok(json!({
        "result": packet_sent_endpoint_v2_data()
    }))]);

    let (status, body) = post(router, &evm_packet_sent_request("V302")).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["statusCode"], 200);
    assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
}

/// Upstream's body: `JSON.stringify` of the Zod-parsed pathway, whose key order is
/// the schema's (`common-model/src/v2/lzMessage.ts:78-85`). Spelled out, because
/// `json!` would sort the keys.
fn upstream_mismatch_body(request: &LzMessageId) -> String {
    let pathway = &request.pathway_id;
    format!(
        r#"cannot find packet event for srcTxHash 0xtx on pathway {{"srcEid":{},"dstEid":{},"sender":{},"receiver":{},"srcChainName":"{}","dstChainName":"{}"}}"#,
        pathway.extra["srcEid"],
        pathway.extra["dstEid"],
        pathway.extra["sender"],
        pathway.extra["receiver"],
        pathway.src_chain_name,
        pathway.dst_chain_name,
    )
}

async fn assert_upstream_mismatch(receipt: Value, request: LzMessageId) {
    assert_upstream_mismatch_with(evm_packet_sent_resolver_config("V302"), receipt, request).await;
}

async fn assert_upstream_mismatch_with(
    config: EvmPacketSentResolverConfig,
    receipt: Value,
    request: LzMessageId,
) {
    let (router, signer_calls, calls) =
        router_over_receipt_with(config, vec![Ok(json!({ "result": receipt }))]);

    let (status, body) = post(router, &request).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body,
        json!({ "statusCode": 400, "body": upstream_mismatch_body(&request) })
    );
    assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.lock().unwrap().len(), 1, "one receipt read");
}

#[tokio::test]
async fn trusted_event_with_other_nonce_is_a_client_error_without_signing() {
    let mut request = evm_packet_sent_request("V302");
    request.nonce += 1;
    assert_upstream_mismatch(packet_sent_endpoint_v2_data(), request).await;
}

#[tokio::test]
async fn trusted_event_with_other_sender_is_a_client_error_without_signing() {
    let mut request = evm_packet_sent_request("V302");
    request.pathway_id.extra.insert(
        "sender".to_string(),
        Value::from("0x0000000000000000000000009999999999999999999999999999999999999999"),
    );
    assert_upstream_mismatch(packet_sent_endpoint_v2_data(), request).await;
}

/// Upstream's log filter ignores an untrusted emitter and then reports the same
/// `Packet does not match lzMessageId` (`endpoint/evm/index.ts:205-231`).
#[tokio::test]
async fn receipt_without_a_trusted_packet_sent_is_upstreams_400_without_signing() {
    let mut forged = packet_sent_endpoint_v2_data();
    forged["logs"][0]["address"] = Value::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_upstream_mismatch(forged, evm_packet_sent_request("V302")).await;
}

#[tokio::test]
async fn resolver_failure_quoting_the_mismatch_text_stays_a_server_error() {
    let (router, signer_calls) = router_over_failing_resolver(
        "provider said: does not match the requested pathway identity".to_string(),
    );

    let (status, body) = post(router, &evm_packet_sent_request("V302")).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["statusCode"], 500, "{body}");
    assert!(body["body"].as_str().unwrap().contains("provider said"));
    assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provider_failure_keeps_its_server_error() {
    let (router, signer_calls, _) =
        router_over_receipt(vec![Err("provider unavailable".to_string())]);

    let (status, body) = post(router, &evm_packet_sent_request("V302")).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["statusCode"], 500, "{body}");
    assert_eq!(signer_calls.load(Ordering::SeqCst), 0);
}

const SEND_ULN_302: &str = "0x3333333333333333333333333333333333333333";
const SEND_ULN_301: &str = "0x4444444444444444444444444444444444444444";
const ULN_V2: &str = "0x5555555555555555555555555555555555555555";
const ENDPOINT_V2: &str = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// Every EVM source contract bound, each at its own address.
fn fully_bound_config() -> EvmPacketSentResolverConfig {
    let mut config = evm_packet_sent_resolver_config("V302");
    config.chain_name_by_eid.insert(101, "ethereum".to_string());
    config.chain_name_by_eid.insert(102, "bsc".to_string());
    let bindings = config
        .packet_sent_bindings_by_chain_name
        .get_mut("ethereum")
        .unwrap();
    bindings.send_uln_301 = Some(SEND_ULN_301.to_string());
    bindings.uln_v2 = Some(ULN_V2.to_string());
    config
}

fn emitted_by(mut receipt: Value, address: &str) -> Value {
    receipt["logs"][0]["address"] = Value::from(address);
    receipt
}

fn uln_v2_request() -> LzMessageId {
    let mut request = evm_packet_sent_request("V2");
    request.pathway_id.extra["srcEid"] = Value::from(101);
    request.pathway_id.extra["dstEid"] = Value::from(102);
    request
}

/// SendUln302 never emits PacketSent; EndpointV2 does, naming SendUln302 as library.
#[tokio::test]
async fn endpoint_v2_event_from_send_uln_302_is_refused_without_signing() {
    assert_upstream_mismatch_with(
        fully_bound_config(),
        emitted_by(packet_sent_endpoint_v2_data(), SEND_ULN_302),
        evm_packet_sent_request("V302"),
    )
    .await;
}

#[tokio::test]
async fn send_uln_301_event_from_another_bound_contract_is_refused_without_signing() {
    for emitter in [ENDPOINT_V2, ULN_V2, SEND_ULN_302] {
        assert_upstream_mismatch_with(
            fully_bound_config(),
            emitted_by(packet_sent_uln301_data(), emitter),
            evm_packet_sent_request("V301"),
        )
        .await;
    }
}

#[tokio::test]
async fn uln_v2_packet_from_another_bound_contract_is_refused_without_signing() {
    for emitter in [ENDPOINT_V2, SEND_ULN_301, SEND_ULN_302] {
        assert_upstream_mismatch_with(
            fully_bound_config(),
            emitted_by(legacy_uln_v2_packet_data(), emitter),
            uln_v2_request(),
        )
        .await;
    }
}

/// EndpointV2 can only name its own send libraries; a V1-side library is not a version.
#[tokio::test]
async fn endpoint_v2_event_naming_a_v1_library_is_refused_without_signing() {
    for (library, version) in [(SEND_ULN_301, "V301"), (ULN_V2, "V2")] {
        let mut receipt = packet_sent_endpoint_v2_data();
        let data = receipt["logs"][0]["data"]
            .as_str()
            .unwrap()
            .replace(&SEND_ULN_302[2..], &library[2..]);
        receipt["logs"][0]["data"] = Value::from(data);
        let mut request = evm_packet_sent_request(version);
        if version == "V2" {
            request = uln_v2_request();
            request.pathway_id.extra["srcEid"] = Value::from(30_101);
            request.pathway_id.extra["dstEid"] = Value::from(30_102);
        }
        assert_upstream_mismatch_with(fully_bound_config(), receipt, request).await;
    }
}

#[tokio::test]
async fn each_bound_emitter_still_signs_its_own_version() {
    for (receipt, request) in [
        (
            packet_sent_endpoint_v2_data(),
            evm_packet_sent_request("V302"),
        ),
        (
            emitted_by(packet_sent_uln301_data(), SEND_ULN_301),
            evm_packet_sent_request("V301"),
        ),
    ] {
        let (router, signer_calls, _) =
            router_over_receipt_with(fully_bound_config(), vec![Ok(json!({ "result": receipt }))]);

        let (status, body) = post(router, &request).await;

        assert_eq!(status, StatusCode::OK, "{request:?} {body}");
        assert_eq!(signer_calls.load(Ordering::SeqCst), 1);
    }
}

/// V2 signing also needs a receive-library read this harness lacks, so its positive
/// is shown at the resolver, the layer the binding lives in.
#[tokio::test]
async fn bound_uln_v2_packet_still_resolves() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig::with_distinct_entities(
                vec![ProviderUri::Uri("https://rpc.example".to_string())],
                1,
            ),
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let resolver = EvmPacketSentResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(vec![Ok(json!({
                "result": emitted_by(legacy_uln_v2_packet_data(), ULN_V2)
            }))])),
        },
        fully_bound_config(),
    );

    let sent_event = resolver
        .get_lz_sent_event("0xtx", &uln_v2_request())
        .await
        .unwrap();

    assert_eq!(sent_event.lz_message_id.uln_send_version, "V2");
    assert_eq!(sent_event.extra["sendLibrary"], ULN_V2);
}
