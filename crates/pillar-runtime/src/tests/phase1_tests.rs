use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt;

struct StalledSource {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}
struct ActiveSource(Arc<AtomicUsize>);
impl Drop for ActiveSource {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl SentEventResolver for StalledSource {
    async fn get_lz_sent_event(
        &self,
        tx: &str,
        id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        if id.pathway_id.src_chain_name == "ethereum" {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let _active = ActiveSource(self.active.clone());
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
        }
        FixedResolver.get_lz_sent_event(tx, id).await
    }
}
fn sign_http(source: &str, nonce: u64) -> Request<Body> {
    let mut input = request_v2();
    input.lz_message_id.pathway_id.src_chain_name = source.to_string();
    input.lz_message_id.nonce = nonce;
    input.lz_message_id.pathway_id.extra = IndexMap::from([
        (
            "srcEid".into(),
            json!(if source == "ethereum" { 30101 } else { 30102 }),
        ),
        ("dstEid".into(), json!(30102)),
        (
            "sender".into(),
            json!("0x1111111111111111111111111111111111111111"),
        ),
        (
            "receiver".into(),
            json!("0x2222222222222222222222222222222222222222"),
        ),
    ]);
    Request::builder()
        .method("POST")
        .uri("/v2/resolve-and-sign")
        .header(
            "authorization",
            "Bearer test-token-0123456789abcdef0123456789",
        )
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&input).unwrap()))
        .unwrap()
}
#[tokio::test]
async fn phase1_runtime_preserves_headroom_and_bounds_overload() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut core = core_api_app();
    core.core.sent_event_resolver = Arc::new(StalledSource {
        entered: entered.clone(),
        release: release.clone(),
        active: active.clone(),
        peak: peak.clone(),
    });
    let vars = HashMap::from([
        (SERVER_PORT.into(), "0".into()),
        (
            pillar_config::PILLAR_API_AUTH_TOKENS.into(),
            "test-token-0123456789abcdef0123456789".into(),
        ),
        (LZ_PROVIDER_CONFIG_TYPE.into(), "LOCAL".into()),
        (LZ_ENV.into(), "mainnet".into()),
        (
            pillar_config::LZ_AVAILABLE_CHAIN_NAMES.into(),
            "ethereum,bsc".into(),
        ),
        (
            LZ_PROVIDER_CONFIG.into(),
            providers_json(
                r#"{"ethereum":{"uris":["https://eth.example"],"quorum":1},"bsc":{"uris":["https://bsc.example"],"quorum":1}}"#,
            ),
        ),
        (
            LZ_QUORUM_STRATEGY_CONFIG.into(),
            strategy_json(
                r#"{"ethereum":{"uris":["https://eth.example"],"quorum":1},"bsc":{"uris":["https://bsc.example"],"quorum":1}}"#,
            ),
        ),
        ("PILLAR_SIGN_CONCURRENCY".into(), "2".into()),
        ("PILLAR_SIGN_CHAIN_CONCURRENCY".into(), "1".into()),
        ("PILLAR_SIGN_QUEUE_CAPACITY".into(), "2".into()),
        ("PILLAR_SIGN_CHAIN_QUEUE_CAPACITY".into(), "1".into()),
        ("PILLAR_ADMISSION_WAIT_MS".into(), "200".into()),
    ]);
    let runtime = RuntimeServerApp::from_env_map(
        vars,
        RecordingTransport {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
        },
        || 777,
    )
    .await
    .unwrap()
    .with_signing_app(Arc::new(core));
    let app = pillar_api::router(runtime, "phase1");
    let mut first = tokio::spawn(app.clone().oneshot(sign_http("ethereum", 1)));
    tokio::select! {
        _ = entered.notified() => {},
        response = &mut first => { let response = response.unwrap().unwrap(); let status = response.status(); let body = to_bytes(response.into_body(), 100_000).await.unwrap(); panic!("first sign did not reach source resolver: {status} {}", String::from_utf8_lossy(&body)); },
        _ = tokio::time::sleep(Duration::from_secs(2)) => { first.abort(); panic!("first sign did not enter source resolver within bounded smoke deadline"); }
    }
    let waiting = tokio::spawn(app.clone().oneshot(sign_http("ethereum", 2)));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let healthy = tokio::time::timeout(
        Duration::from_millis(100),
        app.clone().oneshot(sign_http("bsc", 3)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);
    let overloaded = tokio::time::timeout(
        Duration::from_millis(100),
        app.clone().oneshot(sign_http("ethereum", 4)),
    )
    .await
    .unwrap()
    .unwrap();
    let status = overloaded.status();
    let body: Value =
        serde_json::from_slice(&to_bytes(overloaded.into_body(), 100_000).await.unwrap()).unwrap();
    waiting.abort();
    let _ = waiting.await;
    release.notify_one();
    assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["statusCode"], 500);
    assert!(body["body"].is_string());
    assert!(!body.to_string().contains("\"signatures\""));
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    println!("PHASE1_ADMISSION_ARTIFACT healthy=200 overload=500 source_peak=1 envelope={body}");
}
