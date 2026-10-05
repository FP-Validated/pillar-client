use super::*;
use axum::{body::Bytes, routing::get};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn artifact(name: &str, value: &str) {
    let directory = std::env::var_os("PILLAR_E2E_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../local/e2e-runs")
        });
    static RUN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let directory = directory.join(RUN.get_or_init(|| {
        format!(
            "run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(format!("{name}.json")), value).unwrap();
    println!("{value}");
}

#[tokio::test]
async fn deadline_boundary_returns_eof_without_envelope_100_times() {
    let mut eof = 0;
    for _ in 0..100 {
        let app = pillar_api::router(
            pillar_api::StaticApp::observed_mainnet().with_api_auth_enabled(false),
            "synthetic",
        )
        .layer(axum::middleware::from_fn(
            |request: axum::http::Request<Body>, next: axum::middleware::Next| async move {
                let response = next.run(request).await;
                if let Some(context) = pillar_core::execution::current() {
                    let deadline = context.deadline.unwrap();
                    tokio::time::sleep_until(deadline).await;
                }
                response
            },
        ));
        let observed = app.clone();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection_controlled(
                stream,
                app,
                Duration::from_millis(3),
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(5),
                None,
            )
            .await
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.is_empty(),
            "deadline must close before any response bytes: {response:?}"
        );
        assert!(server.await.unwrap().is_err());
        let metrics = observed
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let text = String::from_utf8(
            axum::body::to_bytes(metrics.into_body(), 1_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            text.contains(
                "pillar_http_outcomes_total{method=\"GET\",path=\"/\",outcome=\"timed_out\"} 1"
            ),
            "{text}"
        );
        assert!(!text.contains("path=\"/\",outcome=\"success\"}"), "{text}");
        eof += 1;
    }
    assert_eq!(eof, 100);
    artifact("T6-deadline-boundary", &format!("{{\"criterion\":\"T6\",\"rounds\":{eof},\"deadline_eof\":{eof},\"http_envelopes\":0,\"wire_bytes\":0,\"verified_timed_out_metrics\":{eof},\"verified_false_success_metrics\":0}}"));
}

struct StreamingBody(tokio::sync::mpsc::Receiver<Bytes>);
impl hyper::body::Body for StreamingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        self.get_mut()
            .0
            .poll_recv(cx)
            .map(|frame| frame.map(|bytes| Ok(hyper::body::Frame::data(bytes))))
    }
}

#[tokio::test]
async fn idle_eviction_preserves_the_entire_active_response_body() {
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let receiver = Arc::new(tokio::sync::Mutex::new(Some(receiver)));
    let fast_entered = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/slow",
            get(move || {
                let receiver = receiver.clone();
                async move {
                    axum::http::Response::builder()
                        .header("Content-Length", 16_384)
                        .body(Body::new(StreamingBody(
                            receiver.lock().await.take().unwrap(),
                        )))
                        .unwrap()
                }
            }),
        )
        .route(
            "/fast",
            get({
                let entered = fast_entered.clone();
                move || {
                    let entered = entered.clone();
                    async move {
                        entered.fetch_add(1, Ordering::SeqCst);
                        "FAST"
                    }
                }
            }),
        );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_, signal) =
        pillar_api::router_with_shutdown(pillar_api::StaticApp::observed_mainnet(), "synthetic");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_until(
        listener,
        app,
        1,
        Duration::from_secs(1),
        Duration::ZERO,
        signal,
        async move {
            stopped.await.unwrap();
            Ok("synthetic-stop")
        },
    ));
    let mut first = TcpStream::connect(address).await.unwrap();
    first
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    sender.send(Bytes::from(vec![b'A'; 8192])).await.unwrap();
    let mut response = Vec::new();
    let body_start = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut chunk = [0; 1024];
            let count = first.read(&mut chunk).await.unwrap();
            assert!(
                count > 0,
                "response must not close before the first body segment"
            );
            response.extend_from_slice(&chunk[..count]);
            if let Some(start) = response.windows(4).position(|window| window == b"\r\n\r\n") {
                if response.len() >= start + 4 + 8192 {
                    break start + 4;
                }
            }
        }
    })
    .await
    .unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    second
        .write_all(b"GET /fast HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(fast_entered.load(Ordering::SeqCst), 0);
    sender.send(Bytes::from(vec![b'B'; 8192])).await.unwrap();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[body_start..body_start + 8192], &[b'A'; 8192]);
    assert_eq!(&response[body_start + 8192..], &[b'B'; 8192]);
    let mut fast = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut fast))
        .await
        .unwrap()
        .unwrap();
    assert!(fast.starts_with(b"HTTP/1.1 200 OK"));
    assert!(fast.ends_with(b"FAST"));
    assert_eq!(fast_entered.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    artifact("T8-active-response-eviction", "{\"criterion\":\"T8\",\"connection_limit\":1,\"delivered_body_bytes\":16384,\"first_segment_verified\":8192,\"last_segment_verified\":8192,\"queued_request_status\":200,\"queued_handler_entered_before_body_complete\":0}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_start_racing_idle_eviction_never_truncates_a_started_response() {
    let mut started = 0;
    let mut evicted = 0;
    for round in 0..40 {
        let entered = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/warm", get(|| async { "WARM" }))
            .route(
                "/slow",
                get({
                    let entered = entered.clone();
                    move || {
                        let entered = entered.clone();
                        async move {
                            entered.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            "STARTED-RESPONSE"
                        }
                    }
                }),
            )
            .route("/fast", get(|| async { "FAST" }));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_, signal) = pillar_api::router_with_shutdown(
            pillar_api::StaticApp::observed_mainnet(),
            "synthetic",
        );
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_until(
            listener,
            app,
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            signal,
            async move {
                stopped.await.unwrap();
                Ok("synthetic-stop")
            },
        ));
        let mut first = TcpStream::connect(address).await.unwrap();
        first
            .write_all(b"GET /warm HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut warm = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !warm.ends_with(b"WARM") {
                let mut bytes = [0; 512];
                let count = first.read(&mut bytes).await.unwrap();
                assert!(count > 0);
                warm.extend_from_slice(&bytes[..count]);
            }
        })
        .await
        .unwrap();
        let write = async {
            if round % 2 == 0 {
                tokio::task::yield_now().await;
            }
            first
                .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
        };
        let new_connection = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(b"GET /fast HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            stream
        };
        let (_write_result, mut second) = tokio::join!(write, new_connection);
        let mut response = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), first.read_to_end(&mut response))
            .await
            .unwrap();
        if entered.load(Ordering::SeqCst) == 1 {
            read.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 OK"));
            assert!(response.ends_with(b"STARTED-RESPONSE"));
            started += 1;
        } else {
            assert!(
                response.is_empty(),
                "a pre-start eviction must not emit a partial response: {response:?}"
            );
            if let Err(error) = read {
                assert!(matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ));
            }
            evicted += 1;
        }
        let mut fast = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut fast))
            .await
            .unwrap()
            .unwrap();
        assert!(fast.starts_with(b"HTTP/1.1 200 OK"));
        assert!(fast.ends_with(b"FAST"));
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
    assert_eq!(started + evicted, 40);
    artifact("T8-start-idle-race", &format!("{{\"criterion\":\"T8\",\"race_rounds\":40,\"started_responses_delivered\":{started},\"prestart_idle_evictions\":{evicted},\"truncated_started_responses\":0,\"competing_requests_status\":200}}"));
}

struct BudgetApp {
    inner: pillar_api::StaticApp,
    resources: Arc<pillar_core::execution::ExecutionResources>,
}
#[async_trait::async_trait]
impl pillar_api::ServerApp for BudgetApp {
    async fn sign_request_v1(
        &self,
        input: pillar_core::PillarApiRequestV1,
    ) -> Result<pillar_core::PillarApiResponse, pillar_api::AppError> {
        self.inner.sign_request_v1(input).await
    }
    async fn sign_request_v2(
        &self,
        input: pillar_core::PillarApiRequestV2,
    ) -> Result<pillar_core::PillarApiResponse, pillar_api::AppError> {
        self.inner.sign_request_v2(input).await
    }
    async fn get_signer_info(
        &self,
        name: String,
    ) -> Result<Vec<pillar_api::SignerInfo>, pillar_api::AppError> {
        self.inner.get_signer_info(name).await
    }
    fn get_available_chain_names(&self) -> Vec<String> {
        self.inner.get_available_chain_names()
    }
    fn get_environment(&self) -> String {
        self.inner.get_environment()
    }
    async fn get_provider_health(
        &self,
    ) -> Result<pillar_core::ProviderHealthSnapshot, pillar_api::AppError> {
        self.inner.get_provider_health().await
    }
    async fn get_provider_health_report(&self) -> Result<serde_json::Value, pillar_api::AppError> {
        self.inner.get_provider_health_report().await
    }
    fn execution_resources(&self) -> Option<Arc<pillar_core::execution::ExecutionResources>> {
        Some(self.resources.clone())
    }
}
#[tokio::test]
async fn drain_grace_closes_all_budgets_and_keeps_started_external_work_unknown() {
    use pillar_core::execution::{
        BudgetError, BudgetLimits, ExecutionResources, FairBudget, Outcome,
    };
    let limits = BudgetLimits {
        active: 4,
        per_lane: 2,
        waiting: 8,
        per_lane_waiting: 4,
        wait: Duration::from_secs(2),
    };
    let lanes = vec!["ethereum".into(), "background".into()];
    let resources = Arc::new(ExecutionResources {
        signing: FairBudget::new(lanes.clone(), limits).unwrap(),
        rpc: FairBudget::new(lanes.clone(), limits).unwrap(),
        kms: FairBudget::new(lanes, limits).unwrap(),
    });
    let mut first = resources
        .rpc
        .acquire_for("ethereum", Some("ethereum"))
        .await
        .unwrap();
    let mut second = resources
        .rpc
        .acquire_for("ethereum", Some("ethereum"))
        .await
        .unwrap();
    let queued = tokio::spawn({
        let resources = resources.clone();
        async move {
            resources
                .rpc
                .acquire_for("ethereum", Some("ethereum"))
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while resources.rpc.totals().waiting != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let entered = Arc::new(Semaphore::new(0));
    let app = Router::new().route(
        "/",
        get({
            let resources = resources.clone();
            let entered = entered.clone();
            move || {
                let resources = resources.clone();
                let entered = entered.clone();
                async move {
                    let mut context = pillar_core::execution::current().unwrap();
                    context.resources = Some(resources.clone());
                    context.source_chain = Some(Arc::from("ethereum"));
                    context
                        .scope(async move {
                            let mut permit = resources
                                .kms
                                .acquire_for("ethereum", Some("synthetic-key"))
                                .await
                                .unwrap();
                            permit.finish(Outcome::Unknown);
                            entered.add_permits(1);
                            std::future::pending::<&'static str>().await
                        })
                        .await
                }
            }
        }),
    );
    let (_, signal) = pillar_api::router_with_shutdown(
        BudgetApp {
            inner: pillar_api::StaticApp::observed_mainnet(),
            resources: resources.clone(),
        },
        "synthetic",
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_until(
        listener,
        app,
        1,
        Duration::from_millis(20),
        Duration::ZERO,
        signal,
        async move {
            stopped.await.unwrap();
            Ok("synthetic-stop")
        },
    ));
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(queued.await.unwrap(), Err(BudgetError::Closed)));
    assert_eq!(resources.rpc.totals().waiting, 0);
    for budget in [&resources.signing, &resources.rpc, &resources.kms] {
        assert!(matches!(
            budget.acquire_for("ethereum", None).await,
            Err(BudgetError::Closed)
        ));
    }
    assert_eq!(resources.kms.totals().active, 0);
    assert_eq!(
        resources.kms.totals().outcomes[Outcome::Unknown as usize],
        1
    );
    assert_eq!(
        resources.kms.totals().outcomes[Outcome::Shutdown as usize],
        1
    );
    first.finish(Outcome::Success);
    second.finish(Outcome::Success);
    drop(first);
    drop(second);
    let mut bytes = Vec::new();
    client.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
    artifact("P3-drain-budget-close","{\"criterion\":\"P3-1\",\"grace_ms\":20,\"closed_budgets\":3,\"queued_rpc_result\":\"Closed\",\"external_unknown\":1,\"kms_active_after_grace\":0,\"sdk_shutdown_misclassified\":0,\"wire_bytes\":0}");
}

#[tokio::test]
async fn completed_response_keeps_success_after_later_shutdown() {
    let context = pillar_core::execution::RequestContext::new(Duration::from_secs(2));
    let metrics = Arc::new(tokio::sync::Mutex::new(pillar_metrics::PillarMetrics::new()));
    let observed = metrics.clone();
    let app = Router::new().route(
        "/",
        get(move || {
            let context = context.clone();
            let metrics = metrics.clone();
            async move {
                let mut guard =
                    metrics
                        .lock()
                        .await
                        .begin_http_request("GET", "/", context.clone());
                guard.finish(200);
                context.shutdown();
                drop(guard);
                "COMPLETED"
            }
        }),
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_connection_controlled(
            stream,
            app,
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(5),
            None,
        )
        .await
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    server.await.unwrap().unwrap();
    assert!(String::from_utf8(response).unwrap().ends_with("COMPLETED"));
    let text = observed
        .lock()
        .await
        .render_prometheus("synthetic", "synthetic");
    assert!(
        text.contains(
            "pillar_http_outcomes_total{method=\"GET\",path=\"/\",outcome=\"success\"} 1"
        ),
        "{text}"
    );
    assert!(!text.contains("outcome=\"shutdown\"}"), "{text}");
    artifact(
        "N7-completion-before-shutdown",
        "{\"wire_body\":\"COMPLETED\",\"success\":1,\"shutdown\":0}",
    );
}
