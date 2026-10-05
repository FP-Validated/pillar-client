use super::*;
use pillar_api::{AppError, ReadinessStatus, ServerApp};
use pillar_core::execution::{BudgetError, BudgetLimits, ExecutionResources, FairBudget, Outcome};
use pillar_core::{PillarApiRequestV1, PillarApiRequestV2, PillarApiResponse, Signature};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Notify};

const DRAINING_ENVELOPE: &str = r#"{"statusCode":500,"body":"resource_draining"}"#;

struct Gate {
    entered: Semaphore,
    release: Notify,
}

/// Admits through the real signing budget, like the production app, so a rejected
/// request is provably absent from both the spy counter and the budget counters.
struct SpyApp {
    signs: Arc<AtomicUsize>,
    gate: Option<Arc<Gate>>,
    resources: Arc<ExecutionResources>,
}

impl SpyApp {
    async fn sign(&self) -> Result<PillarApiResponse, AppError> {
        let _permit = self
            .resources
            .signing
            .acquire("ethereum")
            .await
            .map_err(AppError::Admission)?;
        self.signs.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.entered.add_permits(1);
            gate.release.notified().await;
        }
        Ok(PillarApiResponse {
            signatures: vec![Signature {
                signature: "0xsig".into(),
                address: "0xdvn".into(),
            }],
            payload: "0xpayload".into(),
            debug_info: None,
        })
    }
}

#[async_trait::async_trait]
impl ServerApp for SpyApp {
    async fn sign_request_v1(
        &self,
        _input: PillarApiRequestV1,
    ) -> Result<PillarApiResponse, AppError> {
        self.sign().await
    }
    async fn sign_request_v2(
        &self,
        _input: PillarApiRequestV2,
    ) -> Result<PillarApiResponse, AppError> {
        self.sign().await
    }
    async fn get_signer_info(
        &self,
        _chain_name: String,
    ) -> Result<Vec<pillar_api::SignerInfo>, AppError> {
        Ok(Vec::new())
    }
    fn get_available_chain_names(&self) -> Vec<String> {
        vec!["ethereum".into(), "bsc".into()]
    }
    fn get_environment(&self) -> String {
        "test".into()
    }
    async fn get_provider_health(&self) -> Result<pillar_core::ProviderHealthSnapshot, AppError> {
        Ok(pillar_core::ProviderHealthSnapshot::new())
    }
    async fn get_provider_health_report(&self) -> Result<serde_json::Value, AppError> {
        Ok(serde_json::json!({}))
    }
    fn public_sign_routes(&self) -> bool {
        true
    }
    fn api_auth_enabled(&self) -> bool {
        false
    }
    async fn readiness(&self) -> ReadinessStatus {
        ReadinessStatus::Ready
    }
    fn execution_resources(&self) -> Option<Arc<ExecutionResources>> {
        Some(self.resources.clone())
    }
}

struct Server {
    address: std::net::SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<io::Result<()>>,
    signal: ShutdownSignal,
    signs: Arc<AtomicUsize>,
    gate: Arc<Gate>,
    resources: Arc<ExecutionResources>,
}

fn resources() -> Arc<ExecutionResources> {
    let limits = BudgetLimits {
        active: 4,
        per_lane: 2,
        waiting: 4,
        per_lane_waiting: 2,
        wait: Duration::from_secs(30),
    };
    let lanes = || vec!["ethereum".to_string(), "background".to_string()];
    Arc::new(ExecutionResources {
        signing: FairBudget::new(
            lanes(),
            BudgetLimits {
                per_lane: 1,
                ..limits
            },
        )
        .unwrap(),
        rpc: FairBudget::new(lanes(), limits).unwrap(),
        kms: FairBudget::new(lanes(), limits).unwrap(),
    })
}

async fn start(
    withdrawal: Duration,
    grace: Duration,
    max_connections: usize,
    gated: bool,
) -> Server {
    let signs = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Gate {
        entered: Semaphore::new(0),
        release: Notify::new(),
    });
    let resources = resources();
    let (app, signal) = router_with_shutdown(
        SpyApp {
            signs: signs.clone(),
            gate: gated.then(|| gate.clone()),
            resources: resources.clone(),
        },
        "drain-test",
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(serve_until(
        listener,
        app,
        max_connections,
        grace,
        withdrawal,
        signal.clone(),
        async move {
            stopped.await.unwrap();
            Ok("drain-test")
        },
    ));
    Server {
        address,
        stop: Some(stop),
        task,
        signal,
        signs,
        gate,
        resources,
    }
}

impl Server {
    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.gate.entered.acquire())
            .await
            .expect("the request never reached the spy handler")
            .unwrap()
            .forget();
    }

    async fn signal_shutdown(&mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        while !self.signal.is_triggered() {
            tokio::task::yield_now().await;
        }
    }

    async fn wait_until_refused(&self, within: Duration) {
        tokio::time::timeout(within, async {
            while TcpStream::connect(self.address).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("listener must close");
    }

    async fn finished(self, within: Duration) {
        tokio::time::timeout(within, self.task)
            .await
            .expect("server must finish")
            .unwrap()
            .unwrap();
    }
}

struct Reply {
    status: u16,
    headers: String,
    body: String,
}

async fn send(stream: &mut TcpStream, method: &str, path: &str, body: &str) -> Reply {
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    read_reply(stream).await
}

async fn read_reply(stream: &mut TcpStream) -> Reply {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let (head_end, length) = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..position]).to_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |value| value.trim().parse::<usize>().unwrap());
            break (position + 4, length);
        }
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response head")
            .unwrap();
        assert!(read > 0, "connection closed before a response head");
        buffer.extend_from_slice(&chunk[..read]);
    };
    while buffer.len() < head_end + length {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response body")
            .unwrap();
        assert!(read > 0, "connection closed inside a response body");
        buffer.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    Reply {
        status: head.split(' ').nth(1).unwrap().parse().unwrap(),
        headers: head.to_lowercase(),
        body: String::from_utf8(buffer[head_end..head_end + length].to_vec()).unwrap(),
    }
}

async fn assert_eof(stream: &mut TcpStream) {
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
        .await
        .expect("connection must close")
        .unwrap();
    assert!(rest.is_empty(), "unexpected bytes after the response");
}

const V2: &str = r#"{"srcTxHash":"0xtx","lzMessageId":{"pathwayId":{"srcChainName":"ethereum","dstChainName":"bsc","srcEid":30101,"dstEid":30102,"sender":"0xs","receiver":"0xr"},"nonce":7,"ulnSendVersion":"V302"},"signingContext":{"protocolType":"MESSAGE","expiration":123,"skipVId":false,"blockConfirmation":1},"messageHash":"0xhash"}"#;
const V1: &str = r#"{"srcTxHash":"0xtx","lzMessageId":{"srcChainId":"30101","nonce":7,"dstChainId":"30102","srcUAAddress":"0xs","dstUAAddress":"0xr"},"blockConfirmation":1,"expiration":123,"ulnVersion":"V302","messageHash":"0xhash"}"#;

#[tokio::test]
async fn withdrawal_window_rejects_new_signing_and_readiness_but_keeps_the_listener() {
    let mut server = start(Duration::from_secs(2), Duration::from_secs(6), 8, false).await;
    let mut keep_alive = TcpStream::connect(server.address).await.unwrap();
    let warm = send(&mut keep_alive, "GET", "/", "").await;
    assert_eq!((warm.status, warm.body.as_str()), (200, "HEALTHY"));
    assert!(!warm.headers.contains("connection: close"));
    // Before the signal a signing request is served normally, on a kept-alive
    // connection: the drain machinery changes nothing outside shutdown.
    let signed = send(&mut keep_alive, "POST", "/v2/resolve-and-sign", V2).await;
    assert_eq!(signed.status, 200, "{}", signed.body);
    assert!(!signed.headers.contains("connection: close"));
    assert_eq!(server.signs.load(Ordering::SeqCst), 1);

    server.signal_shutdown().await;

    let mut fresh = TcpStream::connect(server.address).await.unwrap();
    let ready = send(&mut fresh, "GET", "/ready", "").await;
    assert_eq!(ready.status, 503);
    assert!(
        ready.headers.contains("connection: close"),
        "{}",
        ready.headers
    );
    let mut fresh = TcpStream::connect(server.address).await.unwrap();
    let live = send(&mut fresh, "GET", "/", "").await;
    assert_eq!((live.status, live.body.as_str()), (200, "HEALTHY"));
    assert!(live.headers.contains("connection: close"));

    for (method, path, body) in [
        ("POST", "/v2/resolve-and-sign", V2),
        ("POST", "/", V1),
        ("POST", "/v2/resolve-and-sign", "{"),
        ("POST", "/", "not json"),
        ("POST", "/v2/resolve-and-sign", ""),
    ] {
        let mut connection = TcpStream::connect(server.address).await.unwrap();
        let reply = send(&mut connection, method, path, body).await;
        assert_eq!(
            (reply.status, reply.body.as_str()),
            (500, DRAINING_ENVELOPE),
            "{path} {body}"
        );
        assert!(
            reply.headers.contains("connection: close"),
            "{}",
            reply.headers
        );
        assert_eof(&mut connection).await;
    }
    for (method, path, status) in [("GET", "/nope", 404), ("GET", "/v2/resolve-and-sign", 405)] {
        let mut connection = TcpStream::connect(server.address).await.unwrap();
        let reply = send(&mut connection, method, path, "").await;
        assert_eq!(reply.status, status, "{path}");
        assert!(
            reply.headers.contains("connection: close"),
            "{path}: {}",
            reply.headers
        );
        assert_eof(&mut connection).await;
    }

    // A connection that was keep-alive before the transition is told to close.
    let rejected = send(&mut keep_alive, "POST", "/v2/resolve-and-sign", V2).await;
    assert_eq!(
        (rejected.status, rejected.body.as_str()),
        (500, DRAINING_ENVELOPE)
    );
    assert!(rejected.headers.contains("connection: close"));
    assert_eof(&mut keep_alive).await;

    assert_eq!(server.signs.load(Ordering::SeqCst), 1);
    assert_eq!(server.resources.signing.totals().started, 1);
    server.wait_until_refused(Duration::from_secs(5)).await;
    server.finished(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn request_admitted_before_the_signal_completes_after_the_listener_closes() {
    let mut server = start(Duration::from_millis(300), Duration::from_secs(8), 8, true).await;
    let mut client = TcpStream::connect(server.address).await.unwrap();
    client
        .write_all(
            format!(
                "POST /v2/resolve-and-sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{V2}",
                V2.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    server.wait_entered().await;

    server.signal_shutdown().await;
    server.wait_until_refused(Duration::from_secs(5)).await;
    assert!(TcpStream::connect(server.address).await.is_err());
    assert!(
        !server.task.is_finished(),
        "the admitted request still holds the drain"
    );

    server.gate.release.notify_one();
    let reply = read_reply(&mut client).await;
    assert_eq!(reply.status, 200);
    assert!(
        reply.body.contains(r#""payload":"0xpayload""#),
        "{}",
        reply.body
    );
    assert!(reply.headers.contains("connection: close"));
    assert_eof(&mut client).await;
    let resources = server.resources.clone();
    server.finished(Duration::from_secs(5)).await;
    assert!(
        resources.signing.acquire("ethereum").await.is_ok(),
        "clean drain keeps budgets open"
    );
}

#[tokio::test]
async fn grace_deadline_is_absolute_and_closes_budgets_around_stuck_work() {
    let grace = Duration::from_secs(2);
    let mut server = start(Duration::from_secs(1), grace, 8, true).await;
    let mut stuck = TcpStream::connect(server.address).await.unwrap();
    stuck
        .write_all(
            format!(
                "POST /v2/resolve-and-sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{V2}",
                V2.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    server.wait_entered().await;
    // A second sign queues behind the stuck one on the one-slot signing lane.
    let queued = tokio::spawn({
        let signing = server.resources.signing.clone();
        async move { signing.acquire("ethereum").await.map(|_| ()) }
    });
    while server.resources.signing.totals().waiting != 1 {
        tokio::task::yield_now().await;
    }

    let started = Instant::now();
    server.signal_shutdown().await;
    let resources = server.resources.clone();
    server.finished(Duration::from_secs(10)).await;
    let elapsed = started.elapsed();

    assert!(elapsed >= grace, "ended before T0+G: {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(2600),
        "withdrawal extended the grace: {elapsed:?}"
    );
    assert_eq!(queued.await.unwrap(), Err(BudgetError::Closed));
    // Queued waiter drained by close, plus the stuck holder cancelled at the deadline.
    assert_eq!(
        resources.signing.totals().outcomes[Outcome::Shutdown as usize],
        2
    );
    assert_eq!(resources.signing.totals().active, 0);
    for budget in [&resources.signing, &resources.rpc, &resources.kms] {
        assert!(matches!(
            budget.acquire("ethereum").await,
            Err(BudgetError::Closed)
        ));
    }
    let mut bytes = Vec::new();
    stuck.read_to_end(&mut bytes).await.unwrap();
    assert!(
        bytes.is_empty(),
        "stuck request was cancelled without a response"
    );
}

#[tokio::test]
async fn connection_cap_wait_ends_at_the_withdrawal_end_not_the_grace() {
    let withdrawal = Duration::from_millis(500);
    let mut server = start(withdrawal, Duration::from_secs(20), 1, true).await;
    let mut holder = TcpStream::connect(server.address).await.unwrap();
    holder
        .write_all(
            format!(
                "POST /v2/resolve-and-sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{V2}",
                V2.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    server.wait_entered().await;

    let started = Instant::now();
    server.signal_shutdown().await;
    let mut waiting = TcpStream::connect(server.address).await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), waiting.read_to_end(&mut rest))
        .await
        .expect("the cap wait must end by the withdrawal end")
        .unwrap();
    let elapsed = started.elapsed();
    assert!(rest.is_empty());
    assert!(
        elapsed >= withdrawal.saturating_sub(Duration::from_millis(50)),
        "{elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "waited toward the grace: {elapsed:?}"
    );
    assert!(TcpStream::connect(server.address).await.is_err());

    server.gate.release.notify_one();
    assert_eq!(read_reply(&mut holder).await.status, 200);
    server.finished(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn continuous_accepts_cannot_extend_the_withdrawal() {
    let withdrawal = Duration::from_millis(400);
    let mut server = start(withdrawal, Duration::from_secs(20), 64, false).await;
    let accepted = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    server.signal_shutdown().await;
    let hammer = async {
        let client = || {
            let accepted = accepted.clone();
            let address = server.address;
            tokio::spawn(async move {
                loop {
                    match TcpStream::connect(address).await {
                        Ok(stream) => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                            drop(stream);
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        Err(_) => return Instant::now(),
                    }
                }
            })
        };
        let (a, b, c, d) = tokio::join!(client(), client(), client(), client());
        [a.unwrap(), b.unwrap(), c.unwrap(), d.unwrap()]
            .into_iter()
            .max()
            .unwrap()
    };
    let refused_at = tokio::time::timeout(Duration::from_secs(5), hammer)
        .await
        .expect("accept pressure must not hold the listener open");
    assert!(
        accepted.load(Ordering::SeqCst) > 0,
        "the listener must continue accepting during withdrawal"
    );
    assert!(
        refused_at - started < Duration::from_secs(3),
        "{:?}",
        refused_at - started
    );
    server.finished(Duration::from_secs(10)).await;
}

#[tokio::test]
async fn zero_and_tiny_withdrawals_follow_the_same_timeline() {
    for (withdrawal, grace) in [
        (Duration::ZERO, Duration::from_secs(5)),
        (Duration::from_millis(200), Duration::from_secs(1)),
    ] {
        let mut server = start(withdrawal, grace, 8, false).await;
        let mut idle = TcpStream::connect(server.address).await.unwrap();
        assert_eq!(send(&mut idle, "GET", "/", "").await.status, 200);

        let started = Instant::now();
        server.signal_shutdown().await;
        server.wait_until_refused(Duration::from_secs(3)).await;
        assert!(started.elapsed() >= withdrawal.saturating_sub(Duration::from_millis(50)));
        assert_eof(&mut idle).await;
        server.finished(grace).await;
        assert!(started.elapsed() < grace + Duration::from_secs(2));
    }
}
