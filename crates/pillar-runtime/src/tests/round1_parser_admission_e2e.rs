use super::*;
use crate::provider_health::{JsonRpcTransport, ReqwestJsonRpcTransport, RpcError};
use pillar_core::execution::{BudgetLimits, ExecutionResources, FairBudget, RequestContext};
use std::{process::Child, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::Instant,
};

const CHILD_ENV: &str = "PILLAR_R1_PARSER_CHILD";
const TEST_NAME: &str = "tests::round1_parser_admission_e2e::round1_parser_admission_keeps_cross_chain_headroom_and_releases_leases";

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct StalledJsonServer {
    url: String,
    headers_sent: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl StalledJsonServer {
    async fn finish(mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.expect("stalled JSON server task");
        }
    }
}
impl Drop for StalledJsonServer {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 512];
    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        request.extend_from_slice(&chunk[..count]);
    }
    Ok(())
}

async fn stalled_json_server(body: &'static [u8]) -> StalledJsonServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let (headers_tx, headers_sent) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        if read_request(&mut stream).await.is_err() {
            return;
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        if stream.write_all(header.as_bytes()).await.is_err() {
            return;
        }
        let _ = headers_tx.send(());
        let _ = release_rx.await;
        let _ = stream.write_all(body).await;
    });
    StalledJsonServer {
        url: format!("http://{address}/"),
        headers_sent: Some(headers_sent),
        release: Some(release),
        task: Some(task),
    }
}

struct JsonServer(Option<JoinHandle<()>>);
impl JsonServer {
    async fn finish(mut self) {
        if let Some(task) = self.0.take() {
            task.await.expect("JSON server task");
        }
    }
}
impl Drop for JsonServer {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
async fn json_server(body: &'static [u8]) -> (String, JsonServer) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        if read_request(&mut stream).await.is_err() {
            return;
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(body).await;
    });
    (format!("http://{address}/"), JsonServer(Some(task)))
}

fn execution_resources() -> Arc<ExecutionResources> {
    let lanes = ["sourceA", "sourceB", "background", "extra_context"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let limits = BudgetLimits {
        active: 8,
        per_lane: 4,
        waiting: 8,
        per_lane_waiting: 4,
        wait: Duration::from_secs(20),
    };
    let parser_limits = BudgetLimits {
        active: 4,
        per_lane: 3,
        per_lane_waiting: 2,
        ..limits
    };
    Arc::new(ExecutionResources {
        signing: FairBudget::new(lanes.clone(), limits).expect("signing budget"),
        rpc: FairBudget::new(lanes.clone(), limits).expect("RPC budget"),
        kms: FairBudget::new(lanes.clone(), limits).expect("KMS budget"),
        parser: FairBudget::with_lane_resource_limit(lanes, parser_limits, 4, 3)
            .expect("parser budget"),
    })
}

async fn request(
    transport: Arc<ReqwestJsonRpcTransport>,
    resources: Arc<ExecutionResources>,
    chain: &'static str,
    url: String,
    timeout: Duration,
) -> Result<Value, RpcError> {
    let mut context = RequestContext::new(timeout);
    context.resources = Some(resources);
    context.source_chain = Some(Arc::from(chain));
    context
        .scope(transport.get_json_on(chain, url, HashMap::new()))
        .await
}

async fn settle_budget(
    resources: &ExecutionResources,
    parser_active: usize,
    parser_waiting: usize,
    rpc_active: usize,
    deadline: Instant,
) -> bool {
    loop {
        let parser = resources.parser.totals();
        let rpc = resources.rpc.totals();
        if parser.active == parser_active
            && parser.waiting == parser_waiting
            && rpc.active == rpc_active
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn round1_parser_admission_keeps_cross_chain_headroom_and_releases_leases() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let mut child = ChildGuard(
            std::process::Command::new(std::env::current_exe().expect("current test executable"))
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_ENV, "1")
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .expect("spawn isolated parser E2E child"),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().expect("child process status") {
                assert!(
                    status.success(),
                    "isolated parser E2E child failed: {status}"
                );
                return;
            }
            if std::time::Instant::now() >= deadline {
                panic!("isolated parser E2E child exceeded 60s timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    let resources = execution_resources();
    let transport = Arc::new(ReqwestJsonRpcTransport::new().expect("reqwest transport"));
    let mut servers = Vec::new();
    let mut urls = Vec::new();
    for _ in 0..4 {
        let server = stalled_json_server(br#"{"source":"A","ok":true}"#).await;
        urls.push(server.url.clone());
        servers.push(server);
    }
    let mut requests = Vec::new();
    for (index, url) in urls.into_iter().enumerate() {
        let timeout = if index == 3 {
            Duration::from_secs(12)
        } else {
            Duration::from_secs(20)
        };
        requests.push(tokio::spawn(request(
            transport.clone(),
            resources.clone(),
            "sourceA",
            url,
            timeout,
        )));
    }
    let mut headers_seen = Vec::new();
    for server in &mut servers {
        let rx = server.headers_sent.take().expect("header signal");
        headers_seen.push(
            tokio::time::timeout(Duration::from_secs(5), rx)
                .await
                .is_ok(),
        );
    }
    let staged = settle_budget(&resources, 3, 1, 4, Instant::now() + Duration::from_secs(5)).await;

    let (url_b, server_b) = json_server(br#"{"source":"B","value":{"height":731}}"#).await;
    let result_b = tokio::time::timeout(
        Duration::from_secs(3),
        request(
            transport.clone(),
            resources.clone(),
            "sourceB",
            url_b,
            Duration::from_secs(4),
        ),
    )
    .await;
    let result_b = match result_b {
        Ok(result) => result,
        Err(_) => Err(RpcError::Remote("sourceB response deadline elapsed".into())),
    };
    let source_b_value = result_b.as_ref().ok().cloned();
    server_b.finish().await;
    let after_b = resources.parser.totals();
    let after_b_rpc = resources.rpc.totals();
    let deadline_expired = matches!(requests.remove(3).await, Ok(Err(_)));
    let after_deadline = resources.parser.totals();
    let after_deadline_rpc = resources.rpc.totals();
    for request in requests.drain(..3) {
        request.abort();
        let _ = request.await;
    }
    for server in servers.drain(..) {
        server.finish().await;
    }
    let cleanup = settle_budget(&resources, 0, 0, 0, Instant::now() + Duration::from_secs(3)).await;
    let (malformed_url, malformed_server) = json_server(b"{malformed").await;
    let malformed_result = request(
        transport.clone(),
        resources.clone(),
        "sourceB",
        malformed_url,
        Duration::from_secs(4),
    )
    .await;
    let malformed_rejected = malformed_result.is_err();
    malformed_server.finish().await;
    let malformed_cleanup =
        settle_budget(&resources, 0, 0, 0, Instant::now() + Duration::from_secs(3)).await;
    resources.parser.close();
    let (closed_url, closed_server) = json_server(br#"{"closed":true}"#).await;
    let closed_result = request(
        transport.clone(),
        resources.clone(),
        "sourceB",
        closed_url,
        Duration::from_secs(4),
    )
    .await;
    closed_server.finish().await;
    let final_parser = resources.parser.totals();
    let final_rpc = resources.rpc.totals();

    round1_artifact(
        "parser-admission-loopback",
        json!({
            "child_isolated": true,
            "loopback_only": true,
            "a_header_responses_observed": headers_seen,
            "a_parser_staged": staged,
            "a_parser_active_during_b": after_b.active,
            "a_parser_waiting_during_b": after_b.waiting,
            "a_rpc_active_during_b": after_b_rpc.active,
            "b_result": source_b_value,
            "deadline_request_released_parser_waiter": deadline_expired && after_deadline.waiting == 0,
            "parser_after_deadline": {"active": after_deadline.active, "waiting": after_deadline.waiting},
            "rpc_after_deadline": {"active": after_deadline_rpc.active, "waiting": after_deadline_rpc.waiting},
            "cancel_cleanup_reached_zero": cleanup,
            "malformed_json_rejected": malformed_rejected,
            "malformed_json_cleanup_reached_zero": malformed_cleanup,
            "closed_result": format!("{closed_result:?}"),
            "parser_final": {"active": final_parser.active, "waiting": final_parser.waiting},
            "rpc_final": {"active": final_rpc.active, "waiting": final_rpc.waiting}
        }),
    );
    assert!(
        headers_seen.iter().all(|seen| *seen),
        "all four sourceA HTTP headers must arrive before body release"
    );
    assert!(
        staged,
        "expected three parser leases, one queued parser lease, and four RPC leases"
    );
    assert_eq!(
        source_b_value,
        Some(json!({"source":"B","value":{"height":731}}))
    );
    assert_eq!(
        (after_b.active, after_b.waiting, after_b_rpc.active),
        (3, 1, 4)
    );
    assert!(deadline_expired && after_deadline.waiting == 0);
    assert_eq!((after_deadline.active, after_deadline_rpc.active), (3, 3));
    assert!(
        malformed_rejected,
        "malformed loopback JSON must fail parsing"
    );
    assert!(
        malformed_cleanup,
        "malformed JSON response must release parser and RPC leases"
    );
    assert!(
        cleanup,
        "cancelled sourceA calls must release parser and RPC leases"
    );
    assert!(matches!(
        closed_result,
        Err(RpcError::Admission(
            pillar_core::execution::BudgetError::Closed
        ))
    ));
    assert_eq!(
        final_rpc.outcomes[pillar_core::execution::Outcome::Shutdown as usize],
        1
    );
    assert_eq!(
        (final_parser.active, final_parser.waiting, final_rpc.active),
        (0, 0, 0)
    );
}
