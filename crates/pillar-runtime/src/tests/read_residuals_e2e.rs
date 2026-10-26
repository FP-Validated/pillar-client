//! READ residuals: target `eth_call` bodies are parsed in their own pool, so stalled READ
//! targets cannot take the parser slots a request's source reads need; and a body over the
//! transport limit is the oversized-result vote it implies, not a provider failure.
use super::*;
use crate::provider_health::{JsonRpcTransport, ReqwestJsonRpcTransport, RpcError};
use pillar_core::execution::{BudgetLimits, ExecutionResources, FairBudget, RequestContext};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::Instant,
};

const CHILD_ENV: &str = "PILLAR_READ_RESIDUAL_CHILD";
const ADMISSION_TEST: &str =
    "tests::read_residuals_e2e::read_targets_do_not_take_source_parser_slots";

fn artifact(name: &str, value: Value) {
    audit_round_artifact("m22-m25", name, value);
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                return Ok(());
            }
        }
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        request.extend_from_slice(&chunk[..count]);
    }
}

/// Sends a 200 header, then holds the body until released.
struct Stalled {
    url: String,
    headers_sent: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

async fn stalled_server() -> Stalled {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let (headers_tx, headers_sent) = oneshot::channel();
    let (release, release_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        if read_request(&mut stream).await.is_err() {
            return;
        }
        let body = br#"{"jsonrpc":"2.0","id":1,"result":"0x"}"#;
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
    Stalled {
        url,
        headers_sent,
        release,
        task,
    }
}

/// Answers every connection with `body`.
async fn serve_forever(body: Vec<u8>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let body = Arc::new(body);
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                if read_request(&mut stream).await.is_err() {
                    return;
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
            });
        }
    });
    (url, task)
}

/// The production parser budget (`execution.rs`), over the chains of this scenario.
fn resources() -> Arc<ExecutionResources> {
    let lanes = [
        "ethereum",
        "arbitrum",
        "polygon",
        "background",
        "extra_context",
    ]
    .map(str::to_owned)
    .to_vec();
    let generous = BudgetLimits {
        active: 64,
        per_lane: 8,
        waiting: 64,
        per_lane_waiting: 8,
        wait: Duration::from_secs(20),
    };
    let parser = FairBudget::with_lane_resource_limit(
        lanes.clone(),
        BudgetLimits {
            active: 4,
            per_lane: 3,
            waiting: 8,
            per_lane_waiting: 2,
            wait: Duration::from_secs(2),
        },
        4,
        3,
    )
    .unwrap();
    Arc::new(ExecutionResources {
        signing: FairBudget::new(lanes.clone(), generous).unwrap(),
        rpc: FairBudget::new(lanes.clone(), generous).unwrap(),
        kms: FairBudget::new(lanes, generous).unwrap(),
        parser,
    })
}

async fn call(
    transport: Arc<ReqwestJsonRpcTransport>,
    resources: Arc<ExecutionResources>,
    chain: &'static str,
    url: String,
    read_target: bool,
) -> Result<Value, RpcError> {
    let mut context = RequestContext::new(Duration::from_secs(30));
    context.resources = Some(resources);
    context.source_chain = Some(Arc::from("ethereum"));
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []});
    let request = crate::provider_health::rpc_scope(
        chain,
        transport.post_json_scoped(url, HashMap::new(), body),
    );
    if read_target {
        context
            .scope(crate::provider_health::read_target_scope(request))
            .await
    } else {
        context.scope(request).await
    }
}

async fn settle_parser(resources: &ExecutionResources, active: usize) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if resources.parser.totals().active == active {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    false
}

/// Four READ target bodies stall on arbitrum and polygon while the request's own source
/// receipt is read from ethereum. Read as an ordinary call (the old path), the four hold
/// every parser slot and the source read is refused after the 2 s parser wait; read in
/// the READ scope (the new path), they hold none and the source read is answered.
async fn stalled_read_targets_then_source(read_target: bool) -> Value {
    let resources = resources();
    let transport = Arc::new(ReqwestJsonRpcTransport::new().unwrap());
    let mut stalled = Vec::new();
    let mut calls = Vec::new();
    for chain in ["arbitrum", "arbitrum", "polygon", "polygon"] {
        let server = stalled_server().await;
        calls.push(tokio::spawn(call(
            transport.clone(),
            resources.clone(),
            chain,
            server.url.clone(),
            read_target,
        )));
        stalled.push(server);
    }
    for server in &mut stalled {
        tokio::time::timeout(Duration::from_secs(5), &mut server.headers_sent)
            .await
            .expect("stalled READ target sent its header")
            .unwrap();
    }
    let held = if read_target { 0 } else { 4 };
    let settled = settle_parser(&resources, held).await;
    let (source_url, source_server) =
        serve_forever(br#"{"jsonrpc":"2.0","id":1,"result":{"status":"0x1"}}"#.to_vec()).await;
    let started = Instant::now();
    let source = call(
        transport.clone(),
        resources.clone(),
        "ethereum",
        source_url,
        false,
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis();
    let parser_during_source = resources.parser.totals().active;
    for server in stalled {
        let _ = server.release.send(());
        server.task.await.unwrap();
    }
    let mut read_results = Vec::new();
    for call in calls {
        read_results.push(call.await.unwrap().is_ok());
    }
    source_server.abort();
    json!({
        "readTargetScope": read_target,
        "parserSlotsHeldByReadTargets": held,
        "settled": settled,
        "parserActiveDuringSource": parser_during_source,
        "sourceOutcome": format!("{source:?}"),
        "sourceAnswered": source.is_ok(),
        "sourceElapsedMs": elapsed_ms,
        "readTargetsAnsweredAfterRelease": read_results,
    })
}

#[tokio::test]
async fn read_targets_do_not_take_source_parser_slots() {
    if std::env::var_os(CHILD_ENV).is_none() {
        // The process-wide parser semaphores are shared with every other test.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", ADMISSION_TEST, "--nocapture"])
            .env(CHILD_ENV, "1")
            .status()
            .expect("spawn isolated READ admission child");
        assert!(status.success(), "isolated READ admission child: {status}");
        return;
    }
    let before = stalled_read_targets_then_source(false).await;
    let after = stalled_read_targets_then_source(true).await;
    artifact(
        "read-shared-admission",
        json!({"oldPath": before, "newPath": after}),
    );
    assert_eq!(before["settled"], true, "{before}");
    assert_eq!(before["sourceAnswered"], false, "{before}");
    assert!(
        before["sourceOutcome"]
            .as_str()
            .unwrap()
            .contains("Overloaded"),
        "{before}"
    );
    assert_eq!(after["settled"], true, "{after}");
    assert_eq!(after["sourceAnswered"], true, "{after}");
    assert!(
        after["sourceElapsedMs"].as_u64().unwrap() < 2_000,
        "{after}"
    );
    assert_eq!(
        after["readTargetsAnsweredAfterRelease"],
        json!([true, true, true, true])
    );
}

fn oversized_resolver(
    uris: Vec<String>,
    quorum: u64,
) -> RuntimeEvmReadPayloadResolver<ReqwestJsonRpcTransport> {
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "bsc".to_string(),
            ProviderConfig::with_distinct_entities(
                uris.into_iter().map(ProviderUri::Uri).collect(),
                quorum,
            ),
        )]),
        Some(&["bsc".to_string()]),
    )
    .unwrap();
    RuntimeEvmReadPayloadResolver::new(
        &ProviderSnapshotHandle::from_getter(&getter),
        ReqwestJsonRpcTransport::new().unwrap(),
        HashMap::from([(30_102, "bsc".to_string())]),
    )
}

async fn resolve_read(
    resolver: &RuntimeEvmReadPayloadResolver<ReqwestJsonRpcTransport>,
) -> Result<String, AppCoreError> {
    let mut event = read_command_sent_event(evm_read_command_with_block_marker());
    event.read_block_pins = bsc_read_block_pins();
    resolver
        .resolve_payload(
            &event,
            &SigningContext::Read {
                expiration: 123,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        )
        .await
}

/// Every provider answers the READ target with a body over the 4 MiB transport limit. The
/// transport refuses each body; the old path counted that as three failed votes and
/// answered 500 with no quorum, which a caller retries. It is the oversized-result vote,
/// and agreement on it is the 400 refusal `h02_an_oversized_vote_is_one_vote` gives.
#[tokio::test]
async fn read_bodies_over_the_transport_limit_are_an_oversized_vote() {
    let oversized = {
        let mut body = String::from(r#"{"jsonrpc":"2.0","id":1,"result":"0x"#);
        body.push_str(&"ab".repeat(2 * 1024 * 1024 + 16));
        body.push_str(r#""}"#);
        body.into_bytes()
    };
    let small = br#"{"jsonrpc":"2.0","id":1,"result":"0xabab"}"#.to_vec();
    let mut servers = Vec::new();
    let mut big = Vec::new();
    for _ in 0..3 {
        let (url, task) = serve_forever(oversized.clone()).await;
        big.push(url);
        servers.push(task);
    }
    let mut honest = Vec::new();
    for _ in 0..2 {
        let (url, task) = serve_forever(small.clone()).await;
        honest.push(url);
        servers.push(task);
    }

    let transport_refusal = crate::provider_health::rpc_scope(
        "bsc",
        ReqwestJsonRpcTransport::new().unwrap().post_json_scoped(
            big[0].clone(),
            HashMap::new(),
            json!({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": []}),
        ),
    )
    .await
    .expect_err("the transport refuses an oversized body");
    let all_oversized = resolve_read(&oversized_resolver(big.clone(), 2)).await;
    let one_oversized = resolve_read(&oversized_resolver(
        vec![big[0].clone(), honest[0].clone(), honest[1].clone()],
        2,
    ))
    .await;
    for server in servers {
        server.abort();
    }
    artifact(
        "read-oversized-body-vote",
        json!({
            "bodyBytes": oversized.len(),
            "transportRefusal": transport_refusal.to_string(),
            "transportRefusalIsSizeRefusal":
                crate::provider_health::is_response_size_refusal(&transport_refusal),
            "allProvidersOversized": format!("{all_oversized:?}"),
            "oneOversizedTwoHonest": format!("{one_oversized:?}"),
        }),
    );
    assert!(oversized.len() > 4 * 1024 * 1024);
    assert!(crate::provider_health::is_response_size_refusal(
        &transport_refusal
    ));
    match all_oversized {
        Err(AppCoreError::UnresolvableCommand(reason)) => {
            assert!(reason.contains("an eth_call result exceeds"), "{reason}")
        }
        other => panic!("an agreed oversized body is the 400 refusal: {other:?}"),
    }
    assert_eq!(one_oversized.unwrap(), "abab");
}
