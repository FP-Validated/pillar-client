use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Proxy {
    address: std::net::SocketAddr,
    blackhole: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn proxy(upstream: std::net::SocketAddr) -> Proxy {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let blackhole = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(AtomicUsize::new(0));
    let fault = blackhole.clone();
    let count = connections.clone();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                incoming=listener.accept()=>{let (mut client,_)=incoming.unwrap();let fault=fault.clone();count.fetch_add(1,Ordering::SeqCst);tasks.spawn(async move {
                    let mut server=tokio::net::TcpStream::connect(upstream).await.unwrap();let (mut cr,mut cw)=client.split();let (mut sr,mut sw)=server.split();
                    let client_to_server=async {let mut bytes=[0;8192];loop {let size=cr.read(&mut bytes).await?;if size==0{return Ok::<_,std::io::Error>(());} else if !fault.load(Ordering::SeqCst){sw.write_all(&bytes[..size]).await?;}}};
                    let server_to_client=async {let mut bytes=[0;8192];loop {let size=sr.read(&mut bytes).await?;if size==0{return Ok::<_,std::io::Error>(());} else if !fault.load(Ordering::SeqCst){cw.write_all(&bytes[..size]).await?;}}};
                    tokio::select!{_ = client_to_server=>{},_ = server_to_client=>{}}
                });},_ = tasks.join_next(),if !tasks.is_empty()=>{}
            }
        }
    });
    Proxy {
        address,
        blackhole,
        connections,
        task,
    }
}
#[tokio::test]
#[ignore = "Requires explicitly scoped synthetic PostgreSQL"]
async fn postgres_audit_half_open_proxy_reconnects_and_row_lock_recovers() {
    let (url, database, namespace) = case("reconnect").await;
    let mut parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    let upstream = std::net::SocketAddr::from(([127, 0, 0, 1], parsed.port().unwrap()));
    let proxy = proxy(upstream).await;
    parsed.set_port(Some(proxy.address.port())).unwrap();
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let server = Http::open(
        app(parsed.as_str(), &namespace, 16, sdk.clone())
            .await
            .unwrap(),
    )
    .await;
    proxy.blackhole.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let (failed, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    let failed_ms = started.elapsed().as_millis();
    assert_eq!(failed, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body["body"].as_str().unwrap().contains("store unavailable"));
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 0);
    assert!(failed_ms < 2000);
    proxy.blackhole.store(false, Ordering::SeqCst);
    let resumed = tokio::time::Instant::now();
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    let resumed_ms = resumed.elapsed().as_millis();
    assert_eq!(status, reqwest::StatusCode::OK);
    verify(body, &sdk);
    assert!(resumed_ms < 2000);
    assert!(proxy.connections.load(Ordering::SeqCst) >= 2);
    let blocker = Database::open(&url).await;
    blocker
        .client
        .lock()
        .await
        .batch_execute("BEGIN")
        .await
        .unwrap();
    blocker
        .client
        .lock()
        .await
        .query_one(
            "SELECT namespace FROM pillar_audit_namespace WHERE namespace=$1 FOR UPDATE",
            &[&namespace],
        )
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let (locked, _) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    let lock_ms = started.elapsed().as_millis();
    assert_eq!(locked, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 1);
    assert!(lock_ms < 1000);
    blocker
        .client
        .lock()
        .await
        .batch_execute("ROLLBACK")
        .await
        .unwrap();
    let (recovered, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(recovered, reqwest::StatusCode::OK);
    verify(body, &sdk);
    artifact(
        "reconnect-lock",
        &json!({"half_open_failed_status":failed.as_u16(),"half_open_fail_ms":failed_ms,"reconnect_status":status.as_u16(),"reconnect_ms":resumed_ms,"proxy_connections":proxy.connections.load(Ordering::SeqCst),"lock_timeout_status":locked.as_u16(),"lock_wait_ms":lock_ms,"after_unlock_status":recovered.as_u16(),"sdk_calls":sdk.calls.load(Ordering::SeqCst)}),
    );
    server.close().await;
}

#[tokio::test]
#[ignore = "Requires explicitly scoped synthetic PostgreSQL"]
async fn postgres_audit_waiter_timeout_preserves_active_commit_and_session() {
    use pillar_core::audit::{
        AttemptIntent, EffectiveKey, EvidenceKind, SigningAuditStore, ValidatedIntent,
    };
    use pillar_core::execution::RequestContext;
    let (url, database, namespace) = case("waiters").await;
    let mut parsed = url::Url::parse(&url).unwrap();
    let upstream = std::net::SocketAddr::from(([127, 0, 0, 1], parsed.port().unwrap()));
    let proxy = proxy(upstream).await;
    parsed.set_port(Some(proxy.address.port())).unwrap();
    let store = crate::audit::PostgresAuditStore::connect(pillar_config::AuditConfig {
        database_url: parsed.to_string().into(),
        namespace: namespace.clone(),
        timeout: Duration::from_secs(2),
        max_attempts: 16,
    })
    .await
    .unwrap();
    let intent = AttemptIntent {
        validated: ValidatedIntent {
            request_hash: "request".into(),
            validation_hash: "validation".into(),
            source_chain: "ethereum".into(),
            destination_chain: "ethereum".into(),
            expiration: 1,
            provider_generation: 7,
        },
        key: EffectiveKey {
            backend: "AZURE",
            reference: "synthetic/key/7".into(),
            version: "7".into(),
            public_key_hash: "public".into(),
        },
        wallet_hash: "wallet".into(),
        signed_digest: "digest".into(),
        algorithm: "ECDSA",
    };
    let attempt = store.begin(&intent).await.unwrap();
    gate(&database, &namespace, "wallet", 74009, false).await;
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_lock(74009)", &[])
        .await
        .unwrap();
    let active_store = store.clone();
    let active = tokio::spawn(async move {
        active_store
            .record(attempt, EvidenceKind::WalletReturned, Some("hash"))
            .await
    });
    wait_for_gate(&database).await;
    let before = proxy.connections.load(Ordering::SeqCst);
    let health = store.healthy();
    let sign = RequestContext::new(Duration::from_millis(20)).scope(store.begin(&intent));
    let (health, sign) = tokio::join!(health, sign);
    assert!(
        health,
        "readiness answers from its own connection while a signing COMMIT holds the write session"
    );
    assert!(sign.unwrap_err().contains("store unavailable"));
    assert_eq!(
        proxy.connections.load(Ordering::SeqCst),
        before + 1,
        "only the readiness connection is new; the waiting write did not replace the session"
    );
    assert!(
        !active.is_finished(),
        "waiting timeout aborted active COMMIT"
    );
    assert!(store.health_state().load(Ordering::Acquire));
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_unlock(74009)", &[])
        .await
        .unwrap();
    active.await.unwrap().unwrap();
    assert!(store.healthy().await);
    assert!(store.begin(&intent).await.is_ok());
    assert_eq!(proxy.connections.load(Ordering::SeqCst), before + 1);
    assert_eq!(
        evidence(&database, &namespace).await,
        vec![("wallet_returned".into(), Some("hash".into()))]
    );
    artifact(
        "waiter-session",
        &json!({"health_answered_while_commit_held":true,"sign_waiter_timed_out":true,"active_commit_succeeded":true,"connections_added_after_gate":proxy.connections.load(Ordering::SeqCst)-before,"retained_attempts":database.count(&namespace,"attempt").await}),
    );
}
