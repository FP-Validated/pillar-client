#[tokio::test]
async fn phase1_idle_keepalive_does_not_capture_connection_headroom_or_drain() {
    let app = Router::new().route("/", get(|| async { "HEALTHY" }));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_, shutdown_signal) = pillar_api::router_with_shutdown(pillar_api::StaticApp::observed_mainnet(), "phase1");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_until(listener, app, 1, Duration::from_secs(2), Duration::ZERO, shutdown_signal,
        async move { stopped.await.unwrap(); Ok("test") }));
    let mut first = TcpStream::connect(address).await.unwrap();
    first.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0; 512];
    while !bytes.ends_with(b"HEALTHY") {
        let n = tokio::time::timeout(Duration::from_secs(1), first.read(&mut chunk)).await.unwrap().unwrap();
        assert_ne!(n, 0);
        bytes.extend_from_slice(&chunk[..n]);
    }
    let mut second = TcpStream::connect(address).await.unwrap();
    second.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    let served = tokio::time::timeout(Duration::from_millis(750), second.read_to_end(&mut response)).await;
    stop.send(()).unwrap();
    let drain_started = Instant::now();
    let drained = tokio::time::timeout(Duration::from_millis(500), server).await;
    assert!(served.is_ok(), "an answered idle keepalive captured all socket permits");
    assert!(String::from_utf8(response).unwrap().starts_with("HTTP/1.1 200 OK"));
    assert!(drained.is_ok(), "idle keepalive consumed shutdown grace");
    println!("PHASE1_SOCKET_ARTIFACT second_status=200 idle_drain_ms={}", drain_started.elapsed().as_millis());
}

#[tokio::test]
async fn phase1_shutdown_drains_active_handler_but_closes_idle_connections() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let app = Router::new().route("/", get({
        let entered = entered.clone(); let release = release.clone();
        move || { let entered = entered.clone(); let release = release.clone(); async move {
            entered.notify_one(); release.notified().await; "DRAINED"
        }}
    }));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_, shutdown_signal) = pillar_api::router_with_shutdown(pillar_api::StaticApp::observed_mainnet(), "phase1");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = tokio::spawn(serve_until(listener, app, 2, Duration::from_secs(2), Duration::ZERO, shutdown_signal.clone(),
        async move { stopped.await.unwrap(); Ok("test") }));
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    entered.notified().await;
    let _idle = TcpStream::connect(address).await.unwrap();
    stop.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut server).await.is_err());
    assert!(shutdown_signal.is_triggered());
    release.notify_one();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_millis(500), client.read_to_end(&mut response)).await.unwrap().unwrap();
    server.await.unwrap().unwrap();
    assert!(String::from_utf8(response).unwrap().ends_with("DRAINED"));
    println!("PHASE1_DRAIN_ARTIFACT active_response=DRAINED readiness=draining");
}
