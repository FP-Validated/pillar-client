#[tokio::test]
async fn phase1_future_drop_has_exactly_one_terminal_outcome() {
    let app = router(TestApp::with_v2_delay(Duration::from_secs(60)), "phase1");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v2/resolve-and-sign")
        .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
        .header("content-type", "application/json")
        .header("x-request-id", "private-request-canary")
        .body(Body::from(serde_json::to_vec(&v2_request_json(false)).unwrap()))
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(20), app.clone().oneshot(request)).await.is_err());
    let response = app.oneshot(Request::builder().uri("/metrics")
        .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
        .body(Body::empty()).unwrap()).await.unwrap();
    let text = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
    assert!(text.contains("pillar_http_started_total{method=\"POST\",path=\"/v2/resolve-and-sign\"} 1"), "{text}");
    assert!(text.contains("pillar_http_outcomes_total{method=\"POST\",path=\"/v2/resolve-and-sign\",outcome=\"cancelled\"} 1"), "{text}");
    assert!(!text.contains("private-request-canary"));
    assert!(!text.contains("status=\"504\""));
    println!("PHASE1_TERMINAL_ARTIFACT\n{text}");
}

#[tokio::test]
async fn fragmented_request_releases_each_transport_backing_buffer_before_the_next_chunk() {
    struct Allocation {
        bytes: Vec<u8>,
        released: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl AsRef<[u8]> for Allocation {
        fn as_ref(&self) -> &[u8] { &self.bytes }
    }
    impl Drop for Allocation {
        fn drop(&mut self) { self.released.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
    }
    let payload = serde_json::to_vec(&v2_request_json(false)).unwrap();
    let size = payload.len();
    let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = released.clone();
    let stream = futures::stream::unfold((payload, 0usize, released), |(payload, index, released)| async move {
        assert_eq!(released.load(std::sync::atomic::Ordering::SeqCst), index, "previous socket buffer is still retained");
        let byte = *payload.get(index)?;
        let mut bytes = vec![0; 8192];
        bytes[0] = byte;
        let chunk = axum::body::Bytes::from_owner(Allocation { bytes, released: released.clone() }).slice(..1);
        Some((Ok::<_, std::io::Error>(chunk), (payload, index + 1, released)))
    });
    let response = router(TestApp::new(), "audit").oneshot(
        Request::builder().method(Method::POST).uri("/v2/resolve-and-sign")
            .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
            .header("content-type", "application/json")
            .header("transfer-encoding", "chunked")
            .body(Body::from_stream(stream)).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(observed.load(std::sync::atomic::Ordering::SeqCst), size);
}

#[tokio::test]
async fn compressed_signing_requests_enforce_a_member_work_budget() {
    use std::io::Write;
    let payload = serde_json::to_vec(&v2_request_json(false)).unwrap();
    let app = router(TestApp::new(), "audit");
    for (empty_members, expected) in [(1, StatusCode::OK), (32, StatusCode::PAYLOAD_TOO_LARGE)] {
        let mut body = Vec::new();
        for _ in 0..empty_members {
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            body.extend(encoder.finish().unwrap());
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&payload).unwrap();
        body.extend(encoder.finish().unwrap());
        let response = app.clone().oneshot(
            Request::builder().method(Method::POST).uri("/v2/resolve-and-sign")
                .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(Body::from(body)).unwrap(),
        ).await.unwrap();
        assert_eq!(response.status(), expected, "{empty_members} empty members");
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&payload).unwrap();
    let response = app.oneshot(
        Request::builder().method(Method::POST).uri("/v2/resolve-and-sign")
            .header("authorization", format!("Bearer {TEST_AUTH_TOKEN}"))
            .header("content-type", "application/json")
            .header("content-encoding", "deflate")
            .body(Body::from(encoder.finish().unwrap())).unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
