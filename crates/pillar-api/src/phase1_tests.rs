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
