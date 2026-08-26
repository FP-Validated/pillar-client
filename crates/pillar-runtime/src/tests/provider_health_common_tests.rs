use super::*;

#[tokio::test]
async fn provider_health_requires_all_providers_healthy_like_typescript() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "ethereum".to_string(),
            ProviderConfig {
                uris: vec![
                    ProviderUri::Uri("https://healthy-rpc.example".to_string()),
                    ProviderUri::Uri("https://bad-rpc.example".to_string()),
                ],
                quorum: Some(1),
            },
        )]),
        Some(&["ethereum".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls,
        responses: Arc::new(Mutex::new(vec![
            Ok(json!({"result": "0x1"})),
            Err("chain id unavailable".to_string()),
            Err("net version unavailable".to_string()),
        ])),
    };
    let source = RpcProviderHealthSource::from_getter(&getter, transport, || 1);
    let report = source.get_provider_health_report().await;

    assert!(!report["ethereum"].healthy);
    assert_eq!(report["ethereum"].providers.len(), 2);
    assert!(report["ethereum"]
        .providers
        .iter()
        .any(|entry| entry.healthy && entry.numeric_response == Some("1".to_string())));
    assert!(report["ethereum"]
        .providers
        .iter()
        .any(|entry| !entry.healthy && entry.numeric_response.is_none()));

    let snapshot = provider_health_snapshot_from_report(&report);
    assert!(!snapshot["ethereum"]);
}

#[tokio::test]
async fn provider_health_does_not_probe_non_evm_chains_with_evm_rpc_methods() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([(
            "iotal1".to_string(),
            ProviderConfig {
                uris: vec![ProviderUri::Uri("https://iota-rpc.example".to_string())],
                quorum: Some(1),
            },
        )]),
        Some(&["iotal1".to_string()]),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let transport = RecordingTransport {
        calls: calls.clone(),
        responses: Arc::new(Mutex::new(vec![Ok(json!({"result": "123"}))])),
    };
    let source = RpcProviderHealthSource::from_getter_with_chain_types(
        &getter,
        transport,
        || 1234,
        HashMap::from([("iotal1".to_string(), "IOTAMOVE".to_string())]),
    );

    let report = source.get_provider_health_report().await;

    assert!(report["iotal1"].healthy);
    assert_eq!(report["iotal1"].checked_at_unix_ms, 1234);
    assert_eq!(report["iotal1"].providers.len(), 1);
    assert!(report["iotal1"].providers[0].healthy);
    assert_eq!(
        report["iotal1"].providers[0].numeric_response,
        Some("123".to_string())
    );
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].2["method"],
        "iota_getLatestCheckpointSequenceNumber"
    );
    assert_eq!(calls[0].2["params"], json!([]));
}

#[tokio::test]
async fn provider_health_probes_chains_concurrently() {
    let getter = StaticProviderConfig::new(
        indexmap::IndexMap::from([
            (
                "ethereum".to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri("https://ethereum-rpc.example".to_string())],
                    quorum: Some(1),
                },
            ),
            (
                "bsc".to_string(),
                ProviderConfig {
                    uris: vec![ProviderUri::Uri("https://bsc-rpc.example".to_string())],
                    quorum: Some(1),
                },
            ),
        ]),
        Some(&["ethereum".to_string(), "bsc".to_string()]),
    )
    .unwrap();
    let transport = DelayedTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        delay: std::time::Duration::from_millis(120),
        response: Ok(json!({ "result": "0x1" })),
    };
    let source = RpcProviderHealthSource::from_getter(&getter, transport, || 1);

    let started_at = std::time::Instant::now();
    let report = source.get_provider_health_report().await;
    let elapsed = started_at.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(220),
        "chain probes were serialized: elapsed={elapsed:?}"
    );
    assert!(report["ethereum"].healthy);
    assert!(report["bsc"].healthy);
}

/// The invariant the last two rank defects were each half of: what a probe
/// records has to be the key `plan_dispatch` looks up.
///
/// Both defects were "the recorded key is not the looked-up key", found one
/// provider family at a time - first the redacted report URL, then Tron's
/// normalised probe URL. This drives the real path per family: probe the
/// source, seed the tracker from the report it produced, then dispatch and
/// require the unhealthy provider to have been excluded. Every URI carries a
/// credential in the path or query, because a bare host makes every derivation
/// the identity and hides exactly this class of bug.
#[tokio::test]
async fn a_failing_probe_excludes_the_provider_from_dispatch_for_every_family() {
    const SECRET: &str = "rank-identity-test-0123456789abcdef";

    for (chain_name, chain_type, raw_uri) in [
        (
            "bsc",
            "EVM",
            format!("https://rpc.example/v2/{SECRET}"),
        ),
        (
            "aptos",
            "APTOS",
            format!("https://rpc.example/v1?auth={SECRET}"),
        ),
        (
            "initia",
            "INITIA",
            format!("https://rpc.example/v1?key={SECRET}"),
        ),
        (
            "tron",
            "TRON",
            format!("https://rpc.example/jsonrpc?tron-api-key={SECRET}&tron-web-url=https%3A%2F%2Fweb.example"),
        ),
    ] {
        let uri = ProviderUri::Uri(raw_uri.clone());
        let getter = StaticProviderConfig::new(
            indexmap::IndexMap::from([(
                chain_name.to_string(),
                ProviderConfig {
                    uris: vec![uri.clone()],
                    quorum: Some(1),
                },
            )]),
            Some(&[chain_name.to_string()]),
        )
        .unwrap();

        // Every probe this family issues fails, so the provider is unhealthy
        // however many endpoints it touches.
        let source = RpcProviderHealthSource::from_getter_with_chain_types(
            &getter,
            AlwaysFailingTransport,
            || 0,
            HashMap::from([(chain_name.to_string(), chain_type.to_string())]),
        );
        let report = source.get_provider_health_report().await;
        assert!(
            !report[chain_name].healthy,
            "{chain_name}: precondition - the probe has to have failed"
        );

        let tracker = crate::provider_health::ProviderRankTracker::new();
        tracker.seed_from_report(&report).await;

        // What dispatch actually does with the configured URI.
        let error = crate::provider_health::plan_dispatch(&tracker, chain_name, &[uri], 1)
            .await
            .expect_err(&format!(
                "{chain_name}: a provider observed unhealthy must be excluded, so a \
                 quorum of one cannot be met"
            ));
        assert!(
            error.to_string().contains("Not enough healthy providers"),
            "{chain_name}: {error}"
        );
    }
}

#[derive(Clone)]
struct AlwaysFailingTransport;

#[async_trait]
impl JsonRpcTransport for AlwaysFailingTransport {
    async fn post_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
        _body: Value,
    ) -> Result<Value, String> {
        Err("endpoint down".to_string())
    }

    async fn get_json(
        &self,
        _url: String,
        _headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        Err("endpoint down".to_string())
    }
}
