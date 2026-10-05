use super::*;
use pillar_core::{execution::RequestContext, ProviderHealthCache, PROVIDER_HEALTH_CACHE_TTL_MS};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

struct Physical {
    stall: AtomicBool,
    background: AtomicUsize,
    background_peak: AtomicUsize,
    ethereum: AtomicUsize,
    ethereum_peak: AtomicUsize,
    entered: tokio::sync::Semaphore,
    dropped: tokio::sync::Semaphore,
}
struct PhysicalCall<'a> {
    physical: &'a Physical,
    ethereum: bool,
    background: bool,
}
impl Drop for PhysicalCall<'_> {
    fn drop(&mut self) {
        if self.ethereum {
            self.physical.ethereum.fetch_sub(1, Ordering::SeqCst);
        }
        if self.background {
            self.physical.background.fetch_sub(1, Ordering::SeqCst);
            self.physical.dropped.add_permits(1);
        }
    }
}
#[derive(Clone)]
struct StalledHealth {
    inner: ReadVerticalTransport,
    physical: Arc<Physical>,
}
#[async_trait]
impl JsonRpcTransport for StalledHealth {
    async fn post_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
        body: Value,
    ) -> Result<Value, String> {
        let ethereum = !url.contains("bsc-rpc");
        let background =
            self.physical.stall.load(Ordering::SeqCst) && body["method"] == "eth_chainId";
        let _call = PhysicalCall {
            physical: &self.physical,
            ethereum,
            background,
        };
        if ethereum {
            let count = self.physical.ethereum.fetch_add(1, Ordering::SeqCst) + 1;
            self.physical
                .ethereum_peak
                .fetch_max(count, Ordering::SeqCst);
        }
        if background {
            let count = self.physical.background.fetch_add(1, Ordering::SeqCst) + 1;
            self.physical
                .background_peak
                .fetch_max(count, Ordering::SeqCst);
            self.physical.entered.add_permits(1);
            return std::future::pending().await;
        }
        self.inner.post_json(url, headers, body).await
    }
    async fn get_json(
        &self,
        url: String,
        headers: HashMap<String, String>,
    ) -> Result<Value, String> {
        self.inner.get_json(url, headers).await
    }
}

#[tokio::test]
async fn stalled_stale_refresh_reserves_actual_target_headroom_for_http_signing() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let physical = Arc::new(Physical {
        entered: tokio::sync::Semaphore::new(0),
        dropped: tokio::sync::Semaphore::new(0),
        stall: AtomicBool::new(false),
        background: AtomicUsize::new(0),
        background_peak: AtomicUsize::new(0),
        ethereum: AtomicUsize::new(0),
        ethereum_peak: AtomicUsize::new(0),
    });
    let transport = StalledHealth {
        inner: ReadVerticalTransport {
            calls: calls.clone(),
            receipt: read_vertical_receipt(ReadMarker::BlockNumber),
            chain: ReadChain::Stable,
        },
        physical: physical.clone(),
    };
    let mut variables = read_vertical_env_map();
    variables.insert("PILLAR_RPC_CONCURRENCY".into(), "6".into());
    variables.insert("PILLAR_RPC_CHAIN_CONCURRENCY".into(), "2".into());
    let app =
        RuntimeServerApp::from_env_map_with_runtime_core(variables, transport.clone(), || {
            1_767_323_045_000
        })
        .await
        .unwrap();
    let resources = pillar_api::ServerApp::execution_resources(&app).unwrap();
    assert_eq!(resources.rpc.lane_capacity("background"), Some(1));
    let getter = StaticProviderConfig::new(
        IndexMap::from([(
            "ethereum".into(),
            ProviderConfig::with_distinct_entities(
                (0..24)
                    .map(|index| {
                        ProviderUri::Uri(format!("https://eth-rpc.example/background/{index}"))
                    })
                    .collect(),
                1,
            ),
        )]),
        None,
    )
    .unwrap();
    let source = RpcProviderHealthSource::from_getter(&getter, transport, || 1)
        .with_execution_resources(resources.clone());
    let clock = Arc::new(AtomicU64::new(1));
    let clock_copy = clock.clone();
    let cache = ProviderHealthCache::new(source, move || clock_copy.load(Ordering::SeqCst));
    assert!(cache.read().await.unwrap()["ethereum"]);
    clock.store(PROVIDER_HEALTH_CACHE_TTL_MS + 2, Ordering::SeqCst);
    physical.stall.store(true, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    let mut short_caller = RequestContext::new(Duration::from_millis(20));
    short_caller.resources = Some(resources);
    short_caller.source_chain = Some(Arc::from("ethereum"));
    assert!(short_caller.scope(cache.read()).await.unwrap()["ethereum"]);
    tokio::time::timeout(Duration::from_secs(1), physical.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(physical.background.load(Ordering::SeqCst), 1);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, pillar_api::router(app, "synthetic"))
            .with_graceful_shutdown(async {
                stopped.await.unwrap();
            })
            .await
            .unwrap();
    });
    let response = reqwest::Client::new()
        .post(format!("http://{address}/v2/resolve-and-sign"))
        .bearer_auth("test-token-0123456789abcdef0123456789")
        .json(&read_vertical_request(ReadMarker::BlockNumber))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let envelope: Value = response.json().await.unwrap();
    assert_eq!(envelope["statusCode"], 200);
    let response: pillar_core::PillarApiResponse =
        serde_json::from_value(envelope["body"].clone()).unwrap();
    assert_eq!(response.signatures.len(), 1);
    let signature = &response.signatures[0];
    let bytes = hex::decode(signature.signature.trim_start_matches("0x")).unwrap();
    assert_eq!(bytes.len(), 65);
    let hash = hex::decode(
        response
            .debug_info
            .unwrap()
            .dvn_hash_call_data
            .trim_start_matches("0x"),
    )
    .unwrap();
    assert_eq!(hash.len(), 32);
    let mut wrapped = b"\x19Ethereum Signed Message:\n32".to_vec();
    wrapped.extend_from_slice(&hash);
    let digest = <sha3::Keccak256 as sha3::Digest>::digest(wrapped);
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap(),
        k256::ecdsa::RecoveryId::from_byte(bytes[64] - 27).unwrap(),
    )
    .unwrap();
    let public = recovered.to_encoded_point(false);
    let hash = <sha3::Keccak256 as sha3::Digest>::digest(&public.as_bytes()[1..]);
    let recovered_address = format!("0x{}", hex::encode(&hash[12..]));
    assert!(signature.address.eq_ignore_ascii_case(&recovered_address));
    assert!(recovered_address.eq_ignore_ascii_case("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"));
    assert_eq!(
        read_call_blocks(&calls),
        vec![json!({"blockHash": BLOCK_A, "requireCanonical": true}); 2]
    );
    assert_eq!(physical.background_peak.load(Ordering::SeqCst), 1);
    assert_eq!(physical.ethereum_peak.load(Ordering::SeqCst), 2);
    physical.stall.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(11), physical.dropped.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(physical.background.load(Ordering::SeqCst), 0);
    assert!(cache.read().await.unwrap()["ethereum"]);
    stop.send(()).unwrap();
    server.await.unwrap();
    let output = "{\"criterion\":\"T5\",\"background_uris\":24,\"background_physical_max\":1,\"same_target_physical_max\":2,\"caller_deadline_ms\":20,\"independent_round_deadline_s\":10,\"http_status\":200,\"signature_recovered\":true,\"read_pins_verified\":2,\"cached_health_preserved\":true}";
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
    std::fs::write(directory.join("T5-background-headroom.json"), output).unwrap();
    println!("{output}");
}
