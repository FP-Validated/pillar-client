use super::*;
use pillar_signer::{
    AzureEcPublicKey, AzureKmsClient, AzureKmsKeyId, AzureKmsRawSignerAdapterFactory,
    RawSignerAdapterFactory, SignerError,
};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio_postgres::{Client, NoTls};

#[path = "audit_reconnect_e2e.rs"]
mod audit_reconnect_e2e;

struct Database {
    client: tokio::sync::Mutex<Client>,
    driver: tokio::task::JoinHandle<()>,
}
impl Database {
    async fn open(url: &str) -> Arc<Self> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await.unwrap();
        Arc::new(Self {
            client: tokio::sync::Mutex::new(client),
            driver: tokio::spawn(async move {
                connection.await.unwrap();
            }),
        })
    }
    async fn count(&self, namespace: &str, table: &str) -> i64 {
        let query = match table {
            "attempt" => "SELECT count(*) FROM pillar_audit_attempt WHERE namespace=$1",
            "intent" => "SELECT count(*) FROM pillar_audit_intent WHERE namespace=$1",
            "evidence" => "SELECT count(*) FROM pillar_audit_evidence e JOIN pillar_audit_attempt a ON a.id=e.attempt_id WHERE a.namespace=$1",
            _ => panic!("unknown audit table"),
        };
        self.client
            .lock()
            .await
            .query_one(query, &[&namespace])
            .await
            .unwrap()
            .get(0)
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    Slow,
    Stall,
    Fail,
    PartialFail,
    CrashAfterIntent,
    CrashAfterEffect,
}
struct Sdk {
    database: Arc<Database>,
    namespace: String,
    key: k256::ecdsa::SigningKey,
    version: Option<String>,
    behavior: Behavior,
    calls: AtomicUsize,
    entered: tokio::sync::Semaphore,
    finished: tokio::sync::Semaphore,
    returned: Mutex<Vec<String>>,
}
impl Sdk {
    fn new(database: Arc<Database>, namespace: &str, behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            database,
            namespace: namespace.into(),
            key: k256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap(),
            version: Some("7".into()),
            behavior,
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Semaphore::new(0),
            finished: tokio::sync::Semaphore::new(0),
            returned: Mutex::new(Vec::new()),
        })
    }
    fn reference(&self, name: &str) -> String {
        format!(
            "https://synthetic.invalid/keys/{name}/{}",
            self.version.as_deref().unwrap_or("")
        )
    }
}
#[async_trait]
impl AzureKmsClient for Sdk {
    async fn get_ec_public_key_coordinates(
        &self,
        key: &AzureKmsKeyId,
    ) -> Result<AzureEcPublicKey, SignerError> {
        assert!(matches!(key.name.as_str(), "smoke" | "other"));
        let point = self.key.verifying_key().to_encoded_point(false);
        Ok(AzureEcPublicKey {
            key_id: AzureKmsKeyId {
                name: key.name.clone(),
                version: self.version.clone(),
            },
            reference: self.reference(&key.name),
            x: point.x().unwrap().to_vec(),
            y: point.y().unwrap().to_vec(),
        })
    }
    async fn sign_es256k_digest(
        &self,
        key: &AzureKmsKeyId,
        digest: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        assert!(matches!(key.name.as_str(), "smoke" | "other"));
        assert_eq!(key.version, self.version);
        assert_eq!(digest.len(), 32);
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let rows = self.database.client.lock().await.query("SELECT signed_digest,key_reference,key_version,public_key_hash,validation_hash,source_chain,destination_chain,expiration FROM pillar_audit_attempt WHERE namespace=$1 ORDER BY id", &[&self.namespace]).await.unwrap();
        assert!(rows.len() >= call, "every SDK dispatch needs its own already-COMMITTED attempt visible from another connection");
        let row = rows
            .iter()
            .rev()
            .find(|row| row.get::<_, String>(1) == self.reference(&key.name))
            .unwrap();
        assert_eq!(row.get::<_, String>(0), hex::encode(digest));
        assert_eq!(row.get::<_, String>(1), self.reference(&key.name));
        assert_eq!(row.get::<_, String>(2), self.version.as_deref().unwrap());
        assert_eq!(
            row.get::<_, String>(3),
            pillar_core::audit::fingerprint(
                self.key.verifying_key().to_encoded_point(false).as_bytes()
            )
        );
        assert_eq!(row.get::<_, String>(4).len(), 64);
        assert_eq!(row.get::<_, String>(5), "ethereum");
        assert_eq!(row.get::<_, String>(6), "ethereum");
        assert_eq!(row.get::<_, i64>(7), READ_EXPIRATION);
        self.entered.add_permits(1);
        if matches!(self.behavior, Behavior::CrashAfterIntent) {
            std::process::exit(73);
        }
        if matches!(self.behavior, Behavior::Stall) {
            return std::future::pending().await;
        }
        if matches!(self.behavior, Behavior::Slow) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if matches!(self.behavior, Behavior::Fail) {
            return Err(SignerError::Message("synthetic SDK failure".into()));
        }
        if matches!(self.behavior, Behavior::PartialFail) && key.name == "other" {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if evidence(&self.database, &self.namespace)
                        .await
                        .iter()
                        .any(|(kind, _)| kind == "wallet_returned")
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            return Err(SignerError::Message(
                "synthetic second-wallet failure".into(),
            ));
        }
        let (signature, _) = self.key.sign_prehash_recoverable(digest).unwrap();
        if matches!(self.behavior, Behavior::CrashAfterEffect) {
            std::process::exit(74);
        }
        self.returned
            .lock()
            .unwrap()
            .push(hex::encode(signature.to_bytes()));
        self.finished.add_permits(1);
        Ok(signature.to_bytes().to_vec())
    }
}
fn variables(url: &str, namespace: &str, maximum: usize) -> HashMap<String, String> {
    let mut variables = read_vertical_env_map();
    for (name, value) in [
        (SIGNER_TYPE, "KMS"),
        (pillar_config::LZ_KMS_CLOUD_TYPE, "AZURE"),
        (pillar_config::LZ_KMS_IDS, "smoke"),
        (
            pillar_config::AZURE_KEY_VAULT_URL,
            "https://synthetic.invalid",
        ),
        ("PILLAR_AUDIT_ENABLED", "true"),
        ("PILLAR_AUDIT_DATABASE_URL", url),
        ("PILLAR_AUDIT_NAMESPACE", namespace),
        ("PILLAR_AUDIT_TIMEOUT_MS", "1000"),
    ] {
        variables.insert(name.into(), value.into());
    }
    variables.insert("PILLAR_AUDIT_MAX_ATTEMPTS".into(), maximum.to_string());
    variables
}
async fn app(
    url: &str,
    namespace: &str,
    maximum: usize,
    sdk: Arc<Sdk>,
) -> Result<RuntimeServerApp<ReadVerticalTransport>, String> {
    let factory: Arc<dyn RawSignerAdapterFactory> =
        Arc::new(AzureKmsRawSignerAdapterFactory::new(sdk));
    let transport = ReadVerticalTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        receipt: read_vertical_receipt(ReadMarker::BlockNumber),
        chain: ReadChain::Stable,
    };
    crate::signer_runtime::TEST_KMS_RAW_FACTORY
        .scope(
            factory,
            RuntimeServerApp::from_env_map_with_runtime_core(
                variables(url, namespace, maximum),
                transport,
                || 1_767_323_045_000,
            ),
        )
        .await
}
struct Http {
    address: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Http {
    async fn open(app: RuntimeServerApp<ReadVerticalTransport>) -> Self {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, pillar_api::router(app, "synthetic"))
                .with_graceful_shutdown(async {
                    stopped.await.unwrap();
                })
                .await
                .unwrap();
        });
        Self {
            address,
            stop: Some(stop),
            task,
        }
    }
    async fn post(&self, request: &PillarApiRequestV2) -> (reqwest::StatusCode, Value) {
        let response = reqwest::Client::new()
            .post(format!("http://{}/v2/resolve-and-sign", self.address))
            .bearer_auth("test-token-0123456789abcdef0123456789")
            .json(request)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }
    async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        (&mut self.task).await.unwrap();
    }
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn verify(envelope: Value, sdk: &Sdk) -> String {
    assert_eq!(envelope["statusCode"], 200);
    let response: pillar_core::PillarApiResponse =
        serde_json::from_value(envelope["body"].clone()).unwrap();
    assert_eq!(response.signatures.len(), 1);
    let signature = &response.signatures[0];
    let bytes = hex::decode(signature.signature.trim_start_matches("0x")).unwrap();
    assert_eq!(bytes.len(), 65);
    let input = hex::decode(
        response
            .debug_info
            .unwrap()
            .dvn_hash_call_data
            .trim_start_matches("0x"),
    )
    .unwrap();
    assert_eq!(input.len(), 32);
    let mut wrapped = b"\x19Ethereum Signed Message:\n32".to_vec();
    wrapped.extend_from_slice(&input);
    let digest = <sha3::Keccak256 as sha3::Digest>::digest(wrapped);
    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &k256::ecdsa::Signature::from_slice(&bytes[..64]).unwrap(),
        k256::ecdsa::RecoveryId::from_byte(bytes[64] - 27).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered, *sdk.key.verifying_key());
    let hash = <sha3::Keccak256 as sha3::Digest>::digest(
        &recovered.to_encoded_point(false).as_bytes()[1..],
    );
    assert!(signature
        .address
        .eq_ignore_ascii_case(&format!("0x{}", hex::encode(&hash[12..]))));
    signature.signature.clone()
}
async fn evidence(database: &Database, namespace: &str) -> Vec<(String, Option<String>)> {
    database.client.lock().await.query("SELECT e.kind,e.signature_hash FROM pillar_audit_evidence e JOIN pillar_audit_attempt a ON a.id=e.attempt_id WHERE a.namespace=$1 ORDER BY a.id,e.kind", &[&namespace]).await.unwrap().into_iter().map(|row| (row.get(0),row.get(1))).collect()
}
fn artifact(name: &str, value: &Value) {
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
    std::fs::write(
        directory.join(format!("durable-{name}-e2e.json")),
        serde_json::to_vec_pretty(&json!({"verified_assertion_summary": value, "summary_semantics": "post-assertion expectations unless a field is read from counters/status/timing; not a capacity measurement"})).unwrap(),
    )
    .unwrap();
    println!("{value}");
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PILLAR_AUDIT_E2E_DATABASE_URL PostgreSQL instance"]
async fn postgres_audit_production_http_commits_each_attempt_and_result_before_200() {
    let url = std::env::var("PILLAR_AUDIT_E2E_DATABASE_URL").unwrap();
    let database = Database::open(&url).await;
    let namespace = format!(
        "http_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let http = Http::open(app(&url, &namespace, 8, sdk.clone()).await.unwrap()).await;
    let mut signatures = Vec::new();
    for _ in 0..2 {
        let (status, body) = http
            .post(&read_vertical_request(ReadMarker::BlockNumber))
            .await;
        assert_eq!(status, reqwest::StatusCode::OK, "response={body}");
        signatures.push(verify(body, &sdk));
    }
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 2);
    assert_eq!(database.count(&namespace, "attempt").await, 2);
    assert_eq!(database.count(&namespace, "intent").await, 1);
    let rows = evidence(&database, &namespace).await;
    assert_eq!(rows.len(), 4);
    for signature in &signatures {
        let hash = hex::encode(<sha3::Keccak256 as sha3::Digest>::digest(
            signature.as_bytes(),
        ));
        assert!(rows
            .iter()
            .any(|(kind, value)| kind == "wallet_returned"
                && value.as_deref() == Some(hash.as_str())));
    }
    for signature in &signatures {
        let bytes = hex::decode(signature.trim_start_matches("0x")).unwrap();
        let hash = hex::encode(<sha3::Keccak256 as sha3::Digest>::digest(&bytes[..64]));
        assert!(rows
            .iter()
            .any(|(kind, value)| kind == "external_returned"
                && value.as_deref() == Some(hash.as_str())));
    }
    assert!(rows
        .iter()
        .all(|(_, value)| value.as_ref().is_some_and(|value| value.len() == 64)));
    let stored = database.client.lock().await.query("SELECT row_to_json(a)::text FROM pillar_audit_attempt a WHERE namespace=$1 UNION ALL SELECT row_to_json(i)::text FROM pillar_audit_intent i WHERE namespace=$1 UNION ALL SELECT row_to_json(e)::text FROM pillar_audit_evidence e JOIN pillar_audit_attempt a ON a.id=e.attempt_id WHERE a.namespace=$1", &[&namespace]).await.unwrap();
    for row in stored {
        let text: String = row.get(0);
        for signature in &signatures {
            assert!(!text.contains(&signature.trim_start_matches("0x")[..128]));
        }
        assert!(!text.contains(&ReadMarker::BlockNumber.command()));
    }
    let mut invalid = read_vertical_request(ReadMarker::BlockNumber);
    invalid.message_hash = format!("0x{}", "00".repeat(32));
    let (status, _) = http.post(&invalid).await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 2);
    assert_eq!(database.count(&namespace, "attempt").await, 2);
    http.close().await;
    artifact(
        "http-commit",
        &json!({"namespace":namespace,"runtime_router_http_status":200,"recovered_signatures":signatures.len(),"committed_before_sdk_dispatch":sdk.calls.load(Ordering::SeqCst),"attempts":database.count(&namespace,"attempt").await,"immutable_intents":database.count(&namespace,"intent").await,"result_hash_records":rows.len(),"invalid_retry_rejected_without_dispatch":true,"invalid_retry_status":status.as_u16(),"invalid_retry_new_attempts":0,"raw_signatures_stored":0,"raw_read_commands_stored":0}),
    );
}

fn unique(case: &str) -> String {
    format!(
        "{case}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}
async fn case(case: &str) -> (String, Arc<Database>, String) {
    let base = std::env::var("PILLAR_AUDIT_E2E_DATABASE_URL").unwrap();
    let namespace = unique(case);
    let database = Database::open(&base).await;
    database
        .client
        .lock()
        .await
        .batch_execute(&format!("CREATE SCHEMA {namespace}"))
        .await
        .unwrap();
    let mut scoped = url::Url::parse(&base).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={namespace}"))
        .append_pair("application_name", &namespace);
    let url = scoped.to_string();
    (url.clone(), Database::open(&url).await, namespace)
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_concurrent_fresh_schema_charges_one_packet_once() {
    let (scoped, database, namespace) = case("concurrent").await;
    assert_eq!(
        database
            .client
            .lock()
            .await
            .query_one("SELECT to_regclass('pillar_audit_attempt')::text", &[])
            .await
            .unwrap()
            .get::<_, Option<String>>(0),
        None
    );
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let startups =
        futures::future::join_all((0..4).map(|_| app(&scoped, &namespace, 2, sdk.clone()))).await;
    let mut servers = Vec::new();
    for startup in startups {
        servers.push(Http::open(startup.unwrap()).await);
    }
    let request = read_vertical_request(ReadMarker::BlockNumber);
    let outcomes =
        futures::future::join_all(servers.iter().map(|server| server.post(&request))).await;
    // Replays of one packet are retried deliveries, not new retained evidence, so a
    // quota of 2 must not refuse the third and fourth.
    for (status, body) in outcomes {
        assert_eq!(status, reqwest::StatusCode::OK, "response={body}");
        verify(body, &sdk);
    }
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 4);
    assert_eq!(database.count(&namespace, "attempt").await, 4);
    assert_eq!(namespace_attempt_count(&database, &namespace).await, 1);
    for server in &servers {
        assert_eq!(ready_status(server).await, reqwest::StatusCode::OK);
    }

    // A packet the namespace has not seen is charged against the quota: forget this one
    // and fill the namespace, and the same request is now refused before KMS.
    {
        let client = database.client.lock().await;
        client
            .execute(
                "DELETE FROM pillar_audit_packet WHERE namespace=$1",
                &[&namespace],
            )
            .await
            .unwrap();
        client
            .execute(
                "UPDATE pillar_audit_namespace SET attempt_count=max_attempts WHERE namespace=$1",
                &[&namespace],
            )
            .await
            .unwrap();
    }
    // Readiness serves a store probe cached for 250 ms; let the probes above expire.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (status, body) = servers[0].post(&request).await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body["body"]
        .as_str()
        .unwrap()
        .contains("capacity exhausted"));
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 4);
    for server in &servers {
        assert_eq!(
            ready_status(server).await,
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        let text = reqwest::Client::new()
            .get(format!("http://{}/metrics", server.address))
            .bearer_auth("test-token-0123456789abcdef0123456789")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(text
            .lines()
            .any(|line| line == "pillar_signing_audit_enabled 1"));
        assert!(text
            .lines()
            .any(|line| line == "pillar_signing_audit_ready 0"));
    }
    for server in servers {
        server.close().await;
    }
    artifact(
        "concurrent-quota",
        &json!({"fresh_schema_startups":4,"concurrent_replays":4,"http_200":4,"sdk_calls":4,"retained_attempts":4,"namespace_packets_charged":1,"new_packet_when_full_http_500":1,"sdk_calls_after_refusal":4,"all_ready_status_when_full":503,"audit_enabled":1,"audit_ready_after_probe":0}),
    );
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_caps_attempts_per_packet_before_kms() {
    let (url, database, namespace) = case("packet_cap").await;
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let server = Http::open(app(&url, &namespace, 2, sdk.clone()).await.unwrap()).await;
    let request = read_vertical_request(ReadMarker::BlockNumber);
    let (status, body) = server.post(&request).await;
    assert_eq!(status, reqwest::StatusCode::OK, "response={body}");
    verify(body, &sdk);
    database
        .client
        .lock()
        .await
        .execute(
            "UPDATE pillar_audit_packet SET attempts=63 WHERE namespace=$1",
            &[&namespace],
        )
        .await
        .unwrap();
    let (status, body) = server.post(&request).await;
    assert_eq!(status, reqwest::StatusCode::OK, "response={body}");
    verify(body, &sdk);
    let (status, body) = server.post(&request).await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body["body"]
        .as_str()
        .unwrap()
        .contains("capacity exhausted"));
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 2);
    assert_eq!(database.count(&namespace, "attempt").await, 2);
    assert_eq!(namespace_attempt_count(&database, &namespace).await, 1);
    server.close().await;
}

async fn namespace_attempt_count(database: &Database, namespace: &str) -> i64 {
    database
        .client
        .lock()
        .await
        .query_one(
            "SELECT attempt_count FROM pillar_audit_namespace WHERE namespace=$1",
            &[&namespace],
        )
        .await
        .unwrap()
        .get(0)
}

async fn ready_status(server: &Http) -> reqwest::StatusCode {
    reqwest::Client::new()
        .get(format!("http://{}/ready", server.address))
        .bearer_auth("test-token-0123456789abcdef0123456789")
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_retains_unknown_and_appends_late_completion_after_caller_drop() {
    let (url, database, namespace) = case("late").await;
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Slow);
    let application = Arc::new(app(&url, &namespace, 8, sdk.clone()).await.unwrap());
    let resources = pillar_api::ServerApp::execution_resources(application.as_ref()).unwrap();
    let caller = tokio::spawn({
        let application = application.clone();
        async move {
            application
                .sign_request_v2(read_vertical_request(ReadMarker::BlockNumber))
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), sdk.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if evidence(&database, &namespace)
                .await
                .iter()
                .any(|(kind, _)| kind == "outcome_unknown")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(resources.kms.totals().active, 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let rows = evidence(&database, &namespace).await;
            if rows.iter().any(|(kind, value)| {
                kind == "external_returned" && value.as_ref().is_some_and(|value| value.len() == 64)
            }) && resources.kms.totals().active == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let rows = evidence(&database, &namespace).await;
    assert_eq!(rows.len(), 2);
    assert!(!rows.iter().any(|(kind, _)| kind == "wallet_returned"));
    assert_eq!(
        resources.kms.totals().outcomes[pillar_core::execution::Outcome::Unknown as usize],
        1
    );
    assert_eq!(database.count(&namespace, "attempt").await, 1);
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 1);
    drop(application);
    artifact(
        "late-completion",
        &json!({"caller_aborted":true,"sdk_calls":1,"physical_permit_held_until_completion":true,"retained_attempts":1,"unknown_records":1,"late_external_hash_records":1,"wallet_returned_records":0,"kms_outcome_unknown":1}),
    );
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_sdk_failure_is_retained_and_a_new_retry_is_revalidated() {
    let (url, database, namespace) = case("sdk_failure").await;
    let failed = Sdk::new(database.clone(), &namespace, Behavior::Fail);
    let server = Http::open(app(&url, &namespace, 8, failed.clone()).await.unwrap()).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body["body"]
        .as_str()
        .unwrap()
        .contains("synthetic SDK failure"));
    assert_eq!(
        evidence(&database, &namespace).await,
        vec![("outcome_unknown".into(), None)]
    );
    server.close().await;
    let recovered = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let server = Http::open(app(&url, &namespace, 8, recovered.clone()).await.unwrap()).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    verify(body, &recovered);
    assert_eq!(database.count(&namespace, "attempt").await, 2);
    assert_eq!(database.count(&namespace, "intent").await, 1);
    assert_eq!(evidence(&database, &namespace).await.len(), 3);
    server.close().await;
    artifact(
        "sdk-failure-retry",
        &json!({"sdk_failure_http_status":500,"unresolved_attempt_retained":true,"retry_http_status":200,"new_validated_attempts":1,"total_attempts":2,"immutable_intents":1,"old_unknown_removed":false}),
    );
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_refuses_unresolved_and_conflicting_immutable_identity() {
    let (url, database, namespace) = case("identity").await;
    let original = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let server = Http::open(app(&url, &namespace, 8, original.clone()).await.unwrap()).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    verify(body, &original);
    server.close().await;
    let mut conflict = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    Arc::get_mut(&mut conflict).unwrap().key =
        k256::ecdsa::SigningKey::from_slice(&[4; 32]).unwrap();
    let server = Http::open(app(&url, &namespace, 8, conflict.clone()).await.unwrap()).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body["body"].as_str().unwrap().contains("intent conflicts"));
    assert_eq!(conflict.calls.load(Ordering::SeqCst), 0);
    assert_eq!(database.count(&namespace, "attempt").await, 1);
    server.close().await;
    let mut version = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    Arc::get_mut(&mut version).unwrap().version = Some("8".into());
    let server = Http::open(app(&url, &namespace, 8, version.clone()).await.unwrap()).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    verify(body, &version);
    server.close().await;
    assert_eq!(database.count(&namespace, "attempt").await, 2);
    assert_eq!(database.count(&namespace, "intent").await, 2);
    let missing_namespace = unique("missing_version");
    let mut missing = Sdk::new(database.clone(), &missing_namespace, Behavior::Normal);
    Arc::get_mut(&mut missing).unwrap().version = None;
    let error = match app(&url, &missing_namespace, 8, missing.clone()).await {
        Ok(_) => panic!("unresolved identity must fail startup"),
        Err(error) => error,
    };
    assert!(error.contains("unresolved effective key version"));
    assert_eq!(missing.calls.load(Ordering::SeqCst), 0);
    assert_eq!(database.count(&missing_namespace, "attempt").await, 0);
    let unavailable = Sdk::new(database.clone(), &unique("unavailable"), Behavior::Normal);
    let blackhole = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let mut unavailable_url = url::Url::parse(&url).unwrap();
    unavailable_url
        .set_port(Some(blackhole.local_addr().unwrap().port()))
        .unwrap();
    let startup_error = match app(
        unavailable_url.as_str(),
        &unavailable.namespace,
        8,
        unavailable.clone(),
    )
    .await
    {
        Ok(_) => panic!("half-open handshake must refuse startup"),
        Err(error) => error,
    };
    assert!(
        startup_error.contains("store unavailable"),
        "{startup_error}"
    );
    drop(blackhole);
    assert_eq!(unavailable.calls.load(Ordering::SeqCst), 0);
    artifact(
        "immutable-identity",
        &json!({"initial_status":200,"same_version_changed_public_key_status":500,"conflicting_sdk_calls":0,"new_immutable_version_status":200,"immutable_intents":2,"unresolved_identity_startup_refused":true,"unresolved_identity_sdk_calls":0,"store_unavailable_startup_refused":true,"store_unavailable_sdk_calls":0}),
    );
}

async fn gate(database: &Database, namespace: &str, table: &str, lock: i64, reject: bool) {
    let (function, trigger, condition) = match table {
        "attempt" => (
            "audit_e2e_attempt_gate",
            "audit_e2e_attempt_gate",
            "NEW.namespace".to_string(),
        ),
        "wallet" => (
            "audit_e2e_evidence_gate",
            "audit_e2e_evidence_gate",
            "(SELECT namespace FROM pillar_audit_attempt WHERE id=NEW.attempt_id)".to_string(),
        ),
        "external" => (
            "audit_e2e_evidence_gate",
            "audit_e2e_evidence_gate",
            "(SELECT namespace FROM pillar_audit_attempt WHERE id=NEW.attempt_id)".to_string(),
        ),
        _ => panic!("unexpected gate"),
    };
    let table_name = if table == "attempt" {
        "pillar_audit_attempt"
    } else {
        "pillar_audit_evidence"
    };
    let kind = match table {
        "wallet" => " AND NEW.kind='wallet_returned'",
        "external" => " AND NEW.kind='external_returned'",
        _ => "",
    };
    let action = if reject {
        "RAISE EXCEPTION 'synthetic durable write failure'".to_string()
    } else {
        format!("PERFORM pg_advisory_xact_lock({lock})")
    };
    let (trigger_clause, timing, deferral) = if table == "attempt" {
        ("CREATE TRIGGER", "BEFORE", "")
    } else {
        (
            "CREATE CONSTRAINT TRIGGER",
            "AFTER",
            "DEFERRABLE INITIALLY DEFERRED",
        )
    };
    database.client.lock().await.batch_execute(&format!("CREATE OR REPLACE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {condition}='{namespace}'{kind} THEN {action}; END IF; RETURN NEW; END $$; {trigger_clause} {trigger} {timing} INSERT ON {table_name} {deferral} FOR EACH ROW EXECUTE FUNCTION {function}();")).await.unwrap();
}
async fn ungate(database: &Database, table: &str) {
    let (trigger, table) = if table == "attempt" {
        ("audit_e2e_attempt_gate", "pillar_audit_attempt")
    } else {
        ("audit_e2e_evidence_gate", "pillar_audit_evidence")
    };
    database
        .client
        .lock()
        .await
        .batch_execute(&format!(
            "DROP TRIGGER {trigger} ON {table}; DROP FUNCTION {trigger}();"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_never_emits_200_before_result_commit_or_on_store_write_failure() {
    let (url, database, namespace) = case("commit_gate").await;
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
    let server = Http::open(app(&url, &namespace, 8, sdk.clone()).await.unwrap()).await;
    gate(&database, &namespace, "wallet", 74001, false).await;
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_lock(74001)", &[])
        .await
        .unwrap();
    {
        let request = read_vertical_request(ReadMarker::BlockNumber);
        let result = server.post(&request);
        tokio::pin!(result);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut result)
                .await
                .is_err()
        );
        assert_eq!(sdk.calls.load(Ordering::SeqCst), 1);
        let rows = evidence(&database, &namespace).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "external_returned");
        database
            .client
            .lock()
            .await
            .query_one("SELECT pg_advisory_unlock(74001)", &[])
            .await
            .unwrap();
        let (status, body) = result.await;
        assert_eq!(status, reqwest::StatusCode::OK);
        verify(body, &sdk);
        assert_eq!(evidence(&database, &namespace).await.len(), 2);
        ungate(&database, "wallet").await;
    }
    server.close().await;
    let before = unique("begin_failure");
    let sdk = Sdk::new(database.clone(), &before, Behavior::Normal);
    let server = Http::open(app(&url, &before, 8, sdk.clone()).await.unwrap()).await;
    gate(&database, &before, "attempt", 0, true).await;
    let (status, _) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 0);
    assert_eq!(database.count(&before, "attempt").await, 0);
    assert_eq!(database.count(&before, "intent").await, 0);
    ungate(&database, "attempt").await;
    server.close().await;
    let after = unique("external_failure");
    let sdk = Sdk::new(database.clone(), &after, Behavior::Normal);
    let server = Http::open(app(&url, &after, 8, sdk.clone()).await.unwrap()).await;
    gate(&database, &after, "external", 0, true).await;
    let (status, _) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 1);
    assert_eq!(database.count(&after, "attempt").await, 1);
    assert_eq!(
        evidence(&database, &after).await,
        vec![("outcome_unknown".into(), None)]
    );
    ungate(&database, "external").await;
    server.close().await;
    artifact(
        "commit-fail-closed",
        &json!({"http_response_while_deferred_result_commit_trigger_blocked":false,"after_result_commit_status":200,"before_attempt_commit_failure_status":500,"before_attempt_commit_sdk_calls":0,"rolled_back_intents":0,"after_sdk_result_store_failure_status":500,"after_sdk_calls":1,"unresolved_attempt_retained":true,"raw_signature_released_on_failure":false}),
    );
}

pub(super) async fn run_crash_worker() {
    let url = std::env::var("PILLAR_AUDIT_E2E_DATABASE_URL").unwrap();
    let Ok(mode) = std::env::var("PILLAR_AUDIT_E2E_WORKER_MODE") else {
        let (url, database, namespace) = case("missing_wallet_scope").await;
        let config = pillar_config::AuditConfig::from_map(&variables(&url, &namespace, 8))
            .unwrap()
            .unwrap();
        let store = crate::audit::PostgresAuditStore::connect(config)
            .await
            .unwrap();
        let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
        let adapter =
            pillar_signer::AzureKmsRawSignerAdapter::new("smoke".into(), sdk.clone()).unwrap();
        let error = pillar_core::audit::scope_root(
            Some(store),
            Some(Arc::new(pillar_core::audit::AuditWorkers::new(1))),
            1,
            pillar_signer::RawSignerAdapter::sign(
                &adapter,
                pillar_signer::SignRequest {
                    data: vec![1; 32],
                    signature_type: pillar_signer::SignatureType::Ecdsa,
                    private_key_signature_type: pillar_signer::SignatureType::Ecdsa,
                    transform_recovery_id: true,
                    seed_kind: pillar_signer::SeedKind::Bip39,
                },
            ),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("outside validated wallet scope"));
        assert_eq!(sdk.calls.load(Ordering::SeqCst), 0);
        assert_eq!(database.count(&namespace, "attempt").await, 0);
        artifact(
            "missing-wallet-scope",
            &json!({"error":error.to_string(),"sdk_calls":sdk.calls.load(Ordering::SeqCst),"attempts":database.count(&namespace,"attempt").await}),
        );
        return;
    };
    let namespace = std::env::var("PILLAR_AUDIT_E2E_WORKER_NAMESPACE").unwrap();
    let behavior = match mode.as_str() {
        "after-intent" => Behavior::CrashAfterIntent,
        "after-effect" => Behavior::CrashAfterEffect,
        "normal" => Behavior::Normal,
        _ => panic!("unknown crash point"),
    };
    let database = Database::open(&url).await;
    let sdk = Sdk::new(database, &namespace, behavior);
    let application = app(&url, &namespace, 8, sdk).await.unwrap();
    let result = application
        .sign_request_v2(read_vertical_request(ReadMarker::BlockNumber))
        .await;
    panic!("crash worker unexpectedly returned: {}", result.is_ok());
}
fn worker(url: &str, namespace: &str, mode: &str) -> tokio::process::Child {
    tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "tests::read_vertical_tests::durable_process_worker",
            "--nocapture",
        ])
        .env("PILLAR_AUDIT_E2E_DATABASE_URL", url)
        .env("PILLAR_AUDIT_E2E_WORKER_NAMESPACE", namespace)
        .env("PILLAR_AUDIT_E2E_WORKER_MODE", mode)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}
async fn wait_for_gate(database: &Database) {
    tokio::time::timeout(Duration::from_secs(5),async { loop { let waiting=database.client.lock().await.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event='advisory' AND (query='COMMIT' OR query LIKE 'INSERT INTO pillar_audit_%') AND application_name=current_setting('application_name')",&[]).await.unwrap().get::<_,i64>(0); if waiting>0 { break; } tokio::task::yield_now().await; } }).await.unwrap();
}
#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_process_crashes_preserve_unknown_without_replay_or_nonce_lock() {
    let (url, database, namespace) = case("crash_bootstrap").await;
    let bootstrap = app(
        &url,
        &namespace,
        8,
        Sdk::new(database.clone(), &namespace, Behavior::Normal),
    )
    .await
    .unwrap();
    drop(bootstrap);
    let precommit = unique("crash_precommit");
    gate(&database, &precommit, "attempt", 74003, false).await;
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_lock(74003)", &[])
        .await
        .unwrap();
    let mut child = worker(&url, &precommit, "normal");
    wait_for_gate(&database).await;
    assert_eq!(database.count(&precommit, "attempt").await, 0);
    child.kill().await.unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(!output.status.success());
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_unlock(74003)", &[])
        .await
        .unwrap();
    ungate(&database, "attempt").await;
    assert_eq!(database.count(&precommit, "intent").await, 0);
    assert_eq!(database.count(&precommit, "attempt").await, 0);
    for (mode, code) in [("after-intent", 73), ("after-effect", 74)] {
        let namespace = unique("crash_armed");
        let output = tokio::time::timeout(
            Duration::from_secs(10),
            worker(&url, &namespace, mode).wait_with_output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "worker output={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(database.count(&namespace, "attempt").await, 1);
        assert_eq!(database.count(&namespace, "evidence").await, 0);
        let sdk = Sdk::new(database.clone(), &namespace, Behavior::Normal);
        let server = Http::open(app(&url, &namespace, 8, sdk.clone()).await.unwrap()).await;
        let (status, body) = server
            .post(&read_vertical_request(ReadMarker::BlockNumber))
            .await;
        assert_eq!(status, reqwest::StatusCode::OK);
        verify(body, &sdk);
        assert_eq!(sdk.calls.load(Ordering::SeqCst), 1);
        assert_eq!(database.count(&namespace, "attempt").await, 2);
        assert_eq!(database.count(&namespace, "intent").await, 1);
        assert_eq!(database.count(&namespace, "evidence").await, 2);
        server.close().await;
    }
    let result_gap = unique("crash_result_gap");
    gate(&database, &result_gap, "wallet", 74004, false).await;
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_lock(74004)", &[])
        .await
        .unwrap();
    let mut child = worker(&url, &result_gap, "normal");
    wait_for_gate(&database).await;
    assert_eq!(database.count(&result_gap, "attempt").await, 1);
    let rows = evidence(&database, &result_gap).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "external_returned");
    assert_eq!(rows[0].1.as_ref().unwrap().len(), 64);
    child.kill().await.unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(!output.status.success());
    database
        .client
        .lock()
        .await
        .query_one("SELECT pg_advisory_unlock(74004)", &[])
        .await
        .unwrap();
    ungate(&database, "wallet").await;
    let after_disconnect = evidence(&database, &result_gap).await;
    assert_eq!(&after_disconnect[..1], &rows[..1]);
    assert!(after_disconnect
        .iter()
        .all(|row| row.0 == "external_returned" || row.0 == "wallet_returned"));
    let committed_after_disconnect = after_disconnect.len();
    let sdk = Sdk::new(database.clone(), &result_gap, Behavior::Normal);
    let server = Http::open(app(&url, &result_gap, 8, sdk.clone()).await.unwrap()).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::OK);
    verify(body, &sdk);
    assert_eq!(database.count(&result_gap, "attempt").await, 2);
    assert_eq!(
        evidence(&database, &result_gap).await.len(),
        committed_after_disconnect + 2
    );
    server.close().await;
    artifact(
        "process-crash",
        &json!({"killed_before_commit_attempts":0,"killed_before_commit_intents":0,"after_intent_process_exit":73,"after_effect_before_evidence_process_exit":74,"unresolved_armed_attempts_retained":2,"hash_records_committed_after_disconnect":committed_after_disconnect,"old_unknown_or_partial_attempts_deleted":0,"restarted_same_digest_revalidated_new_attempts":3,"cached_signature_replays":0,"permanent_nonce_lock":false}),
    );
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_partial_wallet_failure_never_releases_partial_signatures() {
    let (url, database, namespace) = case("partial").await;
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::PartialFail);
    let factory: Arc<dyn RawSignerAdapterFactory> =
        Arc::new(AzureKmsRawSignerAdapterFactory::new(sdk.clone()));
    let mut variables = variables(&url, &namespace, 8);
    variables.insert(pillar_config::LZ_KMS_IDS.into(), "smoke,other".into());
    let transport = ReadVerticalTransport {
        calls: Arc::new(Mutex::new(Vec::new())),
        receipt: read_vertical_receipt(ReadMarker::BlockNumber),
        chain: ReadChain::Stable,
    };
    let application = crate::signer_runtime::TEST_KMS_RAW_FACTORY
        .scope(
            factory,
            RuntimeServerApp::from_env_map_with_runtime_core(variables, transport, || {
                1_767_323_045_000
            }),
        )
        .await
        .unwrap();
    let server = Http::open(application).await;
    let (status, body) = server
        .post(&read_vertical_request(ReadMarker::BlockNumber))
        .await;
    assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body["body"]
        .as_str()
        .unwrap()
        .contains("synthetic second-wallet failure"));
    let wire = body.to_string();
    assert!(body.get("signatures").is_none());
    assert!(!body["body"].as_str().unwrap().contains("\"signatures\""));
    assert_eq!(sdk.returned.lock().unwrap().len(), 1);
    for raw in sdk.returned.lock().unwrap().iter() {
        assert!(
            !wire.contains(raw),
            "partial r||s signature leaked into 500 body"
        );
    }
    assert_eq!(sdk.calls.load(Ordering::SeqCst), 2);
    assert_eq!(database.count(&namespace, "attempt").await, 2);
    let rows = evidence(&database, &namespace).await;
    assert_eq!(
        rows.iter()
            .filter(|(kind, _)| kind == "external_returned")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|(kind, _)| kind == "wallet_returned")
            .count(),
        1
    );
    assert_eq!(
        rows.iter()
            .filter(|(kind, value)| kind == "outcome_unknown" && value.is_none())
            .count(),
        1
    );
    server.close().await;
    artifact(
        "partial-wallet",
        &json!({"wallets":2,"sdk_calls":sdk.calls.load(Ordering::SeqCst),"retained_attempts":database.count(&namespace,"attempt").await,"successful_wallet_hash_records":1,"other_wallet_unknown_records":1,"http_status":status.as_u16(),"raw_signature_candidates":sdk.returned.lock().unwrap().len(),"partial_signatures_released":0}),
    );
}

#[tokio::test]
#[ignore = "Requires the explicitly scoped synthetic PostgreSQL instance"]
async fn postgres_audit_runtime_owner_drop_aborts_unfinished_workers_without_false_failure() {
    let (url, database, namespace) = case("owner_drop").await;
    let sdk = Sdk::new(database.clone(), &namespace, Behavior::Stall);
    let application = Arc::new(app(&url, &namespace, 8, sdk.clone()).await.unwrap());
    let resources = pillar_api::ServerApp::execution_resources(application.as_ref()).unwrap();
    let caller = tokio::spawn({
        let application = application.clone();
        async move {
            application
                .sign_request_v2(read_vertical_request(ReadMarker::BlockNumber))
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), sdk.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(2), async {
        while evidence(&database, &namespace).await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(resources.kms.totals().active, 1);
    drop(application);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resources.kms.totals().active != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        evidence(&database, &namespace).await,
        vec![("outcome_unknown".into(), None)]
    );
    assert_eq!(database.count(&namespace, "attempt").await, 1);
    assert_eq!(
        resources.kms.totals().outcomes[pillar_core::execution::Outcome::Unknown as usize],
        1
    );
    assert_eq!(sdk.finished.available_permits(), 0);
    artifact(
        "worker-owner-drop",
        &json!({"noncompleting_sdk_calls":1,"runtime_owner_drop_aborts_worker":true,"kms_active_after_owner_drop":0,"kms_outcome_unknown":1,"retained_unknown_attempts":1,"false_failed_records":0,"external_returned_records":0}),
    );
}
