use super::*;
use crate::dvn::{DvnGateClient, DvnGateConfig};
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::State,
    http::{Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use pillar_core::dvn::{
    AuthorizeRequest, Environment, Permit, RegistrySnapshot, SignedEnvelope, PERMIT_SCHEMA,
    REGISTRY_SCHEMA,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

#[derive(Clone, Copy)]
enum Reply {
    Deny,
    BadSignature,
    Expired,
    RequestMismatch,
    Allow,
}
#[derive(Clone)]
struct GateFixture {
    reply: Arc<Mutex<Reply>>,
    registry: SignedEnvelope,
    registrations: Arc<Mutex<Vec<Value>>>,
    subjects: Arc<Mutex<Vec<pillar_core::dvn::Subject>>>,
}
fn sign_payload(payload: &impl serde::Serialize, domain: &str) -> SignedEnvelope {
    let payload = serde_json::to_vec(payload).unwrap();
    let mut signed = domain.as_bytes().to_vec();
    signed.push(0);
    signed.extend_from_slice(&payload);
    SignedEnvelope {
        sha256: pillar_core::dvn::sha256_hex(&payload),
        payload: STANDARD.encode(payload),
        signature: STANDARD.encode(SigningKey::from_bytes(&[9; 32]).sign(&signed).to_bytes()),
        key_id: "http-test".into(),
    }
}
async fn registration(State(state): State<GateFixture>, Json(body): Json<Value>) -> StatusCode {
    state.registrations.lock().unwrap().push(body);
    StatusCode::OK
}
async fn registry(State(state): State<GateFixture>) -> Json<SignedEnvelope> {
    Json(state.registry)
}
async fn authorize(State(state): State<GateFixture>, raw: Bytes) -> Json<Value> {
    let request: AuthorizeRequest = serde_json::from_slice(&raw).unwrap();
    state.subjects.lock().unwrap().push(request.subject.clone());
    let reply = *state.reply.lock().unwrap();
    if matches!(reply, Reply::Deny) {
        return Json(json!({"decision":"deny", "reason":"paused"}));
    }
    let now = pillar_core::dvn::now_ms().unwrap();
    let mut permit = Permit {
        schema_version: PERMIT_SCHEMA.into(),
        decision_id: "http-test-decision".into(),
        environment: request.subject.environment,
        workload_id: "http-test-workload".into(),
        instance_id: request.instance_id,
        boot_id: request.boot_id,
        request_sha256: pillar_core::dvn::sha256_hex(&raw),
        intent_digest: request.intent_digest,
        policy_revision: 1,
        safety_epoch: 1,
        issued_at_ms: now,
        expires_at_ms: now + 2_000,
    };
    if matches!(reply, Reply::Expired) {
        permit.issued_at_ms = now - 2_001;
        permit.expires_at_ms = now - 1;
    }
    if matches!(reply, Reply::RequestMismatch) {
        permit.request_sha256 = "ff".repeat(32);
    }
    let mut envelope = sign_payload(&permit, PERMIT_SCHEMA);
    if matches!(reply, Reply::BadSignature) {
        envelope.signature = STANDARD.encode([0; 64]);
    }
    Json(json!({"decision":"allow", "permit":envelope}))
}
struct GateServer(tokio::task::JoinHandle<()>);
impl Drop for GateServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn gate(reply: Reply) -> (Arc<DvnGateClient>, GateFixture, GateServer) {
    let chains = vec![
        "ethereum".to_string(),
        "bsc".to_string(),
        "solana".to_string(),
    ];
    let snapshot = RegistrySnapshot {
        schema_version: REGISTRY_SCHEMA.into(),
        environment: Environment::Mainnet,
        revision: 1,
        chains: vec![
            pillar_core::dvn::ChainBinding {
                eid: 30101,
                name: "ethereum".into(),
                address_format: "evm".into(),
            },
            pillar_core::dvn::ChainBinding {
                eid: 30102,
                name: "bsc".into(),
                address_format: "evm".into(),
            },
            pillar_core::dvn::ChainBinding {
                eid: 30168,
                name: "solana".into(),
                address_format: "solana".into(),
            },
        ],
        asset_bindings: vec![],
    };
    let state = GateFixture {
        reply: Arc::new(Mutex::new(reply)),
        registry: sign_payload(&snapshot, REGISTRY_SCHEMA),
        registrations: Arc::new(Mutex::new(vec![])),
        subjects: Arc::new(Mutex::new(vec![])),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/internal/v1/dvn/registry", get(registry))
        .route("/internal/v1/dvn/instances", post(registration))
        .route("/internal/v1/dvn/authorize", post(authorize))
        .with_state(state.clone());
    let server = GateServer(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    }));
    let vars = HashMap::from([
        ("LAYERZERO_ENVIRONMENT".into(), "mainnet".into()),
        ("PILLAR_DVN_GATE_URL".into(), url),
        ("PILLAR_DVN_GATE_TOKEN".into(), "test-only".into()),
        ("PILLAR_DVN_GATE_KEY_ID".into(), "http-test".into()),
        (
            "PILLAR_DVN_GATE_PUBLIC_KEY".into(),
            STANDARD.encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes()),
        ),
        ("PILLAR_DVN_WORKLOAD_ID".into(), "http-test-workload".into()),
        ("PILLAR_DVN_INSTANCE_ID".into(), "http-test-instance".into()),
    ]);
    let providers = ProviderSnapshotHandle::new(IndexMap::new(), chains);
    let client = DvnGateClient::connect(DvnGateConfig::from_env(&vars).unwrap(), providers)
        .await
        .unwrap();
    assert!(client.ready().await);
    {
        let registrations = state.registrations.lock().unwrap();
        assert_eq!(registrations.len(), 2);
        assert_eq!(registrations[0]["registryRevision"], 0);
        assert_eq!(registrations[0]["registryDigest"], "");
        assert_eq!(registrations[1]["registryRevision"], 1);
        assert_eq!(registrations[1]["registryDigest"], state.registry.sha256);
    }
    (client, state, server)
}

struct PacketResolver(LzSentEvent);
#[async_trait]
impl SentEventResolver for PacketResolver {
    async fn get_lz_sent_event(
        &self,
        _: &str,
        _: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        Ok(self.0.clone())
    }
}
struct NeverInvokedFactory(Arc<AtomicUsize>);
#[async_trait]
impl RawSignerAdapterFactory for NeverInvokedFactory {
    async fn mnemonic(
        &self,
        _: &str,
        _: ChainType,
        _: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(SignerError::Message("unexpected key access".into()))
    }
    async fn kms(
        &self,
        _: KmsProvider,
        _: &ChainTypeWalletDefinition,
    ) -> Result<Arc<dyn RawSignerAdapter>, SignerError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(SignerError::Message("unexpected KMS access".into()))
    }
}
struct CountSigner(Arc<AtomicUsize>);
#[async_trait]
impl SignerGetter for CountSigner {
    fn backend_scope(&self, _: &str, _: &str) -> Result<String, AppCoreError> {
        Ok("test".into())
    }
    async fn pillar_sign(
        &self,
        chain: &str,
        wallet: &str,
        data: &str,
        permit: &pillar_core::dvn::SigningAuthorization,
    ) -> Result<Signature, AppCoreError> {
        permit.check(chain, wallet, &self.backend_scope(chain, wallet)?, data)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Signature {
            signature: "test-signature".into(),
            address: "test-address".into(),
        })
    }
}

fn packet(source: &str, read: bool) -> LzSentEvent {
    let destination = if read { source } else { "bsc" };
    let src_eid = if read {
        u32::MAX
    } else if source == "solana" {
        30168
    } else {
        30101
    };
    let dst_eid = if read { 30101 } else { 30102 };
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: source.into(),
                dst_chain_name: destination.into(),
                extra: IndexMap::from([
                    ("srcEid".into(), json!(src_eid)),
                    ("dstEid".into(), json!(dst_eid)),
                    (
                        "sender".into(),
                        json!(format!("0x{}{}", "00".repeat(12), "11".repeat(20))),
                    ),
                    (
                        "receiver".into(),
                        json!(format!("0x{}{}", "00".repeat(12), "22".repeat(20))),
                    ),
                ]),
            },
            nonce: 7,
            uln_send_version: json!(if read { "ReadV1002" } else { "V302" }),
        },
        message: "0x010203".into(),
        tx_hash: "0xabc".into(),
        source_evidence: None,
        read_block_pins: vec![],
        extra: IndexMap::from([("guid".into(), json!(format!("0x{}", "33".repeat(32))))]),
    }
}
fn http_app(
    policy: Arc<DvnGateClient>,
    event: LzSentEvent,
    signer: Arc<dyn SignerGetter>,
) -> axum::Router {
    let destination = event.lz_message_id.pathway_id.dst_chain_name.clone();
    let app = PillarApp {
        available_chain_names: Arc::new(vec!["ethereum".into(), "bsc".into(), "solana".into()]),
        wallets_by_chain_name: HashMap::from([(
            destination,
            vec![WalletRef {
                wallet_name: "wallet".into(),
            }],
        )]),
        hash_call_data_builders: HashMap::from([
            (
                "V2".into(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            ),
            (
                "V301".into(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            ),
            (
                "V302".into(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            ),
            (
                "ReadV1002".into(),
                Arc::new(FixedBuilder) as Arc<dyn HashCallDataBuilder>,
            ),
        ]),
        sent_event_resolver: Arc::new(PacketResolver(event)),
        validator: Arc::new(NoopValidator),
        signer_getter: signer,
        signing_policy: policy,
        legacy_chain_name_resolver: Arc::new(FixedChainResolver),
        stage_observer: Arc::new(pillar_core::NoopSignStageObserver),
        debug_mode: false,
    };
    pillar_api::router(
        CoreApiApp::new(
            app,
            "mainnet".into(),
            BTreeMap::new(),
            ProviderHealthSnapshot::new(),
            json!({}),
        )
        .with_api_auth_enabled(false),
        "test",
    )
}
fn request(event: &LzSentEvent, legacy: bool, read: bool) -> (String, Value) {
    if legacy {
        return (
            "/".into(),
            json!({"srcTxHash":"0xabc", "lzMessageId":{
            "srcChainId":1,"dstChainId":56,"nonce":7,"srcUAAddress":"0x11","dstUAAddress":"0x22"},
            "blockConfirmation":1,"expiration":2000000000,"ulnVersion":event.lz_message_id.uln_send_version,"messageHash":"0xhash"}),
        );
    }
    (
        "/v2/resolve-and-sign".into(),
        json!({"srcTxHash":"0xabc", "lzMessageId":event.lz_message_id,
        "messageHash":"0xhash", "signingContext":if read { json!({"protocolType":"READ","expiration":2000000000,"resolvedTimestampTimeMarkers":[]}) }
            else { json!({"protocolType":"MESSAGE","expiration":2000000000,"blockConfirmation":1}) }}),
    )
}
async fn post_sign(
    router: axum::Router,
    event: &LzSentEvent,
    legacy: bool,
    read: bool,
) -> (StatusCode, Value) {
    let (path, body) = request(event, legacy, read);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap(),
    )
}

#[tokio::test]
async fn dvn_denial_invalid_signature_expiry_and_request_binding_block_every_kms_backend_before_key_access(
) {
    for reply in [
        Reply::Deny,
        Reply::BadSignature,
        Reply::Expired,
        Reply::RequestMismatch,
    ] {
        let (gate, state, _server) = gate(reply).await;
        for provider in [KmsProvider::Aws, KmsProvider::Gcp, KmsProvider::Azure] {
            for legacy in [false, true] {
                let calls = Arc::new(AtomicUsize::new(0));
                let signer = KmsSignerGetter::new(
                    HashMap::from([("bsc".into(), ChainType::Evm)]),
                    vec![pillar_signer::WalletDefinition {
                        name: "wallet".into(),
                        by_chain_type: HashMap::from([(
                            ChainType::Evm,
                            ChainTypeWalletDefinition {
                                secret_name: "test-key".into(),
                                signer_kind: Some(WalletSignerKind::Kms { provider }),
                            },
                        )]),
                    }],
                    Arc::new(NeverInvokedFactory(calls.clone())),
                    KmsCredentialFlags {
                        gcp_credentials_set: provider == KmsProvider::Gcp,
                        azure_credentials_set: provider == KmsProvider::Azure,
                    },
                )
                .unwrap();
                let event = packet("ethereum", false);
                let (status, body) = post_sign(
                    http_app(gate.clone(), event.clone(), Arc::new(signer)),
                    &event,
                    legacy,
                    false,
                )
                .await;
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(body["statusCode"], 500);
                assert!(body.get("body").is_some());
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            }
        }
        assert_eq!(
            state.subjects.lock().unwrap().len(),
            6,
            "both HTTP routes must reach Gate, not fail earlier"
        );
    }
}

#[tokio::test]
async fn dvn_read_and_non_evm_traffic_use_physical_chain_scope_without_asset_codec() {
    for (source, read, eid) in [("solana", false, 30168), ("ethereum", true, 30101)] {
        let (gate, state, _server) = gate(Reply::Deny).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let event = packet(source, read);
        let (status, _) = post_sign(
            http_app(gate, event.clone(), Arc::new(CountSigner(calls.clone()))),
            &event,
            false,
            read,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let subjects = state.subjects.lock().unwrap();
        assert_eq!(subjects.len(), 1);
        assert_eq!(subjects[0].src_eid, eid);
        assert_eq!(
            subjects[0].src_endpoint_id,
            if read { u32::MAX } else { eid }
        );
        assert_eq!(
            subjects[0].dst_endpoint_id,
            if read { 30101 } else { 30102 }
        );
        assert_eq!(subjects[0].protocol, "layerzero-v2");
        assert_eq!(
            subjects[0].request_kind,
            if read {
                pillar_core::dvn::RequestKind::Read
            } else {
                pillar_core::dvn::RequestKind::Message
            }
        );
        assert_eq!(subjects[0].asset_binding_id, None);
        assert_eq!(subjects[0].token_sender, None);
    }
}

#[tokio::test]
async fn dvn_retries_are_reauthorized_instead_of_replaying_a_cached_allow() {
    let (gate, state, _server) = gate(Reply::Allow).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let event = packet("ethereum", false);
    for _ in 0..2 {
        let (status, body) = post_sign(
            http_app(
                gate.clone(),
                event.clone(),
                Arc::new(CountSigner(calls.clone())),
            ),
            &event,
            false,
            false,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["statusCode"], 200);
    }
    *state.reply.lock().unwrap() = Reply::Deny;
    let (status, _) = post_sign(
        http_app(gate, event.clone(), Arc::new(CountSigner(calls.clone()))),
        &event,
        false,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.subjects.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn dvn_local_signer_obeys_the_same_mandatory_gate_as_kms() {
    for reply in [Reply::Deny, Reply::Allow] {
        let (gate, state, _server) = gate(reply).await;
        let signer = LocalMnemonicSignerGetter::new(
            HashMap::from([("bsc".into(), ChainType::Evm)]),
            vec![pillar_signer::WalletDefinition {
                name: "wallet".into(),
                by_chain_type: HashMap::from([(
                    ChainType::Evm,
                    ChainTypeWalletDefinition {
                        secret_name: "test-mnemonic-reference".into(),
                        signer_kind: Some(WalletSignerKind::Mnemonic),
                    },
                )]),
            }],
            HashMap::from([(
                "wallet-EVM".into(),
                SignerLocalMnemonic {
                    mnemonic: zeroize::Zeroizing::new(
                        "test test test test test test test test test test test junk".into(),
                    ),
                    path: "m/44'/60'/0'/0/0".into(),
                },
            )]),
        )
        .unwrap();
        // Runtime startup likewise resolves public identity before serving; this is not signing.
        signer.get_signer_info("bsc", "wallet").await.unwrap();
        let event = packet("ethereum", false);
        let (status, body) = post_sign(
            http_app(gate, event.clone(), Arc::new(signer)),
            &event,
            false,
            false,
        )
        .await;
        assert_eq!(state.subjects.lock().unwrap().len(), 1);
        if matches!(reply, Reply::Deny) {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(body["body"].get("signatures").is_none());
        } else {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                body["body"]["signatures"][0]["address"],
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            );
        }
    }
}

#[test]
fn dvn_intent_scope_resolves_actual_wallet_backend_not_available_credentials() {
    let calls = Arc::new(AtomicUsize::new(0));
    let signer = KmsSignerGetter::new(
        HashMap::from([("bsc".into(), ChainType::Evm)]),
        vec![pillar_signer::WalletDefinition {
            name: "wallet".into(),
            by_chain_type: HashMap::from([(
                ChainType::Evm,
                ChainTypeWalletDefinition {
                    secret_name: "immutable-key-reference".into(),
                    signer_kind: Some(WalletSignerKind::Kms {
                        provider: KmsProvider::Aws,
                    }),
                },
            )]),
        }],
        Arc::new(NeverInvokedFactory(calls.clone())),
        KmsCredentialFlags {
            gcp_credentials_set: true,
            azure_credentials_set: true,
        },
    )
    .unwrap();
    assert_eq!(
        signer.backend_scope("bsc", "wallet").unwrap(),
        "kms_aws:immutable-key-reference"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dvn_source_generations_keep_independent_nonce_spaces_across_http_versions() {
    let (gate, state, _server) = gate(Reply::Deny).await;
    let calls = Arc::new(AtomicUsize::new(0));
    for legacy_http in [false, true] {
        for version in ["V2", "V301", "V302"] {
            let mut event = packet("ethereum", false);
            event.lz_message_id.uln_send_version = json!(version);
            if version != "V302" {
                event
                    .lz_message_id
                    .pathway_id
                    .extra
                    .insert("srcEid".into(), json!(101));
                event
                    .lz_message_id
                    .pathway_id
                    .extra
                    .insert("dstEid".into(), json!(102));
            }
            if version == "V2" {
                event.extra.shift_remove("guid");
            }
            let (status, _) = post_sign(
                http_app(
                    gate.clone(),
                    event.clone(),
                    Arc::new(CountSigner(calls.clone())),
                ),
                &event,
                legacy_http,
                false,
            )
            .await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let subjects = state.subjects.lock().unwrap();
    assert_eq!(
        subjects.len(),
        6,
        "all source generations must reach the Gate"
    );
    let physical_pathway_and_nonce = |subject: &pillar_core::dvn::Subject| {
        (
            subject.environment,
            subject.request_kind,
            subject.src_eid,
            subject.dst_eid,
            subject.src_oapp.clone(),
            subject.dst_oapp.clone(),
            subject.nonce.clone(),
        )
    };
    for (subject, (protocol, src_endpoint_id, dst_endpoint_id)) in subjects.iter().zip([
        ("layerzero-v1", 101, 102),
        ("layerzero-v1", 101, 102),
        ("layerzero-v2", 30101, 30102),
        ("layerzero-v1", 101, 102),
        ("layerzero-v1", 101, 102),
        ("layerzero-v2", 30101, 30102),
    ]) {
        assert_eq!(subject.protocol, protocol);
        assert_eq!(subject.src_endpoint_id, src_endpoint_id);
        assert_eq!(subject.dst_endpoint_id, dst_endpoint_id);
        assert_eq!(
            physical_pathway_and_nonce(subject),
            physical_pathway_and_nonce(&subjects[0])
        );
    }
}

#[tokio::test]
async fn dvn_read_channels_keep_independent_native_endpoint_nonce_spaces() {
    let (gate, state, _server) = gate(Reply::Deny).await;
    let calls = Arc::new(AtomicUsize::new(0));
    for (channel, message) in [(u32::MAX, "0x010203"), (u32::MAX - 1, "0x040506")] {
        let mut event = packet("ethereum", true);
        event.lz_message_id.nonce = 1;
        event
            .lz_message_id
            .pathway_id
            .extra
            .insert("srcEid".into(), json!(channel));
        event.message = message.into();
        let (status, _) = post_sign(
            http_app(
                gate.clone(),
                event.clone(),
                Arc::new(CountSigner(calls.clone())),
            ),
            &event,
            false,
            true,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let subjects = state.subjects.lock().unwrap();
    assert_eq!(
        subjects.len(),
        2,
        "both native READ channels must reach the Gate"
    );
    for subject in subjects.iter() {
        assert_eq!(subject.protocol, "layerzero-v2");
        assert_eq!(subject.request_kind, pillar_core::dvn::RequestKind::Read);
        assert_eq!((subject.src_eid, subject.dst_eid), (30101, 30101));
        assert_eq!(subject.dst_endpoint_id, 30101);
        assert_eq!(subject.nonce, "1");
    }
    assert_eq!(subjects[0].src_endpoint_id, u32::MAX);
    assert_eq!(subjects[1].src_endpoint_id, u32::MAX - 1);
    assert_eq!(subjects[0].src_oapp, subjects[1].src_oapp);
    assert_eq!(subjects[0].dst_oapp, subjects[1].dst_oapp);
    assert_ne!(subjects[0].payload_hash, subjects[1].payload_hash);
}

#[tokio::test]
async fn dvn_uln_v2_receiver_migration_preserves_source_identity_and_payload_hash() {
    use sha3::{Digest, Keccak256};

    let (gate, state, _server) = gate(Reply::Deny).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut source = packet("ethereum", false);
    source.lz_message_id.uln_send_version = json!("V2");
    source
        .lz_message_id
        .pathway_id
        .extra
        .insert("srcEid".into(), json!(101));
    source
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".into(), json!(102));
    source.extra.shift_remove("guid");
    // This is the exact hydration used by both V301 and V302 receiver migrations.
    let hydrated = pillar_core::hydrate_uln_v2_sent_event(&source, None).unwrap();
    assert!(hydrated.extra.contains_key("guid"));
    let mut native_v301 = source.clone();
    native_v301.lz_message_id.uln_send_version = json!("V301");
    native_v301
        .extra
        .insert("guid".into(), json!(format!("0x{}", "33".repeat(32))));
    for event in [&source, &hydrated, &native_v301] {
        let (status, _) = post_sign(
            http_app(
                gate.clone(),
                event.clone(),
                Arc::new(CountSigner(calls.clone())),
            ),
            event,
            false,
            false,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let subjects = state.subjects.lock().unwrap();
    assert_eq!(
        subjects.len(),
        3,
        "original, hydrated and native V301 packets must reach the Gate"
    );
    for subject in &subjects[..2] {
        assert_eq!(subject.protocol, "layerzero-v1");
        assert_eq!((subject.src_eid, subject.dst_eid), (30101, 30102));
        assert_eq!(
            (subject.src_endpoint_id, subject.dst_endpoint_id),
            (101, 102)
        );
        assert_eq!(subject.guid, None);
        assert_eq!(
            subject.payload_hash,
            hex::encode(Keccak256::digest([1, 2, 3]))
        );
    }
    assert_ne!(
        subjects[0].source_evidence_digest,
        subjects[1].source_evidence_digest
    );
    let mut before = subjects[0].clone();
    before
        .source_evidence_digest
        .clone_from(&subjects[1].source_evidence_digest);
    assert_eq!(
        before, subjects[1],
        "only attempt evidence may change after receiver hydration"
    );
    assert_eq!(subjects[2].protocol, "layerzero-v1");
    assert_eq!(subjects[2].guid.as_deref(), Some("33".repeat(32).as_str()));
    let mut native_payload = vec![0x33_u8; 32];
    native_payload.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        subjects[2].payload_hash,
        hex::encode(Keccak256::digest(&native_payload))
    );
    assert_ne!(subjects[0].payload_hash, subjects[2].payload_hash);
}
