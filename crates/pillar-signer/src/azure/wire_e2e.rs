use super::*;
use crate::types::{RawSignerAdapter, SeedKind, SignRequest, SignatureType};
use async_trait::async_trait;
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    http::{
        AsyncRawResponse, ClientOptions, HttpClient, Request, RetryOptions, StatusCode, Transport,
    },
};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions};
use pillar_core::audit::{
    self, AttemptIntent, AuditWorkers, EvidenceKind, SigningAuditStore, ValidatedIntent,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

const VERSION: &str = "0123456789abcdef0123456789abcdef";
#[derive(Debug)]
struct Token;
#[async_trait]
impl TokenCredential for Token {
    async fn get_token(
        &self,
        _: &[&str],
        _: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            "synthetic-token",
            azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1),
        ))
    }
}
#[derive(Debug)]
struct Wire {
    kid: String,
    sign_kid: Option<String>,
    status: StatusCode,
    high_s: bool,
    requests: Mutex<Vec<(String, Value)>>,
    key: k256::ecdsa::SigningKey,
}
#[async_trait]
impl HttpClient for Wire {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        let body: Value = match request.body() {
            azure_core::http::Body::Bytes(bytes) if !bytes.is_empty() => {
                serde_json::from_slice(bytes).unwrap()
            }
            _ => Value::Null,
        };
        self.requests
            .lock()
            .unwrap()
            .push((request.url().to_string(), body.clone()));
        if request
            .headers()
            .get_optional_str(&azure_core::http::headers::AUTHORIZATION)
            .is_none()
        {
            let resource = if request
                .url()
                .host_str()
                .unwrap()
                .ends_with("managedhsm.azure.net")
            {
                "https://managedhsm.azure.net"
            } else {
                "https://vault.azure.net"
            };
            let mut headers = azure_core::http::headers::Headers::new();
            headers.insert(azure_core::http::headers::WWW_AUTHENTICATE, format!("Bearer authorization=\"https://login.microsoftonline.com/synthetic\", resource=\"{resource}\""));
            return Ok(AsyncRawResponse::from_bytes(
                StatusCode::Unauthorized,
                headers,
                "",
            ));
        }
        let response = if request.url().path().ends_with("/sign") {
            if self.status != StatusCode::Ok {
                json!({"error":{"code":"Throttled","message":"synthetic HTTP error"}})
            } else {
                assert_eq!(body["alg"], "ES256K");
                let digest =
                    azure_core::base64::decode_url_safe(body["value"].as_str().unwrap()).unwrap();
                assert_eq!(digest, [0x66; 32]);
                let (signature, _) = self.key.sign_prehash_recoverable(&digest).unwrap();
                let signature = if self.high_s {
                    k256::ecdsa::Signature::from_scalars(
                        signature.r().to_bytes(),
                        (-signature.s()).to_bytes(),
                    )
                    .unwrap()
                } else {
                    signature
                };
                let mut value =
                    json!({"value":azure_core::base64::encode_url_safe(signature.to_bytes())});
                if let Some(kid) = &self.sign_kid {
                    value["kid"] = json!(kid);
                }
                value
            }
        } else {
            let point = self.key.verifying_key().to_encoded_point(false);
            json!({"key":{"kid":self.kid,"kty":"EC","crv":"P-256K","x":azure_core::base64::encode_url_safe(point.x().unwrap()),"y":azure_core::base64::encode_url_safe(point.y().unwrap())}})
        };
        Ok(AsyncRawResponse::from_bytes(
            if request.url().path().ends_with("/sign") {
                self.status
            } else {
                StatusCode::Ok
            },
            Default::default(),
            response.to_string(),
        ))
    }
}
fn client(
    host: &str,
    kid: String,
    sign_kid: Option<String>,
    status: StatusCode,
    high_s: bool,
) -> (Arc<AzureKeyVaultKmsClient>, Arc<Wire>) {
    let wire = Arc::new(Wire {
        kid,
        sign_kid,
        status,
        high_s,
        requests: Mutex::new(Vec::new()),
        key: k256::ecdsa::SigningKey::from_slice(&[16; 32]).unwrap(),
    });
    let sdk = KeyClient::new(
        &format!("https://{host}"),
        Arc::new(Token),
        Some(KeyClientOptions {
            client_options: ClientOptions {
                retry: RetryOptions::none(),
                transport: Some(Transport::new(wire.clone())),
                ..Default::default()
            },
            ..Default::default()
        }),
    )
    .unwrap();
    (Arc::new(AzureKeyVaultKmsClient::new(sdk)), wire)
}
fn request() -> SignRequest {
    SignRequest {
        data: vec![0x66; 32],
        signature_type: SignatureType::Ecdsa,
        private_key_signature_type: SignatureType::Ecdsa,
        transform_recovery_id: true,
        seed_kind: SeedKind::Bip39,
    }
}
fn artifact(name: &str, value: Value) {
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
    std::fs::write(directory.join(format!("{name}.json")), value.to_string()).unwrap();
    println!("{value}");
}
#[tokio::test]
async fn azure_wire_real_format_versions_case_retry_and_high_s() {
    let mut rows = Vec::new();
    for host in [
        "synthetic.vault.azure.net",
        "synthetic.managedhsm.azure.net",
    ] {
        let kid = format!("https://{host}/keys/key-a/{VERSION}");
        let (client, wire) = client(host, kid.clone(), Some(kid.clone()), StatusCode::Ok, true);
        let adapter = AzureKmsRawSignerAdapter::new("key-a".into(), client).unwrap();
        let signature = adapter.sign(request()).await.unwrap();
        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(
            &[0x66; 32],
            &k256::ecdsa::Signature::from_slice(&signature[..64]).unwrap(),
            k256::ecdsa::RecoveryId::from_byte(signature[64] - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(recovered, *wire.key.verifying_key());
        assert!(k256::ecdsa::Signature::from_slice(&signature[..64])
            .unwrap()
            .normalize_s()
            .is_none());
        let paths = wire.requests.lock().unwrap().clone();
        assert_eq!(paths.len(), 3);
        assert!(paths[2].0.contains(&format!("/keys/key-a/{VERSION}/sign?")));
        rows.push(json!({"host":host,"resolved_version":VERSION,"http_calls":paths.len(),"high_s_recovered":true}));
        let (client, _) = client_for_case(host, "Key-A", Some(VERSION));
        let error = client
            .get_ec_public_key_coordinates(&AzureKmsKeyId {
                name: "key-a".into(),
                version: None,
            })
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("public key identity changed"));
        rows.push(json!({"host":host,"case_mismatch_error":error.to_string()}));
        let other = format!("https://{host}/keys/key-a/{}", "f".repeat(32));
        let (client, _) = client_for_sign(host, Some(other), StatusCode::Ok);
        let error = client
            .sign_es256k_digest(
                &AzureKmsKeyId {
                    name: "key-a".into(),
                    version: Some(VERSION.into()),
                },
                &[0x66; 32],
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("signing key identity changed"));
        rows.push(json!({"version_mismatch_error":error.to_string()}));
    }
    for status in [StatusCode::TooManyRequests, StatusCode::InternalServerError] {
        let (client, wire) = client_for_sign("synthetic.vault.azure.net", None, status);
        assert!(client
            .sign_es256k_digest(
                &AzureKmsKeyId {
                    name: "key-a".into(),
                    version: Some(VERSION.into())
                },
                &[0x66; 32]
            )
            .await
            .is_err());
        assert_eq!(wire.requests.lock().unwrap().len(), 2);
        rows.push(json!({"http_status":u16::from(status),"sdk_http_calls":wire.requests.lock().unwrap().len()}));
    }
    artifact(
        "R3-azure-wire",
        json!({"transport":"in-process HTTP adapter, real Azure SDK pipeline and JSON models; no cloud", "cases":rows}),
    );
}
fn client_for_case(
    host: &str,
    name: &str,
    version: Option<&str>,
) -> (Arc<AzureKeyVaultKmsClient>, Arc<Wire>) {
    client(
        host,
        format!("https://{host}/keys/{name}/{}", version.unwrap_or("")),
        None,
        StatusCode::Ok,
        false,
    )
}
fn client_for_sign(
    host: &str,
    kid: Option<String>,
    status: StatusCode,
) -> (Arc<AzureKeyVaultKmsClient>, Arc<Wire>) {
    client(
        host,
        format!("https://{host}/keys/key-a/{VERSION}"),
        kid,
        status,
        false,
    )
}
struct Store {
    begun: AtomicUsize,
    kinds: Mutex<Vec<EvidenceKind>>,
}
#[async_trait]
impl SigningAuditStore for Store {
    async fn begin(&self, _: &AttemptIntent) -> Result<i64, String> {
        Ok((self.begun.fetch_add(1, Ordering::SeqCst) + 1) as i64)
    }
    async fn record(&self, _: i64, kind: EvidenceKind, _: Option<&str>) -> Result<(), String> {
        self.kinds.lock().unwrap().push(kind);
        Ok(())
    }
    async fn healthy(&self) -> bool {
        true
    }
}
#[tokio::test]
async fn azure_wire_missing_kid_rejected_inside_owned_audit_worker() {
    let (client, wire) = client_for_sign("synthetic.vault.azure.net", None, StatusCode::Ok);
    let adapter = AzureKmsRawSignerAdapter::new("key-a".into(), client).unwrap();
    let store = Arc::new(Store {
        begun: AtomicUsize::new(0),
        kinds: Mutex::new(Vec::new()),
    });
    let workers = Arc::new(AuditWorkers::new(1));
    let intent = ValidatedIntent {
        request_hash: "request".into(),
        validation_hash: "validation".into(),
        source_chain: "ethereum".into(),
        destination_chain: "ethereum".into(),
        expiration: 1,
        provider_generation: 7,
    };
    let result = audit::scope_root(
        Some(store.clone()),
        Some(workers),
        7,
        audit::scope_intent(
            intent,
            audit::sign_wallet("wallet", async {
                let signature = adapter
                    .sign(request())
                    .await
                    .map_err(|error| pillar_core::AppCoreError::Internal(error.to_string()))?;
                Ok(pillar_core::Signature {
                    signature: hex::encode(signature),
                    address: "synthetic".into(),
                })
            }),
        ),
    )
    .await;
    let error = result.unwrap_err();
    assert!(error
        .to_string()
        .contains("Azure signing key identity missing"));
    assert_eq!(store.begun.load(Ordering::SeqCst), 1);
    assert!(!store
        .kinds
        .lock()
        .unwrap()
        .contains(&EvidenceKind::ExternalReturned));
    artifact(
        "R6-owned-worker-identity",
        json!({"error":error.to_string(),"attempts":store.begun.load(Ordering::SeqCst),"sdk_http_calls":wire.requests.lock().unwrap().len()}),
    );
}

#[tokio::test]
async fn audit_worker_capacity_refused_before_arming_an_attempt() {
    let (client, _) = client_for_sign(
        "synthetic.vault.azure.net",
        Some(format!(
            "https://synthetic.vault.azure.net/keys/key-a/{VERSION}"
        )),
        StatusCode::Ok,
    );
    let adapter = AzureKmsRawSignerAdapter::new("key-a".into(), client).unwrap();
    let store = Arc::new(Store {
        begun: AtomicUsize::new(0),
        kinds: Mutex::new(Vec::new()),
    });
    let workers = Arc::new(AuditWorkers::new(1));
    let reservation = workers.reserve().unwrap();
    workers.spawn(reservation, std::future::pending());
    let intent = ValidatedIntent {
        request_hash: "request".into(),
        validation_hash: "validation".into(),
        source_chain: "ethereum".into(),
        destination_chain: "ethereum".into(),
        expiration: 1,
        provider_generation: 7,
    };
    let result = audit::scope_root(
        Some(store.clone()),
        Some(workers),
        7,
        audit::scope_intent(
            intent,
            audit::sign_wallet("wallet", async {
                let signature = adapter
                    .sign(request())
                    .await
                    .map_err(|error| pillar_core::AppCoreError::Internal(error.to_string()))?;
                Ok(pillar_core::Signature {
                    signature: hex::encode(signature),
                    address: "synthetic".into(),
                })
            }),
        ),
    )
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("resource_overloaded"));
    assert_eq!(store.begun.load(Ordering::SeqCst), 0);
    artifact(
        "R7-worker-reservation",
        json!({"armed_attempts":store.begun.load(Ordering::SeqCst),"capacity_rejected":true}),
    );
}

#[tokio::test]
async fn gcp_empty_response_identity_refused_in_owned_audit_context() {
    assert!(crate::gcp::response_identity_matches("", "version"));
    let store = Arc::new(Store {
        begun: AtomicUsize::new(0),
        kinds: Mutex::new(Vec::new()),
    });
    let workers = Arc::new(AuditWorkers::new(1));
    let (send, receive) = tokio::sync::oneshot::channel();
    audit::scope_root(Some(store), Some(workers.clone()), 9, async {
        let reservation = workers.reserve().unwrap();
        workers.spawn(reservation, audit::scope_external_effect(audit::provider_generation(), async move {
            send.send((audit::enabled(), audit::provider_generation(), crate::gcp::response_identity_matches("", "version"), crate::gcp::response_identity_matches("changed", "version"), crate::gcp::response_identity_matches("version", "version"))).unwrap();
        }));
        let observed = receive.await.unwrap();
        assert_eq!(observed, (true, 9, false, false, true));
        artifact("R6-gcp-identity-context", json!({"audit_enabled_in_worker": observed.0, "provider_generation": observed.1, "empty_identity_allowed": observed.2, "changed_identity_allowed": observed.3, "matched_identity_allowed": observed.4, "scope": "pure GCP identity guard, no GCP HTTP or credentials"}));
    }).await;
}

#[tokio::test]
async fn completion_reservation_obeys_kms_queue_before_writeahead() {
    use pillar_core::execution::{
        BudgetLimits, ExecutionResources, FairBudget, Outcome, RequestContext,
    };
    let limits = BudgetLimits {
        active: 1,
        per_lane: 1,
        waiting: 1,
        per_lane_waiting: 1,
        wait: std::time::Duration::from_secs(2),
    };
    let budget = || FairBudget::new(vec!["ethereum".into()], limits).unwrap();
    let resources = Arc::new(ExecutionResources {
        signing: budget(),
        rpc: budget(),
        kms: budget(),
    });
    let mut holder = resources
        .kms
        .acquire_for("ethereum", Some("key"))
        .await
        .unwrap();
    holder.finish(Outcome::Success);
    let store = Arc::new(Store {
        begun: AtomicUsize::new(0),
        kinds: Mutex::new(Vec::new()),
    });
    let workers = Arc::new(AuditWorkers::new(1));
    workers.spawn(workers.reserve().unwrap(), std::future::pending());
    let mut context = RequestContext::new(std::time::Duration::from_secs(2));
    context.source_chain = Some(Arc::from("ethereum"));
    context.resources = Some(resources.clone());
    let task_store = store.clone();
    let task = tokio::spawn(context.scope(audit::scope_root(
        Some(task_store),
        Some(workers),
        7,
        async {
            crate::effects::sign_owned_effect(
                "key",
                Some(pillar_core::audit::EffectiveKey {
                    backend: "AZURE",
                    reference: "key".into(),
                    version: "7".into(),
                    public_key_hash: "public".into(),
                }),
                &[3; 32],
                "ECDSA",
                async { panic!("SDK must not start") },
            )
            .await
        },
    )));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while resources.kms.totals().waiting != 1 {
            assert!(!task.is_finished(), "worker reservation bypassed KMS queue");
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(resources.kms.totals().active, 1);
    assert_eq!(store.begun.load(Ordering::SeqCst), 0);
    let overflow = resources.kms.acquire_for("ethereum", Some("key")).await;
    assert!(matches!(
        overflow,
        Err(pillar_core::execution::BudgetError::Overloaded)
    ));
    drop(holder);
    assert!(matches!(
        task.await.unwrap(),
        Err(crate::SignerError::Admission(
            pillar_core::execution::BudgetError::Overloaded
        ))
    ));
    let totals = resources.kms.totals();
    assert_eq!((totals.active, totals.waiting, totals.started), (0, 0, 3));
    assert_eq!(totals.outcomes[Outcome::Overloaded as usize], 2);
    assert_eq!(totals.outcomes[Outcome::Error as usize], 0);
    assert_eq!(store.begun.load(Ordering::SeqCst), 0);
    artifact(
        "N2-reservation-order",
        json!({"kms_started":totals.started,"overloaded":totals.outcomes[Outcome::Overloaded as usize],"active":totals.active,"waiting":totals.waiting,"armed_attempts":store.begun.load(Ordering::SeqCst)}),
    );
}
