use super::*;
use ed25519_dalek::{Signer, SigningKey};

fn signed<T: Serialize>(payload: &T, domain: &str) -> SignedEnvelope {
    let payload = serde_json::to_vec(payload).unwrap();
    let mut message = domain.as_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(&payload);
    SignedEnvelope {
        sha256: sha256_hex(&payload),
        payload: STANDARD.encode(payload),
        signature: STANDARD.encode(SigningKey::from_bytes(&[7; 32]).sign(&message).to_bytes()),
        key_id: "test-dvn".into(),
    }
}

fn verifier() -> EnvelopeVerifier {
    EnvelopeVerifier::new(
        "test-dvn".into(),
        &STANDARD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes()),
    )
    .unwrap()
}

fn request(hash: &str, scopes: &[SigningScope]) -> AuthorizeRequest {
    AuthorizeRequest {
        instance_id: "instance".into(),
        boot_id: "boot".into(),
        registry_revision: 3,
        intent_digest: intent_digest(hash, scopes).unwrap(),
        wallet_names: vec!["wallet".into()],
        subject: Subject {
            environment: Environment::Testnet,
            protocol: "layerzero-v2".into(),
            request_kind: RequestKind::Message,
            src_eid: 40101,
            dst_eid: 40102,
            src_endpoint_id: 40101,
            dst_endpoint_id: 40102,
            src_oapp: format!("0x{}", "11".repeat(32)),
            dst_oapp: format!("0x{}", "22".repeat(32)),
            nonce: u64::MAX.to_string(),
            payload_hash: "33".repeat(32),
            guid: None,
            source_evidence_digest: "44".repeat(32),
            asset_binding_id: None,
            token_sender: None,
            token_recipient: None,
            amount_shared_units: None,
        },
    }
}

fn permit(request: &AuthorizeRequest, raw: &[u8], now: u64) -> Permit {
    Permit {
        schema_version: PERMIT_SCHEMA.into(),
        decision_id: "decision".into(),
        environment: request.subject.environment,
        workload_id: "workload".into(),
        instance_id: request.instance_id.clone(),
        boot_id: request.boot_id.clone(),
        request_sha256: sha256_hex(raw),
        intent_digest: request.intent_digest.clone(),
        policy_revision: 5,
        safety_epoch: 8,
        issued_at_ms: now,
        expires_at_ms: now + 2_000,
    }
}
fn scopes() -> Vec<SigningScope> {
    vec![SigningScope {
        chain_name: "solana".into(),
        wallet_name: "wallet".into(),
        backend: "kms_azure".into(),
    }]
}

#[test]
fn rejects_invalid_signature_wrong_domain_and_unknown_fields() {
    let registry = RegistrySnapshot {
        schema_version: REGISTRY_SCHEMA.into(),
        environment: Environment::Testnet,
        revision: 1,
        chains: vec![],
        asset_bindings: vec![],
    };
    let mut envelope = signed(&registry, REGISTRY_SCHEMA);
    assert!(verifier()
        .verify::<RegistrySnapshot>(&envelope, REGISTRY_SCHEMA)
        .is_ok());
    assert!(verifier()
        .verify::<RegistrySnapshot>(&envelope, PERMIT_SCHEMA)
        .is_err());
    envelope.signature = STANDARD.encode([0; 64]);
    assert!(verifier()
        .verify::<RegistrySnapshot>(&envelope, REGISTRY_SCHEMA)
        .is_err());
    let mut json = serde_json::to_value(registry).unwrap();
    json["trusted"] = true.into();
    assert!(verifier()
        .verify::<RegistrySnapshot>(&signed(&json, REGISTRY_SCHEMA), REGISTRY_SCHEMA)
        .is_err());
}

#[test]
fn rejects_every_permit_identity_lifetime_and_revision_mismatch() {
    let hash = "11".repeat(32);
    let request = request(&hash, &scopes());
    let raw = serde_json::to_vec(&request).unwrap();
    let expected = PermitExpectation {
        request: &request,
        raw_request: &raw,
        workload_id: "workload",
        minimum_policy_revision: 5,
        minimum_safety_epoch: 8,
    };
    let now = 1_000_000;
    let valid = permit(&request, &raw, now);
    assert!(verifier()
        .authorize(
            &signed(&valid, PERMIT_SCHEMA),
            &expected,
            &hash,
            scopes(),
            now
        )
        .is_ok());
    for field in [
        "schema", "env", "workload", "instance", "boot", "request", "intent", "revision", "epoch",
        "expired", "future", "ttl", "reverse",
    ] {
        let mut invalid = valid.clone();
        match field {
            "schema" => invalid.schema_version = REGISTRY_SCHEMA.into(),
            "env" => invalid.environment = Environment::Mainnet,
            "workload" => invalid.workload_id.push('x'),
            "instance" => invalid.instance_id.push('x'),
            "boot" => invalid.boot_id.push('x'),
            "request" => invalid.request_sha256 = "00".repeat(32),
            "intent" => invalid.intent_digest = "00".repeat(32),
            "revision" => invalid.policy_revision = 4,
            "epoch" => invalid.safety_epoch = 7,
            "expired" => {
                invalid.issued_at_ms = now - 2_000;
                invalid.expires_at_ms = now;
            }
            "future" => {
                invalid.issued_at_ms = now + 251;
                invalid.expires_at_ms = now + 2_000;
            }
            "ttl" => invalid.expires_at_ms = now + 2_001,
            "reverse" => invalid.expires_at_ms = now - 1,
            _ => unreachable!(),
        }
        assert!(
            verifier()
                .authorize(
                    &signed(&invalid, PERMIT_SCHEMA),
                    &expected,
                    &hash,
                    scopes(),
                    now
                )
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn binds_exact_request_bytes_registry_revision_hash_and_backend_scope() {
    let hash = "11".repeat(32);
    let request = request(&hash, &scopes());
    let raw = serde_json::to_vec(&request).unwrap();
    let now = now_ms().unwrap();
    let envelope = signed(&permit(&request, &raw, now), PERMIT_SCHEMA);
    let expected = PermitExpectation {
        request: &request,
        raw_request: &raw,
        workload_id: "workload",
        minimum_policy_revision: 0,
        minimum_safety_epoch: 0,
    };
    let (authorization, _) = verifier()
        .authorize(&envelope, &expected, &hash, scopes(), now)
        .unwrap();
    assert!(authorization
        .check("solana", "wallet", "kms_azure", &hash)
        .is_ok());
    for (chain, wallet, backend, data) in [
        ("solana", "wallet", "local", hash.as_str()),
        ("aptos", "wallet", "kms_azure", hash.as_str()),
        ("solana", "other", "kms_azure", hash.as_str()),
        ("solana", "wallet", "kms_azure", "bad"),
    ] {
        assert!(authorization.check(chain, wallet, backend, data).is_err());
    }
    let pretty = serde_json::to_vec_pretty(&request).unwrap();
    let changed = PermitExpectation {
        raw_request: &pretty,
        ..expected
    };
    assert!(verifier()
        .authorize(&envelope, &changed, &hash, scopes(), now)
        .is_err());
    let mut changed_request = request;
    changed_request.registry_revision += 1;
    let changed_raw = serde_json::to_vec(&changed_request).unwrap();
    let changed = PermitExpectation {
        request: &changed_request,
        raw_request: &changed_raw,
        workload_id: "workload",
        minimum_policy_revision: 0,
        minimum_safety_epoch: 0,
    };
    assert!(verifier()
        .authorize(&envelope, &changed, &hash, scopes(), now)
        .is_err());
}

#[test]
fn preserves_decimal_nonce_and_rejects_ambiguous_authorize_response() {
    let request = request(&"11".repeat(32), &scopes());
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["subject"]["nonce"], u64::MAX.to_string());
    assert!(crate::json::from_str::<AuthorizeResponse>(
        r#"{"decision":"deny","reason":"paused","permit":{}}"#
    )
    .is_err());
}

#[test]
fn requires_native_endpoint_ids_and_rejects_out_of_range_wire_values() {
    let request = request(&"11".repeat(32), &scopes());
    let json = serde_json::to_value(&request).unwrap();
    assert_eq!(json["subject"]["srcEndpointId"], 40101);
    assert_eq!(json["subject"]["dstEndpointId"], 40102);
    for field in ["srcEndpointId", "dstEndpointId"] {
        let mut missing = json.clone();
        missing["subject"].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<AuthorizeRequest>(missing).is_err());
        for invalid in [
            serde_json::json!(-1),
            serde_json::json!(4_294_967_296_u64),
            serde_json::json!("40101"),
        ] {
            let mut invalid_request = json.clone();
            invalid_request["subject"][field] = invalid;
            assert!(serde_json::from_value::<AuthorizeRequest>(invalid_request).is_err());
        }
    }
}

#[test]
fn accepts_control_repository_shared_wire_fixture_without_reserializing_request() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/dvn-wire-v1.json")).unwrap();
    assert_eq!(fixture["fixtureVersion"], "pillar.dvn-wire-fixture/v1");
    assert_eq!(fixture["testOnly"], true);
    let verifier = EnvelopeVerifier::new(
        "dvn-fixture-key".into(),
        fixture["publicKeyBase64"].as_str().unwrap(),
    )
    .unwrap();
    let signed_registry: SignedEnvelope =
        serde_json::from_value(fixture["signedRegistry"].clone()).unwrap();
    let registry: RegistrySnapshot = verifier.verify(&signed_registry, REGISTRY_SCHEMA).unwrap();
    assert_eq!(serde_json::to_value(registry).unwrap(), fixture["registry"]);
    let signed_permit: SignedEnvelope =
        serde_json::from_value(fixture["signedPermit"].clone()).unwrap();
    let permit: Permit = verifier.verify(&signed_permit, PERMIT_SCHEMA).unwrap();
    assert_eq!(serde_json::to_value(&permit).unwrap(), fixture["permit"]);
    let raw = fixture["authorizeRequestJson"].as_str().unwrap();
    let request: AuthorizeRequest = crate::json::from_str(raw).unwrap();
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        fixture["authorizeRequest"]
    );
    assert_eq!(permit.request_sha256, sha256_hex(raw.as_bytes()));
    assert_eq!(request.subject.protocol, "layerzero-v2");
    assert_eq!(request.subject.nonce, u64::MAX.to_string());
    assert_eq!(request.subject.amount_shared_units.as_deref(), Some("17"));
}

#[tokio::test]
async fn rejects_permit_superseded_while_waiting_for_backend_admission() {
    let hash = "11".repeat(32);
    let request = request(&hash, &scopes());
    let raw = serde_json::to_vec(&request).unwrap();
    let now = now_ms().unwrap();
    let expected = PermitExpectation {
        request: &request,
        raw_request: &raw,
        workload_id: "workload",
        minimum_policy_revision: 0,
        minimum_safety_epoch: 0,
    };
    let (authorization, _) = verifier()
        .authorize(
            &signed(&permit(&request, &raw, now), PERMIT_SCHEMA),
            &expected,
            &hash,
            scopes(),
            now,
        )
        .unwrap();
    let fence = Arc::new(RevisionFence {
        policy_revision: AtomicU64::new(5),
        safety_epoch: AtomicU64::new(8),
        registry_revision: AtomicU64::new(3),
    });
    let authorization = authorization.with_revision_fence(fence.clone(), 5, 8, 3);
    assert!(authorization
        .check("solana", "wallet", "kms_azure", &hash)
        .is_ok());
    authorization
        .scope_effect(async {
            let lease = current_signing_lease().unwrap();
            assert!(lease.check().is_ok());
            fence.safety_epoch.store(9, Ordering::Release);
            assert!(lease.check().is_err());
        })
        .await;
    assert!(authorization
        .check("solana", "wallet", "kms_azure", &hash)
        .is_err());
}
