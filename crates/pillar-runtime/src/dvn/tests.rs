use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use pillar_core::dvn::{Permit, PERMIT_SCHEMA};
use std::future::Future;

tokio::task_local! {
    static TEST_POLICY_SCOPE: ();
}
pub(crate) fn test_policy_enabled() -> bool {
    TEST_POLICY_SCOPE.try_with(|()| ()).is_ok()
}
pub(crate) async fn with_test_policy<F: Future>(future: F) -> F::Output {
    TEST_POLICY_SCOPE.scope((), future).await
}

/// Explicit cfg(test) fixture for pre-existing crypto/provider tests. It still
/// creates a real signed permit; production never accepts this test key.
pub(crate) struct TestSigningPolicy;
#[async_trait]
impl SigningPolicy for TestSigningPolicy {
    async fn authorize(
        &self,
        _: &VerifiedEnvelope<'_>,
        _: &dyn SentEventResolver,
        hash: &str,
        scopes: Vec<SigningScope>,
    ) -> Result<SigningAuthorization, AppCoreError> {
        test_authorization(hash, scopes)
    }
}

pub(crate) fn test_authorization(
    hash: &str,
    scopes: Vec<SigningScope>,
) -> Result<SigningAuthorization, AppCoreError> {
    let request = AuthorizeRequest {
        instance_id: "test-instance".into(),
        boot_id: "test-boot".into(),
        registry_revision: 1,
        subject: Subject {
            environment: Environment::Testnet,
            protocol: "layerzero-v2".into(),
            request_kind: RequestKind::Message,
            src_eid: 40101,
            dst_eid: 40102,
            src_endpoint_id: 40101,
            dst_endpoint_id: 40102,
            src_oapp: format!("0x{}", "00".repeat(32)),
            dst_oapp: format!("0x{}", "00".repeat(32)),
            nonce: "1".into(),
            payload_hash: "00".repeat(32),
            guid: None,
            source_evidence_digest: "00".repeat(32),
            asset_binding_id: None,
            token_sender: None,
            token_recipient: None,
            amount_shared_units: None,
        },
        intent_digest: intent_digest(hash, &scopes)?,
        wallet_names: scopes
            .iter()
            .map(|scope| scope.wallet_name.clone())
            .collect(),
    };
    let raw = serde_json::to_vec(&request).unwrap();
    let now = now_ms()?;
    let permit = Permit {
        schema_version: PERMIT_SCHEMA.into(),
        decision_id: "test-decision".into(),
        environment: Environment::Testnet,
        workload_id: "test-workload".into(),
        instance_id: request.instance_id.clone(),
        boot_id: request.boot_id.clone(),
        request_sha256: sha256_hex(&raw),
        intent_digest: request.intent_digest.clone(),
        policy_revision: 1,
        safety_epoch: 0,
        issued_at_ms: now,
        expires_at_ms: now + 2_000,
    };
    let key = SigningKey::from_bytes(&[9; 32]);
    let payload = serde_json::to_vec(&permit).unwrap();
    let mut signed = b"pillar.dvn-permit/v1\0".to_vec();
    signed.extend_from_slice(&payload);
    let envelope = SignedEnvelope {
        sha256: sha256_hex(&payload),
        payload: STANDARD.encode(payload),
        signature: STANDARD.encode(key.sign(&signed).to_bytes()),
        key_id: "unit-test".into(),
    };
    let verifier = EnvelopeVerifier::new(
        "unit-test".into(),
        &STANDARD.encode(key.verifying_key().as_bytes()),
    )?;
    verifier
        .authorize(
            &envelope,
            &PermitExpectation {
                request: &request,
                raw_request: &raw,
                workload_id: "test-workload",
                minimum_policy_revision: 0,
                minimum_safety_epoch: 0,
            },
            hash,
            scopes,
            now,
        )
        .map(|(authorization, _)| authorization)
}

pub(crate) fn wallet_authorization(
    chain: &str,
    wallet: &str,
    backend: &str,
    hash: &str,
) -> SigningAuthorization {
    test_authorization(
        hash,
        vec![SigningScope {
            chain_name: chain.into(),
            wallet_name: wallet.into(),
            backend: backend.into(),
        }],
    )
    .unwrap()
}

#[test]
fn requires_gate_configuration_and_refuses_credentials_in_urls() {
    assert!(DvnGateConfig::from_env(&HashMap::new()).is_err());
    let mut vars = HashMap::from([
        ("LAYERZERO_ENVIRONMENT".into(), "testnet".into()),
        (
            "PILLAR_DVN_GATE_URL".into(),
            "http://policy.example/".into(),
        ),
        ("PILLAR_DVN_GATE_TOKEN".into(), "secret".into()),
        ("PILLAR_DVN_GATE_KEY_ID".into(), "unit-test".into()),
        (
            "PILLAR_DVN_GATE_PUBLIC_KEY".into(),
            STANDARD.encode(SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes()),
        ),
        ("PILLAR_DVN_WORKLOAD_ID".into(), "test-workload".into()),
        ("PILLAR_DVN_INSTANCE_ID".into(), "test-instance".into()),
    ]);
    assert!(DvnGateConfig::from_env(&vars).is_err());
    for url in [
        "https://user:secret@policy.example/",
        "https://policy.example/?token=secret",
        "https://policy.example/prefix",
    ] {
        vars.insert("PILLAR_DVN_GATE_URL".into(), url.into());
        assert!(DvnGateConfig::from_env(&vars).is_err());
    }
    vars.insert(
        "PILLAR_DVN_GATE_URL".into(),
        "https://policy.example/".into(),
    );
    assert!(DvnGateConfig::from_env(&vars).is_ok());
    vars.remove("PILLAR_DVN_GATE_TOKEN");
    assert!(DvnGateConfig::from_env(&vars).is_err());
}

#[test]
fn validates_non_evm_roster_without_an_asset_adapter() {
    let names = [
        "solana", "aptos", "sui", "iotal1", "starknet", "stellar", "initia", "ton", "canton",
        "movement",
    ]
    .map(str::to_string);
    let chains = runtime_bindings(Environment::Mainnet, &names).unwrap();
    let mut registry = RegistrySnapshot {
        schema_version: REGISTRY_SCHEMA.into(),
        environment: Environment::Mainnet,
        revision: 1,
        chains: chains.clone(),
        asset_bindings: vec![],
    };
    let roster = chains
        .iter()
        .map(|chain| InstanceChain {
            eid: chain.eid,
            name: chain.name.clone(),
            capabilities: vec![
                "protocol:layerzero".into(),
                format!("address-format:{}", chain.address_format),
            ],
        })
        .collect::<Vec<_>>();
    assert!(validate_registry(&registry, Environment::Mainnet, &roster).is_ok());
    registry.chains[0].address_format = "evm".into();
    assert!(validate_registry(&registry, Environment::Mainnet, &roster).is_err());
    registry.chains = chains;
    registry.chains.pop();
    assert!(validate_registry(&registry, Environment::Mainnet, &roster).is_err());
}

#[test]
fn decodes_oft_shared_units_without_truncation_or_sender_inference() {
    let mut bytes = vec![0x11; 32];
    bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        decode_oft_v1(&hex::encode(&bytes)).unwrap(),
        (format!("0x{}", "11".repeat(32)), u64::MAX.to_string())
    );
    bytes.push(1);
    assert!(decode_oft_v1(&hex::encode(&bytes)).is_err());
    bytes.resize(72, 0);
    assert_eq!(
        decode_oft_v1(&hex::encode(&bytes)).unwrap().1,
        u64::MAX.to_string()
    );
    assert!(decode_oft_v1("0x0102").is_err());
}

#[test]
fn rejects_noncanonical_registry_addresses_and_duplicate_pathways() {
    let chains =
        runtime_bindings(Environment::Mainnet, &["ethereum".into(), "bsc".into()]).unwrap();
    let mut registry = RegistrySnapshot {
        schema_version: REGISTRY_SCHEMA.into(),
        environment: Environment::Mainnet,
        revision: 1,
        chains,
        asset_bindings: vec![pillar_core::dvn::AssetBinding {
            id: "test-path".into(),
            asset_id: "test-token".into(),
            asset_group: "test-group".into(),
            src_eid: 30101,
            dst_eid: 30102,
            src_oapp: format!("0x{}{}", "00".repeat(12), "11".repeat(20)),
            dst_oapp: format!("0x{}{}", "00".repeat(12), "22".repeat(20)),
            codec: AssetCodec::Opaque,
            shared_decimals: 6,
        }],
    };
    assert!(validate_registry(&registry, Environment::Mainnet, &[]).is_ok());
    registry
        .asset_bindings
        .push(registry.asset_bindings[0].clone());
    registry.asset_bindings[1].id = "other-id".into();
    assert!(validate_registry(&registry, Environment::Mainnet, &[]).is_err());
    registry.asset_bindings.pop();
    registry.asset_bindings[0].src_oapp = format!("0x{}", "11".repeat(32));
    assert!(validate_registry(&registry, Environment::Mainnet, &[]).is_err());
}

#[test]
fn dvn_source_generation_is_preserved_by_receiver_migration() {
    let mut event = pillar_core::LzSentEvent {
        lz_message_id: pillar_core::LzMessageId {
            pathway_id: pillar_core::PathwayId {
                src_chain_name: "ethereum".into(),
                dst_chain_name: "bsc".into(),
                extra: indexmap::IndexMap::from([
                    ("srcEid".into(), serde_json::json!(101)),
                    ("dstEid".into(), serde_json::json!(102)),
                    (
                        "sender".into(),
                        serde_json::json!(format!("0x{}", "11".repeat(20))),
                    ),
                    (
                        "receiver".into(),
                        serde_json::json!(format!("0x{}", "22".repeat(20))),
                    ),
                ]),
            },
            nonce: 7,
            uln_send_version: serde_json::json!("V2"),
        },
        message: "0x010203".into(),
        tx_hash: "0xabc".into(),
        source_evidence: None,
        read_block_pins: vec![],
        extra: indexmap::IndexMap::new(),
    };
    let hydrated = pillar_core::hydrate_uln_v2_sent_event(&event, None).unwrap();
    assert!(hydrated.extra.contains_key("guid"));
    assert_eq!(source_endpoint_protocol(&hydrated).unwrap(), "layerzero-v1");
    for (version, protocol) in [
        ("V2", "layerzero-v1"),
        ("V301", "layerzero-v1"),
        ("V302", "layerzero-v2"),
        ("ReadV1002", "layerzero-v2"),
    ] {
        event.lz_message_id.uln_send_version = serde_json::json!(version);
        assert_eq!(source_endpoint_protocol(&event).unwrap(), protocol);
    }
    for unsupported in ["V1", "V300", "future-version"] {
        event.lz_message_id.uln_send_version = serde_json::json!(unsupported);
        assert!(source_endpoint_protocol(&event).is_err());
    }
}
