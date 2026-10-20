use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct CountingResolver(Arc<AtomicUsize>);

#[async_trait]
impl SentEventResolver for CountingResolver {
    async fn get_lz_sent_event(
        &self,
        src_tx_hash: &str,
        lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(LzSentEvent {
            lz_message_id: lz_message_id.clone(),
            message: "0x".to_string(),
            tx_hash: src_tx_hash.to_string(),
            source_evidence: None,
            read_block_pins: Vec::new(),
            extra: indexmap::IndexMap::new(),
        })
    }
}

struct PassingValidator;

#[async_trait]
impl AppValidator for PassingValidator {
    async fn validate_message_hash(
        &self,
        _: &PillarApiRequestV2,
        _: &LzSentEvent,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }
    async fn validate_readiness(
        &self,
        _: &LzSentEvent,
        _: &SigningContext,
    ) -> Result<Vec<pillar_core::ReadBlockPin>, AppCoreError> {
        Ok(Vec::new())
    }
    async fn validate_expiration(&self, _: &str, _: i64) -> Result<(), AppCoreError> {
        Ok(())
    }
    async fn validate_payload_signed(
        &self,
        _: &LzSentEvent,
        _: Option<&str>,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }
    async fn validate_extra_context(
        &self,
        _: &LzSentEvent,
        _: &SigningContext,
    ) -> Result<(), AppCoreError> {
        Ok(())
    }
    async fn uln_receive_version(&self, _: &LzMessageId) -> Result<String, AppCoreError> {
        Ok("V2".to_string())
    }
}

struct PassingBuilder;

#[async_trait]
impl HashCallDataBuilder for PassingBuilder {
    async fn build_dvn_hash_call_data(
        &self,
        _: &LzSentEvent,
        _: &SigningContext,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Ok(HashCallDataResult {
            hash_call_data: "0x".to_string(),
            details: json!({}),
        })
    }
}

struct PassingSigner;

#[async_trait]
impl SignerGetter for PassingSigner {
    async fn pillar_sign(&self, _: &str, _: &str, _: &str) -> Result<Signature, AppCoreError> {
        Ok(Signature {
            signature: "0x".to_string(),
            address: "0x".to_string(),
        })
    }
}

struct FixedChainResolver;

impl LegacyChainNameResolver for FixedChainResolver {
    fn get_chain_name(&self, _: &str) -> Result<String, AppCoreError> {
        Ok("ethereum".to_string())
    }
}

fn preflight_app(resolutions: Arc<AtomicUsize>) -> PillarApp {
    PillarApp {
        available_chain_names: Arc::new(vec!["ethereum".to_string(), "bsc".to_string()]),
        wallets_by_chain_name: HashMap::from([(
            "bsc".to_string(),
            vec![WalletRef {
                wallet_name: "wallet".to_string(),
            }],
        )]),
        hash_call_data_builders: HashMap::from([
            (
                "V2".to_string(),
                Arc::new(PassingBuilder) as Arc<dyn HashCallDataBuilder>,
            ),
            (
                "ReadV1002".to_string(),
                Arc::new(PassingBuilder) as Arc<dyn HashCallDataBuilder>,
            ),
        ]),
        sent_event_resolver: Arc::new(CountingResolver(resolutions)),
        validator: Arc::new(PassingValidator),
        signer_getter: Arc::new(PassingSigner),
        legacy_chain_name_resolver: Arc::new(FixedChainResolver),
        stage_observer: Arc::new(pillar_core::NoopSignStageObserver),
        debug_mode: false,
    }
}

fn preflight_request(version: &str, signing_context: SigningContext) -> PillarApiRequestV2 {
    PillarApiRequestV2 {
        src_tx_hash: "0xtx".to_string(),
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: indexmap::IndexMap::new(),
            },
            nonce: 1,
            uln_send_version: Value::String(version.to_string()),
        },
        signing_context,
        message_hash: "0x".to_string(),
    }
}

#[tokio::test]
async fn round1_core_rejects_both_protocol_mismatches_before_source_resolution() {
    let cases = [
        (
            "V2",
            SigningContext::Read {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: Vec::new(),
            },
        ),
        (
            "ReadV1002",
            SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 0,
            },
        ),
    ];
    for (index, (version, context)) in cases.into_iter().enumerate() {
        let resolutions = Arc::new(AtomicUsize::new(0));
        let app = preflight_app(resolutions.clone());
        let result = app
            .sign_request_v2(preflight_request(version, context))
            .await;
        round1_artifact(
            &format!("read-protocol-mismatch-{index}"),
            json!({
                "result": format!("{result:?}"),
                "source_resolver_calls": resolutions.load(Ordering::SeqCst),
            }),
        );
        assert!(matches!(result, Err(AppCoreError::BadRequest(_))));
        assert_eq!(resolutions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn round1_core_rejects_excess_read_markers_before_source_resolution() {
    let marker = ResolvedTimestampTimeMarker {
        block_confirmation: 1,
        is_block_number: false,
        chain_name: "bsc".to_string(),
        block_number: 1,
        timestamp: 1,
    };
    let resolutions = Arc::new(AtomicUsize::new(0));
    let app = preflight_app(resolutions.clone());
    let context = SigningContext::Read {
        expiration: 1,
        skip_v_id: None,
        dvn_address: None,
        resolved_timestamp_time_markers: vec![marker; 258],
    };
    let result = app
        .sign_request_v2(preflight_request("ReadV1002", context))
        .await;
    round1_artifact(
        "read-marker-count-limit",
        json!({
            "result": format!("{result:?}"),
            "resolved_marker_count": 258,
            "source_resolver_calls": resolutions.load(Ordering::SeqCst),
        }),
    );
    assert!(matches!(result, Err(AppCoreError::BadRequest(_))));
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
}
