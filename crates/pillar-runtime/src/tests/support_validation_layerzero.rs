use super::*;

pub(super) struct FixedValidationChecks {
    pub(super) current_timestamp: i64,
    pub(super) calls: Arc<Mutex<Vec<String>>>,
    pub(super) ranges: Arc<Mutex<Vec<ExpirationValidRange>>>,
}

#[async_trait]
impl RuntimeValidationChecks for FixedValidationChecks {
    async fn current_block_timestamp(
        &self,
        dst_chain_name: &str,
        valid_range: ExpirationValidRange,
    ) -> Result<i64, AppCoreError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("timestamp:{dst_chain_name}"));
        self.ranges.lock().unwrap().push(valid_range);
        Ok(self.current_timestamp)
    }

    async fn validate_readiness(
        &self,
        _sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("readiness:{:?}", signing_context.skip_v_id()));
        Ok(())
    }

    async fn validate_payload_not_signed(
        &self,
        _sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("payload:{verifier_address}:{dst_chain_name}"));
        Ok(())
    }

    async fn validate_extra_context(&self, _sent_event: &LzSentEvent) -> Result<(), AppCoreError> {
        self.calls.lock().unwrap().push("extra".to_string());
        Ok(())
    }
}

pub(super) struct FixedChainResolver;

impl LegacyChainNameResolver for FixedChainResolver {
    fn get_chain_name(&self, chain_id: &str) -> Result<String, AppCoreError> {
        match chain_id {
            "1" => Ok("ethereum".to_string()),
            "56" => Ok("bsc".to_string()),
            other => Err(AppCoreError::Internal(format!("Unknown chain id {other}"))),
        }
    }
}

#[derive(Default)]
pub(super) struct RuntimeLayerZeroRecorder {
    pub(super) calls: tokio::sync::Mutex<Vec<String>>,
}

pub(super) fn layerzero_result(payload: &str) -> HashCallDataResult {
    HashCallDataResult {
        hash_call_data: payload.to_string(),
        details: json!({ "proof": { "payload": payload } }),
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for RuntimeLayerZeroRecorder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.calls
            .lock()
            .await
            .push(format!("v2:{block_confirmation}:{expiration}:{v_id}"));
        Ok(layerzero_result("0xv2"))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for RuntimeLayerZeroRecorder {
    async fn build_uln_v3_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.calls.lock().await.push(format!(
            "v3:{block_confirmation}:{expiration}:{v_id}:{}",
            dvn_address.unwrap_or_default()
        ));
        Ok(layerzero_result("0xv3"))
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for RuntimeLayerZeroRecorder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        resolved_payload: String,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.calls.lock().await.push(format!(
            "read:{resolved_payload}:{expiration}:{v_id}:{}",
            dvn_address.unwrap_or_default()
        ));
        Ok(layerzero_result("0xread"))
    }
}

#[async_trait]
impl ReadPayloadResolver for RuntimeLayerZeroRecorder {
    async fn resolve_payload(
        &self,
        _sent_event: &LzSentEvent,
        _signing_context: &SigningContext,
    ) -> Result<String, AppCoreError> {
        Ok("0xresolved".to_string())
    }
}
