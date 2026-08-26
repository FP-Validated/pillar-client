use super::*;

#[async_trait]
impl<T> RuntimeValidationChecks for RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    async fn current_block_timestamp(
        &self,
        dst_chain_name: &str,
        valid_range: ExpirationValidRange,
    ) -> Result<i64, AppCoreError> {
        self.current_block_timestamp_with_quorum(dst_chain_name, valid_range)
            .await
    }

    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        self.validate_readiness_with_quorum(sent_event, signing_context)
            .await
    }

    async fn validate_payload_not_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        self.validate_payload_not_signed_with_quorum(sent_event, verifier_address, dst_chain_name)
            .await
    }

    async fn validate_extra_context(&self, sent_event: &LzSentEvent) -> Result<(), AppCoreError> {
        self.validate_extra_context_request(sent_event).await
    }
}
