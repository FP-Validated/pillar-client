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

    fn validate_read_preflight(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        if let SigningContext::Read {
            resolved_timestamp_time_markers,
            ..
        } = signing_context
        {
            self.validate_read_markers_preflight(sent_event, resolved_timestamp_time_markers)?;
        }
        Ok(())
    }

    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
        self.validate_read_preflight(sent_event, signing_context)?;
        self.validate_readiness_with_quorum(sent_event, signing_context)
            .await
    }
    async fn validate_payload_not_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: Option<&str>,
        dst_chain_name: &str,
        effective_receive_version: Option<&str>,
    ) -> Result<(), AppCoreError> {
        self.validate_payload_not_signed_with_quorum(
            sent_event,
            verifier_address,
            dst_chain_name,
            effective_receive_version,
        )
        .await
    }

    async fn validate_extra_context(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        self.validate_extra_context_request(sent_event, signing_context)
            .await
    }

    async fn uln_receive_version(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError> {
        self.uln_receive_version_with_quorum(lz_message_id).await
    }
}
