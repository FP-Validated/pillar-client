use async_trait::async_trait;
use pillar_core::{
    validate_expiration_bounds, validate_message_hash_for_pillar, AppCoreError, AppValidator,
    LzMessageId, LzSentEvent, PillarApiRequestV2, ReadBlockPin, SigningContext,
};
use std::sync::Arc;

pub const DEFAULT_MAXIMUM_EXPIRATION_SECONDS: i64 = 60 * 60 * 24 * 7;
pub const DEFAULT_MAXIMUM_EXPIRATION_GRACE_PERIOD_SECONDS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpirationValidRange {
    pub min: i64,
    pub max: i64,
}

#[async_trait]
pub trait RuntimeValidationChecks: Send + Sync + 'static {
    async fn current_block_timestamp(
        &self,
        dst_chain_name: &str,
        valid_range: ExpirationValidRange,
    ) -> Result<i64, AppCoreError>;

    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<Vec<ReadBlockPin>, AppCoreError>;

    fn validate_read_preflight(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError>;

    async fn validate_payload_not_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: Option<&str>,
        dst_chain_name: &str,
        effective_receive_version: Option<&str>,
    ) -> Result<Option<u64>, AppCoreError>;

    async fn validate_extra_context(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError>;

    async fn uln_receive_version(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError>;
}

pub struct RuntimeAppValidator<C> {
    checks: Arc<C>,
    maximum_expiration: i64,
    maximum_expiration_grace_period: i64,
}

impl<C> RuntimeAppValidator<C>
where
    C: RuntimeValidationChecks,
{
    pub fn new(checks: Arc<C>) -> Self {
        Self::with_expiration_bounds(
            checks,
            DEFAULT_MAXIMUM_EXPIRATION_SECONDS,
            DEFAULT_MAXIMUM_EXPIRATION_GRACE_PERIOD_SECONDS,
        )
    }

    pub fn with_expiration_bounds(
        checks: Arc<C>,
        maximum_expiration: i64,
        maximum_expiration_grace_period: i64,
    ) -> Self {
        Self {
            checks,
            maximum_expiration,
            maximum_expiration_grace_period,
        }
    }
}

#[async_trait]
impl<C> AppValidator for RuntimeAppValidator<C>
where
    C: RuntimeValidationChecks,
{
    async fn validate_message_hash(
        &self,
        request: &PillarApiRequestV2,
        sent_event: &LzSentEvent,
    ) -> Result<(), AppCoreError> {
        validate_message_hash_for_pillar(request, sent_event)?;
        self.checks
            .validate_read_preflight(sent_event, &request.signing_context)
    }

    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
        self.checks
            .validate_readiness(sent_event, signing_context)
            .await
    }

    async fn validate_expiration(
        &self,
        dst_chain_name: &str,
        expiration: i64,
    ) -> Result<Option<std::time::Instant>, AppCoreError> {
        let valid_range = ExpirationValidRange {
            min: expiration
                .checked_sub(self.maximum_expiration)
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "expiration is outside supported range: expiration={expiration}"
                    ))
                })?,
            max: expiration
                .checked_add(self.maximum_expiration_grace_period)
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "expiration is outside supported range: expiration={expiration}"
                    ))
                })?,
        };
        let current_timestamp = self
            .checks
            .current_block_timestamp(dst_chain_name, valid_range)
            .await?;
        validate_expiration_bounds(
            expiration,
            current_timestamp,
            self.maximum_expiration,
            self.maximum_expiration_grace_period,
        )?;
        // The destination accepts the attestation until `expiration` plus the grace period, by
        // its own clock, and the check above accepts a block time equal to that bound. Block
        // times are whole seconds, so the window runs through the second that equals it: one
        // second past `max - current_timestamp`. Count it from the block time just read, on the
        // monotonic clock, so a slow check cannot leave a window that has closed looking open
        // (GA-366).
        let remaining = valid_range
            .max
            .saturating_sub(current_timestamp)
            .saturating_add(1);
        Ok(
            std::time::Instant::now().checked_add(std::time::Duration::from_secs(
                u64::try_from(remaining).unwrap_or(0),
            )),
        )
    }

    async fn validate_payload_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: Option<&str>,
        dst_chain_name: &str,
        effective_receive_version: Option<&str>,
    ) -> Result<Option<u64>, AppCoreError> {
        self.checks
            .validate_payload_not_signed(
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
        self.checks
            .validate_extra_context(sent_event, signing_context)
            .await
    }

    async fn uln_receive_version(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError> {
        self.checks.uln_receive_version(lz_message_id).await
    }
}
