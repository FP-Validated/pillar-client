use async_trait::async_trait;
use pillar_core::{
    validate_expiration_bounds, validate_message_hash_for_pillar, AppCoreError, AppValidator,
    LzSentEvent, PillarApiRequestV2, SigningContext,
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
    ) -> Result<(), AppCoreError>;

    async fn validate_payload_not_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError>;

    async fn validate_extra_context(&self, sent_event: &LzSentEvent) -> Result<(), AppCoreError>;
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
        validate_message_hash_for_pillar(request, sent_event)
    }

    async fn validate_readiness(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        self.checks
            .validate_readiness(sent_event, signing_context)
            .await
    }

    async fn validate_expiration(
        &self,
        dst_chain_name: &str,
        expiration: i64,
    ) -> Result<(), AppCoreError> {
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
        )
    }

    async fn validate_payload_signed(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        self.checks
            .validate_payload_not_signed(sent_event, verifier_address, dst_chain_name)
            .await
    }

    async fn validate_extra_context(&self, sent_event: &LzSentEvent) -> Result<(), AppCoreError> {
        self.checks.validate_extra_context(sent_event).await
    }
}
