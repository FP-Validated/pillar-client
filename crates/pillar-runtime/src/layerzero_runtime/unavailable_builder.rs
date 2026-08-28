use std::sync::Arc;

use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use pillar_layerzero::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

/// A destination the router knows about but refuses to build for.
///
/// This is a policy type, not a codec gap. The other "unsupported" builders
/// (`TonUlnPayloadBuilder`'s V2 arm, for instance) say a protocol version was
/// never implemented for a chain. This one says the chain's own deployment
/// cannot be trusted, so a payload that would otherwise build correctly must
/// not be produced.
///
/// Registering it keeps the chain out of the default EVM route. Leaving the
/// chain unregistered would be worse than refusing: the router would fall
/// through to the EVM builder and emit an EVM-shaped attestation for a non-EVM
/// destination. And refusing at assembly time instead would take the whole
/// service down over one chain, so the refusal is scoped to requests that
/// actually name this destination.
#[derive(Debug, Clone)]
pub struct UnavailableUlnPayloadBuilder {
    reason: Arc<str>,
}

impl UnavailableUlnPayloadBuilder {
    pub fn new(reason: impl Into<Arc<str>>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    fn refuse(&self) -> AppCoreError {
        AppCoreError::Internal(self.reason.to_string())
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for UnavailableUlnPayloadBuilder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(self.refuse())
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for UnavailableUlnPayloadBuilder {
    async fn build_uln_v3_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _block_confirmation: i64,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(self.refuse())
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for UnavailableUlnPayloadBuilder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        _resolved_payload: String,
        _expiration: i64,
        _v_id: String,
        _dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        Err(self.refuse())
    }
}
