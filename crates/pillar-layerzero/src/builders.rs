use async_trait::async_trait;
use pillar_core::{
    AppCoreError, HashCallDataBuilder, HashCallDataResult, LzSentEvent, SigningContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::packet::extra_u64;
use crate::types::{
    ReadPayloadResolver, UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder,
    ULN_VERSION_READ_V1002, ULN_VERSION_V2, ULN_VERSION_V301, ULN_VERSION_V302,
};

pub fn build_hash_call_data_builders(
    v2: Arc<dyn UlnV2PayloadBuilder>,
    v3: Arc<dyn UlnV3PayloadBuilder>,
    read: Arc<dyn UlnReadV1PayloadBuilder>,
    read_resolver: Arc<dyn ReadPayloadResolver>,
    _environment: impl Into<String>,
) -> HashMap<String, Arc<dyn HashCallDataBuilder>> {
    let uln_v2 = Arc::new(UlnV2HashCallDataBuilder {
        payload_builder: v2,
    });
    let uln_v3 = Arc::new(UlnV3HashCallDataBuilder {
        payload_builder: v3,
    });
    let uln_read = Arc::new(UlnReadV1HashCallDataBuilder {
        payload_builder: read,
        read_resolver,
    });

    HashMap::from([
        (
            ULN_VERSION_V2.to_string(),
            uln_v2 as Arc<dyn HashCallDataBuilder>,
        ),
        (
            ULN_VERSION_V301.to_string(),
            uln_v3.clone() as Arc<dyn HashCallDataBuilder>,
        ),
        (
            ULN_VERSION_V302.to_string(),
            uln_v3 as Arc<dyn HashCallDataBuilder>,
        ),
        (
            ULN_VERSION_READ_V1002.to_string(),
            uln_read as Arc<dyn HashCallDataBuilder>,
        ),
    ])
}

pub struct UlnV2HashCallDataBuilder {
    payload_builder: Arc<dyn UlnV2PayloadBuilder>,
}

#[async_trait]
impl HashCallDataBuilder for UlnV2HashCallDataBuilder {
    async fn build_dvn_hash_call_data(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let SigningContext::Message {
            block_confirmation,
            expiration,
            skip_v_id,
            ..
        } = signing_context
        else {
            return Err(AppCoreError::Internal(
                "Invalid protocol type for ULN V2".to_string(),
            ));
        };
        self.payload_builder
            .build_uln_v2_verify_payload(
                sent_event,
                *block_confirmation,
                *expiration,
                get_v_id(*skip_v_id, sent_event)?,
            )
            .await
    }
}

pub struct UlnV3HashCallDataBuilder {
    payload_builder: Arc<dyn UlnV3PayloadBuilder>,
}

#[async_trait]
impl HashCallDataBuilder for UlnV3HashCallDataBuilder {
    async fn build_dvn_hash_call_data(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let SigningContext::Message {
            block_confirmation,
            expiration,
            skip_v_id,
            dvn_address,
        } = signing_context
        else {
            return Err(AppCoreError::Internal(
                "Invalid protocol type for ULN V3".to_string(),
            ));
        };
        self.payload_builder
            .build_uln_v3_verify_payload(
                sent_event,
                *block_confirmation,
                *expiration,
                get_v_id(*skip_v_id, sent_event)?,
                dvn_address.as_deref(),
            )
            .await
    }
}

pub struct UlnReadV1HashCallDataBuilder {
    payload_builder: Arc<dyn UlnReadV1PayloadBuilder>,
    read_resolver: Arc<dyn ReadPayloadResolver>,
}

#[async_trait]
impl HashCallDataBuilder for UlnReadV1HashCallDataBuilder {
    async fn build_dvn_hash_call_data(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<HashCallDataResult, AppCoreError> {
        let SigningContext::Read {
            expiration,
            skip_v_id,
            dvn_address,
            ..
        } = signing_context
        else {
            return Err(AppCoreError::Internal(
                "Invalid protocol type for ULN V3".to_string(),
            ));
        };
        let resolved_payload = self
            .read_resolver
            .resolve_payload(sent_event, signing_context)
            .await?;
        self.payload_builder
            .build_uln_read_v1_verify_payload(
                sent_event,
                resolved_payload,
                *expiration,
                get_v_id(*skip_v_id, sent_event)?,
                dvn_address.as_deref(),
            )
            .await
    }
}

fn get_v_id(skip_v_id: Option<bool>, sent_event: &LzSentEvent) -> Result<String, AppCoreError> {
    if skip_v_id == Some(true) {
        return Ok(String::new());
    }
    let dst_eid = extra_u64(sent_event, "dstEid")?;
    if dst_eid > u32::MAX as u64 {
        return Err(AppCoreError::Internal("dstEid exceeds u32".to_string()));
    }
    if dst_eid > 30_000 {
        Ok((dst_eid % 30_000).to_string())
    } else {
        Ok(dst_eid.to_string())
    }
}
