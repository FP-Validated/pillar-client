use async_trait::async_trait;
use pillar_core::{
    AppCoreError, HashCallDataBuilder, HashCallDataResult, LzSentEvent, SigningContext,
};
use std::{collections::HashMap, sync::Arc};

use crate::types::{
    ReadPayloadResolver, UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder,
    ULN_VERSION_READ_V1002, ULN_VERSION_V2, ULN_VERSION_V301, ULN_VERSION_V302,
};

/// `v_id_by_chain_name` is the destination-chain vId table, keyed the way upstream
/// keys it (TS: `apps/gasolina/src/app/hashCallDataBuilder/ulnV3.ts:59-63` passes
/// `dstChainName`). It is resolved once at startup because the vId is signed: a
/// value derived per request from the packet cannot be reconciled against the
/// deployment tables the way a startup table can.
pub fn build_hash_call_data_builders(
    v2: Arc<dyn UlnV2PayloadBuilder>,
    v3: Arc<dyn UlnV3PayloadBuilder>,
    read: Arc<dyn UlnReadV1PayloadBuilder>,
    read_resolver: Arc<dyn ReadPayloadResolver>,
    v_id_by_chain_name: HashMap<String, String>,
) -> HashMap<String, Arc<dyn HashCallDataBuilder>> {
    let v_id_by_chain_name = Arc::new(v_id_by_chain_name);
    let uln_v2 = Arc::new(UlnV2HashCallDataBuilder {
        payload_builder: v2,
        v_id_by_chain_name: v_id_by_chain_name.clone(),
    });
    let uln_v3 = Arc::new(UlnV3HashCallDataBuilder {
        payload_builder: v3,
        v_id_by_chain_name: v_id_by_chain_name.clone(),
    });
    let uln_read = Arc::new(UlnReadV1HashCallDataBuilder {
        payload_builder: read,
        read_resolver,
        v_id_by_chain_name,
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
    v_id_by_chain_name: Arc<HashMap<String, String>>,
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
                get_v_id(*skip_v_id, sent_event, &self.v_id_by_chain_name)?,
            )
            .await
    }
}

pub struct UlnV3HashCallDataBuilder {
    payload_builder: Arc<dyn UlnV3PayloadBuilder>,
    v_id_by_chain_name: Arc<HashMap<String, String>>,
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
                get_v_id(*skip_v_id, sent_event, &self.v_id_by_chain_name)?,
                dvn_address.as_deref(),
            )
            .await
    }
}

pub struct UlnReadV1HashCallDataBuilder {
    payload_builder: Arc<dyn UlnReadV1PayloadBuilder>,
    read_resolver: Arc<dyn ReadPayloadResolver>,
    v_id_by_chain_name: Arc<HashMap<String, String>>,
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
                get_v_id(*skip_v_id, sent_event, &self.v_id_by_chain_name)?,
                dvn_address.as_deref(),
            )
            .await
    }
}

fn get_v_id(
    skip_v_id: Option<bool>,
    sent_event: &LzSentEvent,
    v_id_by_chain_name: &HashMap<String, String>,
) -> Result<String, AppCoreError> {
    if skip_v_id == Some(true) {
        return Ok(String::new());
    }
    let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
    // Upstream throws when the destination has no vId, so refuse rather than
    // sign a payload carrying a guessed verifier id.
    v_id_by_chain_name
        .get(dst_chain_name)
        .cloned()
        .ok_or_else(|| {
            AppCoreError::Internal(format!("No vId configured for chain {dst_chain_name}"))
        })
}
