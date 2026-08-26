use async_trait::async_trait;
use pillar_core::{AppCoreError, HashCallDataResult, LzSentEvent};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::types::{UlnReadV1PayloadBuilder, UlnV2PayloadBuilder, UlnV3PayloadBuilder};

#[derive(Clone)]
pub struct DestinationUlnPayloadBuilderRouter {
    default_v2: Arc<dyn UlnV2PayloadBuilder>,
    default_v3: Arc<dyn UlnV3PayloadBuilder>,
    default_read: Arc<dyn UlnReadV1PayloadBuilder>,
    v2_by_dst_chain: HashMap<String, Arc<dyn UlnV2PayloadBuilder>>,
    v3_by_dst_chain: HashMap<String, Arc<dyn UlnV3PayloadBuilder>>,
    read_by_dst_chain: HashMap<String, Arc<dyn UlnReadV1PayloadBuilder>>,
    unsupported_non_evm_destinations: HashSet<String>,
}

impl DestinationUlnPayloadBuilderRouter {
    pub fn new(
        default_v2: Arc<dyn UlnV2PayloadBuilder>,
        default_v3: Arc<dyn UlnV3PayloadBuilder>,
        default_read: Arc<dyn UlnReadV1PayloadBuilder>,
    ) -> Self {
        Self {
            default_v2,
            default_v3,
            default_read,
            v2_by_dst_chain: HashMap::new(),
            v3_by_dst_chain: HashMap::new(),
            read_by_dst_chain: HashMap::new(),
            unsupported_non_evm_destinations: HashSet::new(),
        }
    }

    pub fn with_unsupported_non_evm_destinations(
        mut self,
        chain_names: impl IntoIterator<Item = String>,
    ) -> Self {
        self.unsupported_non_evm_destinations.extend(chain_names);
        self
    }

    pub fn with_chain_builder(
        mut self,
        chain_name: impl Into<String>,
        v2: Arc<dyn UlnV2PayloadBuilder>,
        v3: Arc<dyn UlnV3PayloadBuilder>,
        read: Arc<dyn UlnReadV1PayloadBuilder>,
    ) -> Self {
        let chain_name = chain_name.into();
        self.v2_by_dst_chain.insert(chain_name.clone(), v2);
        self.v3_by_dst_chain.insert(chain_name.clone(), v3);
        self.read_by_dst_chain.insert(chain_name, read);
        self
    }

    fn dst_chain_name(sent_event: &LzSentEvent) -> &str {
        &sent_event.lz_message_id.pathway_id.dst_chain_name
    }

    fn unsupported_non_evm_destination_error(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<(), AppCoreError> {
        let dst_chain_name = Self::dst_chain_name(sent_event);
        if self
            .unsupported_non_evm_destinations
            .contains(dst_chain_name)
        {
            return Err(AppCoreError::Internal(format!(
                "Unsupported LayerZero destination chain type for {dst_chain_name}"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl UlnV2PayloadBuilder for DestinationUlnPayloadBuilderRouter {
    async fn build_uln_v2_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.unsupported_non_evm_destination_error(sent_event)?;
        let builder = self
            .v2_by_dst_chain
            .get(Self::dst_chain_name(sent_event))
            .unwrap_or(&self.default_v2);
        builder
            .build_uln_v2_verify_payload(sent_event, block_confirmation, expiration, v_id)
            .await
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for DestinationUlnPayloadBuilderRouter {
    async fn build_uln_v3_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.unsupported_non_evm_destination_error(sent_event)?;
        let builder = self
            .v3_by_dst_chain
            .get(Self::dst_chain_name(sent_event))
            .unwrap_or(&self.default_v3);
        builder
            .build_uln_v3_verify_payload(
                sent_event,
                block_confirmation,
                expiration,
                v_id,
                dvn_address,
            )
            .await
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for DestinationUlnPayloadBuilderRouter {
    async fn build_uln_read_v1_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        resolved_payload: String,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.unsupported_non_evm_destination_error(sent_event)?;
        let builder = self
            .read_by_dst_chain
            .get(Self::dst_chain_name(sent_event))
            .unwrap_or(&self.default_read);
        builder
            .build_uln_read_v1_verify_payload(
                sent_event,
                resolved_payload,
                expiration,
                v_id,
                dvn_address,
            )
            .await
    }
}
