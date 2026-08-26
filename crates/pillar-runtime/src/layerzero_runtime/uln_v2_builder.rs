use super::*;

#[derive(Clone)]
pub(crate) struct RuntimeEvmUlnV2PayloadBuilder<T> {
    providers: crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    payload_builder: EvmUlnPayloadBuilder,
    rank_tracker: Arc<ProviderRankTracker>,
}

impl<T> RuntimeEvmUlnV2PayloadBuilder<T>
where
    T: JsonRpcTransport,
{
    pub(crate) fn new(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        payload_builder: EvmUlnPayloadBuilder,
    ) -> Self {
        Self {
            providers: providers.clone(),
            transport,
            payload_builder,
            rank_tracker: Arc::new(ProviderRankTracker::new()),
        }
    }

    /// Shares one rank tracker with validation checks / the background
    /// reprobe loop instead of keeping independent state (see server_app).
    pub(crate) fn with_rank_tracker(mut self, rank_tracker: Arc<ProviderRankTracker>) -> Self {
        self.rank_tracker = rank_tracker;
        self
    }

    async fn mpt_hash_info_with_quorum(
        &self,
        src_chain_name: &str,
        tx_hash: &str,
    ) -> Result<UlnV2HashInfo, AppCoreError> {
        let snapshot = self.providers.load();
        let dispatch = snapshot
            .dispatch(&self.rank_tracker, src_chain_name)
            .await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let tx_hash = tx_hash.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_uln_v2_mpt_hash_info(transport, url, headers, &tx_hash)
                    .await
                    .ok();
                let observation =
                    observation.map(|observation| (observation.fingerprint.clone(), observation));
                (index, observation)
            });
        }
        let context = format!("ULN V2 derived-hash for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        Ok(observation.hash_info)
    }

    async fn inbound_proof_type_with_quorum(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<String, AppCoreError> {
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        let snapshot = self.providers.load();
        let dispatch = snapshot
            .dispatch(&self.rank_tracker, dst_chain_name)
            .await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;

        let uln_v2_contract = self
            .payload_builder
            .uln_v2_contract_for_chain(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("No EVM ULN V2 contract for {dst_chain_name}"))
            })?
            .to_string();
        let src_eid = pathway_extra_u64(sent_event, "srcEid")?;
        let receiver =
            evm_address_from_pathway_value(&pathway_extra_string_value(sent_event, "receiver")?)?;

        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let uln_v2_contract = uln_v2_contract.clone();
            let receiver = receiver.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_uln_v2_inbound_proof_type(
                    transport,
                    url,
                    headers,
                    &uln_v2_contract,
                    src_eid,
                    &receiver,
                )
                .await
                .ok();
                let observation =
                    observation.map(|observation| (observation.fingerprint.clone(), observation));
                (index, observation)
            });
        }
        let context = format!("ULN V2 inbound proofType for chain {dst_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        Ok(observation.proof_type)
    }
}

#[async_trait]
impl<T> UlnV2PayloadBuilder for RuntimeEvmUlnV2PayloadBuilder<T>
where
    T: JsonRpcTransport,
{
    async fn build_uln_v2_verify_payload(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<pillar_core::HashCallDataResult, AppCoreError> {
        let src_chain_name = &sent_event.lz_message_id.pathway_id.src_chain_name;
        let proof_type = match uln_v2_inbound_proof_type(sent_event) {
            Some(proof_type) => proof_type,
            None => self.inbound_proof_type_with_quorum(sent_event).await?,
        };
        let hash_info = match proof_type.as_str() {
            "2" => {
                let packet_emit_address = sent_event
                    .extra
                    .get("packetEmitAddress")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AppCoreError::Internal(
                            "Missing sent_event.extra.packetEmitAddress for ULN V2 Feather proof"
                                .to_string(),
                        )
                    })?;
                derive_evm_feather_hash_info(sent_event, packet_emit_address)?
            }
            "1" => {
                self.mpt_hash_info_with_quorum(src_chain_name, &sent_event.tx_hash)
                    .await?
            }
            proof_type => {
                return Err(AppCoreError::Internal(format!(
                    "Unknown ULN V2 proof type {proof_type}"
                )));
            }
        };
        self.payload_builder
            .build_uln_v2_verify_payload_from_hash_info(
                sent_event,
                hash_info,
                block_confirmation,
                expiration,
                &v_id,
            )
    }
}

pub(crate) fn uln_v2_inbound_proof_type(sent_event: &LzSentEvent) -> Option<String> {
    sent_event.extra.get("inboundProofType").and_then(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .or_else(|| value.as_u64().map(|value| value.to_string()))
    })
}
