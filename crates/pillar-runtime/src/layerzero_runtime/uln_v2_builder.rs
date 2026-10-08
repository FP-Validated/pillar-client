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
        source_evidence: Option<&pillar_core::EvmSourceEvidence>,
    ) -> Result<UlnV2HashInfo, AppCoreError> {
        crate::provider_health::rpc_scope(src_chain_name, async {
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
                let source_evidence = source_evidence.cloned();
                requests.push(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let observation = provider_response(
                        observe_uln_v2_mpt_hash_info(
                            transport,
                            url,
                            headers,
                            &tx_hash,
                            source_evidence.as_ref(),
                        )
                        .await,
                    );
                    let observation = observation.map(|observation| {
                        observation
                            .map(|observation| (observation.fingerprint.clone(), observation))
                    });
                    (index, observation)
                });
            }
            let context = format!("ULN V2 derived-hash for chain {src_chain_name}");
            let observation =
                resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                    .await?;
            Ok(observation.hash_info)
        })
        .await
    }

    async fn inbound_proof_library_with_quorum(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<(String, u64), AppCoreError> {
        crate::provider_health::rpc_scope(
            &sent_event.lz_message_id.pathway_id.dst_chain_name,
            async {
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
                        AppCoreError::Internal(format!(
                            "No EVM ULN V2 contract for {dst_chain_name}"
                        ))
                    })?
                    .to_string();
                let src_eid = pathway_extra_u64(sent_event, "srcEid")?;
                let receiver = evm_address_from_pathway_value(&pathway_extra_string_value(
                    sent_event, "receiver",
                )?)?;

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
                        let observation = provider_response(
                            observe_uln_v2_inbound_proof_type(
                                transport,
                                url,
                                headers,
                                &uln_v2_contract,
                                src_eid,
                                &receiver,
                            )
                            .await,
                        );
                        let observation = observation.map(|observation| {
                            observation
                                .map(|observation| (observation.fingerprint.clone(), observation))
                        });
                        (index, observation)
                    });
                }
                let context = format!("ULN V2 inbound proofType for chain {dst_chain_name}");
                let observation =
                    resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                        .await?;
                Ok((observation.proof_type, observation.utils_version))
            },
        )
        .await
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
        let (proof_type, utils_version) =
            self.inbound_proof_library_with_quorum(sent_event).await?;
        // Aptos's V1 SDK has a feather proof builder only (`lz-v1-sdk/src/aptos/aptos.ts:93,735-740`).
        if src_chain_name == "aptos" && proof_type != "2" {
            return Err(AppCoreError::Internal(format!(
                "Unknown proof type {proof_type}"
            )));
        }
        let hash_info = match proof_type.as_str() {
            "2" => {
                // Every deployed FPValidator with published source hard-codes `utilsVersion = 1`
                // and reads bytes [0..32] of the proof as the source ULN; any other version has
                // no verifiable on-chain meaning, so the bytes it would bind are not signed.
                if utils_version != FEATHER_PROOF_UTILS_VERSION {
                    let receiver = pathway_extra_string_value(sent_event, "receiver")?;
                    return Err(AppCoreError::BadRequest(format!(
                        "Receiver {receiver} on chain {} uses a feather proof library with \
                         utilsVersion {utils_version}; only utilsVersion \
                         {FEATHER_PROOF_UTILS_VERSION} is supported, refusing to sign",
                        sent_event.lz_message_id.pathway_id.dst_chain_name
                    )));
                }
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
                if src_chain_name == "aptos" {
                    pillar_layerzero::derive_aptos_feather_hash_info(
                        sent_event,
                        packet_emit_address,
                    )?
                } else {
                    derive_evm_feather_hash_info(sent_event, packet_emit_address)?
                }
            }
            "1" => {
                self.mpt_hash_info_with_quorum(
                    src_chain_name,
                    &sent_event.tx_hash,
                    sent_event.source_evidence.as_ref(),
                )
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

const FEATHER_PROOF_UTILS_VERSION: u64 = 1;
