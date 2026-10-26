use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: Option<&str>,
        dst_chain_name: &str,
        effective_receive_version: Option<&str>,
    ) -> Result<(), AppCoreError> {
        crate::provider_health::rpc_scope(
            &sent_event.lz_message_id.pathway_id.dst_chain_name,
            async {
                // Legacy V1 packets have no V2 payload to query.
                if !sent_event.extra.contains_key("guid") {
                    return Ok(());
                }
                if is_chain_native_payload_signed_destination(dst_chain_name) {
                    // The native duplicate query needs a DVN address; EVM resolution does not.
                    let Some(verifier_address) = verifier_address else {
                        return Ok(());
                    };
                    return self
                        .validate_chain_native_payload_not_signed_with_quorum(
                            sent_event,
                            verifier_address,
                            dst_chain_name,
                            effective_receive_version,
                        )
                        .await;
                }

                let snapshot = self.providers.load();
                let dispatch = snapshot
                    .dispatch(&self.rank_tracker, dst_chain_name)
                    .await?;
                let ChainDispatch {
                    config: provider_config,
                    quorum,
                    plan,
                } = dispatch;

                let contracts = self
                    .evm_receive_contracts_by_chain_name
                    .get(dst_chain_name)
                    .ok_or_else(|| {
                        AppCoreError::Internal(format!(
                            "No EVM LayerZero receive contracts for chain {dst_chain_name}"
                        ))
                    })?;
                let dst_eid = pathway_extra_u64(sent_event, "dstEid")?;
                let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
                // A V3 packet names the receiver as bytes32; the endpoint and the ULN
                // both take an `address`. Narrowed once here, so every call in the
                // observation - the endpoint reads and the READ `getReadLibConfig` call -
                // sees the same 20-byte value.
                let oapp = evm_address_from_pathway_value(&pathway_extra_string_value(
                    sent_event, "receiver",
                )?)?;
                let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;

                let requests = FuturesUnordered::new();
                for DispatchEntry { index, uri, delay } in plan {
                    let (url, headers) = provider_uri_parts(uri);
                    let transport = self.transport.clone();
                    let oapp = oapp.clone();
                    let proof = proof.clone();
                    let verifier_address = verifier_address.map(ToOwned::to_owned);
                    let contracts = contracts.clone();
                    requests.push(async move {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        let observation = provider_response(
                            observe_payload_signed(
                                transport,
                                url,
                                headers,
                                EvmPayloadSignedObservation {
                                    contracts: &contracts,
                                    oapp: &oapp,
                                    remote_eid: src_eid,
                                    dst_eid,
                                    proof: &proof,
                                    verifier_address: verifier_address.as_deref(),
                                },
                            )
                            .await,
                        );
                        (index, observation)
                    });
                }
                let context = format!("payload-signed validation for chain {dst_chain_name}");
                let agreed_validity =
                    resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                        .await?;

                payload_signed_validation_result(agreed_validity, sent_event, dst_chain_name)
            },
        )
        .await
    }

    /// Which ULN version the destination receiver receives on, read from the
    /// requested pathway before resolution as upstream does (TS 1.2.66:
    /// `app.ts:263-271`) and agreed by provider quorum including the library
    /// address. Resolution later requires the packet to carry these same eids
    /// and receiver, so the answer is the one the resolved packet would get.
    pub(crate) async fn uln_receive_version_with_quorum(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError> {
        let dst_chain_name = &lz_message_id.pathway_id.dst_chain_name;
        if dst_chain_name == "aptos" {
            return self
                .aptos_uln_receive_version_with_quorum(lz_message_id)
                .await;
        }
        crate::provider_health::rpc_scope(dst_chain_name, async {
            let contracts = self
                .evm_receive_contracts_by_chain_name
                .get(dst_chain_name)
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "The receive library of {dst_chain_name} cannot be read, so a ULN \
                         V2-sent message to it cannot be routed; refusing to sign"
                    ))
                })?;
            let pathway_u64 = |key: &str| {
                lz_message_id
                    .pathway_id
                    .extra
                    .get(key)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}"))
                    })
            };
            let dst_eid = pathway_u64("dstEid")?;
            // Every provider would fail identically; say so instead of reporting a split.
            if dst_eid < crate::provider_health::EVM_ENDPOINT_V2_ID_BASE
                && contracts.endpoint_v1.is_none()
            {
                return Err(AppCoreError::Internal(format!(
                    "No V1 Endpoint contract configured for {dst_chain_name}"
                )));
            }
            let src_eid = u32::try_from(pathway_u64("srcEid")?).map_err(|_| {
                AppCoreError::Internal("lzMessageId.pathwayId.srcEid exceeds u32".to_string())
            })?;
            let receiver = lz_message_id
                .pathway_id
                .extra
                .get("receiver")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppCoreError::Internal("Missing lzMessageId.pathwayId.receiver".to_string())
                })?;
            let oapp = evm_address_from_pathway_value(receiver)?;
            let snapshot = self.providers.load();
            let ChainDispatch {
                config: provider_config,
                quorum,
                plan,
            } = snapshot
                .dispatch(&self.rank_tracker, dst_chain_name)
                .await?;

            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                let oapp = oapp.clone();
                let contracts = contracts.clone();
                requests.push(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let observation = provider_response(
                        observe_receive_uln_version(
                            transport, url, headers, &contracts, &oapp, src_eid, dst_eid,
                        )
                        .await,
                    );
                    (index, observation)
                });
            }
            let context = format!("receive library lookup for chain {dst_chain_name}");
            match resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?
            {
                ReceiveUlnVersion::Known(version) => Ok(version.to_string()),
                // Upstream's `err.message` on the thrown string literal.
                ReceiveUlnVersion::Unsupported(_) => Err(AppCoreError::Internal(
                    "Unsupported ULN version: undefined".to_string(),
                )),
                ReceiveUlnVersion::Invalid(address) => Err(AppCoreError::Internal(format!(
                    "Invalid ULN version for lib: {}",
                    evm_checksum_address(&address)
                ))),
            }
        })
        .await
    }

    /// Upstream's `getUlnReceiveDetails` for an Aptos EndpointV1 receiver
    /// (`lz-v2-sdk/src/uln/move/index.ts:137-194`): `endpoint_view::get_receive_msglib`, where
    /// only `(2, 0)` is ULN301 and anything else ULN V2; agreed by provider quorum.
    async fn aptos_uln_receive_version_with_quorum(
        &self,
        lz_message_id: &LzMessageId,
    ) -> Result<String, AppCoreError> {
        crate::provider_health::rpc_scope("aptos", async {
            let contracts = self.aptos_v301_contracts.clone().ok_or_else(|| {
                AppCoreError::BadRequest(
                    "The receive library of aptos cannot be read, so a ULN V2-sent message to \
                     it cannot be routed; refusing to sign"
                        .to_string(),
                )
            })?;
            let extra = &lz_message_id.pathway_id.extra;
            let src_eid = extra
                .get("srcEid")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    AppCoreError::Internal("Missing lzMessageId.pathwayId.srcEid".to_string())
                })?
                .to_string();
            let receiver = extra
                .get("receiver")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppCoreError::Internal("Missing lzMessageId.pathwayId.receiver".to_string())
                })?;
            let receiver = aptos_address_bytes32(receiver).ok_or_else(|| {
                AppCoreError::BadRequest("The receiver is not an Aptos address".to_string())
            })?;
            let function = format!("{}::endpoint_view::get_receive_msglib", contracts.view);
            let snapshot = self.providers.load();
            let provider_config = snapshot.provider_config("aptos")?;
            let quorum = required_provider_quorum(provider_config, "aptos")?;
            let plan = plan_dispatch(&self.rank_tracker, "aptos", quorum).await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = move_provider_uri_parts("aptos", uri);
                let transport = self.transport.clone();
                let function = function.clone();
                let receiver = receiver.clone();
                let src_eid = src_eid.clone();
                requests.push(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let library = move_view_values(
                        &transport,
                        "aptos",
                        &url,
                        headers,
                        &function,
                        &[receiver.as_str(), src_eid.as_str()],
                        &["address", "u64"],
                    )
                    .await;
                    let observation = provider_response(library.map(|library| {
                        let version = (
                            library.first().and_then(move_u64),
                            library.get(1).and_then(move_u64),
                        );
                        let uln = if version == (Some(2), Some(0)) {
                            "V301"
                        } else {
                            "V2"
                        };
                        (format!("{version:?}"), uln.to_string())
                    }));
                    (index, observation)
                });
            }
            resolve_provider_quorum(
                requests,
                provider_config.uris.len(),
                quorum,
                "receive library lookup for chain aptos",
            )
            .await
        })
        .await
    }

    async fn validate_chain_native_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
        effective_receive_version: Option<&str>,
    ) -> Result<(), AppCoreError> {
        if dst_chain_name == "solana" {
            return self
                .validate_solana_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if matches!(dst_chain_name, "aptos" | "initia" | "movement") {
            return self
                .validate_move_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                    effective_receive_version,
                )
                .await;
        }
        if dst_chain_name == "starknet" {
            return self
                .validate_starknet_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if dst_chain_name == "ton" {
            return self
                .validate_ton_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if matches!(dst_chain_name, "sui" | "iotal1") {
            return self
                .validate_sui_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if dst_chain_name == "stellar" {
            return self
                .validate_stellar_payload_not_signed_with_quorum(
                    sent_event,
                    verifier_address,
                    dst_chain_name,
                )
                .await;
        }
        if dst_chain_name == "canton" {
            let snapshot = self.providers.load();
            let sequencer =
                canton_sequencer(dst_chain_name, snapshot.provider_config(dst_chain_name)?)?;
            let signed =
                canton_payload_signed(&self.transport, &sequencer, sent_event, verifier_address)
                    .await?;
            return payload_signed_validation_result(
                if signed {
                    PayloadSignedValidity::Signed
                } else {
                    PayloadSignedValidity::NotSigned
                },
                sent_event,
                dst_chain_name,
            );
        }
        unreachable!("chain-native destination was not dispatched: {dst_chain_name}");
    }

    async fn validate_move_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
        effective_receive_version: Option<&str>,
    ) -> Result<(), AppCoreError> {
        let uln_version = effective_receive_version
            .or_else(|| uln_version_value(&sent_event.lz_message_id))
            .ok_or_else(|| AppCoreError::Internal("ulnSendVersion must be a string".to_string()))?;
        if uln_version == "V301" && dst_chain_name == "aptos" {
            return self
                .validate_aptos_v301_payload_not_signed_with_quorum(sent_event, verifier_address)
                .await;
        }
        if uln_version != "V302" {
            return Err(AppCoreError::BadRequest(format!(
                "Unsupported {dst_chain_name} payload-signed validation for {uln_version}"
            )));
        }
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        let endpoint_v2 = self
            .move_endpoint_v2_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Move EndpointV2 contract configured for {dst_chain_name}"
                ))
            })?;
        let uln_302 = self
            .move_uln_302_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Move ULN302 contract configured for {dst_chain_name}"
                ))
            })?;
        let views = self
            .move_views_by_chain_name
            .get(dst_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No Move LayerZeroViews contract configured for {dst_chain_name}"
                ))
            })?;
        let receiver = pathway_extra_string_value(sent_event, "receiver")?;
        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, dst_chain_name, quorum).await?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = move_provider_uri_parts(dst_chain_name, uri);
            let transport = self.transport.clone();
            let proof = proof.clone();
            let endpoint_v2 = endpoint_v2.clone();
            let uln_302 = uln_302.clone();
            let views = views.clone();
            let receiver = receiver.clone();
            let verifier_address = verifier_address.to_string();
            let chain_name = dst_chain_name.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = provider_response(
                    observe_move_payload_signed(
                        transport,
                        url,
                        headers,
                        MovePayloadSignedObservation {
                            chain_name: &chain_name,
                            endpoint_v2: &endpoint_v2,
                            uln_302: &uln_302,
                            views: &views,
                            receiver: &receiver,
                            src_eid,
                            verifier_address: &verifier_address,
                            packet_header: &proof.packet_header,
                            payload_hash: &proof.payload_hash,
                        },
                    )
                    .await,
                );
                (index, observation)
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        payload_signed_validation_result(validity, sent_event, dst_chain_name)
    }

    /// Upstream `validatePayloadSigned` for an Aptos destination on EndpointV1
    /// (`app.ts:403-422`, `uln/move/index.ts:137-194`, `uln/aptos/index.ts:270-465`).
    async fn validate_aptos_v301_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
    ) -> Result<(), AppCoreError> {
        let contracts = self.aptos_v301_contracts.clone().ok_or_else(|| {
            AppCoreError::Internal("No Aptos EndpointV1 contracts configured".to_string())
        })?;
        let src_chain_name = &sent_event.lz_message_id.pathway_id.src_chain_name;
        // Only an EVM-shaped source can send V301 to Aptos, and upstream's
        // `getAddressEncodedByChain` encodes its sender as 20 bytes.
        if is_chain_native_payload_signed_destination(src_chain_name) {
            return Err(AppCoreError::BadRequest(format!(
                "Unsupported aptos payload-signed validation for V301 from {src_chain_name}"
            )));
        }
        let sender =
            evm_address_from_padded_hex(&pathway_extra_string_value(sent_event, "sender")?)
                .ok_or_else(|| {
                    AppCoreError::BadRequest("V301 sender is not an EVM address".to_string())
                })?;
        let receiver = pathway_extra_string_value(sent_event, "receiver")?;
        let receiver_bytes32 = aptos_address_bytes32(&receiver).ok_or_else(|| {
            AppCoreError::BadRequest("V301 receiver is not an Aptos address".to_string())
        })?;
        let src_eid = pathway_extra_u32(sent_event, "srcEid")?;
        let nonce = sent_event.lz_message_id.nonce;
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config("aptos")?;
        let quorum = required_provider_quorum(provider_config, "aptos")?;
        let plan = plan_dispatch(&self.rank_tracker, "aptos", quorum).await?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = move_provider_uri_parts("aptos", uri);
            let transport = self.transport.clone();
            let contracts = contracts.clone();
            let receiver = receiver.clone();
            let receiver_bytes32 = receiver_bytes32.clone();
            let sender = sender.clone();
            let verifier_address = verifier_address.to_string();
            let proof = proof.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = provider_response(
                    observe_aptos_v301_payload_signed(
                        transport,
                        url,
                        headers,
                        AptosV301Observation {
                            contracts: &contracts,
                            receiver: &receiver,
                            receiver_bytes32: &receiver_bytes32,
                            src_eid,
                            sender: &sender,
                            nonce,
                            verifier_address: &verifier_address,
                            packet_header: &proof.packet_header,
                            payload_hash: &proof.payload_hash,
                        },
                    )
                    .await,
                );
                (index, observation)
            });
        }
        let context = "payload-signed validation for chain aptos";
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, context).await?;
        payload_signed_validation_result(validity, sent_event, "aptos")
    }

    async fn validate_starknet_payload_not_signed_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        verifier_address: &str,
        dst_chain_name: &str,
    ) -> Result<(), AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(dst_chain_name)?;
        if provider_config.uris.is_empty() {
            return Err(AppCoreError::Internal(format!(
                "No provider URI for chain {dst_chain_name}"
            )));
        }
        let uln_address = self.starknet_uln_302.as_deref().ok_or_else(|| {
            AppCoreError::Internal("No Starknet ULN302 contract configured".to_string())
        })?;
        let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
        let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, dst_chain_name, quorum).await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let uln_address = uln_address.to_string();
            let verifier_address = verifier_address.to_string();
            let proof = proof.clone();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = provider_response(
                    observe_starknet_payload_signed(
                        transport,
                        url,
                        headers,
                        &uln_address,
                        &verifier_address,
                        &proof.packet_header,
                        &proof.payload_hash,
                    )
                    .await,
                );
                (
                    index,
                    observation.map(|value| value.map(|value| (format!("{value:?}"), value))),
                )
            });
        }
        let context = format!("payload-signed validation for chain {dst_chain_name}");
        let validity =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        payload_signed_validation_result(validity, sent_event, dst_chain_name)
    }

    /// Refuses a Starknet MESSAGE signature whose `blockConfirmation` is below the
    /// OApp's effective receive confirmations: `verify` stores it over this DVN's
    /// previous verification and `_check_verifiable` never counts it. Upstream signs it.
    pub(crate) async fn validate_starknet_confirmation_floor_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
    ) -> Result<(), AppCoreError> {
        let dst_chain_name = sent_event.lz_message_id.pathway_id.dst_chain_name.as_str();
        crate::provider_health::rpc_scope(dst_chain_name, async {
            let snapshot = self.providers.load();
            let provider_config = snapshot.provider_config(dst_chain_name)?;
            if provider_config.uris.is_empty() {
                return Err(AppCoreError::Internal(format!(
                    "No provider URI for chain {dst_chain_name}"
                )));
            }
            let uln_address = self.starknet_uln_302.as_deref().ok_or_else(|| {
                AppCoreError::Internal("No Starknet ULN302 contract configured".to_string())
            })?;
            let proof = compute_lz_packet_v1_proof_from_event(sent_event)?;
            let header = decode_bytes32_or_longer(&proof.packet_header)
                .map_err(|error| AppCoreError::Internal(error.to_string()))?;
            let (src_eid, receiver) = starknet_header_receive_path(&header).ok_or_else(|| {
                AppCoreError::Internal("Starknet packet header is not 81 bytes".to_string())
            })?;
            let quorum = required_provider_quorum(provider_config, dst_chain_name)?;
            let plan = plan_dispatch(&self.rank_tracker, dst_chain_name, quorum).await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                let uln_address = uln_address.to_string();
                let receiver = receiver.clone();
                requests.push(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let observation = observe_starknet_required_confirmations(
                        &transport,
                        url,
                        headers,
                        &uln_address,
                        &receiver,
                        src_eid,
                    )
                    .await
                    .map(|required| Some((required.to_string(), required)));
                    (index, observation)
                });
            }
            let context = format!("receive confirmations for chain {dst_chain_name}");
            let required: u64 =
                resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                    .await?;
            if u64::try_from(block_confirmation).is_ok_and(|requested| requested >= required) {
                return Ok(());
            }
            Err(AppCoreError::BadRequest(format!(
                "blockConfirmation {block_confirmation} is below the {required} confirmations \
                 the destination receive config requires"
            )))
        })
        .await
    }
}

fn is_chain_native_payload_signed_destination(dst_chain_name: &str) -> bool {
    matches!(
        dst_chain_name,
        "solana"
            | "aptos"
            | "initia"
            | "movement"
            | "starknet"
            | "ton"
            | "sui"
            | "iotal1"
            | "stellar"
            | "canton"
    )
}

pub(crate) fn payload_signed_validation_result(
    validity: PayloadSignedValidity,
    sent_event: &LzSentEvent,
    dst_chain_name: &str,
) -> Result<(), AppCoreError> {
    match validity {
        PayloadSignedValidity::NotSigned => Ok(()),
        PayloadSignedValidity::Signed => Err(AppCoreError::BadRequest(format!(
            "{} for message {} on chain {}",
            PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX,
            crate::provider_health::resolved_message_id_json(&sent_event.lz_message_id),
            dst_chain_name,
        ))),
        PayloadSignedValidity::Missing => Err(AppCoreError::Internal(format!(
            "Payload-signed validation unavailable for chain {dst_chain_name}"
        ))),
        // Nothing about retrying changes the receiver's configuration, so this
        // is the caller's problem to fix, the same classification upstream's
        // `NonRetryableError` gets.
        PayloadSignedValidity::UnsupportedReceiveLibrary => Err(AppCoreError::BadRequest(format!(
            "Receiver {} on chain {} receives on a library this service cannot validate; \
                 refusing to sign",
            pathway_extra_string_value(sent_event, "receiver")
                .unwrap_or_else(|_| "<unknown>".to_string()),
            dst_chain_name,
        ))),
    }
}

struct AptosV301Observation<'a> {
    contracts: &'a AptosV301Contracts,
    receiver: &'a str,
    receiver_bytes32: &'a str,
    src_eid: u32,
    sender: &'a str,
    nonce: u64,
    verifier_address: &'a str,
    packet_header: &'a str,
    payload_hash: &'a str,
}

async fn observe_aptos_v301_payload_signed<T>(
    transport: T,
    base_url: String,
    headers: HashMap<String, String>,
    observation: AptosV301Observation<'_>,
) -> Result<(String, PayloadSignedValidity), RpcError>
where
    T: JsonRpcTransport,
{
    use sha3::{Digest, Keccak256};

    let AptosV301Observation {
        contracts,
        receiver,
        receiver_bytes32,
        src_eid,
        sender,
        nonce,
        verifier_address,
        packet_header,
        payload_hash,
    } = observation;
    let view = |function: String, arguments: Vec<&str>, types: &'static [&'static str]| {
        let transport = transport.clone();
        let base_url = base_url.clone();
        let headers = headers.clone();
        let arguments: Vec<String> = arguments.into_iter().map(str::to_string).collect();
        async move {
            let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
            move_view_values(
                &transport, "aptos", &base_url, headers, &function, &arguments, types,
            )
            .await
        }
    };
    let src_eid = src_eid.to_string();
    // `getUlnReceiveDetails`: only (2, 0) is ULN301; anything else is V2, for which
    // upstream has no receive config and refuses.
    let library = view(
        format!("{}::endpoint_view::get_receive_msglib", contracts.view),
        vec![receiver_bytes32, &src_eid],
        &["address", "u64"],
    )
    .await?;
    let version = (
        library.first().and_then(move_u64),
        library.get(1).and_then(move_u64),
    );
    if version != (Some(2), Some(0)) {
        return Ok((
            format!("library:{version:?}"),
            PayloadSignedValidity::UnsupportedReceiveLibrary,
        ));
    }
    let config = view(
        format!("{}::endpoint_view::get_config", contracts.view),
        vec![receiver, "2", "0", &src_eid, "3"],
        &["address", "u64", "u8", "u64", "u8"],
    )
    .await?;
    let required_confirmations = config
        .first()
        .and_then(Value::as_str)
        .and_then(move_uln_config_confirmations)
        .ok_or(RpcError::Unavailable)?;
    let header =
        hex::decode(packet_header.trim_start_matches("0x")).map_err(|_| RpcError::Unavailable)?;
    let header_hash = format!("0x{}", hex::encode(Keccak256::digest(header)));
    let confirmations = view(
        format!(
            "{}::msglib::get_verification_confirmations",
            contracts.uln_301
        ),
        vec![&header_hash, payload_hash, verifier_address],
        &["vector<u8>", "vector<u8>", "address"],
    )
    .await?;
    // Upstream reads `length > 0 && Number(result[0]) >= confirmations`, but the view returns 0
    // for a DVN with no record, which the chain's `is_verified` treats as unverified (M-21).
    let confirmations = match confirmations.first() {
        None => None,
        Some(value) => Some(move_u64(value).ok_or(RpcError::Unavailable)?),
    };
    let dvn_confirmed =
        confirmations.is_some_and(|count| count > 0 && count >= required_confirmations);
    let verification_state = view(
        format!("{}::uln_301::verifiable", contracts.view_uln301),
        vec![packet_header, payload_hash],
        &["vector<u8>", "vector<u8>"],
    )
    .await?
    .first()
    .and_then(move_u8)
    .ok_or(RpcError::Unavailable)?;
    if verification_state > 4 {
        return Err(RpcError::Remote(format!(
            "Unknown Aptos V301 verification state: {verification_state}"
        )));
    }
    // Upstream maps 2 (VERIFIED) to signed; only 0 (VERIFYING) triggers nonce/hash reads.
    let verified = if verification_state == 2 {
        Some((0, None, true))
    } else if verification_state != 0 {
        Some((0, None, false))
    } else {
        let inbound_nonce = view(
            format!("{}::endpoint_view::inbound_nonce", contracts.view),
            vec![receiver, &src_eid, sender],
            &["address", "u64", "vector<u8>"],
        )
        .await?
        .first()
        .and_then(move_u64)
        .ok_or(RpcError::Unavailable)?;
        let stored_hash = if nonce <= inbound_nonce {
            None
        } else {
            Some(
                aptos_v1_payload_hash(
                    &transport, &base_url, &headers, contracts, receiver, &src_eid, sender, nonce,
                )
                .await?,
            )
        };
        let verified =
            nonce <= inbound_nonce || stored_hash.as_ref().is_some_and(|hash| hash != "");
        Some((inbound_nonce, stored_hash, verified))
    };
    let signed = dvn_confirmed || verified.as_ref().is_some_and(|(_, _, verified)| *verified);
    let validity = if signed {
        PayloadSignedValidity::Signed
    } else {
        PayloadSignedValidity::NotSigned
    };
    Ok((
        format!("{required_confirmations}:{confirmations:?}:{verification_state}:{verified:?}"),
        validity,
    ))
}

/// Upstream `getPayloadHash` (`uln/aptos/index.ts:417-465`): the receiver's V1
/// `Channels` table entry for the remote, then its `payload_hashs` entry for the nonce.
/// An HTTP 404 for either, as for a missing resource, means no stored hash (`""`).
#[allow(clippy::too_many_arguments)]
async fn aptos_v1_payload_hash<T>(
    transport: &T,
    base_url: &str,
    headers: &HashMap<String, String>,
    contracts: &AptosV301Contracts,
    receiver: &str,
    src_eid: &str,
    sender: &str,
    nonce: u64,
) -> Result<Value, RpcError>
where
    T: JsonRpcTransport,
{
    let base = base_url.trim_end_matches('/');
    let layerzero = &contracts.layerzero;
    let lookup = async {
        let account = encode_path_segment(receiver).ok_or(RpcError::Unavailable)?;
        let channels = transport
            .get_json_scoped(
                format!("{base}/accounts/{account}/resource/{layerzero}::channel::Channels"),
                headers.clone(),
            )
            .await?;
        let states = channels
            .pointer("/data/states/handle")
            .and_then(Value::as_str)
            .and_then(encode_path_segment)
            .ok_or(RpcError::Unavailable)?;
        let channel = transport
            .post_json_scoped(
                format!("{base}/tables/{states}/item"),
                headers.clone(),
                json!({
                    "key_type": format!("{layerzero}::channel::Remote"),
                    "value_type": format!("{layerzero}::channel::Channel"),
                    "key": { "chain_id": src_eid, "addr": sender },
                }),
            )
            .await?;
        let payload_hashes = channel
            .pointer("/payload_hashs/handle")
            .and_then(Value::as_str)
            .and_then(encode_path_segment)
            .ok_or(RpcError::Unavailable)?;
        transport
            .post_json_scoped(
                format!("{base}/tables/{payload_hashes}/item"),
                headers.clone(),
                json!({
                    "key_type": "u64",
                    "value_type": "vector<u8>",
                    "key": nonce.to_string(),
                }),
            )
            .await
    };
    match lookup.await {
        Err(error) if is_http_not_found(&error) => Ok(Value::from("")),
        other => other,
    }
}

/// `Number(value)` for a Move view's u64, which the Aptos API renders as a string.
fn move_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

fn move_u8(value: &Value) -> Option<u8> {
    u8::try_from(move_u64(value)?).ok()
}

/// Upstream `getAddressEncodedByChain` for an EVM chain: the last 20 bytes of the
/// value left-padded to 32, lower-cased.
fn evm_address_from_padded_hex(value: &str) -> Option<String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.len() > 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{digits:0>64}");
    Some(format!("0x{}", padded[24..].to_ascii_lowercase()))
}

/// Upstream `getAddressInHex("aptos", …)`: 32 bytes, zero-padded, lower-cased.
fn aptos_address_bytes32(value: &str) -> Option<String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.is_empty()
        || digits.len() > 64
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(format!("0x{:0>64}", digits.to_ascii_lowercase()))
}

struct MovePayloadSignedObservation<'a> {
    chain_name: &'a str,
    endpoint_v2: &'a str,
    uln_302: &'a str,
    views: &'a str,
    receiver: &'a str,
    src_eid: u32,
    verifier_address: &'a str,
    packet_header: &'a str,
    payload_hash: &'a str,
}

async fn observe_move_payload_signed<T>(
    transport: T,
    base_url: String,
    headers: HashMap<String, String>,
    observation: MovePayloadSignedObservation<'_>,
) -> Result<(String, PayloadSignedValidity), RpcError>
where
    T: JsonRpcTransport,
{
    use sha3::{Digest, Keccak256};

    let MovePayloadSignedObservation {
        chain_name,
        endpoint_v2,
        uln_302,
        views,
        receiver,
        src_eid,
        verifier_address,
        packet_header,
        payload_hash,
    } = observation;
    // `None` throughout: upstream's provider rejects when a view cannot be
    // read, so a provider that failed contributes nothing to the quorum rather
    // than agreeing with every other provider that also failed.
    let Ok(header) = hex::decode(packet_header.trim_start_matches("0x")) else {
        return Err(RpcError::Unavailable);
    };
    let header_hash = format!("0x{}", hex::encode(Keccak256::digest(header)));
    let src_eid = src_eid.to_string();
    let receiver_bytes32 = aptos_address_bytes32(receiver).ok_or(RpcError::Unavailable)?;
    let receive_library = move_view_value(
        &transport,
        chain_name,
        &base_url,
        headers.clone(),
        &format!("{endpoint_v2}::endpoint::get_effective_receive_library"),
        &[&receiver_bytes32, &src_eid],
        &["address", "u32"],
    )
    .await?
    .as_str()
    .and_then(aptos_address_bytes32)
    .ok_or(RpcError::Unavailable)?;
    let config = move_view_value(
        &transport,
        chain_name,
        &base_url,
        headers.clone(),
        &format!("{endpoint_v2}::endpoint::get_config"),
        &[receiver, uln_302, &src_eid, "3"],
        &["address", "address", "u32", "u32"],
    )
    .await?;
    let required_confirmations = config
        .as_str()
        .and_then(move_uln_config_confirmations)
        .ok_or(RpcError::Unavailable)?;
    let state = move_view_numeric(
        &transport,
        chain_name,
        &base_url,
        headers.clone(),
        &format!("{views}::uln_302::verifiable"),
        &[packet_header, payload_hash],
        &["vector<u8>", "vector<u8>"],
    )
    .await?;
    // Upstream `mapVerificationState` accepts enum values 0..=4 and throws for
    // every other numeric state; a provider error must not vote as unsigned.
    if state > 4 {
        return Err(RpcError::Unavailable);
    }
    let confirmation_values = move_view_values(
        &transport,
        chain_name,
        &base_url,
        headers,
        &format!("{uln_302}::msglib::get_verification_confirmations"),
        &[&header_hash, payload_hash, verifier_address],
        &["vector<u8>", "vector<u8>", "address"],
    )
    .await?;
    // The view returns 0 for a DVN with no record (`[]` never comes back); the chain's
    // `is_verified` treats that as unverified even when 0 are required, so only a positive
    // count signs (M-21, a deliberate departure from upstream's `>=`). Malformed present
    // values still throw and remove this provider's vote.
    let confirmations = match confirmation_values.first() {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .or_else(|| value.as_str()?.parse().ok())
                .ok_or(RpcError::Unavailable)?,
        ),
    };
    let validity = if state == 2
        || confirmations.is_some_and(|value| value > 0 && value >= required_confirmations)
    {
        PayloadSignedValidity::Signed
    } else {
        PayloadSignedValidity::NotSigned
    };
    Ok((
        format!("{receive_library}:{state}:{confirmations:?}:{required_confirmations}"),
        validity,
    ))
}

fn move_uln_config_confirmations(encoded: &str) -> Option<u64> {
    let bytes = hex::decode(encoded.trim_start_matches("0x")).ok()?;
    let confirmations = bytes.get(..8)?.try_into().ok()?;
    let required_count = usize::from(*bytes.get(9)?);
    let optional_count_at = 10 + required_count * 32;
    let optional_count = usize::from(*bytes.get(optional_count_at)?);
    let flags_at = optional_count_at + 1 + optional_count * 32;
    let flags = bytes.get(flags_at..)?;
    if flags.len() != 3 || flags.iter().any(|flag| *flag > 1) {
        return None;
    }
    // Move's encoded ULN config uses network byte order, not BCS integer encoding.
    Some(u64::from_be_bytes(confirmations))
}

async fn move_view_value<T>(
    transport: &T,
    chain_name: &str,
    base_url: &str,
    headers: HashMap<String, String>,
    function: &str,
    arguments: &[&str],
    argument_types: &[&str],
) -> Result<Value, RpcError>
where
    T: JsonRpcTransport,
{
    move_view_values(
        transport,
        chain_name,
        base_url,
        headers,
        function,
        arguments,
        argument_types,
    )
    .await?
    .into_iter()
    .next()
    .ok_or(RpcError::Unavailable)
}

/// The Aptos REST `/view` JSON contract: integers up to `u32` are JSON numbers and
/// wider ones decimal strings; a public fullnode answers any other shape with HTTP 400.
fn aptos_view_argument(value: &str, move_type: &str) -> Option<Value> {
    match move_type {
        "u8" => Some(Value::from(value.parse::<u8>().ok()?)),
        "u16" => Some(Value::from(value.parse::<u16>().ok()?)),
        "u32" => Some(Value::from(value.parse::<u32>().ok()?)),
        "u64" => value.parse::<u64>().ok().map(|_| Value::from(value)),
        "u128" => value.parse::<u128>().ok().map(|_| Value::from(value)),
        "address" | "vector<u8>" => Some(Value::from(value)),
        _ => None,
    }
}

async fn move_view_values<T>(
    transport: &T,
    chain_name: &str,
    base_url: &str,
    headers: HashMap<String, String>,
    function: &str,
    arguments: &[&str],
    argument_types: &[&str],
) -> Result<Vec<Value>, RpcError>
where
    T: JsonRpcTransport,
{
    if chain_name == "initia" {
        let mut function_parts = function.split("::");
        let account = function_parts.next().ok_or(RpcError::Unavailable)?;
        let module = function_parts.next().ok_or(RpcError::Unavailable)?;
        let function_name = function_parts.next().ok_or(RpcError::Unavailable)?;
        if function_parts.next().is_some() {
            return Err(RpcError::Unavailable);
        }
        let encoded_arguments = arguments
            .iter()
            .zip(argument_types)
            .map(|(argument, argument_type)| initia_bcs_argument(argument, argument_type))
            .collect::<Option<Vec<_>>>()
            .ok_or(RpcError::Unavailable)?;
        let response = transport
            .post_json_scoped(
                format!(
        "{}/initia/move/v1/accounts/{account}/modules/{module}/view_functions/{function_name}",
        base_url.trim_end_matches('/')
    ),
                headers,
                json!({"type_args": [], "args": encoded_arguments}),
            )
            .await?;
        initia_view_values(&response, function_name).ok_or(RpcError::Unavailable)
    } else {
        let encoded_arguments = arguments
            .iter()
            .zip(argument_types)
            .map(|(argument, argument_type)| aptos_view_argument(argument, argument_type))
            .collect::<Option<Vec<_>>>()
            .ok_or(RpcError::Unavailable)?;
        let response = transport
            .post_json_scoped(
                format!("{}/view", base_url.trim_end_matches('/')),
                headers,
                json!({
                    "function": function,
                    "type_arguments": [],
                    "arguments": encoded_arguments,
                }),
            )
            .await?;
        response.as_array().cloned().ok_or(RpcError::Unavailable)
    }
}

async fn move_view_numeric<T>(
    transport: &T,
    chain_name: &str,
    base_url: &str,
    headers: HashMap<String, String>,
    function: &str,
    arguments: &[&str],
    argument_types: &[&str],
) -> Result<u64, RpcError>
where
    T: JsonRpcTransport,
{
    let value = move_view_value(
        transport,
        chain_name,
        base_url,
        headers,
        function,
        arguments,
        argument_types,
    )
    .await?;
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .ok_or(RpcError::Unavailable)
}

fn initia_view_values(response: &Value, function: &str) -> Option<Vec<Value>> {
    let data = response.get("data")?.as_str()?;
    let values =
        match crate::provider_health::parse_json_with_limits(data.as_bytes(), false).ok()? {
            Value::Array(values) => values,
            value => vec![value],
        };
    let valid_arity = if function == "get_effective_receive_library" {
        values.len() == 2 && values[1].is_boolean()
    } else {
        values.len() == 1
    };
    valid_arity.then_some(values)
}

fn initia_bcs_argument(value: &str, argument_type: &str) -> Option<String> {
    use base64::Engine;

    let mut bytes = match argument_type {
        "vector<u8>" => {
            let value = hex::decode(value.trim_start_matches("0x")).ok()?;
            let mut encoded = encode_uleb128(value.len());
            encoded.extend(value);
            encoded
        }
        "address" => {
            let value = hex::decode(value.trim_start_matches("0x")).ok()?;
            if value.len() > 32 {
                return None;
            }
            let mut encoded = vec![0; 32 - value.len()];
            encoded.extend(value);
            encoded
        }
        "u32" => value.parse::<u32>().ok()?.to_le_bytes().to_vec(),
        _ => return None,
    };
    Some(base64::engine::general_purpose::STANDARD.encode(&mut bytes))
}

fn encode_uleb128(mut value: usize) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

/// `UltraLightNode302._verified` for this DVN: `submitted && confirmations >= required`,
/// with `required` the OApp's effective receive confirmations. The contract's own
/// `has_payload_signed`, which upstream calls, is true for any stored verification,
/// so a below-requirement one that `commit` never counts would pin the duplicate
/// check while `verify` would overwrite it. The verification is read from storage
/// because no view returns it; the slot derivation is pinned against mainnet in
/// `tests/onchain_provenance/starknet_hash_lookup.json`.
async fn observe_starknet_payload_signed<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    uln_address: &str,
    verifier_address: &str,
    packet_header: &str,
    payload_hash: &str,
) -> Result<PayloadSignedValidity, RpcError>
where
    T: JsonRpcTransport,
{
    let Ok(header) = decode_bytes32_or_longer(packet_header) else {
        return Err(RpcError::Unavailable);
    };
    let Ok(payload_hash) = decode_bytes32(payload_hash) else {
        return Err(RpcError::Unavailable);
    };
    let Some((src_eid, receiver)) = starknet_header_receive_path(&header) else {
        return Err(RpcError::Unavailable);
    };
    use sha3::{Digest, Keccak256};
    let header_hash: [u8; 32] = Keccak256::digest(&header).into();
    let Some(slot) = starknet_hash_lookup_slot(&header_hash, &payload_hash, verifier_address)
    else {
        return Err(RpcError::Unavailable);
    };
    let read_slot = |offset: u8| {
        let key = starknet_slot_offset(&slot, offset);
        let transport = transport.clone();
        let (url, headers) = (url.clone(), headers.clone());
        async move {
            let response = transport
                .post_json_scoped(
                    url,
                    headers,
                    json!({
                        "method": "starknet_getStorageAt",
                        "params": [uln_address, key, "latest"],
                        "id": 1,
                        "jsonrpc": "2.0",
                    }),
                )
                .await?;
            response
                .get("result")
                .and_then(Value::as_str)
                .and_then(starknet_felt_u64)
                .ok_or(RpcError::Unavailable)
        }
    };
    match read_slot(0).await? {
        0 => return Ok(PayloadSignedValidity::NotSigned),
        1 => {}
        _ => return Err(RpcError::Unavailable),
    }
    let stored = read_slot(1).await?;
    let required = observe_starknet_required_confirmations(
        &transport,
        url,
        headers,
        uln_address,
        &receiver,
        src_eid,
    )
    .await?;
    Ok(if stored >= required {
        PayloadSignedValidity::Signed
    } else {
        PayloadSignedValidity::NotSigned
    })
}

/// `get_oapp_uln_receive_config(receiver, src_eid)`: the effective receive config,
/// whose first serialized member is `confirmations`.
pub(crate) async fn observe_starknet_required_confirmations<T>(
    transport: &T,
    url: String,
    headers: HashMap<String, String>,
    uln_address: &str,
    receiver: &str,
    src_eid: u32,
) -> Result<u64, RpcError>
where
    T: JsonRpcTransport,
{
    let response = transport
        .post_json_scoped(
            url,
            headers,
            json!({
                "method": "starknet_call",
                "params": [{
                    "contract_address": uln_address,
                    "entry_point_selector": starknet_selector("get_oapp_uln_receive_config"),
                    "calldata": [normalize_starknet_felt(receiver), format!("0x{src_eid:x}")],
                }, "latest"],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await?;
    response
        .get("result")
        .and_then(Value::as_array)
        .and_then(|result| result.first())
        .and_then(Value::as_str)
        .and_then(starknet_felt_u64)
        .ok_or(RpcError::Unavailable)
}

/// `srcEid` and `receiver` of a PacketV1 header: version(1) nonce(8) srcEid(4)
/// sender(32) dstEid(4) receiver(32).
pub(crate) fn starknet_header_receive_path(header: &[u8]) -> Option<(u32, String)> {
    if header.len() != 81 {
        return None;
    }
    let src_eid = u32::from_be_bytes(header[9..13].try_into().ok()?);
    Some((src_eid, format!("0x{}", hex::encode(&header[49..81]))))
}

/// `hash_lookup.entry(header_hash).entry(payload_hash).entry(dvn)`: Pedersen over
/// `sn_keccak("hash_lookup")`, each `Bytes32` as its `u256` low then high half, then
/// the DVN address, reduced into the storage address range `[0, 2^251 - 256)`.
pub(crate) fn starknet_hash_lookup_slot(
    header_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    dvn: &str,
) -> Option<num_bigint::BigUint> {
    use starknet_crypto::{pedersen_hash, Felt};
    let half = |bytes: &[u8]| {
        let mut word = [0u8; 32];
        word[16..].copy_from_slice(bytes);
        Felt::from_bytes_be(&word)
    };
    let mut state = Felt::from_hex(&starknet_selector("hash_lookup")).ok()?;
    for hash in [header_hash, payload_hash] {
        state = pedersen_hash(&state, &half(&hash[16..]));
        state = pedersen_hash(&state, &half(&hash[..16]));
    }
    state = pedersen_hash(&state, &Felt::from_hex(&normalize_starknet_felt(dvn)).ok()?);
    let bound = (num_bigint::BigUint::from(1u8) << 251u32) - 256u32;
    Some(num_bigint::BigUint::from_bytes_be(&state.to_bytes_be()) % bound)
}

fn starknet_slot_offset(slot: &num_bigint::BigUint, offset: u8) -> String {
    format!("0x{:x}", slot + offset)
}

fn starknet_felt_u64(value: &str) -> Option<u64> {
    let digits = value.strip_prefix("0x")?.trim_start_matches('0');
    if digits.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(digits, 16).ok()
}

fn decode_bytes32(value: &str) -> Result<[u8; 32], hex::FromHexError> {
    let decoded = hex::decode(value.trim_start_matches("0x"))?;
    if decoded.len() != 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    Ok(decoded.try_into().expect("length checked"))
}

fn decode_bytes32_or_longer(value: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let decoded = hex::decode(value.trim_start_matches("0x"))?;
    if decoded.len() < 32 {
        return Err(hex::FromHexError::InvalidStringLength);
    }
    Ok(decoded)
}

fn normalize_starknet_felt(value: &str) -> String {
    let normalized = value.trim_start_matches("0x").trim_start_matches('0');
    format!(
        "0x{}",
        if normalized.is_empty() {
            "0"
        } else {
            normalized
        }
    )
}

fn starknet_selector(name: &str) -> String {
    use sha3::{Digest, Keccak256};
    let mut hash: [u8; 32] = Keccak256::digest(name.as_bytes()).into();
    hash[0] &= 0x03;
    normalize_starknet_felt(&hex::encode(hash))
}
