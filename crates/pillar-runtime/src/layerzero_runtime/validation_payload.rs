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
    ) -> Result<(), AppCoreError> {
        crate::provider_health::rpc_scope(
            &sent_event.lz_message_id.pathway_id.dst_chain_name,
            async {
                // No guid means a ULN V1 message, and the chain-native already-signed
                // read is a V2 construct: there is no V2 payload to ask about, so there
                // is nothing being skipped. This is a protocol distinction, NOT a check
                // being dropped - a security review read it as fail-open. The two tests
                // that pin it are `..._skips_legacy_payload_without_guid` and
                // `..._skips_ton_payload_without_guid`, whose own assertion message says
                // "V1 messages are skipped".
                //
                // Contrast the Stellar arm below, which refuses. That is a different
                // condition - a V2 pathway whose check is genuinely unavailable - and it
                // correctly fails closed.
                if !sent_event.extra.contains_key("guid") {
                    return Ok(());
                }
                if is_chain_native_payload_signed_destination(dst_chain_name) {
                    // Without an address the question "has this DVN already signed?" has no
                    // subject, so skip the caller-selected duplicate query rather than refuse
                    // the request. Upstream gates the same call at apps/gasolina/src/app/app.ts:494.
                    // The EVM arm below is different: its receive-library resolution needs no
                    // address, so it remains unconditional.
                    let Some(verifier_address) = verifier_address else {
                        return Ok(());
                    };
                    return self
                        .validate_chain_native_payload_not_signed_with_quorum(
                            sent_event,
                            verifier_address,
                            dst_chain_name,
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
    ) -> Result<(), AppCoreError> {
        let uln_version = uln_version_value(&sent_event.lz_message_id)
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
    // `confirmationResult.length > 0 && Number(confirmationResult[0]) >= confirmations`.
    let confirmations = match confirmations.first() {
        None => None,
        Some(value) => Some(move_u64(value).ok_or(RpcError::Unavailable)?),
    };
    let dvn_confirmed = confirmations.is_some_and(|count| count >= required_confirmations);
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
    if digits.len() > 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
    // Upstream treats an empty vector as false even when required confirmations is 0;
    // malformed present values still throw and remove this provider's vote.
    let confirmations = match confirmation_values.first() {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .or_else(|| value.as_str()?.parse().ok())
                .ok_or(RpcError::Unavailable)?,
        ),
    };
    let validity =
        if state == 2 || confirmations.is_some_and(|value| value >= required_confirmations) {
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
    // Gasolina's pinned `deserializeUlnConfig` uses common-move `extractU64`,
    // which decodes this contract-owned blob in network byte order. This is not
    // generic Move BCS integer decoding.
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
    let response = if chain_name == "initia" {
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
        transport
            .post_json_scoped(
                format!(
        "{}/initia/move/v1/accounts/{account}/modules/{module}/view_functions/{function_name}",
        base_url.trim_end_matches('/')
    ),
                headers,
                json!({"type_args": [], "args": encoded_arguments}),
            )
            .await?
    } else {
        let encoded_arguments = arguments
            .iter()
            .zip(argument_types)
            .map(|(argument, argument_type)| aptos_view_argument(argument, argument_type))
            .collect::<Option<Vec<_>>>()
            .ok_or(RpcError::Unavailable)?;
        transport
            .post_json_scoped(
                format!("{}/view", base_url.trim_end_matches('/')),
                headers,
                json!({
                    "function": function,
                    "type_arguments": [],
                    "arguments": encoded_arguments,
                }),
            )
            .await?
    };
    move_view_result_values(&response).ok_or(RpcError::Unavailable)
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

fn move_view_result_values(response: &Value) -> Option<Vec<Value>> {
    let decoded = response
        .get("data")
        .and_then(Value::as_str)
        .and_then(|data| serde_json::from_str::<Value>(data).ok());
    let response = decoded.as_ref().unwrap_or(response);
    response.as_array().cloned()
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
    use sha3::{Digest, Keccak256};
    let header_hash: [u8; 32] = Keccak256::digest(header).into();
    let calldata = [
        starknet_u256_low(&header_hash),
        starknet_u256_high(&header_hash),
        starknet_u256_low(&payload_hash),
        starknet_u256_high(&payload_hash),
        normalize_starknet_felt(verifier_address),
    ];
    let response = transport
        .post_json_scoped(
            url,
            headers,
            json!({
                "method": "starknet_call",
                "params": [{
                    "contract_address": uln_address,
                    "entry_point_selector": starknet_selector("has_payload_signed"),
                    "calldata": calldata,
                }, "latest"],
                "id": 1,
                "jsonrpc": "2.0",
            }),
        )
        .await?;
    match Some(response)
        .and_then(|response| {
            response
                .get("result")?
                .as_array()?
                .first()?
                .as_str()
                .map(str::to_string)
        })
        .as_deref()
    {
        Some("0x0" | "0") => Ok(PayloadSignedValidity::NotSigned),
        Some("0x1" | "1") => Ok(PayloadSignedValidity::Signed),
        _ => Err(RpcError::Unavailable),
    }
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

fn starknet_u256_low(value: &[u8; 32]) -> String {
    normalize_starknet_felt(&hex::encode(&value[16..]))
}

fn starknet_u256_high(value: &[u8; 32]) -> String {
    normalize_starknet_felt(&hex::encode(&value[..16]))
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
