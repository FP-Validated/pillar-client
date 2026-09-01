use super::*;

const ANCHOR_EVENT_EMIT_DISCRIMINATOR: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];
const PACKET_SENT_EVENT_DISCRIMINATOR: [u8; 8] = [0x00, 0x5c, 0xa7, 0xc9, 0x8b, 0x2e, 0xab, 0x52];

fn normalize_move_account_for_resolver(address: &str) -> String {
    let value = strip_hex_prefix(address).to_ascii_lowercase();
    format!("0x{value:0>64}")
}

#[derive(Clone)]
pub struct EvmPacketSentResolver<T> {
    providers: crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    config: EvmPacketSentResolverConfig,
    metrics: Option<Arc<tokio::sync::Mutex<PillarMetrics>>>,
}

impl<T> EvmPacketSentResolver<T>
where
    T: JsonRpcTransport,
{
    pub fn new(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        config: EvmPacketSentResolverConfig,
    ) -> Self {
        Self {
            providers: providers.clone(),
            transport,
            config: EvmPacketSentResolverConfig {
                chain_name_by_eid: config.chain_name_by_eid,
                uln_version_by_send_library_address_by_chain_name: config
                    .uln_version_by_send_library_address_by_chain_name
                    .into_iter()
                    .map(|(chain_name, versions)| (chain_name, normalize_address_map(versions)))
                    .collect(),
                trusted_packet_emitters_by_chain_name: config
                    .trusted_packet_emitters_by_chain_name
                    .into_iter()
                    .map(|(chain_name, emitters)| {
                        (
                            chain_name,
                            emitters
                                .into_iter()
                                .map(|emitter| normalize_address(&emitter))
                                .collect(),
                        )
                    })
                    .collect(),
                trusted_solana_endpoint_program_ids: config.trusted_solana_endpoint_program_ids,
                trusted_solana_send_library_addresses: config.trusted_solana_send_library_addresses,
                trusted_starknet_endpoint_addresses: config
                    .trusted_starknet_endpoint_addresses
                    .into_iter()
                    .map(|address| normalize_move_account_for_resolver(&address))
                    .collect(),
                trusted_stellar_endpoint_addresses: config
                    .trusted_stellar_endpoint_addresses
                    .into_iter()
                    .map(|address| normalize_stellar_address(&address))
                    .collect(),
                trusted_ton_packet_emitters_by_chain_name: config
                    .trusted_ton_packet_emitters_by_chain_name
                    .into_iter()
                    .map(|(chain_name, emitters)| {
                        (
                            chain_name,
                            emitters
                                .into_iter()
                                .map(|emitter| normalize_ton_address(&emitter))
                                .collect(),
                        )
                    })
                    .collect(),
                trusted_move_packet_emitters_by_chain_name: config
                    .trusted_move_packet_emitters_by_chain_name
                    .into_iter()
                    .map(|(chain_name, emitters)| {
                        (
                            chain_name,
                            emitters
                                .into_iter()
                                .map(|emitter| normalize_move_account_for_resolver(&emitter))
                                .collect(),
                        )
                    })
                    .collect(),
            },
            metrics: None,
        }
    }

    pub fn with_metrics(mut self, metrics: Arc<tokio::sync::Mutex<PillarMetrics>>) -> Self {
        self.metrics = Some(metrics);
        self
    }
    async fn get_receipt_logs(
        &self,
        src_chain_name: &str,
        src_tx_hash: &str,
    ) -> Result<Vec<EvmReceiptLog>, AppCoreError> {
        let result = self
            .get_quorum_rpc_result(
                src_chain_name,
                json!({
                    "method": "eth_getTransactionReceipt",
                    "params": [src_tx_hash],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
                "receipt",
            )
            .await?;
        if result.is_null() {
            return Err(AppCoreError::Internal(format!(
                "Transaction receipt not found for {src_tx_hash}"
            )));
        }
        let receipt: EvmTransactionReceipt = serde_json::from_value(result)
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        Ok(receipt.logs)
    }

    async fn get_solana_transaction(
        &self,
        src_chain_name: &str,
        src_tx_hash: &str,
    ) -> Result<Value, AppCoreError> {
        let result = self
            .get_quorum_rpc_result(
                src_chain_name,
                json!({
                    "method": "getTransaction",
                    "params": [
                        src_tx_hash,
                        {

                            "encoding": "jsonParsed",
                            "commitment": "finalized",
                            "maxSupportedTransactionVersion": 0,
                        },
                    ],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
                "Solana transaction",
            )
            .await?;
        if result.is_null() {
            return Err(AppCoreError::Internal(format!(
                "Transaction not found for {src_tx_hash}"
            )));
        }
        Ok(result)
    }
    async fn get_move_transaction(
        &self,
        chain_name: &str,
        src_tx_hash: &str,
    ) -> Result<Value, AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(chain_name)?;
        let quorum = required_provider_quorum(provider_config, chain_name)?;
        let mut requests = FuturesUnordered::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let transport = self.transport.clone();
            let (url, headers) = move_provider_uri_parts(chain_name, uri);
            let chain_name = chain_name.to_string();
            let tx_hash = src_tx_hash.to_string();
            requests.push(async move {
                (
                    index,
                    fetch_move_transaction(transport, &chain_name, url, headers, &tx_hash).await,
                )
            });
        }
        let mut accumulator = ExactQuorumAccumulator::new(provider_config.uris.len(), quorum);
        while let Some((index, response)) = requests.next().await {
            let observation = response
                .ok()
                .and_then(|value| serde_json::to_string(&value).ok().map(|key| (key, value)));
            accumulator.record(index, observation);
            if let Some(value) = accumulator.unambiguous_result() {
                return Ok(value);
            }
        }
        self.finish_quorum(
            chain_name,
            accumulator,
            &format!("Move transaction for {src_tx_hash}"),
        )
        .await
    }
    async fn get_sui_events(
        &self,
        chain_name: &str,
        src_tx_hash: &str,
    ) -> Result<Value, AppCoreError> {
        self.get_quorum_rpc_result(
            chain_name,
            json!({
                "method": sui_rpc_method(chain_name, "queryEvents"),
                "params": [{"Transaction": src_tx_hash}, null, null, true],
                "id": 1,
                "jsonrpc": "2.0",
            }),
            "Sui transaction events",
        )
        .await
    }

    fn move_packet_to_lz_sent_event(
        &self,
        expected_src_chain_name: &str,
        src_tx_hash: &str,
        event: MovePacketSentEvent,
    ) -> Result<LzSentEvent, AppCoreError> {
        let src_chain_name = self.chain_name_for_eid(event.packet.src_eid)?;
        if src_chain_name != expected_src_chain_name {
            return Err(AppCoreError::Internal(
                "Move PacketSent source chain mismatch".to_string(),
            ));
        }
        let dst_chain_name = self.chain_name_for_eid(event.packet.dst_eid)?;
        let mut pathway_extra = IndexMap::new();
        pathway_extra.insert("srcEid".to_string(), Value::from(event.packet.src_eid));
        pathway_extra.insert("dstEid".to_string(), Value::from(event.packet.dst_eid));
        pathway_extra.insert(
            "sender".to_string(),
            Value::from(event.packet.sender.clone()),
        );
        pathway_extra.insert(
            "receiver".to_string(),
            Value::from(event.packet.receiver.clone()),
        );
        let mut extra = IndexMap::new();
        extra.insert("guid".to_string(), Value::from(event.packet.guid));
        extra.insert("options".to_string(), Value::from(event.options));
        extra.insert(
            "sendLibrary".to_string(),
            event
                .send_library
                .clone()
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        extra.insert(
            "packetEmitAddress".to_string(),
            Value::from(event.endpoint_address),
        );
        Ok(LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name,
                    dst_chain_name,
                    extra: pathway_extra,
                },
                nonce: event.packet.nonce,
                uln_send_version: Value::from(if event.send_library.is_some() {
                    ULN_VERSION_V302
                } else {
                    ULN_VERSION_V301
                }),
            },
            message: event.packet.message,
            tx_hash: src_tx_hash.to_string(),
            extra,
        })
    }

    async fn get_quorum_rpc_result(
        &self,
        chain_name: &str,
        body: Value,
        context: &str,
    ) -> Result<Value, AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(chain_name)?;
        let quorum = required_provider_quorum(provider_config, chain_name)?;
        let mut requests = FuturesUnordered::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let transport = self.transport.clone();
            let (url, headers) = provider_uri_parts(uri);
            let body = body.clone();
            requests.push(async move { (index, transport.post_json(url, headers, body).await) });
        }
        let mut accumulator = ExactQuorumAccumulator::new(provider_config.uris.len(), quorum);
        while let Some((index, response)) = requests.next().await {
            let observation = response
                .ok()
                .and_then(|response| response.get("result").cloned())
                .map(|result| {
                    serde_json::to_string(&result)
                        .map(|fingerprint| (fingerprint, result))
                        .map_err(|error| AppCoreError::Internal(error.to_string()))
                })
                .transpose()?;
            accumulator.record(index, observation);
            if let Some(result) = accumulator.unambiguous_result() {
                return Ok(result);
            }
        }

        self.finish_quorum(chain_name, accumulator, context).await
    }

    /// Every quorum path ends here so the counter cannot fall out of step with
    /// the accumulator. `pillar_provider_request_errors_total{kind="quorum"}` is
    /// documented as "quorum was not met for that chain", and the Move and TON
    /// resolvers build their own accumulators; when they called `finish`
    /// directly, a whole chain family could fail on every provider while the
    /// counter an operator alerts on stayed at zero.
    ///
    /// The counter follows the verdict, not the fact that the response loop
    /// ended, so it is recorded from `result.is_err()` rather than from reaching
    /// this point. That ordering used to be load-bearing for a second reason:
    /// the TON path skipped URIs whose `v3-endpoint` will not parse while still
    /// declaring the full configured count, so `remaining` never fell to zero,
    /// `unambiguous_result` never fired, and `finish` succeeded on a silently
    /// smaller pool — successes that a record-then-consult order counted as
    /// quorum failures. `get_ton_transaction_trace` now sizes the accumulator by
    /// the number of URIs it actually dispatched to and refuses up front when
    /// that is below quorum, so every path declares what it asked. Keep the
    /// verdict-driven ordering regardless: it is what makes this counter mean
    /// "quorum was not met" instead of "a response loop finished".
    async fn finish_quorum<V: Clone>(
        &self,
        chain_name: &str,
        accumulator: ExactQuorumAccumulator<V>,
        context: &str,
    ) -> Result<V, AppCoreError> {
        let result = accumulator.finish(context);
        if result.is_err() {
            if let Some(metrics) = &self.metrics {
                let mut metrics = metrics.lock().await;
                metrics.record_provider_request_error(chain_name, "quorum");
            }
        }
        result
    }

    fn solana_transaction_to_lz_sent_event(
        &self,
        src_tx_hash: &str,
        transaction: &Value,
        expected_lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        match transaction.pointer("/meta/err") {
            Some(error) if error.is_null() => {}
            Some(error) => {
                return Err(AppCoreError::BadRequest(format!(
                    "Solana transaction failed: {error}"
                )))
            }
            None => {
                return Err(AppCoreError::Internal(
                    "Missing Solana transaction status".to_string(),
                ))
            }
        }
        for event in decode_solana_packet_sent_events(transaction) {
            if !self
                .config
                .trusted_solana_endpoint_program_ids
                .contains(&event.endpoint_program_id)
                || !self
                    .config
                    .trusted_solana_send_library_addresses
                    .contains(&event.send_library)
            {
                continue;
            }
            let sent_event =
                self.solana_packet_to_lz_sent_event(src_tx_hash, event, transaction)?;
            if lz_message_id_matches(expected_lz_message_id, &sent_event.lz_message_id) {
                return Ok(sent_event);
            }
        }
        Err(AppCoreError::Internal(format!(
            "Unable to find a trusted Solana PacketSent event for {src_tx_hash}"
        )))
    }

    fn solana_packet_to_lz_sent_event(
        &self,
        src_tx_hash: &str,
        event: SolanaPacketSentEvent,
        transaction: &Value,
    ) -> Result<LzSentEvent, AppCoreError> {
        let packet = event.packet;
        let mut pathway_extra = IndexMap::new();
        pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
        pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
        pathway_extra.insert("sender".to_string(), Value::from(packet.sender));
        pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver));
        let mut extra = IndexMap::new();
        extra.insert("guid".to_string(), Value::from(packet.guid));
        extra.insert("options".to_string(), Value::from(event.options));
        extra.insert("sendLibrary".to_string(), Value::from(event.send_library));
        extra.insert(
            "packetEmitAddress".to_string(),
            Value::from(event.endpoint_program_id),
        );
        if let Some(slot) = transaction.get("slot").and_then(Value::as_u64) {
            extra.insert("slot".to_string(), Value::from(slot));
            extra.insert("blockNumber".to_string(), Value::from(slot));
        }
        if let Some(block_time) = transaction.get("blockTime").and_then(Value::as_i64) {
            extra.insert("blockTimestamp".to_string(), Value::from(block_time));
        }
        Ok(LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name: self.chain_name_for_eid(packet.src_eid)?,
                    dst_chain_name: self.chain_name_for_eid(packet.dst_eid)?,
                    extra: pathway_extra,
                },
                nonce: packet.nonce,
                uln_send_version: Value::from(ULN_VERSION_V302),
            },
            message: packet.message,
            tx_hash: src_tx_hash.to_string(),
            extra,
        })
    }

    fn packet_sent_to_lz_sent_event(
        &self,
        src_chain_name: &str,
        src_tx_hash: &str,
        packet_sent: EvmPacketSent,
        log_address: &str,
    ) -> Result<LzSentEvent, AppCoreError> {
        if !self
            .config
            .trusted_packet_emitters_by_chain_name
            .get(src_chain_name)
            .is_some_and(|emitters| emitters.contains(&normalize_address(log_address)))
        {
            return Err(AppCoreError::Internal(format!(
                "Untrusted PacketSent emitter {log_address} for chain {src_chain_name}"
            )));
        }
        let send_library = packet_sent
            .send_library
            .clone()
            .unwrap_or_else(|| log_address.to_string());
        let uln_send_version = self
            .config
            .uln_version_by_send_library_address_by_chain_name
            .get(src_chain_name)
            .and_then(|versions| versions.get(&normalize_address(&send_library)))
            .cloned()
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No ULN send version for send library {send_library} on chain {src_chain_name}"
                ))
            })?;
        let mut packet = packet_sent.packet;
        // The flip is upstream's, and it comes before the pathway is formed:
        //
        //   if (UlnVersion.ReadV1002 === ulnSendVersion) {
        //       // Flip srcEid and dstEid for the packet
        //       ;[packet.srcEid, packet.dstEid] = [packet.dstEid, packet.srcEid]
        //   }
        //
        // TS: `packages/sdks/lz-v2-sdk/src/endpoint/evm/decoders/index.ts:292-295`.
        // After it, a read packet's `src_eid` holds the read channel and `dst_eid` holds
        // the chain.
        if uln_send_version == ULN_VERSION_READ_V1002 {
            std::mem::swap(&mut packet.src_eid, &mut packet.dst_eid);
        }
        // Both names then come from `dst_eid`, because `src_eid` is a channel and not a
        // chain. Upstream:
        //
        //   const srcChainName = isLzReadEndpointId(rawPathwayId.srcEid)
        //       ? getChainName(rawPathwayId.dstEid)
        //       : getChainName(rawPathwayId.srcEid)
        //   const dstChainName = getChainName(rawPathwayId.dstEid)
        //
        // TS: `formatPathwayId`, `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:19-36`;
        // `isLzReadEndpointId` is `packages/common-model/src/utils/index.ts:38-40` over
        // `ChannelId` from `@layerzerolabs/lz-definitions@3.1.2`.
        //
        // Previously both ids were looked up unconditionally, so the post-flip `src_eid`
        // lookup hit a channel id. `chain_name_by_eid` is built from chain names
        // (`runtime_chain_name_by_endpoint_id`) and never holds one, so every read packet
        // failed here - before reaching the payload builders. Read could not complete at
        // all, which is why correcting it cannot regress a working pathway. The flipped
        // ids themselves are left exactly as upstream leaves them: both are signed
        // (`encode_lz_packet_v1` writes `src_eid` at bytes[9..13] and `dst_eid` at
        // bytes[45..49] of the packet header) and `compute_lz_packet_v1_proof` branches
        // the signed payload hash on `src_eid`.
        let dst_chain_name = self.chain_name_for_eid(packet.dst_eid)?;
        let src_chain_name = if is_lz_read_endpoint_id(packet.src_eid) {
            dst_chain_name.clone()
        } else {
            self.chain_name_for_eid(packet.src_eid)?
        };
        let mut pathway_extra = IndexMap::new();
        pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
        pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
        pathway_extra.insert("sender".to_string(), Value::from(packet.sender));
        pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver));
        let mut extra = IndexMap::new();
        extra.insert("guid".to_string(), Value::from(packet.guid));
        extra.insert("options".to_string(), Value::from(packet_sent.options));
        extra.insert("sendLibrary".to_string(), Value::from(send_library));
        extra.insert("packetEmitAddress".to_string(), Value::from(log_address));
        Ok(LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name,
                    dst_chain_name,
                    extra: pathway_extra,
                },
                nonce: packet.nonce,
                uln_send_version: Value::from(uln_send_version),
            },
            message: packet.message,
            tx_hash: src_tx_hash.to_string(),
            extra,
        })
    }

    async fn get_ton_transaction_trace(&self, src_tx_hash: &str) -> Result<Value, AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config("ton")?;
        let quorum = required_provider_quorum(provider_config, "ton")?;
        let mut requests = FuturesUnordered::new();
        let mut dispatched = 0usize;
        let mut unusable = Vec::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let Some((endpoint, _, headers)) = ton_v3_provider_uri_parts(uri) else {
                unusable.push(index);
                continue;
            };
            dispatched += 1;
            // Sink-side refusal, as in `move_tx_url`; the API boundary's
            // `srcTxHash` shape check is the first gate, not the only one.
            let Some(encoded_tx_hash) = encode_path_segment(src_tx_hash) else {
                return Err(AppCoreError::BadRequest(format!(
                    "srcTxHash {src_tx_hash} cannot be used as a TON trace path segment"
                )));
            };
            let url = format!(
                "{}/traces/{}",
                endpoint.trim_end_matches('/'),
                encoded_tx_hash
            );
            let transport = self.transport.clone();
            requests.push(async move {
                (
                    index,
                    transport
                        .get_json(url, headers)
                        .await
                        .ok()
                        .and_then(|value| {
                            serde_json::to_string(&value)
                                .ok()
                                .map(|fingerprint| (fingerprint, value))
                        }),
                )
            });
        }
        // Size the accumulator by what was actually dispatched, not by the
        // configured URI count. A URI whose `v3-endpoint` will not parse is
        // never asked, so declaring it kept `processed` below `total` forever:
        // `unambiguous_result` could never fire, and `finish` settled on
        // whatever arrived from a pool that was silently smaller than the
        // operator configured. Refusing up front mirrors `plan_dispatch`, and
        // naming the unusable URIs makes the misconfiguration visible.
        if !unusable.is_empty() {
            tracing::warn!(
                chain = "ton",
                unusable_uri_indexes = ?unusable,
                dispatched,
                configured = provider_config.uris.len(),
                "TON provider URIs without a parseable v3-endpoint are excluded from quorum"
            );
        }
        if dispatched < quorum {
            return Err(AppCoreError::Internal(format!(
                "TON transaction trace for {src_tx_hash} needs quorum {quorum} but only {dispatched} of {} configured providers have a parseable v3-endpoint",
                provider_config.uris.len()
            )));
        }
        let mut accumulator = ExactQuorumAccumulator::new(dispatched, quorum);
        while let Some((index, observation)) = requests.next().await {
            accumulator.record(index, observation);
            if let Some(value) = accumulator.unambiguous_result() {
                return Ok(value);
            }
        }
        self.finish_quorum(
            "ton",
            accumulator,
            &format!("TON transaction trace for {src_tx_hash}"),
        )
        .await
    }

    fn chain_name_for_eid(&self, eid: u32) -> Result<String, AppCoreError> {
        self.config
            .chain_name_by_eid
            .get(&eid)
            .cloned()
            .ok_or_else(|| AppCoreError::Internal(format!("No chain name for endpoint id {eid}")))
    }
}

#[async_trait]
impl<T> SentEventResolver for EvmPacketSentResolver<T>
where
    T: JsonRpcTransport,
{
    async fn get_lz_sent_event(
        &self,
        src_tx_hash: &str,
        lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        if lz_message_id.pathway_id.src_chain_name == "solana" {
            let transaction = self
                .get_solana_transaction(&lz_message_id.pathway_id.src_chain_name, src_tx_hash)
                .await?;
            return self.solana_transaction_to_lz_sent_event(
                src_tx_hash,
                &transaction,
                lz_message_id,
            );
        }
        if matches!(
            lz_message_id.pathway_id.src_chain_name.as_str(),
            "aptos" | "initia" | "movement"
        ) {
            let src_chain_name = &lz_message_id.pathway_id.src_chain_name;
            let trusted = self
                .config
                .trusted_move_packet_emitters_by_chain_name
                .get(src_chain_name)
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "Unsupported LayerZero source chain {src_chain_name}"
                    ))
                })?;
            let transaction = self
                .get_move_transaction(src_chain_name, src_tx_hash)
                .await?;
            if transaction.get("success") == Some(&Value::Bool(false)) {
                return Err(AppCoreError::BadRequest(format!(
                    "Move transaction failed: {src_tx_hash}"
                )));
            }
            let events = decode_move_packet_sent_events(src_chain_name, &transaction, trusted);
            for event in events {
                let sent_event =
                    self.move_packet_to_lz_sent_event(src_chain_name, src_tx_hash, event)?;
                if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                    return Ok(sent_event);
                }
            }
            return Err(AppCoreError::Internal(format!(
                "Unable to find a trusted Move PacketSent event for {src_tx_hash}"
            )));
        }
        if matches!(
            lz_message_id.pathway_id.src_chain_name.as_str(),
            "sui" | "iotal1"
        ) {
            let src_chain_name = &lz_message_id.pathway_id.src_chain_name;
            let trusted = self
                .config
                .trusted_move_packet_emitters_by_chain_name
                .get(src_chain_name)
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "Unsupported LayerZero source chain {src_chain_name}"
                    ))
                })?;
            let events = self.get_sui_events(src_chain_name, src_tx_hash).await?;
            for event in decode_sui_packet_sent_events(src_chain_name, &events, trusted) {
                let event = MovePacketSentEvent {
                    endpoint_address: event.endpoint_address,
                    packet: event.packet,
                    options: event.options,
                    send_library: event.send_library,
                };
                let sent_event =
                    self.move_packet_to_lz_sent_event(src_chain_name, src_tx_hash, event)?;
                if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                    return Ok(sent_event);
                }
            }
            return Err(AppCoreError::Internal(format!(
                "Unable to find a trusted Sui PacketSent event for {src_tx_hash}"
            )));
        }
        if lz_message_id.pathway_id.src_chain_name == "starknet" {
            let receipt = self
                .get_quorum_rpc_result(
                    "starknet",
                    json!({
                        "method": "starknet_getTransactionReceipt",
                        "params": [src_tx_hash],
                        "id": 1,
                        "jsonrpc": "2.0",
                    }),
                    "Starknet transaction receipt",
                )
                .await?;
            let succeeded =
                receipt.get("execution_status").and_then(Value::as_str) == Some("SUCCEEDED");
            if !succeeded {
                return Err(AppCoreError::BadRequest(format!(
                    "Starknet transaction failed: {src_tx_hash}"
                )));
            }
            let events = decode_starknet_packet_sent_events(
                &receipt,
                &self.config.trusted_starknet_endpoint_addresses,
            );
            for event in events {
                let sent_event = starknet_packet_to_lz_sent_event(
                    src_tx_hash,
                    event,
                    &self.config.chain_name_by_eid,
                )?;
                if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                    return Ok(sent_event);
                }
            }
            return Err(AppCoreError::Internal(format!(
                "Unable to find a trusted Starknet PacketSent event for {src_tx_hash}"
            )));
        }
        if lz_message_id.pathway_id.src_chain_name == "stellar" {
            let transaction = self
                .get_quorum_rpc_result(
                    "stellar",
                    json!({
                        "method": "getTransaction",
                        "params": {"hash": src_tx_hash},
                        "id": 1,
                        "jsonrpc": "2.0",
                    }),
                    "Stellar transaction",
                )
                .await?;
            if transaction.get("status").and_then(Value::as_str) != Some("SUCCESS") {
                return Err(AppCoreError::BadRequest(format!(
                    "Stellar transaction failed: {src_tx_hash}"
                )));
            }
            let events = decode_stellar_packet_sent_events(
                &transaction,
                &self.config.trusted_stellar_endpoint_addresses,
            );
            for event in events {
                let sent_event = stellar_packet_to_lz_sent_event(
                    src_tx_hash,
                    event,
                    &self.config.chain_name_by_eid,
                )?;
                if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                    return Ok(sent_event);
                }
            }
            return Err(AppCoreError::Internal(format!(
                "Unable to find a trusted Stellar PacketSent event for {src_tx_hash}"
            )));
        }
        if lz_message_id.pathway_id.src_chain_name == "ton" {
            let trusted = self
                .config
                .trusted_ton_packet_emitters_by_chain_name
                .get("ton")
                .ok_or_else(|| {
                    AppCoreError::BadRequest("Unsupported LayerZero source chain ton".to_string())
                })?;
            let trace = self.get_ton_transaction_trace(src_tx_hash).await?;
            for event in
                decode_ton_packet_sent_events(&trace, trusted, &self.config.chain_name_by_eid)
            {
                let src_chain_name = self.chain_name_for_eid(event.packet.src_eid)?;
                let dst_chain_name = self.chain_name_for_eid(event.packet.dst_eid)?;
                if src_chain_name != "ton" {
                    continue;
                }
                let mut pathway_extra = IndexMap::new();
                pathway_extra.insert("srcEid".to_string(), Value::from(event.packet.src_eid));
                pathway_extra.insert("dstEid".to_string(), Value::from(event.packet.dst_eid));
                pathway_extra.insert(
                    "sender".to_string(),
                    Value::from(event.packet.sender.clone()),
                );
                pathway_extra.insert(
                    "receiver".to_string(),
                    Value::from(event.packet.receiver.clone()),
                );
                let mut extra = IndexMap::new();
                extra.insert("guid".to_string(), Value::from(event.packet.guid.clone()));
                extra.insert("options".to_string(), event.options);
                extra.insert("sendLibrary".to_string(), Value::from(event.send_library));
                extra.insert(
                    "packetEmitAddress".to_string(),
                    Value::from(event.endpoint_address),
                );
                extra.insert("blockNumber".to_string(), Value::from(event.block_number));
                extra.insert(
                    "blockHash".to_string(),
                    Value::from(event.block_number.to_string()),
                );
                let sent_event = LzSentEvent {
                    lz_message_id: LzMessageId {
                        pathway_id: PathwayId {
                            src_chain_name,
                            dst_chain_name,
                            extra: pathway_extra,
                        },
                        nonce: event.packet.nonce,
                        uln_send_version: Value::from(ULN_VERSION_V302),
                    },
                    message: event.packet.message,
                    tx_hash: event.tx_hash,
                    extra,
                };
                if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                    return Ok(sent_event);
                }
            }
            return Err(AppCoreError::Internal(format!(
                "Unable to find a trusted TON PacketSent event for {src_tx_hash}"
            )));
        }
        if !self
            .config
            .trusted_packet_emitters_by_chain_name
            .contains_key(&lz_message_id.pathway_id.src_chain_name)
        {
            return Err(AppCoreError::BadRequest(format!(
                "Unsupported LayerZero source chain {}",
                lz_message_id.pathway_id.src_chain_name
            )));
        }
        let logs = self
            .get_receipt_logs(&lz_message_id.pathway_id.src_chain_name, src_tx_hash)
            .await?;
        let mut found_trusted_decoded_event = false;
        for log in logs {
            if !self
                .config
                .trusted_packet_emitters_by_chain_name
                .get(&lz_message_id.pathway_id.src_chain_name)
                .is_some_and(|emitters| emitters.contains(&normalize_address(&log.address)))
            {
                continue;
            }
            let Ok(packet_sent) = decode_evm_packet_sent_log(&log.topics, &log.data) else {
                continue;
            };
            // Non-fatal for the same reason the decode above is. A batching
            // transaction can emit several PacketSent events, and this
            // conversion fails for an unknown send library or an endpoint id
            // this deployment does not map. Propagating that aborted the scan
            // for every other event in the receipt, including the one the
            // request asked for. The bookkeeping below still separates "a
            // trusted event was present but no pathway matched" from "no
            // trusted event at all".
            let Ok(sent_event) = self.packet_sent_to_lz_sent_event(
                &lz_message_id.pathway_id.src_chain_name,
                src_tx_hash,
                packet_sent,
                &log.address,
            ) else {
                continue;
            };
            found_trusted_decoded_event = true;
            if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                return Ok(sent_event);
            }
        }
        if found_trusted_decoded_event {
            return Err(AppCoreError::Internal(format!(
                "Found a PacketSent event from a trusted PacketSent emitter for {src_tx_hash}, but it does not match the requested pathway identity"
            )));
        }
        Err(AppCoreError::Internal(format!(
            "Unable to find PacketSent event from a trusted PacketSent emitter for {src_tx_hash}"
        )))
    }
}

struct SolanaPacketSentEvent {
    endpoint_program_id: String,
    send_library: String,
    packet: LzPacketV1,
    options: String,
}

fn decode_solana_packet_sent_events(transaction: &Value) -> Vec<SolanaPacketSentEvent> {
    transaction
        .pointer("/meta/innerInstructions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|group| group.get("instructions").and_then(Value::as_array))
        .flatten()
        .filter_map(decode_solana_packet_sent_event_instruction)
        .collect()
}

fn decode_solana_packet_sent_event_instruction(
    instruction: &Value,
) -> Option<SolanaPacketSentEvent> {
    let endpoint_program_id = instruction.get("programId")?.as_str()?.to_string();
    let encoded = instruction.get("data")?.as_str()?;
    let decoded = bs58::decode(encoded).into_vec().ok()?;
    if decoded.get(..8)? != ANCHOR_EVENT_EMIT_DISCRIMINATOR
        || decoded.get(8..16)? != PACKET_SENT_EVENT_DISCRIMINATOR
    {
        return None;
    }

    let mut cursor = 16;
    let packet_bytes = take_solana_event_bytes(&decoded, &mut cursor)?;
    let options = take_solana_event_bytes(&decoded, &mut cursor)?;
    let send_library_bytes = decoded.get(cursor..cursor.checked_add(32)?)?;
    let packet = decode_lz_packet_v1(&format!("0x{}", hex::encode(packet_bytes))).ok()?;
    Some(SolanaPacketSentEvent {
        endpoint_program_id,
        send_library: bs58::encode(send_library_bytes).into_string(),
        packet,
        options: format!("0x{}", hex::encode(options)),
    })
}

fn take_solana_event_bytes<'a>(decoded: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let length_bytes: [u8; 4] = decoded
        .get(*cursor..cursor.checked_add(4)?)?
        .try_into()
        .ok()?;
    *cursor = cursor.checked_add(4)?;
    let length = u32::from_le_bytes(length_bytes) as usize;
    let end = cursor.checked_add(length)?;
    let value = decoded.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}
