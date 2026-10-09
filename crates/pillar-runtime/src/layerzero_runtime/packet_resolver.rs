use super::*;

const ANCHOR_EVENT_EMIT_DISCRIMINATOR: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];
const PACKET_SENT_EVENT_DISCRIMINATOR: [u8; 8] = [0x00, 0x5c, 0xa7, 0xc9, 0x8b, 0x2e, 0xab, 0x52];
#[allow(clippy::large_enum_variant)]
pub(crate) enum SourceEventConversion {
    Converted(LzSentEvent),
    NotOurs,
    SourceFault(AppCoreError),
}

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
                packet_sent_bindings_by_chain_name: config
                    .packet_sent_bindings_by_chain_name
                    .into_iter()
                    .map(|(chain_name, bindings)| {
                        (
                            chain_name,
                            EvmPacketSentBindings {
                                endpoint_v2: normalize_address(&bindings.endpoint_v2),
                                endpoint_v2_send_library_versions: normalize_address_map(
                                    bindings.endpoint_v2_send_library_versions,
                                ),
                                send_uln_301: bindings
                                    .send_uln_301
                                    .as_deref()
                                    .map(normalize_address),
                                uln_v2: bindings.uln_v2.as_deref().map(normalize_address),
                            },
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
                aptos_v1_source: config.aptos_v1_source.map(|source| AptosV1Source {
                    layerzero_account: normalize_move_account_for_resolver(
                        &source.layerzero_account,
                    ),
                    endpoint_v1_id: source.endpoint_v1_id,
                    uln_301: normalize_move_account_for_resolver(&source.uln_301),
                }),
                max_eth_get_logs_block_range_by_chain_name: config
                    .max_eth_get_logs_block_range_by_chain_name,
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
    ) -> Result<EvmTransactionReceipt, AppCoreError> {
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
        // Still refused, but as upstream reports it: a reverted transaction has no
        // PacketSent log, so its sdk ends in `Packet does not match lzMessageId`.
        if receipt.status != "1" {
            return Err(packet_does_not_match(src_tx_hash));
        }
        Ok(receipt)
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
                            "maxSupportedTransactionVersion": crate::SOLANA_MAX_SUPPORTED_TRANSACTION_VERSION,
                        },
                    ],
                    "id": 1,
                    "jsonrpc": "2.0",
                }),
                "Solana transaction",
            )
            .await?;
        // Upstream's Solana quorum call returns null rather than throwing
        // NotFoundError, so its sdk's plain `Transaction not found` 500 follows
        // (`multiprovider/src/solana.ts:222-258`, `endpoint/solana/index.ts:154-156`).
        if result.is_null() {
            return Err(AppCoreError::Internal("Transaction not found".to_string()));
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
        let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..provider_config.uris.len());
        while let Some((index, response)) = requests.next().await {
            let observation = provider_response(response).map(|response| {
                response
                    .and_then(|value| serde_json::to_string(&value).ok().map(|key| (key, value)))
            });
            accumulator.record_result(index, observation)?;
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

    /// One Aptos-family REST GET, agreed by the provider quorum on the whole answer.
    async fn get_aptos_json(
        &self,
        chain: &str,
        url_for: impl Fn(&str) -> Option<String>,
        context: &str,
    ) -> Result<Value, AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(chain)?;
        let quorum = required_provider_quorum(provider_config, chain)?;
        let mut requests = FuturesUnordered::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let transport = self.transport.clone();
            let (base, headers) = move_provider_uri_parts(chain, uri);
            let url = url_for(&base);
            requests.push(async move {
                let response = match url {
                    Some(url) => transport.get_json_scoped(url, headers).await,
                    None => Err(RpcError::Remote(
                        "Unusable Aptos ledger version".to_string(),
                    )),
                };
                (index, response)
            });
        }
        let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..provider_config.uris.len());
        while let Some((index, response)) = requests.next().await {
            let observation = provider_response(response).map(|response| {
                response
                    .and_then(|value| serde_json::to_string(&value).ok().map(|key| (key, value)))
            });
            accumulator.record_result(index, observation)?;
            if let Some(value) = accumulator.unambiguous_result() {
                return Ok(value);
            }
        }
        self.finish_quorum(chain, accumulator, context).await
    }

    /// `LZAptosSdk.getLZSentEventFromSrcTxHash`: the transaction at the ledger version
    /// `srcTxHash` names, each V1 `packet_event::OutboundEvent` in it decoded, and the
    /// one matching the request (`lz-v1-sdk/src/aptos/aptos.ts:913-946`,
    /// `common-aptos/src/utils.ts:51-72,140-201`).
    async fn resolve_aptos_v1_packet(
        &self,
        source: &AptosV1Source,
        src_tx_hash: &str,
        lz_message_id: &LzMessageId,
    ) -> Result<LzSentEvent, AppCoreError> {
        let version = aptos_ledger_version(src_tx_hash)?;
        let transaction = self
            .get_aptos_json(
                "aptos",
                |base| aptos_transaction_by_version_url(base, &version),
                &format!("Aptos transaction at version {version}"),
            )
            .await?;
        let events = transaction
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| AppCoreError::Internal("tx.events is not iterable".to_string()))?;
        let event_type = format!("{}::packet_event::OutboundEvent", source.layerzero_account);
        let mut block: Option<(Value, Value)> = None;
        for event in events {
            if event.get("type").and_then(Value::as_str) != Some(event_type.as_str()) {
                continue;
            }
            let encoded = event
                .pointer("/data/encoded_packet")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let digits = encoded
                .strip_prefix("0x")
                .or_else(|| encoded.strip_prefix("0X"))
                .unwrap_or(encoded);
            let bytes = hex::decode(digits)
                .map_err(|error| AppCoreError::Internal(format!("encoded_packet: {error}")))?;
            let packet = pillar_layerzero::decode_aptos_v1_packet(&bytes, aptos_v1_address_size)?;
            if u32::from(packet.src_chain_id) != source.endpoint_v1_id {
                return Err(AppCoreError::Internal(format!(
                    "potential attack: srcChainId({} from aptos mismatch srcChainId({}) in packet ",
                    source.endpoint_v1_id, packet.src_chain_id
                )));
            }
            let dst_chain_name =
                pillar_config::layerzero_legacy_chain_name(u32::from(packet.dst_chain_id))
                    .ok_or_else(|| {
                        AppCoreError::Internal(format!(
                            "Invariant failed: Invalid endpointId: {}",
                            packet.dst_chain_id
                        ))
                    })?
                    .to_string();
            let (block_hash, block_number) = match &block {
                Some(block) => block.clone(),
                None => {
                    let fetched = self
                        .get_aptos_json(
                            "aptos",
                            |base| move_block_by_version_url(base, &version),
                            &format!("Aptos block at version {version}"),
                        )
                        .await?;
                    let height = fetched
                        .get("block_height")
                        .and_then(Value::as_str)
                        .map(pillar_core::js_parse_int)
                        .filter(|height| height.is_finite() && height.fract() == 0.0)
                        .map_or(Value::Null, |height| Value::from(height as i64));
                    let read = (
                        fetched.get("block_hash").cloned().unwrap_or(Value::Null),
                        height,
                    );
                    block = Some(read.clone());
                    read
                }
            };
            let mut pathway_extra = IndexMap::new();
            pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_chain_id));
            pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_chain_id));
            pathway_extra.insert(
                "sender".to_string(),
                Value::from(format!("0x{}", hex::encode(&packet.src_address))),
            );
            pathway_extra.insert(
                "receiver".to_string(),
                Value::from(format!("0x{}", hex::encode(&packet.dst_address))),
            );
            let mut extra = IndexMap::new();
            extra.insert(
                "packetEmitAddress".to_string(),
                Value::from(source.layerzero_account.clone()),
            );
            extra.insert("blockHash".to_string(), block_hash);
            extra.insert("blockNumber".to_string(), block_number);
            let sent_event = LzSentEvent {
                lz_message_id: LzMessageId {
                    pathway_id: PathwayId {
                        src_chain_name: "aptos".to_string(),
                        dst_chain_name,
                        extra: pathway_extra,
                    },
                    nonce: packet.nonce,
                    uln_send_version: Value::from(ULN_VERSION_V2),
                },
                message: format!("0x{}", hex::encode(&packet.payload)),
                tx_hash: version.clone(),
                extra,
                source_evidence: None,
                read_block_pins: Vec::new(),
            };
            if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                return Ok(sent_event);
            }
        }
        Err(packet_does_not_match(src_tx_hash))
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
    ) -> Result<SourceEventConversion, AppCoreError> {
        let src_chain_name = match self.chain_name_for_eid(event.packet.src_eid) {
            Ok(name) => name,
            Err(error) => return Ok(SourceEventConversion::SourceFault(error)),
        };
        if src_chain_name != expected_src_chain_name {
            return Ok(SourceEventConversion::SourceFault(AppCoreError::Internal(
                "Move PacketSent source chain mismatch".to_string(),
            )));
        }
        let dst_chain_name = match super::source_events_starknet::chain_name_for_packet_eid(
            &self.config.chain_name_by_eid,
            event.packet.dst_eid,
        ) {
            Ok(name) => name,
            Err(_) => return Ok(SourceEventConversion::NotOurs),
        };
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
        let options = match event.options {
            Ok(options) if options == "0x" && event.uln_send_version == ULN_VERSION_V301 => {
                json!({})
            }
            Ok(options) => {
                let bytes = hex::decode(strip_hex_prefix(&options))
                    .map_err(|error| AppCoreError::Internal(error.to_string()))?;
                decode_move_relayer_options(&bytes, &dst_chain_name)
                    .map_err(AppCoreError::Internal)?
            }
            Err(error) => return Err(AppCoreError::Internal(error)),
        };
        extra.insert("options".to_string(), options);
        let send_library = match &event.send_library {
            Some(library) => Value::from(normalize_move_account_for_resolver(library)),
            None => self
                .config
                .aptos_v1_source
                .as_ref()
                .map(|source| Value::from(source.uln_301.clone()))
                .ok_or_else(|| {
                    AppCoreError::Internal(format!(
                        "No Aptos V1 ULN301 for a V301 send on {src_chain_name}"
                    ))
                })?,
        };
        extra.insert("sendLibrary".to_string(), send_library);
        extra.insert(
            "packetEmitAddress".to_string(),
            Value::from(event.endpoint_address),
        );
        Ok(SourceEventConversion::Converted(LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name,
                    dst_chain_name,
                    extra: pathway_extra,
                },
                nonce: event.packet.nonce,
                uln_send_version: Value::from(event.uln_send_version),
            },
            message: event.packet.message,
            tx_hash: src_tx_hash.to_string(),
            source_evidence: None,
            read_block_pins: Vec::new(),
            extra,
        }))
    }

    async fn get_quorum_rpc_result(
        &self,
        chain_name: &str,
        body: Value,
        context: &str,
    ) -> Result<Value, AppCoreError> {
        crate::provider_health::rpc_scope(chain_name, async {
            let snapshot = self.providers.load();
            let provider_config = snapshot.provider_config(chain_name)?;
            let quorum = required_provider_quorum(provider_config, chain_name)?;
            let receipt_expected_tx_hash = (body.get("method").and_then(Value::as_str)
                == Some("eth_getTransactionReceipt"))
            .then(|| body.pointer("/params/0").and_then(Value::as_str))
            .flatten();
            let mut requests = FuturesUnordered::new();
            for (index, uri) in provider_config.uris.iter().enumerate() {
                let transport = self.transport.clone();
                let (url, headers) = provider_uri_parts(uri);
                let body = body.clone();
                requests.push(async move {
                    (index, transport.post_json_scoped(url, headers, body).await)
                });
            }
            let mut accumulator =
                ExactQuorumAccumulator::new(quorum, 0..provider_config.uris.len());
            while let Some((index, response)) = requests.next().await {
                let observation = provider_response(response).and_then(|response| {
                    response
                        .and_then(|mut response| response.get_mut("result").map(Value::take))
                        .map(|result| {
                            if result.is_null() {
                                return Ok(("null".to_string(), result));
                            }
                            if let Some(expected_tx_hash) = receipt_expected_tx_hash {
                                serde_json::from_value::<EvmTransactionReceipt>(result)
                                    .map_err(|error| RpcError::Remote(error.to_string()))
                                    .and_then(|receipt| {
                                        receipt
                                            .normalize(expected_tx_hash)
                                            .map_err(RpcError::Remote)
                                    })
                                    .and_then(|receipt| {
                                        let fingerprint = evm_receipt_fingerprint(&receipt)
                                            .map_err(RpcError::Remote)?;
                                        let value = serde_json::to_value(receipt)
                                            .map_err(|error| RpcError::Remote(error.to_string()))?;
                                        Ok((fingerprint, value))
                                    })
                            } else {
                                serde_json::to_string(&result)
                                    .map(|fingerprint| (fingerprint, result))
                                    .map_err(|error| RpcError::Remote(error.to_string()))
                            }
                        })
                        .transpose()
                });
                accumulator.record_result(index, observation)?;
                if let Some(result) = accumulator.unambiguous_result() {
                    return Ok(result);
                }
            }

            self.finish_quorum(chain_name, accumulator, context).await
        })
        .await
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
        accumulator: ExactQuorumAccumulator<'_, V>,
        context: &str,
    ) -> Result<V, AppCoreError> {
        let result = accumulator.finish(context);
        if result.is_err() && !matches!(result, Err(AppCoreError::Admission(_))) {
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
        // Upstream's extractor returns null unless `meta.err` is exactly null, and
        // the sdk then throws a plain `Transaction not found`, a 500
        // (`common-solana/src/events.ts:48-55`, `endpoint/solana/index.ts:154-156`).
        if !transaction.pointer("/meta/err").is_some_and(Value::is_null) {
            return Err(AppCoreError::Internal("Transaction not found".to_string()));
        }
        // Upstream's extractor keeps only the endpoint program's events and
        // returns null for none, which is `Transaction not found` too
        // (`common-solana/src/events.ts:58-91`).
        let endpoint_events = decode_solana_packet_sent_events(transaction)
            .into_iter()
            .filter(|event| {
                self.config
                    .trusted_solana_endpoint_program_ids
                    .contains(&event.endpoint_program_id)
            })
            .collect::<Vec<_>>();
        if endpoint_events.is_empty() {
            return Err(AppCoreError::Internal("Transaction not found".to_string()));
        }
        let mut first_source_fault = None;
        for event in endpoint_events {
            if !self
                .config
                .trusted_solana_send_library_addresses
                .contains(&event.send_library)
            {
                continue;
            }
            let sent_event =
                match self.solana_packet_to_lz_sent_event(src_tx_hash, event, transaction) {
                    Ok(SourceEventConversion::Converted(sent_event)) => sent_event,
                    Ok(SourceEventConversion::NotOurs) => continue,
                    Ok(SourceEventConversion::SourceFault(error)) => {
                        first_source_fault.get_or_insert(error);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            if lz_message_id_matches(expected_lz_message_id, &sent_event.lz_message_id) {
                return Ok(sent_event);
            }
        }
        Err(first_source_fault.unwrap_or_else(|| {
            AppCoreError::Internal("Could not find sentEvent that matches lzMessageId".to_string())
        }))
    }

    fn solana_packet_to_lz_sent_event(
        &self,
        src_tx_hash: &str,
        event: SolanaPacketSentEvent,
        transaction: &Value,
    ) -> Result<SourceEventConversion, AppCoreError> {
        let packet = event.packet;
        let src_chain_name = match self.chain_name_for_eid(packet.src_eid) {
            Ok(name) => name,
            Err(error) => return Ok(SourceEventConversion::SourceFault(error)),
        };
        let Some(dst_chain_name) = self.config.chain_name_by_eid.get(&packet.dst_eid).cloned()
        else {
            return Ok(SourceEventConversion::NotOurs);
        };
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
        Ok(SourceEventConversion::Converted(LzSentEvent {
            lz_message_id: LzMessageId {
                pathway_id: PathwayId {
                    src_chain_name,
                    dst_chain_name,
                    extra: pathway_extra,
                },
                nonce: packet.nonce,
                uln_send_version: Value::from(ULN_VERSION_V302),
            },
            message: packet.message,
            tx_hash: src_tx_hash.to_string(),
            source_evidence: None,
            read_block_pins: Vec::new(),
            extra,
        }))
    }

    fn packet_sent_to_lz_sent_event(
        &self,
        src_chain_name: &str,
        src_tx_hash: &str,
        packet_sent: EvmPacketSent,
        log_address: &str,
        source_evidence: EvmSourceEvidence,
    ) -> Result<SourceEventConversion, AppCoreError> {
        let bindings = self
            .config
            .packet_sent_bindings_by_chain_name
            .get(src_chain_name)
            .ok_or_else(|| {
                AppCoreError::Internal(format!("No PacketSent bindings for chain {src_chain_name}"))
            })?;
        let (send_library, uln_send_version) =
            bound_evm_packet_sent_version(bindings, &packet_sent.kind, log_address).map_err(
                |reason| {
                    AppCoreError::Internal(format!(
                "Untrusted PacketSent from {log_address} on chain {src_chain_name}: {reason}"
            ))
                },
            )?;
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
        let read_packet = is_lz_read_endpoint_id(packet.src_eid);
        let (src_chain_name, dst_chain_name) = if read_packet {
            let chain_name = match self.chain_name_for_eid(packet.dst_eid) {
                Ok(name) => name,
                Err(error) => return Ok(SourceEventConversion::SourceFault(error)),
            };
            (chain_name.clone(), chain_name)
        } else {
            let src_chain_name = match self.chain_name_for_eid(packet.src_eid) {
                Ok(name) => name,
                Err(error) => return Ok(SourceEventConversion::SourceFault(error)),
            };
            let Some(dst_chain_name) = self.config.chain_name_by_eid.get(&packet.dst_eid).cloned()
            else {
                return Ok(SourceEventConversion::NotOurs);
            };
            (src_chain_name, dst_chain_name)
        };
        let mut pathway_extra = IndexMap::new();
        pathway_extra.insert("srcEid".to_string(), Value::from(packet.src_eid));
        pathway_extra.insert("dstEid".to_string(), Value::from(packet.dst_eid));
        pathway_extra.insert("sender".to_string(), Value::from(packet.sender));
        pathway_extra.insert("receiver".to_string(), Value::from(packet.receiver));
        let mut extra = IndexMap::new();
        // A ULNv2 `Packet` has no guid and no options; upstream's V1 event carries neither,
        // and payload-signed validation keys V1-vs-V2 handling on the guid's absence.
        if uln_send_version != ULN_VERSION_V2 {
            extra.insert("guid".to_string(), Value::from(packet.guid));
            let options = hex::decode(strip_hex_prefix(&packet_sent.options))
                .map_err(|error| AppCoreError::Internal(format!("PacketSent options: {error}")))?;
            let options = decode_evm_relayer_options(&options, &dst_chain_name)
                .map_err(|error| AppCoreError::Internal(format!("PacketSent options: {error}")))?;
            extra.insert("options".to_string(), options);
        }
        extra.insert("sendLibrary".to_string(), Value::from(send_library));
        extra.insert("packetEmitAddress".to_string(), Value::from(log_address));
        Ok(SourceEventConversion::Converted(LzSentEvent {
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
            source_evidence: Some(source_evidence),
            read_block_pins: Vec::new(),
            extra,
        }))
    }

    async fn get_ton_transaction_trace(&self, src_tx_hash: &str) -> Result<Value, AppCoreError> {
        crate::provider_health::rpc_scope("ton", async { let snapshot = self.providers.load();
    let provider_config = snapshot.provider_config("ton")?;
    let quorum = required_provider_quorum(provider_config, "ton")?;
    let mut requests = FuturesUnordered::new();
    let mut dispatched = Vec::new();
    let mut unusable = Vec::new();
    for (index, uri) in provider_config.uris.iter().enumerate() {
        let Some((endpoint, _, headers)) = ton_v3_provider_uri_parts(uri) else {
            unusable.push(index);
            continue;
        };
        dispatched.push(index);
        // Sink-side refusal, as in `move_tx_url`; the core's `srcTxHash` shape
        // check is the first gate, not the only one.
        let Some(encoded_tx_hash) = encode_path_segment(src_tx_hash) else {
            return Err(AppCoreError::BadRequest(format!(
                "srcTxHash {src_tx_hash} cannot be used as a TON trace query value"
            )));
        };
        let transport = self.transport.clone();
        requests.push(async move {
            let observation =
                fetch_ton_transaction_trace(&transport, &endpoint, &headers, &encoded_tx_hash).await;
            (
                index,
                observation.map(|tree| tree.and_then(|tree| ton_trace_quorum_fingerprint(&tree).map(|fingerprint| (fingerprint, tree)))),
            )
        });
    }
    // The accumulator only counts what was actually dispatched: a URI whose
    // `v3-endpoint` will not parse is never asked, and counting it as pending would
    // keep `unambiguous_result` from ever firing. Refusing up front mirrors
    // `plan_dispatch`, and naming the unusable URIs makes the misconfiguration visible.
    if !unusable.is_empty() {
        tracing::warn!(
            chain = "ton",
            unusable_uri_indexes = ?unusable,
            dispatched = dispatched.len(),
            configured = provider_config.uris.len(),
            "TON provider URIs without a parseable v3-endpoint are excluded from quorum"
        );
    }
    if !quorum.is_met_by(&dispatched) {
        return Err(AppCoreError::Internal(format!(
            "TON transaction trace for {src_tx_hash} needs quorum {} but only {} of {} configured providers have a parseable v3-endpoint",
            quorum.describe(),
            dispatched.len(),
            provider_config.uris.len()
        )));
    }
    let mut accumulator = ExactQuorumAccumulator::new(quorum, dispatched);
    while let Some((index, observation)) = requests.next().await {
        accumulator.record_result(index, observation)?;
        if let Some(value) = accumulator.unambiguous_result() {
            return Ok(value);
        }
    }
    self.finish_quorum(
        "ton",
        accumulator,
        &format!("TON transaction trace for {src_tx_hash}"),
    )
    .await }).await
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
        crate::provider_health::rpc_scope(&lz_message_id.pathway_id.src_chain_name, async {
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
                if src_chain_name == "aptos" && lz_message_id.uln_send_version == ULN_VERSION_V2 {
                    let source = self.config.aptos_v1_source.clone().ok_or_else(|| {
                        AppCoreError::BadRequest(
                            "Unsupported LayerZero source chain aptos".to_string(),
                        )
                    })?;
                    return self
                        .resolve_aptos_v1_packet(&source, src_tx_hash, lz_message_id)
                        .await;
                }
                if matches!(src_chain_name.as_str(), "initia" | "movement")
                    && lz_message_id.uln_send_version == ULN_VERSION_V301
                {
                    // Upstream has no Initia/Movement EndpointV1 eid mapping for the V1 packet eids.
                    return Err(AppCoreError::BadRequest(format!(
                        "LayerZero V301 source event resolution is unavailable for {src_chain_name}: no EndpointV1 eid mapping"
                    )));
                }
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
                // A failed Move transaction emits no PacketSent; upstream's matcher then
                // reports `Did not find correct PacketSent() event` (`endpoint/aptos/index.ts:276-283`).
                if transaction.get("success") == Some(&Value::Bool(false)) {
                    return Err(AppCoreError::Internal(format!(
                        "Did not find correct PacketSent() event in tx {src_tx_hash}"
                    )));
                }
                // Upstream picks the event token by the requested version, extracts every
                // event of it (any throw fails the read) and then matches on the identity
                // alone (`endpoint/aptos/index.ts:234-256`). The destination chain name must
                // also agree here: the signer, expiration check and duplicate query are picked
                // by the request's name while the call data follows the packet.
                let token_version = lz_message_id.uln_send_version.as_str().unwrap_or_default();
                let events = decode_move_packet_sent_events(
                    src_chain_name,
                    &transaction,
                    trusted,
                    token_version,
                )
                .map_err(AppCoreError::Internal)?;
                let mut converted = Vec::with_capacity(events.len());
                let mut first_source_fault = None;
                for event in events {
                    match self.move_packet_to_lz_sent_event(src_chain_name, src_tx_hash, event)? {
                        SourceEventConversion::Converted(sent_event) => converted.push(sent_event),
                        SourceEventConversion::NotOurs => {}
                        SourceEventConversion::SourceFault(error) => {
                            first_source_fault.get_or_insert(error);
                        }
                    }
                }
                let mut sent_event = match converted.into_iter().find(|sent_event| {
                    lz_message_identity_matches(lz_message_id, &sent_event.lz_message_id)
                        && lz_message_id.pathway_id.dst_chain_name
                            == sent_event.lz_message_id.pathway_id.dst_chain_name
                }) {
                    Some(sent_event) => sent_event,
                    None => return Err(first_source_fault.unwrap_or_else(|| AppCoreError::Internal(format!(
                        "Did not find correct PacketSent() event in tx {src_tx_hash}"
                    )))),
                };
                if sent_event.lz_message_id.uln_send_version == ULN_VERSION_V301 {
                    // `onChainEvent.txHash`: the ledger version on Aptos, the hash on Initia.
                    let field = if src_chain_name == "initia" { "txhash" } else { "version" };
                    let version = transaction
                        .get(field)
                        .and_then(|version| {
                            version
                                .as_str()
                                .map(ToString::to_string)
                                .or_else(|| version.as_u64().map(|version| version.to_string()))
                        })
                        .unwrap_or_default();
                    let options = self
                        .aptos_family_v301_options(
                            src_chain_name,
                            &sent_event,
                            &aptos_ledger_version(&version)?,
                        )
                        .await?;
                    sent_event.extra.insert("options".to_string(), options);
                }
                return Ok(sent_event);
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
                let events = decode_sui_packet_sent_events(&events, trusted)
                    .map_err(AppCoreError::Internal)?;
                let mut converted = Vec::with_capacity(events.len());
                let mut first_source_fault = None;
                for event in events {
                    match self.move_packet_to_lz_sent_event(src_chain_name, src_tx_hash, event)? {
                        SourceEventConversion::Converted(sent_event) => converted.push(sent_event),
                        SourceEventConversion::NotOurs => {}
                        SourceEventConversion::SourceFault(error) => {
                            first_source_fault.get_or_insert(error);
                        }
                    }
                }
                if let Some(sent_event) = converted
                    .into_iter()
                    .find(|sent_event| lz_message_id_matches(lz_message_id, &sent_event.lz_message_id))
                {
                    return Ok(sent_event);
                }
                return Err(first_source_fault.unwrap_or_else(|| AppCoreError::Internal(format!(
                    "Did not find correct PacketSent() event in tx {src_tx_hash}"
                ))));
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
                    return Err(AppCoreError::Internal(format!(
                        "Transaction failed for tx {src_tx_hash}"
                    )));
                }
                // `endpoint/starknet/index.ts:214-216`.
                if receipt
                    .get("block_hash")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    return Err(AppCoreError::Internal(format!(
                        "Block hash not yet populated for tx {src_tx_hash}"
                    )));
                }
                let events = decode_starknet_packet_sent_events(
                    &receipt,
                    &self.config.trusted_starknet_endpoint_addresses,
                )
                .map_err(AppCoreError::Internal)?;
                let mut converted = Vec::with_capacity(events.len());
                let mut first_source_fault = None;
                for event in events {
                    match starknet_packet_to_lz_sent_event(
                        src_tx_hash,
                        event,
                        &self.config.chain_name_by_eid,
                    )? {
                        SourceEventConversion::Converted(sent_event) => converted.push(sent_event),
                        SourceEventConversion::NotOurs => {}
                        SourceEventConversion::SourceFault(error) => {
                            first_source_fault.get_or_insert(error);
                        }
                    }
                }
                if let Some(sent_event) = converted
                    .into_iter()
                    .find(|sent_event| lz_message_id_matches(lz_message_id, &sent_event.lz_message_id))
                {
                    return Ok(sent_event);
                }
                return Err(first_source_fault.unwrap_or_else(|| packet_does_not_match(src_tx_hash)));
            }
            if lz_message_id.pathway_id.src_chain_name == "canton" {
                let snapshot = self.providers.load();
                let sequencer = canton_sequencer("canton", snapshot.provider_config("canton")?)?;
                return crate::provider_health::rpc_scope(
                    "canton",
                    resolve_canton_packet_sent(&self.transport, &sequencer, src_tx_hash, lz_message_id),
                )
                .await;
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
                    return Err(AppCoreError::Internal(format!(
                        "Transaction failed for tx {src_tx_hash}"
                    )));
                }
                let events = decode_stellar_packet_sent_events(
                    &transaction,
                    &self.config.trusted_stellar_endpoint_addresses,
                )
                .map_err(AppCoreError::Internal)?;
                let mut converted = Vec::with_capacity(events.len());
                let mut first_source_fault = None;
                for event in events {
                    match stellar_packet_to_lz_sent_event(
                        src_tx_hash,
                        event,
                        &self.config.chain_name_by_eid,
                    )? {
                        SourceEventConversion::Converted(sent_event) => converted.push(sent_event),
                        SourceEventConversion::NotOurs => {}
                        SourceEventConversion::SourceFault(error) => {
                            first_source_fault.get_or_insert(error);
                        }
                    }
                }
                if let Some(sent_event) = converted
                    .into_iter()
                    .find(|sent_event| lz_message_id_matches(lz_message_id, &sent_event.lz_message_id))
                {
                    return Ok(sent_event);
                }
                return Err(first_source_fault.unwrap_or_else(|| packet_does_not_match(src_tx_hash)));
            }
            if lz_message_id.pathway_id.src_chain_name == "ton" {
                let trusted = self
                    .config
                    .trusted_ton_packet_emitters_by_chain_name
                    .get("ton")
                    .ok_or_else(|| {
                        AppCoreError::BadRequest(
                            "Unsupported LayerZero source chain ton".to_string(),
                        )
                    })?;
                 let trace = self.get_ton_transaction_trace(src_tx_hash).await?;
                let mut first_source_fault = None;
                 for event in
                     decode_ton_packet_sent_events(&trace, trusted, &self.config.chain_name_by_eid)
                 {
                    let src_chain_name = match self.chain_name_for_eid(event.packet.src_eid) {
                        Ok(name) => name,
                        Err(error) => {
                            first_source_fault.get_or_insert(error);
                            continue;
                        }
                    };
                    let Some(dst_chain_name) = self.config.chain_name_by_eid.get(&event.packet.dst_eid).cloned() else {
                        continue;
                    };
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
                        source_evidence: None,
                        read_block_pins: Vec::new(),
                    };
                    if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                        return Ok(sent_event);
                    }
                }
                return Err(first_source_fault.unwrap_or_else(|| AppCoreError::Internal(
                    "Packet sent event not found or not valid".to_string(),
                )));
            }
            if !self
                .config
                .packet_sent_bindings_by_chain_name
                .contains_key(&lz_message_id.pathway_id.src_chain_name)
            {
                return Err(AppCoreError::BadRequest(format!(
                    "Unsupported LayerZero source chain {}",
                    lz_message_id.pathway_id.src_chain_name
                )));
            }
            let receipt = self
                .get_receipt_logs(&lz_message_id.pathway_id.src_chain_name, src_tx_hash)
                .await?;
            let block_hash = receipt.block_hash;
            let status = receipt.status;
            let block_number = receipt.block_number
                .parse::<i64>()
                .map_err(|error| AppCoreError::Internal(error.to_string()))?;
            let logs = receipt.logs;
            let mut first_source_fault = None;
            for log in logs {
                let Ok(packet_sent) = decode_evm_packet_sent_log(
                    &log.topics,
                    &log.data,
                    &legacy_destination_address_size,
                ) else {
                    continue;
                };
                let Some(packet_log_index) = log.log_index.parse::<u64>().ok()
                else {
                    continue;
                };
                let source_evidence = EvmSourceEvidence {
                    block_hash: block_hash.clone(),
                    block_number,
                    status: status.clone(),
                    packet_log_index,
                    transaction_hash: receipt.transaction_hash.clone(),
                    packet_log_address: log.address.clone(),
                    packet_log_topics: log.topics,
                    packet_log_data: log.data,
                };
                // Non-fatal for the same reason the decode above is. A batching
                // transaction can emit several PacketSent events, and this
                // conversion fails for an unbound emitter/event pair, an unknown send
                // library or an endpoint id this deployment does not map. Propagating
                // that aborted the scan for every other event in the receipt, including
                // the one the request asked for; upstream logs and skips it too
                // (`evm/index.ts:222-228`).
                let sent_event = match self.packet_sent_to_lz_sent_event(
                    &lz_message_id.pathway_id.src_chain_name,
                    src_tx_hash,
                    packet_sent,
                    &log.address,
                    source_evidence,
                ) {
                    Ok(SourceEventConversion::Converted(sent_event)) => sent_event,
                    Ok(SourceEventConversion::NotOurs) => continue,
                    Ok(SourceEventConversion::SourceFault(error)) => {
                        first_source_fault.get_or_insert(error);
                        continue;
                    }
                    Err(_) => continue,
                };
                if lz_message_id_matches(lz_message_id, &sent_event.lz_message_id) {
                    return Ok(sent_event);
                }
            }
            Err(first_source_fault.unwrap_or_else(|| packet_does_not_match(src_tx_hash)))
        })
        .await
    }

    async fn refresh_uln_v2_sent_event(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<Option<pillar_core::UlnV2RefreshedEvent>, AppCoreError> {
        let src_chain_name = sent_event.lz_message_id.pathway_id.src_chain_name.clone();
        crate::provider_health::rpc_scope(&src_chain_name, async {
            if src_chain_name == "aptos" {
                self.refresh_aptos_uln_v2_sent_event(sent_event).await
            } else {
                self.refresh_evm_uln_v2_sent_event(sent_event).await
            }
        })
        .await
    }
}

fn json_rpc_body(method: &str, params: Value) -> Value {
    json!({"method": method, "params": params, "id": 1, "jsonrpc": "2.0"})
}

/// Upstream's `.replace(/^(0x)0*/i, '$1')` on a Move account in an event type.
fn strip_move_account_zeros(account: &str) -> String {
    let digits = strip_hex_prefix(account).trim_start_matches('0');
    format!("0x{digits}")
}

/// `getAddressInHex(getChainName(eid), address)` as bytes.
fn aptos_v1_guid_address(eid: u64, address: &str) -> Result<Vec<u8>, AppCoreError> {
    let chain_name = u32::try_from(eid)
        .ok()
        .and_then(pillar_config::layerzero_legacy_chain_name)
        .ok_or_else(|| {
            AppCoreError::Internal(format!("Invariant failed: Invalid endpointId: {eid}"))
        })?;
    let rendered = crate::provider_health::address_encoded_by_chain(chain_name, address)
        .ok_or_else(|| {
            AppCoreError::Internal(format!("invalid address {address} for {chain_name}"))
        })?;
    let mut bytes = if chain_name == "solana" {
        bs58::decode(&rendered)
            .into_vec()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?
    } else {
        hex::decode(strip_hex_prefix(&rendered))
            .map_err(|error| AppCoreError::Internal(error.to_string()))?
    };
    if chain_name == "solana" && bytes.len() < 32 {
        bytes.splice(0..0, std::iter::repeat_n(0, 32 - bytes.len()));
    }
    Ok(bytes)
}

/// `calculateAptosGuid` (`common-aptos/src/utils.ts:464-486`): sha3-256 over the
/// nonce, both u16 chain ids and both addresses in their chains' hex encodings.
pub(crate) fn aptos_v1_guid(lz_message_id: &LzMessageId) -> Result<String, AppCoreError> {
    let pathway = &lz_message_id.pathway_id.extra;
    let eid = |key: &str| {
        pathway
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}")))
    };
    let address = |key: &str| {
        pathway
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| AppCoreError::Internal(format!("Missing lzMessageId.pathwayId.{key}")))
    };
    let u16_eid = |value: u64| {
        u16::try_from(value).map_err(|_| {
            AppCoreError::Internal(format!(
                "The value of \"value\" is out of range. It must be >= 0 and <= 65535. Received {value}"
            ))
        })
    };
    let (src_eid, dst_eid) = (eid("srcEid")?, eid("dstEid")?);
    let mut encoded = lz_message_id.nonce.to_be_bytes().to_vec();
    encoded.extend_from_slice(&u16_eid(src_eid)?.to_be_bytes());
    encoded.extend(aptos_v1_guid_address(src_eid, address("sender")?)?);
    encoded.extend_from_slice(&u16_eid(dst_eid)?.to_be_bytes());
    encoded.extend(aptos_v1_guid_address(dst_eid, address("receiver")?)?);
    Ok(format!(
        "0x{}",
        hex::encode(<sha3::Sha3_256 as sha3::Digest>::digest(encoded))
    ))
}

/// What JavaScript's `.replace(/0x/i, '')` and `Buffer.from(_, 'hex')` make of an
/// adapter params value, or the TypeError reading it would throw.
fn aptos_adapter_params_bytes(raw: &Value) -> Result<Vec<u8>, AppCoreError> {
    let text = match raw {
        Value::String(text) => text,
        Value::Null => {
            return Err(AppCoreError::Internal(
                "Cannot read properties of null (reading 'replace')".to_string(),
            ))
        }
        _ => {
            return Err(AppCoreError::Internal(
                "rawAdapterParams.replace is not a function".to_string(),
            ))
        }
    };
    let lower = text.to_ascii_lowercase();
    let stripped = match lower.find("0x") {
        Some(at) => format!("{}{}", &text[..at], &text[at + 2..]),
        None => text.clone(),
    };
    Ok(pillar_layerzero::node_buffer_from_hex(&stripped))
}

pub(super) fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Value::String(text) => !text.is_empty(),
        _ => true,
    }
}

impl<T> EvmPacketSentResolver<T>
where
    T: JsonRpcTransport,
{
    /// One Aptos-family REST POST, agreed by the provider quorum on the whole answer.
    async fn post_aptos_json(
        &self,
        chain: &str,
        url_for: impl Fn(&str) -> Option<String>,
        body: Value,
        context: &str,
    ) -> Result<Value, AppCoreError> {
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(chain)?;
        let quorum = required_provider_quorum(provider_config, chain)?;
        let mut requests = FuturesUnordered::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let transport = self.transport.clone();
            let (base, headers) = move_provider_uri_parts(chain, uri);
            let url = url_for(&base);
            let body = body.clone();
            requests.push(async move {
                let response = match url {
                    Some(url) => transport.post_json_scoped(url, headers, body).await,
                    None => Err(RpcError::Remote("Unusable Aptos table handle".to_string())),
                };
                (index, response)
            });
        }
        let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..provider_config.uris.len());
        while let Some((index, response)) = requests.next().await {
            let observation = provider_response(response).map(|response| {
                response
                    .and_then(|value| serde_json::to_string(&value).ok().map(|key| (key, value)))
            });
            accumulator.record_result(index, observation)?;
            if let Some(value) = accumulator.unambiguous_result() {
                return Ok(value);
            }
        }
        self.finish_quorum(chain, accumulator, context).await
    }

    /// `LZAptosSdk.getLZSentEvent` (`lz-v1-sdk/src/aptos/aptos.ts:518-537,843-854`): the send's
    /// executor adapter params decide the gas of the rebuilt event. Every failure propagates.
    async fn refresh_aptos_uln_v2_sent_event(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<Option<pillar_core::UlnV2RefreshedEvent>, AppCoreError> {
        let source = self.config.aptos_v1_source.clone().ok_or_else(|| {
            AppCoreError::BadRequest("Unsupported LayerZero source chain aptos".to_string())
        })?;
        let version = aptos_ledger_version(&sent_event.tx_hash)?;
        let raw = self
            .aptos_executor_adapter_params("aptos", &source, &sent_event.lz_message_id, &version)
            .await?;
        let gas = pillar_layerzero::aptos_adapter_params_gas(&raw)?;
        Ok(Some(pillar_core::UlnV2RefreshedEvent {
            sent_event: sent_event.clone(),
            lz_receive_gas: Some(gas),
        }))
    }

    /// `getAdapterParams` (`lz-v1-sdk/src/aptos/utils.ts:16-101`, `aptos/views.ts:221-244`):
    /// the adapter params of the send's `executor_v2::ExecutorRequested`, else of its
    /// `executor_v1::RequestEvent` (the executor's table default when `0x`), as the bytes
    /// JavaScript's `.replace(/0x/i, '')` and `Buffer.from(_, 'hex')` make of them. Both
    /// executors live under the V1 LayerZero account; upstream reads it on `chain`.
    async fn aptos_executor_adapter_params(
        &self,
        chain: &str,
        source: &AptosV1Source,
        lz_message_id: &LzMessageId,
        ledger_version: &str,
    ) -> Result<Vec<u8>, AppCoreError> {
        let guid = aptos_v1_guid(lz_message_id)?;
        let transaction = self
            .get_aptos_json(
                chain,
                |base| aptos_transaction_by_version_url(base, ledger_version),
                "Aptos transaction",
            )
            .await?;
        let events = transaction
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                AppCoreError::Internal(
                    "Cannot read properties of undefined (reading 'filter')".to_string(),
                )
            })?;
        let account = strip_move_account_zeros(&source.layerzero_account);
        let find = |event_type: String| {
            events.iter().find(|event| {
                event.get("type").and_then(Value::as_str) == Some(event_type.as_str())
                    && event.pointer("/data/guid").and_then(Value::as_str) == Some(guid.as_str())
            })
        };
        let executor_v2 = find(format!("{account}::executor_v2::ExecutorRequested"))
            .and_then(|event| event.pointer("/data/adapter_params"))
            .filter(|raw| js_truthy(raw))
            .cloned();
        let raw = match executor_v2 {
            Some(raw) => raw,
            None => {
                let event =
                    find(format!("{account}::executor_v1::RequestEvent")).ok_or_else(|| {
                        AppCoreError::Internal(
                            "Cannot read properties of undefined (reading 'data')".to_string(),
                        )
                    })?;
                let raw = match event.get("data") {
                    None => {
                        return Err(AppCoreError::Internal(
                            "Cannot read properties of undefined (reading 'adapter_params')"
                                .to_string(),
                        ))
                    }
                    Some(Value::Null) => {
                        return Err(AppCoreError::Internal(
                            "Cannot read properties of null (reading 'adapter_params')".to_string(),
                        ))
                    }
                    Some(data) => data.get("adapter_params").cloned().ok_or_else(|| {
                        AppCoreError::Internal(
                            "Cannot read properties of undefined (reading 'replace')".to_string(),
                        )
                    })?,
                };
                if raw.as_str() == Some("0x") {
                    Value::from(hex::encode(
                        self.aptos_default_adapter_params(chain, source, lz_message_id)
                            .await?,
                    ))
                } else {
                    raw
                }
            }
        };
        aptos_adapter_params_bytes(&raw)
    }

    /// `updateLzSentEventOptionsForUln301` (`lz-v2-sdk/src/endpoint/aptos/index.ts:182-232`):
    /// a V301 send's options gain its executor adapter params' gas, and their native drop.
    async fn aptos_family_v301_options(
        &self,
        chain: &str,
        sent_event: &LzSentEvent,
        ledger_version: &str,
    ) -> Result<Value, AppCoreError> {
        let source = self.config.aptos_v1_source.clone().ok_or_else(|| {
            AppCoreError::BadRequest(format!("Unsupported LayerZero source chain {chain}"))
        })?;
        let raw = self
            .aptos_executor_adapter_params(
                chain,
                &source,
                &sent_event.lz_message_id,
                ledger_version,
            )
            .await?;
        let adapter = pillar_layerzero::decode_aptos_adapter_params(&raw)?;
        let dst_chain_name = &sent_event.lz_message_id.pathway_id.dst_chain_name;
        let mut options = sent_event
            .extra
            .get("options")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut drops = Vec::new();
        // `normalizeAdapterParams` keeps a native drop only for type 2 with a non-zero amount
        // and a receiver of the destination's address size.
        if adapter.kind == 2
            && adapter.airdrop_amount != 0
            && adapter.airdrop_address.len() == destination_address_size(dst_chain_name)
        {
            drops.push(json!({
                "amount": adapter.airdrop_amount.to_string(),
                "receiver": native_drop_receiver(dst_chain_name, &adapter.airdrop_address),
            }));
        }
        if let Some(Value::Array(existing)) = options.get("nativeDrop") {
            drops.extend(existing.iter().cloned());
        }
        let current_gas = options
            .get("lzReceive")
            .and_then(|receive| receive.get("gas"))
            .and_then(Value::as_str)
            .unwrap_or("0")
            .parse::<num_bigint::BigUint>()
            .map_err(|error| AppCoreError::Internal(error.to_string()))?;
        let value = options
            .get("lzReceive")
            .and_then(|receive| receive.get("value"))
            .cloned()
            .unwrap_or_else(|| Value::from("0"));
        options.insert(
            "lzReceive".to_string(),
            json!({"gas": (current_gas + adapter.gas).to_string(), "value": value}),
        );
        if !drops.is_empty() {
            options.insert("nativeDrop".to_string(), Value::Array(drops));
        }
        Ok(Value::Object(options))
    }

    /// `getDefaultAdapterParams`: the `executor_v1::AdapterParamsConfig` table entry for
    /// the destination, or type 1 with zero gas when that entry cannot be read.
    async fn aptos_default_adapter_params(
        &self,
        chain: &str,
        source: &AptosV1Source,
        lz_message_id: &LzMessageId,
    ) -> Result<Vec<u8>, AppCoreError> {
        let resource_type = format!(
            "{}::executor_v1::AdapterParamsConfig",
            source.layerzero_account
        );
        let resource = self
            .get_aptos_json(
                chain,
                |base| aptos_account_resource_url(base, &source.layerzero_account, &resource_type),
                "Aptos adapter params config",
            )
            .await?;
        let fallback = || {
            let mut bytes = vec![0, 1];
            bytes.extend_from_slice(&0u64.to_be_bytes());
            bytes
        };
        let Some(handle) = resource
            .pointer("/data/params/handle")
            .and_then(Value::as_str)
        else {
            return Ok(fallback());
        };
        let key = lz_message_id
            .pathway_id
            .extra
            .get("dstEid")
            .map(|eid| eid.to_string())
            .unwrap_or_default();
        let item = self
            .post_aptos_json(
                chain,
                |base| aptos_table_item_url(base, handle),
                json!({"key_type": "u64", "value_type": "vector<u8>", "key": key}),
                "Aptos adapter params table",
            )
            .await;
        Ok(match item {
            Ok(Value::String(text)) => {
                pillar_layerzero::node_buffer_from_hex(strip_hex_prefix(&text))
            }
            _ => fallback(),
        })
    }

    /// `LZEvmSdk.getLZSentEvent` (`lz-v1-sdk/src/evm/index.ts:966-1071`): the receipt is
    /// read again and its matching `Packet` kept if its adapter params decode; otherwise
    /// the ULNv2 `Packet` logs around the send's block are searched, a reorg having moved
    /// it. Adapter-params failures are swallowed there, so they end in `None`; only the
    /// receipt read, the block range lookup and the log read propagate.
    async fn refresh_evm_uln_v2_sent_event(
        &self,
        sent_event: &LzSentEvent,
    ) -> Result<Option<pillar_core::UlnV2RefreshedEvent>, AppCoreError> {
        let chain = sent_event.lz_message_id.pathway_id.src_chain_name.as_str();
        let lz_message_id = &sent_event.lz_message_id;
        let uln = self
            .config
            .packet_sent_bindings_by_chain_name
            .get(chain)
            .and_then(|bindings| bindings.uln_v2.clone())
            .ok_or_else(|| AppCoreError::Internal("Unsupported ULN version V2".to_string()))?;
        let receipt = self
            .get_quorum_rpc_result(
                chain,
                json_rpc_body("eth_getTransactionReceipt", json!([sent_event.tx_hash])),
                "receipt",
            )
            .await?;
        let receipt = (!receipt.is_null()).then_some(receipt);
        if let Some(receipt) = &receipt {
            for event in self.uln_v2_packet_events(chain, &uln, &sent_event.tx_hash, receipt) {
                if !lz_message_id_matches(lz_message_id, &event.lz_message_id) {
                    continue;
                }
                if let Some(gas) = self
                    .uln_v2_adapter_params_gas(chain, &uln, lz_message_id, receipt)
                    .await
                {
                    return Ok(Some(pillar_core::UlnV2RefreshedEvent {
                        sent_event: event,
                        lz_receive_gas: Some(gas),
                    }));
                }
            }
        }
        let range = self
            .config
            .max_eth_get_logs_block_range_by_chain_name
            .get(chain)
            .copied()
            .ok_or_else(|| {
                AppCoreError::Internal(
                    "Cannot read properties of undefined (reading 'maxEthGetLogsBlockRange')"
                        .to_string(),
                )
            })?;
        let half = i64::from(range / 2);
        let center = receipt
            .as_ref()
            .and_then(|receipt| receipt.get("blockNumber"))
            .and_then(numeric_response)
            .and_then(|number| number.parse::<i64>().ok())
            .or_else(|| {
                sent_event
                    .source_evidence
                    .as_ref()
                    .map(|evidence| evidence.block_number)
            })
            .ok_or_else(|| AppCoreError::Internal("Invalid receipt block number".to_string()))?;
        let mut from_block = center - half;
        if from_block < 0 {
            // ethers resolves a negative block tag against the latest block.
            let latest = self
                .get_quorum_rpc_result(
                    chain,
                    json_rpc_body("eth_blockNumber", json!([])),
                    "block number",
                )
                .await?;
            let latest = numeric_response(&latest)
                .and_then(|number| number.parse::<i64>().ok())
                .ok_or_else(|| AppCoreError::Internal("Invalid block number".to_string()))?;
            from_block = (latest + from_block).max(0);
        }
        let logs = self
            .get_quorum_rpc_result(
                chain,
                json_rpc_body(
                    "eth_getLogs",
                    json!([{
                        "fromBlock": format!("0x{from_block:x}"),
                        "toBlock": format!("0x{:x}", center + half),
                        "address": uln,
                        "topics": [pillar_layerzero::ULN_V2_PACKET_TOPIC],
                    }]),
                ),
                "logs",
            )
            .await?;
        for log in logs.as_array().into_iter().flatten() {
            let Some(tx_hash) = log.get("transactionHash").and_then(Value::as_str) else {
                continue;
            };
            let Some(event) = self.uln_v2_packet_event_from_log(chain, &uln, tx_hash, log, None)
            else {
                continue;
            };
            if !lz_message_id_matches(lz_message_id, &event.lz_message_id) {
                continue;
            }
            let Ok(receipt) = self
                .get_quorum_rpc_result(
                    chain,
                    json_rpc_body("eth_getTransactionReceipt", json!([tx_hash])),
                    "receipt",
                )
                .await
            else {
                continue;
            };
            if receipt.is_null() {
                continue;
            }
            let status = receipt.get("status").and_then(Value::as_str);
            let Some(event) = self.uln_v2_packet_event_from_log(chain, &uln, tx_hash, log, status)
            else {
                continue;
            };
            if let Some(gas) = self
                .uln_v2_adapter_params_gas(chain, &uln, lz_message_id, &receipt)
                .await
            {
                return Ok(Some(pillar_core::UlnV2RefreshedEvent {
                    sent_event: event,
                    lz_receive_gas: Some(gas),
                }));
            }
        }
        Ok(None)
    }

    /// Each ULNv2 `Packet` log of `uln` in a receipt, as this resolver reads a send.
    fn uln_v2_packet_events(
        &self,
        chain: &str,
        uln: &str,
        tx_hash: &str,
        receipt: &Value,
    ) -> Vec<LzSentEvent> {
        let status = receipt.get("status").and_then(Value::as_str);
        receipt
            .get("logs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|log| {
                let log = log.as_object().map(|_| log)?;
                let mut log = log.clone();
                if let (Some(object), Some(block_hash), Some(block_number)) = (
                    log.as_object_mut(),
                    receipt.get("blockHash").cloned(),
                    receipt.get("blockNumber").cloned(),
                ) {
                    object.insert("blockHash".to_string(), block_hash);
                    object.insert("blockNumber".to_string(), block_number);
                }
                self.uln_v2_packet_event_from_log(chain, uln, tx_hash, &log, status)
            })
            .collect()
    }

    fn uln_v2_packet_event_from_log(
        &self,
        chain: &str,
        uln: &str,
        tx_hash: &str,
        log: &Value,
        status: Option<&str>,
    ) -> Option<LzSentEvent> {
        let address = log.get("address").and_then(Value::as_str)?;
        let topics: Vec<String> = log
            .get("topics")
            .and_then(Value::as_array)?
            .iter()
            .map(|topic| topic.as_str().map(str::to_string))
            .collect::<Option<_>>()?;
        if !address.eq_ignore_ascii_case(uln)
            || !topics.first().is_some_and(|topic| {
                topic.eq_ignore_ascii_case(pillar_layerzero::ULN_V2_PACKET_TOPIC)
            })
        {
            return None;
        }
        let packet_sent = decode_evm_packet_sent_log(
            &topics,
            log.get("data").and_then(Value::as_str)?,
            &legacy_destination_address_size,
        )
        .ok()?;
        let number = |key: &str| {
            log.get(key)
                .and_then(numeric_response)
                .and_then(|value| value.parse::<i64>().ok())
        };
        let source_evidence = EvmSourceEvidence {
            block_hash: log
                .get("blockHash")
                .and_then(Value::as_str)?
                .to_ascii_lowercase(),
            block_number: number("blockNumber")?,
            status: status.unwrap_or_default().to_string(),
            packet_log_index: u64::try_from(number("logIndex")?).ok()?,
            transaction_hash: log
                .get("transactionHash")
                .and_then(Value::as_str)
                .unwrap_or(tx_hash)
                .to_ascii_lowercase(),
            packet_log_address: address.to_ascii_lowercase(),
            packet_log_topics: topics
                .iter()
                .map(|topic| topic.to_ascii_lowercase())
                .collect(),
            packet_log_data: log
                .get("data")
                .and_then(Value::as_str)?
                .to_ascii_lowercase(),
        };
        let SourceEventConversion::Converted(event) = self
            .packet_sent_to_lz_sent_event(chain, tx_hash, packet_sent, address, source_evidence)
            .ok()?
        else {
            return None;
        };
        (event.lz_message_id.uln_send_version == ULN_VERSION_V2).then_some(event)
    }

    /// `getAdapterParams` (`lz-v1-sdk/src/evm/index.ts:840-920`): scanning the receipt from
    /// its last log, the `RelayerParams` nearest below the matching `Packet`. A packet at
    /// index 0 never qualifies (`lzMessageLogIndex &&`). `None` is any of its throws.
    async fn uln_v2_adapter_params_gas(
        &self,
        chain: &str,
        uln: &str,
        lz_message_id: &LzMessageId,
        receipt: &Value,
    ) -> Option<String> {
        let logs = receipt.get("logs").and_then(Value::as_array)?;
        let mut packet_index = None;
        for (index, log) in logs.iter().enumerate().rev() {
            let Some(topic0) = log
                .get("topics")
                .and_then(Value::as_array)
                .and_then(|topics| topics.first())
                .and_then(Value::as_str)
            else {
                continue;
            };
            let at_uln = log
                .get("address")
                .and_then(Value::as_str)
                .is_some_and(|address| address.eq_ignore_ascii_case(uln));
            if at_uln && topic0.eq_ignore_ascii_case(pillar_layerzero::ULN_V2_PACKET_TOPIC) {
                let mut log = log.clone();
                if let Some(object) = log.as_object_mut() {
                    object.insert("blockHash".to_string(), json!("0x"));
                    object.insert("blockNumber".to_string(), json!("0x0"));
                    object.entry("logIndex").or_insert(json!("0x0"));
                }
                let tx_hash = log
                    .get("transactionHash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if self
                    .uln_v2_packet_event_from_log(chain, uln, &tx_hash, &log, None)
                    .is_some_and(|event| lz_message_id_matches(lz_message_id, &event.lz_message_id))
                {
                    packet_index = Some(index);
                }
            }
            if packet_index.is_some_and(|found| found != 0)
                && at_uln
                && topic0.eq_ignore_ascii_case(pillar_layerzero::ULN_V2_RELAYER_PARAMS_TOPIC)
            {
                let data =
                    hex::decode(strip_hex_prefix(log.get("data").and_then(Value::as_str)?)).ok()?;
                let (adapter_params, proof_type) =
                    pillar_layerzero::decode_uln_v2_relayer_params_log(&data).ok()?;
                let raw = if adapter_params.is_empty() {
                    let dst_eid = lz_message_id
                        .pathway_id
                        .extra
                        .get("dstEid")
                        .and_then(Value::as_u64)
                        .and_then(|eid| u16::try_from(eid).ok())?;
                    let result = self
                        .get_quorum_rpc_result(
                            chain,
                            json_rpc_body(
                                "eth_call",
                                json!([{
                                    "to": uln,
                                    "data": pillar_layerzero::encode_uln_v2_default_adapter_params_call(dst_eid, proof_type),
                                }, "latest"]),
                            ),
                            "default adapter params",
                        )
                        .await
                        .ok()?;
                    let returned = hex::decode(strip_hex_prefix(result.as_str()?)).ok()?;
                    pillar_layerzero::decode_abi_bytes_return(&returned).ok()?
                } else {
                    adapter_params
                };
                return pillar_layerzero::evm_adapter_params_gas(&raw);
            }
        }
        None
    }
}

/// The emitter must be the one contract whose interface produced `kind`, and the
/// version follows from that pairing alone; anything else is refused.
pub(crate) fn bound_evm_packet_sent_version(
    bindings: &EvmPacketSentBindings,
    kind: &EvmPacketSentKind,
    emitter: &str,
) -> Result<(String, String), String> {
    let normalized = normalize_address(emitter);
    match kind {
        EvmPacketSentKind::EndpointV2 { send_library } => {
            if normalized != bindings.endpoint_v2 {
                return Err("EndpointV2 PacketSent not emitted by EndpointV2".to_string());
            }
            let version = bindings
                .endpoint_v2_send_library_versions
                .get(&normalize_address(send_library))
                .ok_or_else(|| {
                    format!("send library {send_library} is not an EndpointV2 library")
                })?;
            Ok((send_library.clone(), version.clone()))
        }
        EvmPacketSentKind::SendUln301 => {
            if bindings.send_uln_301.as_deref() != Some(normalized.as_str()) {
                return Err("SendUln301 PacketSent not emitted by SendUln301".to_string());
            }
            Ok((emitter.to_string(), ULN_VERSION_V301.to_string()))
        }
        EvmPacketSentKind::UltraLightNodeV2 => {
            if bindings.uln_v2.as_deref() != Some(normalized.as_str()) {
                return Err("ULNv2 Packet not emitted by UltraLightNodeV2".to_string());
            }
            Ok((emitter.to_string(), ULN_VERSION_V2.to_string()))
        }
    }
}

/// Upstream's `Packet does not match lzMessageId` (EVM, Starknet, Stellar endpoint
/// sdks), thrown both when no trusted PacketSent exists and when none matches;
/// `app.ts:479-488` answers it with the 400 `cannot find packet event ...`.
fn packet_does_not_match(src_tx_hash: &str) -> AppCoreError {
    AppCoreError::BadRequest(format!(
        "No trusted PacketSent event in {src_tx_hash} {}",
        pillar_core::PACKET_IDENTITY_MISMATCH_ERROR_SUFFIX
    ))
}

/// `getAddressSizeInBytesFromChainId`: 32 for a non-EVM chain id, 20 otherwise.
fn aptos_v1_address_size(chain_id: u16) -> usize {
    match pillar_config::layerzero_legacy_chain_name(u32::from(chain_id)) {
        Some(chain_name)
            if chain_name == "solana"
                || crate::provider_health::address_encoded_by_chain(chain_name, "0x00")
                    .is_some_and(|rendered| rendered.len() == 66) =>
        {
            32
        }
        _ => 20,
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

/// `getAddressSizeInBytes(getChainName(dstChainId))`, 20 where the id names no chain
/// (`lz-v1-sdk/src/evm/decoders/index.ts:48-56`).
fn legacy_destination_address_size(dst_chain_id: u32) -> usize {
    pillar_config::layerzero_legacy_chain_name(dst_chain_id)
        .map(destination_address_size)
        .unwrap_or(20)
}
