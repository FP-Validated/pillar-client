use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_readiness_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
        match signing_context {
            SigningContext::Message {
                block_confirmation, ..
            } => self
                .validate_message_readiness_with_quorum(sent_event, *block_confirmation)
                .await
                .map(|()| Vec::new()),
            SigningContext::Read {
                resolved_timestamp_time_markers,
                ..
            } => {
                self.validate_read_time_markers(sent_event, resolved_timestamp_time_markers)
                    .await
            }
        }
    }

    async fn validate_message_readiness_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        block_confirmation: i64,
    ) -> Result<(), AppCoreError> {
        crate::provider_health::rpc_scope(&sent_event.lz_message_id.pathway_id.src_chain_name, async { let src_chain_name = &sent_event.lz_message_id.pathway_id.src_chain_name;
    let snapshot = self.providers.load();
    let provider_config = snapshot.provider_config(src_chain_name)?;
    if provider_config.uris.is_empty() {
        return Err(AppCoreError::Internal(format!(
            "No provider URI for chain {src_chain_name}"
        )));
    }
    if src_chain_name == "solana" {
        return self
            .validate_solana_readiness_with_quorum(
                src_chain_name,
                &sent_event.tx_hash,
                block_confirmation,
                provider_config,
            )
            .await;
    }
    if src_chain_name == "ton" {
        let agreed_seqno = sent_event
            .extra
            .get("blockNumber")
            .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()));
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum).await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let transport = self.transport.clone();
            let seqno = agreed_seqno;
            let required = block_confirmation;
            let parts = ton_v3_provider_uri_parts(uri);
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = match (parts, seqno) {
                    (Some((endpoint, _, headers)), Some(seqno)) => {
                        observe_ton_block_confirmations(transport, endpoint, headers, seqno, required).await
                    }
                    _ => Ok(BlockConfirmationObservation {
                        validity: BlockConfirmationValidity::Missing,
                        current_confirmations: None,
                    }),
                };
                (index, observation.map(|observation| Some((format!("{:?}", observation.validity), observation))))
            });
        }
        let context = "block confirmation for chain ton".to_string();
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?;
        return match observation.validity {
            BlockConfirmationValidity::Sufficient { .. } => Ok(()),
            BlockConfirmationValidity::Insufficient { .. } => {
                Err(AppCoreError::BadRequest(format!(
                    "block confirmations not met, current block confirmation: {}",
                    observation.current_confirmations.unwrap_or_default()
                )))
            }
            BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
                "Transaction trace or masterchain info not found for {}",
                sent_event.tx_hash
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
            BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
                format!("source receipt binding changed: {reason}"),
            )),
        };
    }
    if matches!(src_chain_name.as_str(), "aptos" | "initia" | "movement") {
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum)
        .await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = move_provider_uri_parts(src_chain_name, uri);
            let transport = self.transport.clone();
            let chain_name = src_chain_name.to_string();
            let tx_hash = sent_event.tx_hash.clone();
            let required_confirmations = block_confirmation;
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_move_block_confirmations(
                    transport,
                    &chain_name,
                    url,
                    headers,
                    &tx_hash,
                    required_confirmations,
                )
                .await;
                (index, observation.map(|observation| Some((format!("{:?}", observation.validity), observation))))
            });
        }
        let context = format!("block confirmation for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?;
        return match observation.validity {
            BlockConfirmationValidity::Sufficient { .. } => Ok(()),
            BlockConfirmationValidity::Insufficient { .. } => {
                let current_confirmations =
                    observation.current_confirmations.unwrap_or_default();
                Err(AppCoreError::BadRequest(format!(
                    "block confirmations not met, current block confirmation: {current_confirmations}"
                )))
            }
            BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
                "Transaction receipt or block not found for {}",
                sent_event.tx_hash
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
            BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
                format!("source receipt binding changed: {reason}"),
            )),
        };
    }
    if matches!(src_chain_name.as_str(), "sui" | "iotal1") {
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum)
        .await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let chain_name = src_chain_name.to_string();
            let tx_hash = sent_event.tx_hash.clone();
            let required_confirmations = block_confirmation;
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_sui_block_confirmations_rpc(
                    transport,
                    &chain_name,
                    url,
                    headers,
                    &tx_hash,
                    required_confirmations,
                )
                .await;
                let observation = observation.map(|observation| {
                let validity = match observation.validity {
                    SuiBlockConfirmationValidity::Sufficient => {
                        BlockConfirmationValidity::Sufficient {
                            receipt_block_hash: String::new(),
                            receipt_block_number: 0,
                        }
                    }
                    SuiBlockConfirmationValidity::Insufficient => {
                        BlockConfirmationValidity::Insufficient {
                            receipt_block_hash: String::new(),
                            receipt_block_number: 0,
                        }
                    }
                    SuiBlockConfirmationValidity::Missing => BlockConfirmationValidity::Missing,
                    SuiBlockConfirmationValidity::InvalidRange => {
                        BlockConfirmationValidity::InvalidRange
                    }
                };
                BlockConfirmationObservation { validity,
                current_confirmations: observation.current_confirmations }
                });
                (index, observation.map(|observation| Some((format!("{:?}", observation.validity), observation))))
            });
        }
        let context = format!("block confirmation for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?;
        return match observation.validity {
            BlockConfirmationValidity::Sufficient { .. } => Ok(()),
            BlockConfirmationValidity::Insufficient { .. } => {
                let current_confirmations =
                    observation.current_confirmations.unwrap_or_default();
                Err(AppCoreError::BadRequest(format!(
                    "block confirmations not met, current block confirmation: {current_confirmations}"
                )))
            }
            BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
                "Transaction receipt or block not found for {}",
                sent_event.tx_hash
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
            BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
                format!("source receipt binding changed: {reason}"),
            )),
        };
    }
    if src_chain_name == "canton" {
        let sequencer = canton_sequencer(src_chain_name, provider_config)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| AppCoreError::Internal(error.to_string()))?
            .as_secs_f64()
            .floor();
        let nonce = sent_event
            .extra
            .get("blockNumber")
            .and_then(Value::as_f64)
            .unwrap_or(f64::NAN);
        let current =
            canton_block_confirmations(&self.transport, &sequencer, nonce, now).await?;
        if current < block_confirmation as f64 {
            return Err(AppCoreError::BadRequest(format!(
                "block confirmations not met, current block confirmation: {}",
                pillar_core::js_number_f64(current)
            )));
        }
        return Ok(());
    }
    if src_chain_name == "starknet" {
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum)
        .await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let tx_hash = sent_event.tx_hash.clone();
            let required_confirmations = block_confirmation;
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_starknet_block_confirmations(
                    transport,
                    url,
                    headers,
                    &tx_hash,
                    required_confirmations,
                )
                .await;
                (index, observation.map(|observation| Some((format!("{:?}", observation.validity), observation))))
            });
        }
        let context = format!("block confirmation for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?;
        return match observation.validity {
            BlockConfirmationValidity::Sufficient { .. } => Ok(()),
            BlockConfirmationValidity::Insufficient { .. } => {
                let current_confirmations =
                    observation.current_confirmations.unwrap_or_default();
                Err(AppCoreError::BadRequest(format!(
                    "block confirmations not met, current block confirmation: {current_confirmations}"
                )))
            }
            BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
                "Transaction receipt or block not found for {}",
                sent_event.tx_hash
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
            BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
                format!("source receipt binding changed: {reason}"),
            )),
        };
    }
    if src_chain_name == "stellar" {
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum)
        .await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let tx_hash = sent_event.tx_hash.clone();
            let required_confirmations = block_confirmation;
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_stellar_block_confirmations(
                    transport,
                    url,
                    headers,
                    &tx_hash,
                    required_confirmations,
                )
                .await;
                (index, observation.map(|observation| Some((format!("{:?}", observation.validity), observation))))
            });
        }
        let context = format!("block confirmation for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?;
        return match observation.validity {
            BlockConfirmationValidity::Sufficient { .. } => Ok(()),
            BlockConfirmationValidity::Insufficient { .. } => {
                let current_confirmations =
                    observation.current_confirmations.unwrap_or_default();
                Err(AppCoreError::BadRequest(format!(
                    "block confirmations not met, current block confirmation: {current_confirmations}"
                )))
            }
            BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
                "Transaction receipt or block not found for {}",
                sent_event.tx_hash
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
            BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
                format!("source receipt binding changed: {reason}"),
            )),
        };
    }
    if sent_event.source_evidence.is_none() {
        return Err(AppCoreError::Internal(
            "Missing source evidence for EVM readiness".to_string(),
        ));
    }
    let quorum = required_provider_quorum(provider_config, src_chain_name)?;
    let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum)
    .await?;
    let requests = FuturesUnordered::new();
    for DispatchEntry { index, uri, delay } in plan {
        let (url, headers) = provider_uri_parts(uri);
        let transport = self.transport.clone();
        let tx_hash = sent_event.tx_hash.clone();
        let source_evidence = sent_event.source_evidence.clone();
        requests.push(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let observation = observe_block_confirmations(
                transport,
                url,
                headers,
                &tx_hash,
                source_evidence.as_ref(),
                block_confirmation,
                matches!(src_chain_name.as_str(), "polygon" | "tron"),
            )
            .await;
            (index, observation.map(|observation| Some((format!("{:?}", observation.validity), observation))))
        });
    }
    let context = format!("block confirmation for chain {src_chain_name}");
    let observation = match resolve_provider_quorum_with_zero_signal(
        requests,
        provider_config.uris.len(),
        quorum,
        &context,
    )
    .await
    {
        Ok(observation) => observation,
        Err(QuorumResolutionFailure::ZeroSuccessfulResponses) => {
            return Err(AppCoreError::Internal(format!(
                "Transaction receipt or block not found for {}",
                sent_event.tx_hash
            )));
        }
        Err(QuorumResolutionFailure::Other(error)) => return Err(error),
    };

    match observation.validity {
        BlockConfirmationValidity::Sufficient { .. } => Ok(()),
        BlockConfirmationValidity::Insufficient { .. } => {
            let current_confirmations = observation.current_confirmations.unwrap_or_default();
            Err(AppCoreError::BadRequest(format!(
                "block confirmations not met, current block confirmation: {current_confirmations}"
            )))
        }
        BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
            "Transaction receipt or block not found for {}",
            sent_event.tx_hash
        ))),
        BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
            "block confirmation range overflow".to_string(),
        )),
        BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
            format!("source receipt binding changed: {reason}"),
        )),
    } }).await
    }

    async fn validate_solana_readiness_with_quorum(
        &self,
        src_chain_name: &str,
        tx_hash: &str,
        required_confirmations: i64,
        provider_config: &pillar_config::ProviderConfig,
    ) -> Result<(), AppCoreError> {
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(&self.rank_tracker, src_chain_name, quorum).await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let tx_hash = tx_hash.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_solana_slot_confirmations(
                    transport,
                    url,
                    headers,
                    &tx_hash,
                    required_confirmations,
                )
                .await;

                (
                    index,
                    observation.map(|observation| {
                        Some((format!("{:?}", observation.validity), observation))
                    }),
                )
            });
        }
        let context = format!("block confirmation for chain {src_chain_name}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;

        match observation.validity {
            BlockConfirmationValidity::Sufficient { .. } => Ok(()),
            BlockConfirmationValidity::Insufficient { .. } => {
                let current_confirmations = observation.current_confirmations.unwrap_or_default();
                Err(AppCoreError::BadRequest(format!(
                    "block confirmations not met, current block confirmation: {current_confirmations}"
                )))
            }
            BlockConfirmationValidity::Missing => Err(AppCoreError::Internal(format!(
                "Transaction receipt or block not found for {tx_hash}"
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
            BlockConfirmationValidity::SourceChanged(reason) => Err(AppCoreError::BadRequest(
                format!("source receipt binding changed: {reason}"),
            )),
        }
    }
}

pub(super) fn readiness_response(response: Result<Value, RpcError>) -> Result<Value, RpcError> {
    let response = response?;
    if let Some(error) = response.get("error") {
        return Err(RpcError::Remote(error.to_string()));
    }
    Ok(response)
}

async fn observe_ton_block_confirmations<T>(
    transport: T,
    endpoint: String,
    headers: HashMap<String, String>,
    tx_seqno: i64,
    required_confirmations: i64,
) -> Result<BlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    if required_confirmations < 0 || tx_seqno < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    }
    let current_response = readiness_response(
        transport
            .get_json_scoped(
                format!("{}/masterchainInfo", endpoint.trim_end_matches('/')),
                headers,
            )
            .await,
    )?;
    let current = current_response
        .pointer("/last/seqno")
        .and_then(Value::as_i64)
        .or_else(|| {
            current_response
                .pointer("/last/seqno")
                .and_then(Value::as_str)?
                .parse()
                .ok()
        });
    let current = current.ok_or_else(|| {
        RpcError::Remote("TON masterchain info has no valid latest seqno".to_string())
    })?;
    let confirmations = (current - tx_seqno).max(0);
    let validity = if confirmations >= required_confirmations {
        BlockConfirmationValidity::Sufficient {
            receipt_block_hash: tx_seqno.to_string(),
            receipt_block_number: tx_seqno,
        }
    } else {
        BlockConfirmationValidity::Insufficient {
            receipt_block_hash: tx_seqno.to_string(),
            receipt_block_number: tx_seqno,
        }
    };
    Ok(BlockConfirmationObservation {
        validity,
        current_confirmations: Some(confirmations),
    })
}

async fn observe_solana_slot_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> Result<BlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    let transaction_transport = transport.clone();
    let transaction = transaction_transport.post_json_scoped(url.clone(),
headers.clone(),
json!({
    "method": "getTransaction",
    "params": [
        tx_hash,
        {
            "encoding": "json",
            "commitment": "finalized",
            "maxSupportedTransactionVersion": crate::SOLANA_MAX_SUPPORTED_TRANSACTION_VERSION,
        },
    ],
    "id": 1,
    "jsonrpc": "2.0",
}),);
    let slot = transport.post_json_scoped(
        url,
        headers,
        json!({
            "method": "getSlot",
            "params": [{ "commitment": "finalized" }],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let (transaction_response, slot_response) = tokio::join!(transaction, slot);

    let transaction_response = readiness_response(transaction_response)?;
    let slot_response = readiness_response(slot_response)?;
    let transaction_result = transaction_response.get("result").ok_or_else(|| {
        RpcError::Remote("Solana getTransaction response has no result".to_string())
    })?;
    if transaction_result.is_null() {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        });
    }
    let tx_slot = parse_solana_transaction_slot(&transaction_response).map_err(RpcError::Remote)?;
    let current_slot = parse_solana_current_slot(&slot_response).map_err(RpcError::Remote)?;

    let (Some(current_confirmations), Some(required_slot)) = (
        current_slot.checked_sub(tx_slot),
        tx_slot.checked_add(required_confirmations),
    ) else {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    };
    if tx_slot < 0 || current_slot < 0 || required_confirmations < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    }
    let validity = if current_slot >= required_slot {
        BlockConfirmationValidity::Sufficient {
            receipt_block_hash: tx_slot.to_string(),
            receipt_block_number: tx_slot,
        }
    } else {
        BlockConfirmationValidity::Insufficient {
            receipt_block_hash: tx_slot.to_string(),
            receipt_block_number: tx_slot,
        }
    };
    Ok(BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    })
}

fn parse_solana_transaction_slot(response: &Value) -> Result<i64, String> {
    response
        .get("result")
        .filter(|result| !result.is_null())
        .and_then(|result| result.get("slot"))
        .and_then(Value::as_i64)
        .ok_or_else(|| "Missing Solana transaction slot".to_string())
}

fn parse_solana_current_slot(response: &Value) -> Result<i64, String> {
    response
        .get("result")
        .and_then(Value::as_i64)
        .ok_or_else(|| "Missing Solana current slot".to_string())
}

async fn observe_starknet_block_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> Result<BlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    let receipt_transport = transport.clone();
    let receipt = receipt_transport.post_json_scoped(
        url.clone(),
        headers.clone(),
        json!({
            "method": "starknet_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let current = transport.post_json_scoped(
        url,
        headers,
        json!({
            "method": "starknet_blockNumber",
            "params": [],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let (receipt_response, current_response) = tokio::join!(receipt, current);
    let receipt_response = readiness_response(receipt_response)?;
    let receipt_block = match receipt_response.get("result") {
        None | Some(Value::Null) => None,
        Some(result) => match result.get("block_hash").and_then(Value::as_str) {
            None => None,
            Some(hash) => {
                let number = result
                    .get("block_number")
                    .and_then(numeric_response)
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| {
                        RpcError::Remote("Malformed Starknet receipt block_number".to_string())
                    })?;
                Some((hash.to_string(), number))
            }
        },
    };
    let current_response = readiness_response(current_response)?;
    let current_block = current_response
        .get("result")
        .and_then(numeric_response)
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| RpcError::Remote("Malformed Starknet block number".to_string()))?;
    let (Some((receipt_hash, receipt_number)), current_number) = (receipt_block, current_block)
    else {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        });
    };
    let (Some(current_confirmations), Some(required_block)) = (
        current_number.checked_sub(receipt_number),
        receipt_number.checked_add(required_confirmations),
    ) else {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    };
    if receipt_number < 0 || current_number < 0 || required_confirmations < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    }
    let validity = if current_number >= required_block {
        BlockConfirmationValidity::Sufficient {
            receipt_block_hash: receipt_hash,
            receipt_block_number: receipt_number,
        }
    } else {
        BlockConfirmationValidity::Insufficient {
            receipt_block_hash: receipt_hash,
            receipt_block_number: receipt_number,
        }
    };
    Ok(BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    })
}

async fn observe_stellar_block_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> Result<BlockConfirmationObservation, RpcError>
where
    T: JsonRpcTransport,
{
    let transaction_transport = transport.clone();
    let transaction = transaction_transport.post_json_scoped(
        url.clone(),
        headers.clone(),
        json!({
            "method": "getTransaction",
            "params": {"hash": tx_hash},
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let latest = transport.post_json_scoped(
        url,
        headers,
        json!({
            "method": "getLatestLedger",
            "params": {},
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let (transaction_response, latest_response) = tokio::join!(transaction, latest);
    let transaction_response = readiness_response(transaction_response)?;
    let transaction_ledger = match transaction_response.get("result") {
        None | Some(Value::Null) => None,
        Some(result) => match result.get("status").and_then(Value::as_str) {
            Some("NOT_FOUND") | Some("FAILED") => None,
            Some("SUCCESS") => Some(
                result
                    .get("ledger")
                    .and_then(numeric_response)
                    .and_then(|value| value.parse::<i64>().ok())
                    .ok_or_else(|| {
                        RpcError::Remote("Malformed Stellar transaction ledger".to_string())
                    })?,
            ),
            _ => {
                return Err(RpcError::Remote(
                    "Malformed Stellar transaction status".to_string(),
                ))
            }
        },
    };
    let current_ledger = readiness_response(latest_response)?
        .get("result")
        .and_then(|result| result.get("sequence"))
        .and_then(numeric_response)
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| RpcError::Remote("Malformed Stellar ledger sequence".to_string()))?;
    let Some(transaction_ledger) = transaction_ledger else {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        });
    };
    let (Some(current_confirmations), Some(required_ledger)) = (
        current_ledger.checked_sub(transaction_ledger),
        transaction_ledger.checked_add(required_confirmations),
    ) else {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    };
    if transaction_ledger < 0 || current_ledger < 0 || required_confirmations < 0 {
        return Ok(BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        });
    }
    let validity = if current_ledger >= required_ledger {
        BlockConfirmationValidity::Sufficient {
            receipt_block_hash: transaction_ledger.to_string(),
            receipt_block_number: transaction_ledger,
        }
    } else {
        BlockConfirmationValidity::Insufficient {
            receipt_block_hash: transaction_ledger.to_string(),
            receipt_block_number: transaction_ledger,
        }
    };
    Ok(BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    })
}

#[cfg(test)]
mod ton_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RecordingTransport {
        responses: Arc<Mutex<Vec<Result<Value, String>>>>,
        urls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl JsonRpcTransport for RecordingTransport {
        async fn post_json(
            &self,
            _url: String,
            _headers: HashMap<String, String>,
            _body: Value,
        ) -> Result<Value, String> {
            Err("unexpected POST".to_string())
        }

        async fn get_json(
            &self,
            url: String,
            _headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            self.urls
                .lock()
                .map_err(|_| "recording transport mutex poisoned".to_string())?
                .push(url);
            self.responses
                .lock()
                .map_err(|_| "recording transport mutex poisoned".to_string())?
                .remove(0)
        }
    }

    async fn observe(trace: Value, head: i64, tx_hash: &str) -> BlockConfirmationObservation {
        observe_recording(trace, head, tx_hash).await.0
    }

    async fn observe_recording(
        trace: Value,
        head: i64,
        tx_hash: &str,
    ) -> (BlockConfirmationObservation, Vec<String>) {
        let urls = Arc::new(Mutex::new(Vec::new()));
        let transport = RecordingTransport {
            responses: Arc::new(Mutex::new(vec![Ok(json!({"last": {"seqno": head}}))])),
            urls: urls.clone(),
        };
        let observation = match ton_test_transaction_seqno(&trace, tx_hash) {
            Some(seqno) => observe_ton_block_confirmations(
                transport,
                "https://ton-v3.example".to_string(),
                HashMap::new(),
                seqno,
                5,
            )
            .await
            .unwrap(),
            None => BlockConfirmationObservation {
                validity: BlockConfirmationValidity::Missing,
                current_confirmations: None,
            },
        };
        let urls = urls.lock().unwrap().clone();
        (observation, urls)
    }

    fn ton_test_transaction_seqno(trace: &Value, tx_hash: &str) -> Option<i64> {
        if let Some(transaction) = trace.get("transaction") {
            if transaction.get("hash").and_then(Value::as_str) == Some(tx_hash) {
                return transaction.get("mc_block_seqno")?.as_i64();
            }
        }
        trace
            .pointer("/events/0/transactions")?
            .get(tx_hash)?
            .get("mc_block_seqno")?
            .as_i64()
    }

    /// toncenter v3 `/events`: an external message lands at seqno 100 and the
    /// PacketSent emission happens three hops later, at seqno 105.
    fn packet_sent_five_blocks_after_root() -> Value {
        let transaction = |hash: &str, seqno: i64, lt: &str| json!({"hash": hash, "lt": lt, "mc_block_seqno": seqno, "in_msg": {"hash": format!("{hash}-in")}});
        json!({"events": [{
            "trace": {"tx_hash": "root", "children": [
                {"tx_hash": "endpoint", "children": [
                    {"tx_hash": "channel", "children": [
                        {"tx_hash": "packet-sent", "children": []}
                    ]}
                ]},
                {"tx_hash": "refund", "children": []}
            ]},
            "transactions": {
                "root": transaction("root", 100, "1000"),
                "endpoint": transaction("endpoint", 102, "1001"),
                "channel": transaction("channel", 104, "1002"),
                "packet-sent": transaction("packet-sent", 105, "1003"),
                "refund": transaction("refund", 101, "1004"),
            }
        }]})
    }

    #[tokio::test]
    async fn ton_masterchain_seqno_confirmations_are_quorum_ready() {
        let observation = observe(
            json!({"transaction": {"hash": "tx", "mc_block_seqno": 100}, "children": []}),
            105,
            "tx",
        )
        .await;
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Sufficient { .. }
        ));
        assert_eq!(observation.current_confirmations, Some(5));
    }

    #[tokio::test]
    async fn ton_confirmations_count_from_the_packet_sent_transaction_not_the_trace_root() {
        let observation = observe(packet_sent_five_blocks_after_root(), 105, "packet-sent").await;
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Insufficient {
                receipt_block_number: 105,
                ..
            }
        ));
        assert_eq!(observation.current_confirmations, Some(0));

        let observation = observe(packet_sent_five_blocks_after_root(), 110, "packet-sent").await;
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Sufficient {
                receipt_block_number: 105,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn ton_confirmations_fail_closed_when_the_trace_lacks_the_transaction() {
        let observation = observe(packet_sent_five_blocks_after_root(), 200, "elsewhere").await;
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Missing
        ));
        assert_eq!(observation.current_confirmations, None);
    }

    #[tokio::test]
    async fn ton_confirmations_use_agreed_packet_seqno_without_trace_resolution() {
        const PACKET_SENT: &str = "xl/S/EtS8UMfIBSN5KWDG/XZ7tv3ovs2k3zRO+e7K5w=";
        const ROOT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let trace = json!({"events": [{
            "trace": {"tx_hash": ROOT, "children": [{"tx_hash": PACKET_SENT, "children": []}]},
            "transactions": {
                ROOT: {"hash": ROOT, "lt": "1000", "mc_block_seqno": 100},
                PACKET_SENT: {"hash": PACKET_SENT, "lt": "1001", "mc_block_seqno": 105},
            }
        }]});
        let (observation, urls) = observe_recording(trace, 110, PACKET_SENT).await;
        assert_eq!(urls, ["https://ton-v3.example/masterchainInfo"]);
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Sufficient {
                receipt_block_number: 105,
                ..
            }
        ));
    }
    #[tokio::test]
    async fn ton_masterchain_transport_failure_is_not_a_missing_vote() {
        let transport = RecordingTransport {
            responses: Arc::new(Mutex::new(vec![Err("HTTP 500".to_string())])),
            urls: Arc::new(Mutex::new(Vec::new())),
        };
        let result = observe_ton_block_confirmations(
            transport,
            "https://ton-v3.example".to_string(),
            HashMap::new(),
            100,
            5,
        )
        .await;
        assert!(result.is_err(), "transport failures must be non-votes");
    }
}
