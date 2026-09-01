use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) async fn validate_readiness_with_quorum(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<(), AppCoreError> {
        let block_confirmation = match signing_context {
            SigningContext::Message {
                block_confirmation, ..
            } => block_confirmation,
            SigningContext::Read {
                resolved_timestamp_time_markers,
                ..
            } => {
                return self
                    .validate_read_time_markers(sent_event, resolved_timestamp_time_markers)
                    .await;
            }
        };

        let src_chain_name = &sent_event.lz_message_id.pathway_id.src_chain_name;
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
                    *block_confirmation,
                    provider_config,
                )
                .await;
        }
        if src_chain_name == "ton" {
            let quorum = required_provider_quorum(provider_config, src_chain_name)?;
            let plan = plan_dispatch(
                &self.rank_tracker,
                src_chain_name,
                &provider_config.uris,
                quorum,
            )
            .await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let transport = self.transport.clone();
                let tx_hash = sent_event.tx_hash.clone();
                let required = *block_confirmation;
                let parts = ton_v3_provider_uri_parts(uri);
                requests.push(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let observation = match parts {
                        Some((endpoint, _, headers)) => {
                            observe_ton_block_confirmations(
                                transport, endpoint, headers, &tx_hash, required,
                            )
                            .await
                        }
                        None => BlockConfirmationObservation {
                            validity: BlockConfirmationValidity::Missing,
                            current_confirmations: None,
                        },
                    };
                    let fingerprint = format!("{:?}", observation.validity);
                    (index, Some((fingerprint, observation)))
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
            };
        }
        if matches!(src_chain_name.as_str(), "aptos" | "initia" | "movement") {
            let quorum = required_provider_quorum(provider_config, src_chain_name)?;
            let plan = plan_dispatch(
                &self.rank_tracker,
                src_chain_name,
                &provider_config.uris,
                quorum,
            )
            .await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = move_provider_uri_parts(src_chain_name, uri);
                let transport = self.transport.clone();
                let chain_name = src_chain_name.to_string();
                let tx_hash = sent_event.tx_hash.clone();
                let required_confirmations = *block_confirmation;
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
                    let fingerprint = format!("{:?}", observation.validity);
                    (index, Some((fingerprint, observation)))
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
            };
        }
        if matches!(src_chain_name.as_str(), "sui" | "iotal1") {
            let quorum = required_provider_quorum(provider_config, src_chain_name)?;
            let plan = plan_dispatch(
                &self.rank_tracker,
                src_chain_name,
                &provider_config.uris,
                quorum,
            )
            .await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                let chain_name = src_chain_name.to_string();
                let tx_hash = sent_event.tx_hash.clone();
                let required_confirmations = *block_confirmation;
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
                    let observation = BlockConfirmationObservation {
                        validity,
                        current_confirmations: observation.current_confirmations,
                    };
                    let fingerprint = format!("{:?}", observation.validity);
                    (index, Some((fingerprint, observation)))
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
            };
        }
        if src_chain_name == "starknet" {
            let quorum = required_provider_quorum(provider_config, src_chain_name)?;
            let plan = plan_dispatch(
                &self.rank_tracker,
                src_chain_name,
                &provider_config.uris,
                quorum,
            )
            .await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                let tx_hash = sent_event.tx_hash.clone();
                let required_confirmations = *block_confirmation;
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
                    let fingerprint = format!("{:?}", observation.validity);
                    (index, Some((fingerprint, observation)))
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
            };
        }
        if src_chain_name == "stellar" {
            let quorum = required_provider_quorum(provider_config, src_chain_name)?;
            let plan = plan_dispatch(
                &self.rank_tracker,
                src_chain_name,
                &provider_config.uris,
                quorum,
            )
            .await?;
            let requests = FuturesUnordered::new();
            for DispatchEntry { index, uri, delay } in plan {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                let tx_hash = sent_event.tx_hash.clone();
                let required_confirmations = *block_confirmation;
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
                    let fingerprint = format!("{:?}", observation.validity);
                    (index, Some((fingerprint, observation)))
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
            };
        }
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(
            &self.rank_tracker,
            src_chain_name,
            &provider_config.uris,
            quorum,
        )
        .await?;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let tx_hash = sent_event.tx_hash.clone();
            let block_confirmation = *block_confirmation;
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_block_confirmations(
                    transport,
                    url,
                    headers,
                    &tx_hash,
                    block_confirmation,
                )
                .await;
                let fingerprint = format!("{:?}", observation.validity);
                (index, Some((fingerprint, observation)))
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
                "Transaction receipt or block not found for {}",
                sent_event.tx_hash
            ))),
            BlockConfirmationValidity::InvalidRange => Err(AppCoreError::BadRequest(
                "block confirmation range overflow".to_string(),
            )),
        }
    }

    async fn validate_solana_readiness_with_quorum(
        &self,
        src_chain_name: &str,
        tx_hash: &str,
        required_confirmations: i64,
        provider_config: &pillar_config::ProviderConfig,
    ) -> Result<(), AppCoreError> {
        let quorum = required_provider_quorum(provider_config, src_chain_name)?;
        let plan = plan_dispatch(
            &self.rank_tracker,
            src_chain_name,
            &provider_config.uris,
            quorum,
        )
        .await?;
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
                let fingerprint = format!("{:?}", observation.validity);
                (index, Some((fingerprint, observation)))
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
        }
    }
}

async fn observe_ton_block_confirmations<T>(
    transport: T,
    endpoint: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> BlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    if required_confirmations < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    }
    // Fourth and last `/traces/` splice, encoded like its three siblings. This
    // one's `tx_hash` is provider-controlled rather than caller-controlled - it
    // comes from `transaction["hash"]` in a trace response - so the API boundary's
    // shape gate does not cover it and the encoding is the only guard.
    let Some(encoded_tx_hash) = encode_path_segment(tx_hash) else {
        // Fail closed rather than build a URL this hash could re-target. This
        // one's value is provider-controlled - it comes from
        // `transaction["hash"]` in a trace response - so the API boundary's
        // shape gate never saw it.
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let trace = transport
        .get_json(
            format!(
                "{}/traces/{}",
                endpoint.trim_end_matches('/'),
                encoded_tx_hash
            ),
            headers.clone(),
        )
        .await
        .ok();
    let Some(trace) = trace else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let tx_seqno = trace
        .pointer("/transaction/mc_block_seqno")
        .and_then(Value::as_i64)
        .or_else(|| {
            trace
                .pointer("/transaction/mc_block_seqno")
                .and_then(Value::as_str)?
                .parse()
                .ok()
        });
    let Some(tx_seqno) = tx_seqno else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let current_response = transport
        .get_json(
            format!("{}/masterchainInfo", endpoint.trim_end_matches('/')),
            headers,
        )
        .await
        .ok();
    let current = current_response.as_ref().and_then(|value| {
        value
            .pointer("/last/seqno")
            .and_then(Value::as_i64)
            .or_else(|| {
                value
                    .pointer("/last/seqno")
                    .and_then(Value::as_str)?
                    .parse()
                    .ok()
            })
    });
    let Some(current) = current else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
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
    BlockConfirmationObservation {
        validity,
        current_confirmations: Some(confirmations),
    }
}

async fn observe_solana_slot_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> BlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    let transaction_transport = transport.clone();
    let transaction = transaction_transport.post_json(
        url.clone(),
        headers.clone(),
        json!({
            "method": "getTransaction",
            "params": [
                tx_hash,
                {
                    "encoding": "json",
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 0,
                },
            ],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let slot = transport.post_json(
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

    let Some((tx_slot, current_slot)) = transaction_response
        .ok()
        .and_then(|transaction| parse_solana_transaction_slot(&transaction).ok())
        .zip(
            slot_response
                .ok()
                .and_then(|slot| parse_solana_current_slot(&slot).ok()),
        )
    else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };

    let (Some(current_confirmations), Some(required_slot)) = (
        current_slot.checked_sub(tx_slot),
        tx_slot.checked_add(required_confirmations),
    ) else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    };
    if tx_slot < 0 || current_slot < 0 || required_confirmations < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
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
    BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    }
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
) -> BlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    let receipt_transport = transport.clone();
    let receipt = receipt_transport.post_json(
        url.clone(),
        headers.clone(),
        json!({
            "method": "starknet_getTransactionReceipt",
            "params": [tx_hash],
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let current = transport.post_json(
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
    let receipt_block = receipt_response.ok().and_then(|response| {
        let result = response.get("result")?;
        let hash = result.get("block_hash")?.as_str()?.to_string();
        let number = result
            .get("block_number")
            .and_then(numeric_response)?
            .parse::<i64>()
            .ok()?;
        Some((hash, number))
    });
    let current_block = current_response
        .ok()
        .and_then(|response| response.get("result").and_then(numeric_response))
        .and_then(|value| value.parse::<i64>().ok());
    let (Some((receipt_hash, receipt_number)), Some(current_number)) =
        (receipt_block, current_block)
    else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let (Some(current_confirmations), Some(required_block)) = (
        current_number.checked_sub(receipt_number),
        receipt_number.checked_add(required_confirmations),
    ) else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    };
    if receipt_number < 0 || current_number < 0 || required_confirmations < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
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
    BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    }
}

async fn observe_stellar_block_confirmations<T>(
    transport: T,
    url: String,
    headers: HashMap<String, String>,
    tx_hash: &str,
    required_confirmations: i64,
) -> BlockConfirmationObservation
where
    T: JsonRpcTransport,
{
    let transaction_transport = transport.clone();
    let transaction = transaction_transport.post_json(
        url.clone(),
        headers.clone(),
        json!({
            "method": "getTransaction",
            "params": {"hash": tx_hash},
            "id": 1,
            "jsonrpc": "2.0",
        }),
    );
    let latest = transport.post_json(
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
    let transaction_ledger = transaction_response.ok().and_then(|response| {
        let result = response.get("result")?;
        (result.get("status").and_then(Value::as_str) == Some("SUCCESS")).then(|| {
            result
                .get("ledger")
                .and_then(numeric_response)?
                .parse::<i64>()
                .ok()
        })?
    });
    let current_ledger = latest_response.ok().and_then(|response| {
        response
            .get("result")
            .and_then(|result| result.get("sequence"))
            .and_then(numeric_response)
            .and_then(|value| value.parse::<i64>().ok())
    });
    let (Some(transaction_ledger), Some(current_ledger)) = (transaction_ledger, current_ledger)
    else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::Missing,
            current_confirmations: None,
        };
    };
    let (Some(current_confirmations), Some(required_ledger)) = (
        current_ledger.checked_sub(transaction_ledger),
        transaction_ledger.checked_add(required_confirmations),
    ) else {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
    };
    if transaction_ledger < 0 || current_ledger < 0 || required_confirmations < 0 {
        return BlockConfirmationObservation {
            validity: BlockConfirmationValidity::InvalidRange,
            current_confirmations: None,
        };
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
    BlockConfirmationObservation {
        validity,
        current_confirmations: Some(current_confirmations),
    }
}

#[cfg(test)]
mod ton_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RecordingTransport {
        responses: Arc<Mutex<Vec<Result<Value, String>>>>,
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
            _url: String,
            _headers: HashMap<String, String>,
        ) -> Result<Value, String> {
            self.responses
                .lock()
                .map_err(|_| "recording transport mutex poisoned".to_string())?
                .remove(0)
        }
    }

    #[tokio::test]
    async fn ton_masterchain_seqno_confirmations_are_quorum_ready() {
        let transport = RecordingTransport {
            responses: Arc::new(Mutex::new(vec![
                Ok(json!({"transaction": {"mc_block_seqno": 100}})),
                Ok(json!({"last": {"seqno": 105}})),
            ])),
        };
        let observation = observe_ton_block_confirmations(
            transport,
            "https://ton-v3.example".to_string(),
            HashMap::new(),
            "tx",
            5,
        )
        .await;
        assert!(matches!(
            observation.validity,
            BlockConfirmationValidity::Sufficient { .. }
        ));
        assert_eq!(observation.current_confirmations, Some(5));
    }
}
