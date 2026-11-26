use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub(crate) fn validate_read_markers_preflight(
        &self,
        sent_event: &LzSentEvent,
        markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<(), AppCoreError> {
        if markers.len() > pillar_core::MAX_READ_MARKERS {
            return Err(AppCoreError::BadRequest(format!(
                "resolvedTimestampTimeMarkers count exceeds maximum {}",
                pillar_core::MAX_READ_MARKERS
            )));
        }
        let mut block_numbers_by_timestamp = HashMap::new();
        let mut unique_markers = Vec::with_capacity(markers.len());
        let mut seen_markers = HashSet::new();
        for marker in markers {
            if marker.is_block_number {
                return Err(AppCoreError::BadRequest(
                    "resolvedTimestampTimeMarkers must contain timestamp markers".to_string(),
                ));
            }
            if !seen_markers.insert((
                marker.chain_name.as_str(),
                marker.timestamp,
                marker.block_number,
                marker.block_confirmation,
            )) {
                continue;
            }
            if marker
                .block_number
                .checked_add(marker.block_confirmation)
                .is_none()
            {
                return Err(AppCoreError::BadRequest(
                    "block confirmation range overflow".to_string(),
                ));
            }
            if marker.block_confirmation < 0 {
                return Err(AppCoreError::BadRequest(
                    "blockConfirmation cannot be negative".to_string(),
                ));
            }
            if marker.timestamp < 0 {
                return Err(AppCoreError::BadRequest(
                    "resolved timestamp cannot be negative".to_string(),
                ));
            }
            if marker.block_number < 1 {
                return Err(AppCoreError::BadRequest(format!(
                    "Invalid resolved time marker for chainName {}: blockNumber {} must be >= 1",
                    marker.chain_name, marker.block_number
                )));
            }
            let key = (marker.chain_name.as_str(), marker.timestamp);
            if block_numbers_by_timestamp
                .insert(key, marker.block_number)
                .is_some_and(|block_number| block_number != marker.block_number)
            {
                return Err(AppCoreError::BadRequest(format!(
                    "Conflicting resolved blocks for chainName {} timestamp {}",
                    marker.chain_name, marker.timestamp
                )));
            }
            unique_markers.push(marker);
        }
        if sent_event.lz_message_id.uln_send_version.as_str() == Some(ULN_VERSION_READ_V1002) {
            let command_markers = extract_evm_read_resolved_time_markers(&sent_event.message)?;
            let mut matched = vec![false; unique_markers.len()];
            for marker in command_markers {
                let chain_name = self
                    .evm_chain_name_by_eid
                    .get(&marker.target_eid)
                    .ok_or_else(|| {
                        AppCoreError::BadRequest(format!(
                            "No chainName found for read command endpointId {}",
                            marker.target_eid
                        ))
                    })?;
                if let ReadTimeMarker::BlockNumber { block_number } = marker.marker {
                    if block_number > i64::MAX as u64
                        || (block_number as i64)
                            .checked_add(i64::from(marker.block_confirmation))
                            .is_none()
                    {
                        return Err(AppCoreError::BadRequest(format!(
                            "Invalid read command block number for chainName {chain_name}: {block_number}"
                        )));
                    }
                }
                if let ReadTimeMarker::Timestamp { timestamp } = marker.marker {
                    if timestamp > i64::MAX as u64 {
                        return Err(AppCoreError::BadRequest(format!(
                            "Invalid read command timestamp {timestamp}"
                        )));
                    }
                    let found = unique_markers.iter().position(|resolved| {
                        resolved.chain_name == *chain_name
                            && resolved.timestamp == timestamp as i64
                            && resolved.block_confirmation == marker.block_confirmation as i64
                    });
                    match found {
                        Some(index) => matched[index] = true,
                        None => {
                            return Err(AppCoreError::BadRequest(format!(
                                "Missing resolved timestamp time marker for chainName {chain_name} timestamp {timestamp} and blockConfirmation {}",
                                marker.block_confirmation
                            )))
                        }
                    }
                }
            }
            if matched.iter().any(|matched| !matched) {
                return Err(AppCoreError::BadRequest(
                    "resolvedTimestampTimeMarkers do not match ReadV1002 timestamp markers"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) async fn validate_read_time_markers(
        &self,
        sent_event: &LzSentEvent,
        markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
        use futures::{stream::FuturesOrdered, TryStreamExt};
        self.validate_read_markers_preflight(sent_event, markers)?;
        // Keyed by pinned block; the strictest requirement names the marker kind it came from.
        let mut requirements = indexmap::IndexMap::<(&str, i64), (i64, &str)>::new();
        if sent_event.lz_message_id.uln_send_version.as_str() == Some(ULN_VERSION_READ_V1002) {
            for marker in extract_evm_read_resolved_time_markers(&sent_event.message)? {
                if let ReadTimeMarker::BlockNumber { block_number } = marker.marker {
                    let chain_name = self
                        .evm_chain_name_by_eid
                        .get(&marker.target_eid)
                        .ok_or_else(|| {
                            AppCoreError::BadRequest(format!(
                                "No chainName found for read command endpointId {}",
                                marker.target_eid
                            ))
                        })?;
                    let height = i64::try_from(block_number).map_err(|_| {
                        AppCoreError::BadRequest("read command block number exceeds i64".into())
                    })?;
                    let required = height
                        .checked_add(i64::from(marker.block_confirmation))
                        .ok_or_else(|| {
                            AppCoreError::BadRequest("block confirmation range overflow".into())
                        })?;
                    let current = requirements
                        .entry((chain_name.as_str(), height))
                        .or_insert((required, "read command block marker"));
                    if required > current.0 {
                        *current = (required, "read command block marker");
                    }
                }
            }
        }
        for marker in markers {
            let required = marker
                .block_number
                .checked_add(marker.block_confirmation)
                .ok_or_else(|| {
                    AppCoreError::BadRequest("block confirmation range overflow".into())
                })?;
            let current = requirements
                .entry((marker.chain_name.as_str(), marker.block_number))
                .or_insert((required, "time marker"));
            if required > current.0 {
                *current = (required, "time marker");
            }
        }
        let mut headers = indexmap::IndexSet::new();
        for key in requirements.keys() {
            headers.insert(*key);
        }
        for marker in markers {
            if marker.block_number > 1 {
                headers.insert((marker.chain_name.as_str(), marker.block_number - 1));
            }
        }
        let batches = headers.len().div_ceil(4) + requirements.len().div_ceil(4);
        let stall_budget = super::read_payload::read_stall_budget(batches + requirements.len() / 2);
        let mut blocks = HashMap::with_capacity(headers.len());
        let mut headers = headers.into_iter();
        loop {
            let mut pending = FuturesOrdered::new();
            for (chain, height) in headers.by_ref().take(4) {
                pending.push_back(async move {
                    self.block_time_with_quorum(chain, height, stall_budget)
                        .await
                        .map(|block| ((chain, height), block))
                });
            }
            if pending.is_empty() {
                break;
            }
            while let Some((key, block)) = pending.try_next().await? {
                blocks.insert(key, block);
            }
        }
        for marker in markers {
            let block = &blocks[&(marker.chain_name.as_str(), marker.block_number)];
            let previous = if marker.block_number == 1 {
                None
            } else {
                blocks.get(&(marker.chain_name.as_str(), marker.block_number - 1))
            };
            if !block_matches_resolved_timestamp(block, previous, marker.timestamp) {
                return Err(AppCoreError::BadRequest(format!(
                    "Invalid resolved time marker for chainName {}: blockNumber {} does not cover timestamp {}",
                    marker.chain_name, marker.block_number, marker.timestamp
                )));
            }
        }
        let mut pins = Vec::with_capacity(requirements.len());
        let mut requirements = requirements.into_iter();
        loop {
            let mut pending = FuturesOrdered::new();
            for ((chain, height), (required, kind)) in requirements.by_ref().take(4) {
                let block = &blocks[&(chain, height)];
                pending.push_back(async move {
                    let (sufficient, latest) = self.block_confirmation_satisfied_with_quorum(
                        chain, block, required, stall_budget
                    ).await?;
                    if !sufficient {
                        return Err(AppCoreError::BadRequest(format!(
                            "Block confirmation for chainName {chain} for {kind} is greater than current block number: {required} > {latest}"
                        )));
                    }
                    Ok::<_, AppCoreError>((chain, block))
                });
            }
            if pending.is_empty() {
                break;
            }
            while let Some((chain, block)) = pending.try_next().await? {
                push_read_block_pin(&mut pins, chain, block)?;
            }
        }
        let mut chains = indexmap::IndexSet::new();
        for pin in &pins {
            chains.insert(pin.chain_name.as_str());
        }
        for chain in chains {
            let chain_pins = pins
                .iter()
                .filter(|pin| pin.chain_name == chain)
                .collect::<Vec<_>>();
            if chain_pins.len() > 1 {
                self.pins_share_one_history_with_quorum(chain, &chain_pins, stall_budget)
                    .await?;
            }
        }
        Ok(pins)
    }

    /// Pins at different heights come from separate quorum rounds, so a provider common to two
    /// subsets could back pins that no single chain history contains.
    async fn pins_share_one_history_with_quorum(
        &self,
        chain_name: &str,
        pins: &[&ReadBlockPin],
        stall_budget: std::time::Duration,
    ) -> Result<(), AppCoreError> {
        crate::provider_health::rpc_scope(chain_name, async {
            let snapshot = self.providers.load();
            let dispatch = snapshot.read_dispatch(&self.rank_tracker, chain_name, stall_budget).await?;
            let ChainDispatch { config, quorum, plan } = dispatch;
            let requests = quorum_requests(plan, |index, uri| {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                async move {
                    let observation = async {
                        // Two reads at a time keep several providers inside the chain's RPC lane.
                        let mut reads = futures::stream::iter(0..pins.len())
                            .map(|index| {
                                let pin = pins[index];
                                let transport = transport.clone();
                                let url = url.clone();
                                let headers = headers.clone();
                                async move {
                                    observe_read_block(transport, url, headers, pin.block_number, None)
                                        .await
                                        .map(|block| block.is_some_and(|observed| {
                                            observed.block.hash.eq_ignore_ascii_case(&pin.block_hash)
                                        }))
                                }
                            })
                            .buffer_unordered(2);
                        let mut failure = None;
                        while let Some(read) = reads.next().await {
                            match read {
                                Ok(false) => return Ok("diverged"),
                                Ok(true) => {}
                                Err(error) => { failure.get_or_insert(error); }
                            }
                        }
                        failure.map_or(Ok("consistent"), Err)
                    }
                    .await;
                    let vote = provider_response(observation)
                        .map(|result| result.map(|verdict| (verdict.to_string(), verdict)));
                    (index, vote)
                }
            });
            let context = format!("READ pinned blocks of one history for chain {chain_name}");
            match resolve_provider_quorum(requests, config.uris.len(), quorum, &context).await? {
                "consistent" => Ok(()),
                _ => Err(AppCoreError::BadRequest(format!(
                    "READ pinned blocks on chain {chain_name} do not belong to one canonical history"
                ))),
            }
        })
        .await
    }

    async fn block_confirmation_satisfied_with_quorum(
        &self,
        chain_name: &str,
        pinned_block: &BlockTime,
        required_block_number: i64,
        stall_budget: std::time::Duration,
    ) -> Result<(bool, i64), AppCoreError> {
        crate::provider_health::rpc_scope(chain_name, async {
            let owned_chain = chain_name.to_string();
            let chain_type = static_chain_type_by_chain_name(std::slice::from_ref(&owned_chain))
                .ok()
                .and_then(|types| types.get(chain_name).cloned());
            if chain_type.as_deref() != Some("EVM") {
                return Err(AppCoreError::Internal(format!(
                    "Unsupported chain type: {} (read time markers are EVM-only) for chain {chain_name}",
                    chain_type.as_deref().unwrap_or("unknown")
                )));
            }
            let snapshot = self.providers.load();
            let dispatch = snapshot.read_dispatch(&self.rank_tracker, chain_name, stall_budget).await?;
            let ChainDispatch { config, quorum, plan } = dispatch;
            let pinned_height = u64::try_from(pinned_block.number)
                .map_err(|_| AppCoreError::Internal("Invalid READ block height".into()))?;
            let requests = quorum_requests(plan, |index, uri| {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                async move {
                    let observation = async {
                        let latest = observe_block_time(
                            transport.clone(), url.clone(), headers.clone(), "latest",
                        ).await?;
                        let canonical = observe_read_block(
                            transport, url, headers, pinned_height, Some(latest.block.number),
                        ).await?;
                        if !canonical.is_some_and(|block| block.block.hash.eq_ignore_ascii_case(&pinned_block.hash)) {
                            return Ok::<_, AppCoreError>(None);
                        }
                        Ok(Some(latest))
                    }.await;
                    let vote = provider_response(observation).map(|result| {
                        result.map(|observed| match observed {
                            None => ("source-changed".to_string(), None),
                            Some(block) => {
                                let latest_block_number = block.block.number;
                                let sufficient = latest_block_number >= required_block_number;
                                (
                                    if sufficient { "sufficient".to_string() } else { "insufficient".to_string() },
                                    Some((sufficient, latest_block_number)),
                                )
                            }
                        })
                    });
                    (index, vote)
                }
            });
            let context = format!("READ block confirmation threshold for chain {chain_name}");
            resolve_provider_quorum(requests, config.uris.len(), quorum, &context)
                .await?
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "READ pinned block {} is no longer canonical at height {}",
                        pinned_block.hash, pinned_block.number
                    ))
                })
        })
        .await
    }

    async fn block_time_with_quorum(
        &self,
        chain_name: &str,
        block_number: i64,
        stall_budget: std::time::Duration,
    ) -> Result<BlockTime, AppCoreError> {
        crate::provider_health::rpc_scope(chain_name, async {
            // Time-marker block resolution is EVM-only, matching TS
            // `ChainTimeMarkerValidatorSdkFactory` which throws for non-EVM chain
            // types. Fail closed with a clear error instead of issuing an
            // EVM-shaped `eth_getBlockByNumber` against a non-EVM RPC.
            let owned_chain = chain_name.to_string();
            let chain_type = static_chain_type_by_chain_name(std::slice::from_ref(&owned_chain))
                .ok()
                .and_then(|types| types.get(chain_name).cloned());
            if chain_type.as_deref() != Some("EVM") {
                return Err(AppCoreError::Internal(format!(
            "Unsupported chain type: {} (read time markers are EVM-only) for chain {chain_name}",
            chain_type.as_deref().unwrap_or("unknown")
        )));
            }
            let height = u64::try_from(block_number)
                .map_err(|_| AppCoreError::BadRequest("Invalid READ block height".into()))?;
            let snapshot = self.providers.load();
            let dispatch = snapshot
                .read_dispatch(&self.rank_tracker, chain_name, stall_budget)
                .await?;
            let ChainDispatch {
                config: provider_config,
                quorum,
                plan,
            } = dispatch;
            let requests = quorum_requests(plan, |index, uri| {
                let (url, headers) = provider_uri_parts(uri);
                let transport = self.transport.clone();
                async move {
                    let observation = provider_response(
                        observe_read_block(transport, url, headers, height, None).await,
                    )
                    .map(|vote| {
                        vote.map(|block| match block {
                            Some(block) => (block.fingerprint, Some(block.block)),
                            None => ("source-changed".into(), None),
                        })
                    });
                    (index, observation)
                }
            });
            let context = format!("block for chain {chain_name} block 0x{height:x}");
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context)
                .await?
                .ok_or_else(|| {
                    AppCoreError::BadRequest(format!(
                        "READ block at height {height} is not canonical on chain {chain_name}"
                    ))
                })
        })
        .await
    }
}

/// Records the block a marker was validated against. Two quorum reads of one
/// height that disagree on its hash mean the chain reorganised during
/// validation, which is refused rather than resolved by picking one.
fn push_read_block_pin(
    pins: &mut Vec<ReadBlockPin>,
    chain_name: &str,
    block: &BlockTime,
) -> Result<(), AppCoreError> {
    let block_number = u64::try_from(block.number).map_err(|_| {
        AppCoreError::Internal(format!(
            "Invalid block number {} for chain {chain_name}",
            block.number
        ))
    })?;
    let block_hash = block.hash.to_ascii_lowercase();
    match pins
        .iter()
        .find(|pin| pin.chain_name == chain_name && pin.block_number == block_number)
    {
        Some(existing) if existing.block_hash == block_hash => Ok(()),
        Some(existing) => Err(AppCoreError::BadRequest(format!(
            "Block {block_number} on chain {chain_name} changed hash during read validation: {} != {block_hash}",
            existing.block_hash
        ))),
        None => {
            pins.push(ReadBlockPin {
                chain_name: chain_name.to_string(),
                block_number,
                block_hash,
            });
            Ok(())
        }
    }
}
