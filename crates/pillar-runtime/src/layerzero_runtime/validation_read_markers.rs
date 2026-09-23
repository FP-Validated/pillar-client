use super::*;

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    /// Validates every READ time marker and returns the block each one was
    /// validated against. The hashes are what `read_payload.rs` pins its
    /// `eth_call`s to; without them the read would be answered from whatever
    /// block sits at the same height when the builder runs.
    pub(crate) async fn validate_read_time_markers(
        &self,
        sent_event: &LzSentEvent,
        markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<Vec<ReadBlockPin>, AppCoreError> {
        let mut pins = Vec::new();
        if sent_event.lz_message_id.uln_send_version.as_str() == Some(ULN_VERSION_READ_V1002) {
            let command_markers = extract_evm_read_resolved_time_markers(&sent_event.message)?;
            self.validate_read_command_markers(&command_markers, markers, &mut pins)
                .await?;
        }
        for marker in markers {
            if marker.is_block_number {
                return Err(AppCoreError::BadRequest(
                    "resolvedTimestampTimeMarkers must contain timestamp markers".to_string(),
                ));
            }
            if marker.block_confirmation < 0 {
                return Err(AppCoreError::BadRequest(
                    "blockConfirmation cannot be negative".to_string(),
                ));
            }
            if marker.block_number < 1 {
                return Err(AppCoreError::BadRequest(format!(
                    "Invalid resolved time marker for chainName {}: blockNumber {} must be >= 1",
                    marker.chain_name, marker.block_number
                )));
            }

            let block = self
                .block_time_with_quorum(&marker.chain_name, marker.block_number)
                .await?;
            push_read_block_pin(&mut pins, &marker.chain_name, &block)?;
            let previous_block = if marker.block_number == 1 {
                None
            } else {
                Some(
                    self.block_time_with_quorum(&marker.chain_name, marker.block_number - 1)
                        .await?,
                )
            };
            if !block_matches_resolved_timestamp(&block, previous_block.as_ref(), marker.timestamp)
            {
                return Err(AppCoreError::BadRequest(format!(
                    "Invalid resolved time marker for chainName {}: blockNumber {} with resolved timestamp {} does not meet actual timestamp for blockNumber {} and previous blockNumber {}",
                    marker.chain_name,
                    marker.block_number,
                    marker.timestamp,
                    block.timestamp,
                    previous_block
                        .as_ref()
                        .map(|block| block.timestamp.to_string())
                        .unwrap_or_else(|| "null".to_string())
                )));
            }

            let latest = self
                .block_time_for_tag_with_quorum(&marker.chain_name, "latest")
                .await?;
            let required_block_number = marker
                .block_number
                .checked_add(marker.block_confirmation)
                .ok_or_else(|| {
                    AppCoreError::BadRequest("block confirmation range overflow".to_string())
                })?;
            if required_block_number > latest.number {
                return Err(AppCoreError::BadRequest(format!(
                    "Block confirmation for chainName {} for time marker is greater than current block number: {} > {}",
                    marker.chain_name, required_block_number, latest.number
                )));
            }
        }
        Ok(pins)
    }

    async fn validate_read_command_markers(
        &self,
        command_markers: &[ReadResolvedTimeMarker],
        resolved_markers: &[ResolvedTimestampTimeMarker],
        pins: &mut Vec<ReadBlockPin>,
    ) -> Result<(), AppCoreError> {
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
            match marker.marker {
                ReadTimeMarker::Timestamp { timestamp } => {
                    let Some(resolved) = resolved_markers.iter().find(|resolved| {
                        !resolved.is_block_number
                            && resolved.chain_name == *chain_name
                            && resolved.timestamp == timestamp as i64
                    }) else {
                        return Err(AppCoreError::BadRequest(format!(
                            "Missing resolved timestamp time marker for chainName {chain_name} timestamp {timestamp}"
                        )));
                    };
                    if resolved.block_confirmation != marker.block_confirmation as i64 {
                        return Err(AppCoreError::BadRequest(format!(
                            "Resolved timestamp time marker blockConfirmation mismatch for chainName {chain_name} timestamp {timestamp}: {} != {}",
                            resolved.block_confirmation,
                            marker.block_confirmation
                        )));
                    }
                }
                ReadTimeMarker::BlockNumber { block_number } => {
                    if block_number > i64::MAX as u64 {
                        return Err(AppCoreError::BadRequest(format!(
                            "Invalid read command block number for chainName {chain_name}: {block_number}"
                        )));
                    }
                    // Upstream never looks this block up at all; the hash is
                    // needed so the read cannot drift to a sibling. Pinned
                    // before the depth check, as timestamp markers are, so the
                    // depth is measured after the block it vouches for.
                    let block = self
                        .block_time_with_quorum(chain_name, block_number as i64)
                        .await?;
                    push_read_block_pin(pins, chain_name, &block)?;
                    let latest = self
                        .block_time_for_tag_with_quorum(chain_name, "latest")
                        .await?;
                    let required_block_number = (block_number as i64)
                        .checked_add(i64::from(marker.block_confirmation))
                        .ok_or_else(|| {
                            AppCoreError::BadRequest(
                                "block confirmation range overflow".to_string(),
                            )
                        })?;
                    if required_block_number > latest.number {
                        return Err(AppCoreError::BadRequest(format!(
                            "Block confirmation for chainName {chain_name} for read command block marker is greater than current block number: {required_block_number} > {}",
                            latest.number
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    async fn block_time_with_quorum(
        &self,
        chain_name: &str,
        block_number: i64,
    ) -> Result<BlockTime, AppCoreError> {
        self.block_time_for_tag_with_quorum(chain_name, &format!("0x{block_number:x}"))
            .await
    }

    async fn block_time_for_tag_with_quorum(
        &self,
        chain_name: &str,
        block_tag: &str,
    ) -> Result<BlockTime, AppCoreError> {
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
        let snapshot = self.providers.load();
        let dispatch = snapshot.dispatch(&self.rank_tracker, chain_name).await?;
        let ChainDispatch {
            config: provider_config,
            quorum,
            plan,
        } = dispatch;
        let requests = FuturesUnordered::new();
        for DispatchEntry { index, uri, delay } in plan {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let block_tag = block_tag.to_string();
            requests.push(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let observation = observe_block_time(transport, url, headers, &block_tag)
                    .await
                    .ok();
                let observation =
                    observation.map(|observation| (observation.fingerprint.clone(), observation));
                (index, observation)
            });
        }
        let context = format!("block for chain {chain_name} block {block_tag}");
        let observation =
            resolve_provider_quorum(requests, provider_config.uris.len(), quorum, &context).await?;
        Ok(observation.block)
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
