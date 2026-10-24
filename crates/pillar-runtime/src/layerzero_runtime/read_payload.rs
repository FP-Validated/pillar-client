use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
pub(crate) struct RuntimeEvmReadPayloadResolver<T> {
    providers: crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    chain_name_by_eid: HashMap<u32, String>,
    call_permits: Arc<Semaphore>,
    chain_permits: Arc<HashMap<String, Arc<Semaphore>>>,
    per_chain: usize,
}

/// How many READ calls may be in flight; a call holds its permits, and so its providers'
/// votes, until its quorum resolves.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadCallLimits {
    /// Across the process: bounds the votes held in memory.
    pub(crate) process: usize,
    /// Per target chain, and per command phase, so a chain whose providers stall holds at
    /// most this many of `process`. Chain permits are granted in arrival order and a
    /// command queues no more calls than this, so a later command waits behind a few
    /// calls of a large one, not behind all of them.
    pub(crate) per_chain: usize,
}
/// Three chains stalling at once still leave a fourth four calls; a lone 256-request command
/// with lzMap finishes in the 58 s request deadline while each call takes under ~0.45 s.
const READ_CALL_LIMITS: ReadCallLimits = ReadCallLimits {
    process: 16,
    per_chain: 4,
};

/// An ABI `bytes` return is its data plus a 64-byte head and at most 31 bytes of padding.
const ABI_BYTES_OVERHEAD: usize = 64 + 31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeReadResolvedResponse {
    request: String,
    response: String,
}

/// What the payload resolver needs to turn a command marker into the block it
/// must read: the caller's timestamp resolutions, and the hashes readiness
/// agreed on for them.
#[derive(Clone, Copy)]
struct ReadBlocks<'a> {
    resolved_markers: &'a [ResolvedTimestampTimeMarker],
    pins: &'a [ReadBlockPin],
}

impl<T> RuntimeEvmReadPayloadResolver<T>
where
    T: JsonRpcTransport,
{
    pub(crate) fn new(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        chain_name_by_eid: HashMap<u32, String>,
    ) -> Self {
        Self::new_with_call_limits(providers, transport, chain_name_by_eid, READ_CALL_LIMITS)
    }

    pub(crate) fn new_with_call_limits(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        chain_name_by_eid: HashMap<u32, String>,
        limits: ReadCallLimits,
    ) -> Self {
        assert!(
            0 < limits.per_chain && limits.per_chain <= limits.process,
            "read call limits must nest: {limits:?}"
        );
        let chain_permits = chain_name_by_eid
            .values()
            .map(|chain| (chain.clone(), Arc::new(Semaphore::new(limits.per_chain))))
            .collect();
        Self {
            providers: providers.clone(),
            transport,
            chain_name_by_eid,
            call_permits: Arc::new(Semaphore::new(limits.process)),
            chain_permits: Arc::new(chain_permits),
            per_chain: limits.per_chain,
        }
    }

    fn chain_name_for_eid(&self, eid: u32) -> Result<&str, AppCoreError> {
        self.chain_name_by_eid
            .get(&eid)
            .map(String::as_str)
            .ok_or_else(|| AppCoreError::Internal(format!("No chain name for endpoint id {eid}")))
    }

    fn block_number_for_marker(
        &self,
        chain_name: &str,
        marker: ReadTimeMarker,
        resolved_markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<u64, AppCoreError> {
        match marker {
            ReadTimeMarker::BlockNumber { block_number } => {
                if block_number == 0 {
                    Err(AppCoreError::BadRequest(
                        "Malformed command: Block number cannot be zero!".to_string(),
                    ))
                } else {
                    Ok(block_number)
                }
            }
            ReadTimeMarker::Timestamp { timestamp } => resolved_markers
                .iter()
                .find(|resolved| {
                    !resolved.is_block_number
                        && resolved.chain_name == chain_name
                        && resolved.timestamp == timestamp as i64
                })
                .map(|resolved| {
                    if resolved.block_number < 1 {
                        Err(AppCoreError::Internal(format!(
                            "Invalid resolved time marker for chainName {chain_name}: blockNumber {} must be >= 1",
                            resolved.block_number
                        )))
                    } else {
                        Ok(resolved.block_number as u64)
                    }
                })
                .transpose()?
                .ok_or_else(|| {
                    AppCoreError::Internal(format!(
                        "Missing resolved timestamp time marker for chainName {chain_name} timestamp {timestamp}"
                    ))
                }),
        }
    }

    /// The call is issued against the exact block readiness validated, as an
    /// EIP-1898 `{blockHash, requireCanonical: true}` parameter. A provider
    /// whose canonical chain no longer contains that block, or that does not
    /// understand the object form, errors and loses its vote; there is
    /// deliberately no number-tagged fallback, because that is the read that
    /// could come from a sibling block the validator never saw.
    async fn call_evm_view_at_marker(
        &self,
        target_eid: u32,
        marker: ReadTimeMarker,
        to: &str,
        call_data: &str,
        max_result_bytes: usize,
        blocks: ReadBlocks<'_>,
    ) -> Result<String, AppCoreError> {
        let chain_name = self.chain_name_for_eid(target_eid)?;
        crate::provider_health::rpc_scope(chain_name, async {
        let block_number =
            self.block_number_for_marker(chain_name, marker, blocks.resolved_markers)?;
        let pin = blocks
            .pins
            .iter()
            .find(|pin| pin.chain_name == chain_name && pin.block_number == block_number)
            .ok_or_else(|| {
                AppCoreError::Internal(format!(
                    "No validated block identity for chainName {chain_name} block {block_number}; refusing an unpinned read"
                ))
            })?;
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(chain_name)?;
        let quorum = required_provider_quorum(provider_config, chain_name)?;
        let block = json!({ "blockHash": pin.block_hash, "requireCanonical": true });
        let closed = |_| AppCoreError::Admission(pillar_core::execution::BudgetError::Closed);
        // Chain first, then process, always in that order, so no call holds one while
        // another waits on it in reverse.
        let _chain_permit = self
            .chain_permits
            .get(chain_name)
            .ok_or_else(|| AppCoreError::Internal(format!("No READ call lane for {chain_name}")))?
            .acquire()
            .await
            .map_err(closed)?;
        let _permit = self.call_permits.acquire().await.map_err(closed)?;
        let mut requests = FuturesUnordered::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let (url, headers) = provider_uri_parts(uri);
            let transport = self.transport.clone();
            let block = block.clone();
            requests.push(async move {
                let vote = crate::provider_health::eth_call_read_observation_at_block(
                    transport,
                    url,
                    headers,
                    to,
                    call_data,
                    block,
                    max_result_bytes,
                )
                .await
                .map(Some)
                .map_err(RpcError::from);
                (index, vote)
            });
        }
        let mut accumulator = ExactQuorumAccumulator::new(quorum, 0..provider_config.uris.len());
        while let Some((index, observation)) = requests.next().await {
            accumulator.record_result(index, observation)?;
            if let Some(result) = accumulator.unambiguous_result() {
                return read_observation_result(result);
            }
        }
        read_observation_result(accumulator.finish("ReadV1002 eth_call")?)
        })
        .await
    }

    async fn resolve_request_payload(
        &self,
        request: EvmReadRequest,
        blocks: ReadBlocks<'_>,
    ) -> Result<RuntimeReadResolvedResponse, AppCoreError> {
        let response = self
            .call_evm_view_at_marker(
                request.target_eid,
                request.marker,
                &request.to,
                &request.calldata,
                pillar_core::MAX_READ_RESULT_BYTES,
                blocks,
            )
            .await?;
        Ok(RuntimeReadResolvedResponse {
            request: request.request,
            response: strip_hex_prefix(&response).to_string(),
        })
    }

    async fn resolve_compute_payload(
        &self,
        cmd: &str,
        compute: EvmReadCompute,
        responses: Vec<RuntimeReadResolvedResponse>,
        blocks: ReadBlocks<'_>,
    ) -> Result<String, AppCoreError> {
        let mapped_responses = if compute.setting == EvmReadComputeSetting::OnlyReduce {
            responses
                .into_iter()
                .map(|response| response.response)
                .collect::<Vec<_>>()
        } else {
            let mapped_bytes = AtomicUsize::new(0);
            let calls = responses
                .iter()
                .map(|response| async {
                    let call_data =
                        build_evm_lz_map_call_data(&response.request, &response.response)?;
                    let mapped = self.compute_call(&compute, &call_data, blocks).await?;
                    charge_read_results(&mapped_bytes, &mapped, "lzMap results")?;
                    Ok(mapped)
                })
                .collect();
            in_command_order(calls, self.per_chain).await?
        };

        if compute.setting == EvmReadComputeSetting::OnlyMap {
            return Ok(mapped_responses.concat());
        }

        let call_data = build_evm_lz_reduce_call_data(cmd, &mapped_responses)?;
        self.compute_call(&compute, &call_data, blocks).await
    }

    /// An lzMap or lzReduce call: its result is ABI `bytes`, so the vote admits the encoding
    /// overhead and the decoded data is held to the cap.
    async fn compute_call(
        &self,
        compute: &EvmReadCompute,
        call_data: &str,
        blocks: ReadBlocks<'_>,
    ) -> Result<String, AppCoreError> {
        let raw = self
            .call_evm_view_at_marker(
                compute.target_eid,
                compute.marker,
                &compute.to,
                call_data,
                pillar_core::MAX_READ_RESULT_BYTES + ABI_BYTES_OVERHEAD,
                blocks,
            )
            .await?;
        let data = strip_hex_prefix(&decode_evm_bytes_result(&raw)?).to_string();
        if data.len() / 2 > pillar_core::MAX_READ_RESULT_BYTES {
            return Err(result_too_large());
        }
        Ok(data)
    }
}

#[async_trait]
impl<T> ReadPayloadResolver for RuntimeEvmReadPayloadResolver<T>
where
    T: JsonRpcTransport,
{
    async fn resolve_payload(
        &self,
        sent_event: &LzSentEvent,
        signing_context: &SigningContext,
    ) -> Result<String, AppCoreError> {
        let SigningContext::Read {
            resolved_timestamp_time_markers,
            ..
        } = signing_context
        else {
            return Err(AppCoreError::Internal(
                "Invalid protocol type for read payload resolver".to_string(),
            ));
        };
        let blocks = ReadBlocks {
            resolved_markers: resolved_timestamp_time_markers,
            pins: &sent_event.read_block_pins,
        };
        let command = decode_evm_read_command(&sent_event.message)?;
        let request_bytes = AtomicUsize::new(0);
        let calls = command
            .requests
            .into_iter()
            .map(|request| async {
                let response = self.resolve_request_payload(request, blocks).await?;
                charge_read_results(&request_bytes, &response.response, "request results")?;
                Ok(response)
            })
            .collect();
        let responses = in_command_order(calls, self.per_chain).await?;
        if let Some(compute) = command.compute {
            self.resolve_compute_payload(&sent_event.message, compute, responses, blocks)
                .await
        } else {
            let mut resolved_payload = String::with_capacity(request_bytes.into_inner() * 2);
            for response in responses {
                resolved_payload.push_str(&response.response);
            }
            Ok(resolved_payload)
        }
    }
}

/// Runs one command phase with at most `limit` calls in flight and returns the results in
/// command order. The first error drops the calls still running.
async fn in_command_order<F, R>(calls: Vec<F>, limit: usize) -> Result<Vec<R>, AppCoreError>
where
    F: std::future::Future<Output = Result<R, AppCoreError>>,
{
    async fn tagged<F, R>(index: usize, call: F) -> Result<(usize, R), AppCoreError>
    where
        F: std::future::Future<Output = Result<R, AppCoreError>>,
    {
        call.await.map(|result| (index, result))
    }

    let mut results = Vec::with_capacity(calls.len());
    let mut pending = calls.into_iter().enumerate();
    let mut running = FuturesUnordered::new();
    for (index, call) in pending.by_ref().take(limit) {
        running.push(tagged(index, call));
    }
    while let Some(completion) = running.next().await {
        results.push(completion?);
        if let Some((index, call)) = pending.next() {
            running.push(tagged(index, call));
        }
    }
    results.sort_unstable_by_key(|(index, _)| *index);
    Ok(results.into_iter().map(|(_, result)| result).collect())
}

/// Charged on completion, before the result is kept, so a phase never holds more than the cap.
fn charge_read_results(used: &AtomicUsize, hex: &str, phase: &str) -> Result<(), AppCoreError> {
    let bytes = hex.len() / 2;
    let total = used.fetch_add(bytes, Ordering::Relaxed) + bytes;
    if total > pillar_core::MAX_READ_RESULT_BYTES {
        return Err(AppCoreError::UnresolvableCommand(format!(
            "ReadV1002 command is unresolvable: {phase} exceed {} bytes",
            pillar_core::MAX_READ_RESULT_BYTES
        )));
    }
    Ok(())
}

fn result_too_large() -> AppCoreError {
    AppCoreError::UnresolvableCommand(format!(
        "ReadV1002 command is unresolvable: an eth_call result exceeds {} bytes at the pinned block",
        pillar_core::MAX_READ_RESULT_BYTES
    ))
}

fn read_observation_result(
    observation: crate::provider_health::ReadCallObservation,
) -> Result<String, AppCoreError> {
    use crate::provider_health::ReadCallObservation;
    match observation {
        ReadCallObservation::Data { value } => Ok(value),
        ReadCallObservation::NoCode => Err(AppCoreError::UnresolvableCommand(
            "ReadV1002 command is unresolvable: target has no code at the pinned block".into(),
        )),
        ReadCallObservation::ExecutionRevert => Err(AppCoreError::UnresolvableCommand(
            "ReadV1002 command is unresolvable: execution reverted at the pinned block".into(),
        )),
        ReadCallObservation::ResultTooLarge => Err(result_too_large()),
    }
}
