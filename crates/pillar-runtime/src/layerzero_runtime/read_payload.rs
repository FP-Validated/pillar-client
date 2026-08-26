use super::*;

#[derive(Clone)]
pub(crate) struct RuntimeEvmReadPayloadResolver<T> {
    providers: crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    chain_name_by_eid: HashMap<u32, String>,
    rpc_permits: Arc<Semaphore>,
}

const MAX_CONCURRENT_READ_RPC_REQUESTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeReadResolvedResponse {
    request: String,
    response: String,
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
        Self::new_with_rpc_limit(
            providers,
            transport,
            chain_name_by_eid,
            MAX_CONCURRENT_READ_RPC_REQUESTS,
        )
    }

    pub(crate) fn new_with_rpc_limit(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
        chain_name_by_eid: HashMap<u32, String>,
        max_concurrent_rpc: usize,
    ) -> Self {
        assert!(max_concurrent_rpc > 0, "read RPC limit must be positive");
        Self {
            providers: providers.clone(),
            transport,
            chain_name_by_eid,
            rpc_permits: Arc::new(Semaphore::new(max_concurrent_rpc)),
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
                    Err(AppCoreError::Internal(
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

    async fn call_evm_view_at_marker(
        &self,
        target_eid: u32,
        marker: ReadTimeMarker,
        to: &str,
        call_data: &str,
        resolved_markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<String, AppCoreError> {
        let chain_name = self.chain_name_for_eid(target_eid)?;
        let block_number = self.block_number_for_marker(chain_name, marker, resolved_markers)?;
        let snapshot = self.providers.load();
        let provider_config = snapshot.provider_config(chain_name)?;
        let quorum = required_provider_quorum(provider_config, chain_name)?;
        let block_tag = format!("0x{block_number:x}");
        let mut requests = FuturesUnordered::new();
        for (index, uri) in provider_config.uris.iter().enumerate() {
            let transport = self.transport.clone();
            let (url, headers) = provider_uri_parts(uri);
            let to = to.to_string();
            let call_data = call_data.to_string();
            let block_tag = block_tag.clone();
            let rpc_permits = self.rpc_permits.clone();
            requests.push(async move {
                let observation = match rpc_permits.acquire_owned().await {
                    Ok(_permit) => {
                        eth_call_at_block(transport, url, headers, &to, &call_data, &block_tag)
                            .await
                    }
                    Err(_) => Err(AppCoreError::Internal(
                        "ReadV1002 RPC admission closed".to_string(),
                    )),
                };
                (index, observation)
            });
        }
        let mut accumulator = ExactQuorumAccumulator::new(provider_config.uris.len(), quorum);
        while let Some((index, observation)) = requests.next().await {
            accumulator.record(index, observation.ok().map(|value| (value.clone(), value)));
            if let Some(result) = accumulator.unambiguous_result() {
                return Ok(result);
            }
        }
        accumulator.finish("ReadV1002 eth_call")
    }

    async fn resolve_request_payload(
        &self,
        request: EvmReadRequest,
        resolved_markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<RuntimeReadResolvedResponse, AppCoreError> {
        let response = self
            .call_evm_view_at_marker(
                request.target_eid,
                request.marker,
                &request.to,
                &request.calldata,
                resolved_markers,
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
        resolved_markers: &[ResolvedTimestampTimeMarker],
    ) -> Result<String, AppCoreError> {
        let mapped_responses = if compute.setting == EvmReadComputeSetting::OnlyReduce {
            responses
                .iter()
                .map(|response| response.response.clone())
                .collect::<Vec<_>>()
        } else {
            try_join_all(responses.iter().map(|response| async {
                let call_data = build_evm_lz_map_call_data(&response.request, &response.response)?;
                let raw = self
                    .call_evm_view_at_marker(
                        compute.target_eid,
                        compute.marker,
                        &compute.to,
                        &call_data,
                        resolved_markers,
                    )
                    .await?;
                Ok::<String, AppCoreError>(
                    strip_hex_prefix(&decode_evm_bytes_result(&raw)?).to_string(),
                )
            }))
            .await?
        };

        if compute.setting == EvmReadComputeSetting::OnlyMap {
            return Ok(format!("0x{}", mapped_responses.join("")));
        }

        let call_data = build_evm_lz_reduce_call_data(cmd, &mapped_responses)?;
        let raw = self
            .call_evm_view_at_marker(
                compute.target_eid,
                compute.marker,
                &compute.to,
                &call_data,
                resolved_markers,
            )
            .await?;
        decode_evm_bytes_result(&raw)
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
        let command = decode_evm_read_command(&sent_event.message)?;
        let responses =
            try_join_all(command.requests.into_iter().map(|request| {
                self.resolve_request_payload(request, resolved_timestamp_time_markers)
            }))
            .await?;
        if let Some(compute) = command.compute {
            self.resolve_compute_payload(
                &sent_event.message,
                compute,
                responses,
                resolved_timestamp_time_markers,
            )
            .await
        } else {
            let mut resolved_payload = String::from("0x");
            for response in responses {
                resolved_payload.push_str(&response.response);
            }
            Ok(resolved_payload)
        }
    }
}
