use super::*;
use std::future::Future;

impl<T> RpcProviderHealthSource<T>
where
    T: JsonRpcTransport,
{
    pub(super) fn chain_type_for_provider_health(&self, chain_name: &str) -> &str {
        self.chain_type_by_chain_name
            .get(chain_name)
            .map(String::as_str)
            .unwrap_or("EVM")
    }

    pub(super) async fn probe_evm_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        collect_health_probes(
            config
                .uris
                .iter()
                .map(|uri| {
                    let transport = self.transport.clone();
                    let (url, headers) = provider_uri_parts(uri);
                    ranked(
                        chain_name,
                        uri,
                        probe_json_rpc_provider(transport, url, headers),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .await
    }

    pub(super) async fn probe_aptos_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        let mut probes = Vec::<BoxFuture<'static, Result<ProviderHealthEntry, RpcError>>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            let (url, headers) = aptos_provider_uri_parts(uri);
            probes.push(Box::pin(ranked(
                chain_name,
                uri,
                probe_aptos_provider_health(transport, url, headers),
            )));
            if let Some(request) = aptos_indexer_provider_health_request(
                uri,
                chain_name.eq_ignore_ascii_case("movement"),
            ) {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    probe_aptos_indexer_provider_health(transport, request).await
                }));
            }
        }

        collect_health_probes(probes).await
    }

    pub(super) async fn probe_solana_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        collect_health_probes(
            config
                .uris
                .iter()
                .map(|uri| {
                    let transport = self.transport.clone();
                    let (url, headers) = provider_uri_parts(uri);
                    ranked(
                        chain_name,
                        uri,
                        probe_solana_provider_health(transport, url, headers),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .await
    }

    pub(super) async fn probe_sui_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        collect_health_probes(
            config
                .uris
                .iter()
                .map(|uri| {
                    let transport = self.transport.clone();
                    let probe_chain_name = chain_name.to_string();
                    let (url, headers) = provider_uri_parts(uri);
                    ranked(chain_name, uri, async move {
                        probe_sui_provider_health(&probe_chain_name, transport, url, headers).await
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await
    }

    pub(super) async fn probe_starknet_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        collect_health_probes(
            config
                .uris
                .iter()
                .map(|uri| {
                    let transport = self.transport.clone();
                    let (url, headers) = provider_uri_parts(uri);
                    ranked(
                        chain_name,
                        uri,
                        probe_starknet_provider_health(transport, url, headers),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .await
    }

    pub(super) async fn probe_stellar_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        collect_health_probes(
            config
                .uris
                .iter()
                .map(|uri| {
                    let transport = self.transport.clone();
                    let (url, headers) = provider_uri_parts(uri);
                    ranked(
                        chain_name,
                        uri,
                        probe_stellar_provider_health(transport, url, headers),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .await
    }

    pub(super) async fn probe_ton_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        let mut probes = Vec::<BoxFuture<'static, Result<ProviderHealthEntry, RpcError>>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            let (report_url, request_url, headers) = ton_v2_provider_uri_parts(uri);
            probes.push(Box::pin(ranked(
                chain_name,
                uri,
                probe_ton_v2_provider_health(transport, report_url, request_url, headers),
            )));
            if let (Some((report_url, request_url, headers)), Some(rank_key)) =
                (ton_v3_provider_uri_parts(uri), ton_v3_rank_key(uri))
            {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    let mut entry =
                        probe_ton_v3_provider_health(transport, report_url, request_url, headers)
                            .await?;
                    entry.rank_key = rank_key;
                    Ok(entry)
                }));
            }
        }

        collect_health_probes(probes).await
    }

    pub(super) async fn probe_initia_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        let mut probes = Vec::<BoxFuture<'static, Result<ProviderHealthEntry, RpcError>>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            let (url, headers) = initia_provider_uri_parts(uri);
            probes.push(Box::pin(ranked(
                chain_name,
                uri,
                probe_initia_provider_health(transport, url, headers),
            )));
            if let Some(request) = initia_indexer_provider_health_request(uri) {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    probe_initia_indexer_provider_health(transport, request).await
                }));
            }
        }

        collect_health_probes(probes).await
    }

    pub(super) async fn probe_tron_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        let mut probes = Vec::<BoxFuture<'static, Result<ProviderHealthEntry, RpcError>>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            // Tron's probe dials what `tron_json_rpc_provider_uri_parts` derives
            // (userinfo as a header, `tron-api-key`/`tron-web-url` stripped), but
            // signing dispatches the configured URI as an EVM-shaped chain; `ranked`
            // keys the entry by the latter, which is what `plan_dispatch` looks up.
            let (url, headers) = tron_json_rpc_provider_uri_parts(uri);
            probes.push(Box::pin(ranked(
                chain_name,
                uri,
                probe_json_rpc_block_number_provider(transport, url, headers),
            )));
            if let Some((report_url, request_url, headers)) = tron_web_provider_uri_parts(uri) {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    probe_tron_web_provider_health(transport, report_url, request_url, headers)
                        .await
                }));
            }
        }

        collect_health_probes(probes).await
    }

    /// `RpcCantonSdk.getProviderHealth`: each `rpc` entry's ledger-end offset
    /// (`rpc-sdk/src/canton/index.ts:328-336`). The sequencer entry is not ranked, as upstream.
    pub(super) async fn probe_canton_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Result<Vec<ProviderHealthEntry>, RpcError> {
        collect_health_probes(
            config
                .uris
                .iter()
                .map(|uri| {
                    let transport = self.transport.clone();
                    let auth = self.canton_ledger_auth.clone();
                    let (entry_uri, _) = provider_uri_parts(uri);
                    ranked(chain_name, uri, async move {
                        let started_at = Instant::now();
                        let response = match crate::layerzero_runtime::canton_ledger_end_offset(
                            &transport, &entry_uri, &auth,
                        )
                        .await
                        {
                            Ok(offset) => offset,
                            Err(error) => health_error_response(error)?,
                        };
                        Ok(normalize_provider_health_entry(
                            entry_uri,
                            response,
                            Some(started_at.elapsed().as_millis() as u64),
                        ))
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await
    }
}

/// A voting probe's entry, keyed by the identity `plan_dispatch` looks up for `uri`.
fn ranked<F>(
    chain_name: &str,
    uri: &pillar_config::ProviderUri,
    probe: F,
) -> impl Future<Output = Result<ProviderHealthEntry, RpcError>> + Send + 'static
where
    F: Future<Output = Result<ProviderHealthEntry, RpcError>> + Send + 'static,
{
    let rank_key = provider_rank_key(chain_name, uri);
    async move {
        let mut entry = probe.await?;
        entry.rank_key = rank_key;
        Ok(entry)
    }
}

tokio::task_local! { static PROBE_SHARE: usize; }

pub(super) fn background_probe_capacity() -> Option<usize> {
    pillar_core::execution::current()
        .and_then(|context| context.resources)
        .and_then(|resources| resources.rpc.lane_capacity("background"))
}

pub(super) async fn with_probe_share<F: Future>(share: Option<usize>, future: F) -> F::Output {
    match share {
        Some(share) => PROBE_SHARE.scope(share, future).await,
        None => future.await,
    }
}

async fn collect_health_probes<I, F>(probes: I) -> Result<Vec<ProviderHealthEntry>, RpcError>
where
    I: IntoIterator<Item = F> + Send,
    I::IntoIter: Send,
    F: Future<Output = Result<ProviderHealthEntry, RpcError>> + Send,
{
    let share = PROBE_SHARE
        .try_with(|share| *share)
        .ok()
        .or_else(background_probe_capacity)
        .unwrap_or(usize::MAX);
    let probes = probes
        .into_iter()
        .enumerate()
        .map(|(index, probe)| indexed_probe(index, probe))
        .collect::<Vec<_>>();
    let mut entries = futures::stream::iter(probes)
        .buffer_unordered(share)
        .try_collect::<Vec<_>>()
        .await?;
    entries.sort_unstable_by_key(|(index, _)| *index);
    Ok(entries.into_iter().map(|(_, entry)| entry).collect())
}

async fn indexed_probe<F>(index: usize, probe: F) -> Result<(usize, ProviderHealthEntry), RpcError>
where
    F: Future<Output = Result<ProviderHealthEntry, RpcError>>,
{
    probe.await.map(|entry| (index, entry))
}
