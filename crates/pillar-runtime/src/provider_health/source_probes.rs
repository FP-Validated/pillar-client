use super::*;

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
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        join_all(config.uris.iter().map(|uri| {
            let transport = self.transport.clone();
            let (url, headers) = provider_uri_parts(uri);
            async move { probe_json_rpc_provider(transport, url, headers).await }
        }))
        .await
    }

    pub(super) async fn probe_aptos_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        let mut probes = Vec::<BoxFuture<'static, ProviderHealthEntry>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            let (url, headers) = aptos_provider_uri_parts(uri);
            probes.push(Box::pin(async move {
                probe_aptos_provider_health(transport, url, headers).await
            }));
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

        join_all(probes).await
    }

    pub(super) async fn probe_solana_provider_health(
        &self,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        join_all(config.uris.iter().map(|uri| {
            let transport = self.transport.clone();
            let (url, headers) = provider_uri_parts(uri);
            async move { probe_solana_provider_health(transport, url, headers).await }
        }))
        .await
    }

    pub(super) async fn probe_sui_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        join_all(config.uris.iter().map(|uri| {
            let transport = self.transport.clone();
            let chain_name = chain_name.to_string();
            let (url, headers) = provider_uri_parts(uri);
            async move { probe_sui_provider_health(&chain_name, transport, url, headers).await }
        }))
        .await
    }

    pub(super) async fn probe_starknet_provider_health(
        &self,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        join_all(config.uris.iter().map(|uri| {
            let transport = self.transport.clone();
            let (url, headers) = provider_uri_parts(uri);
            async move { probe_starknet_provider_health(transport, url, headers).await }
        }))
        .await
    }

    pub(super) async fn probe_stellar_provider_health(
        &self,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        join_all(config.uris.iter().map(|uri| {
            let transport = self.transport.clone();
            let (url, headers) = provider_uri_parts(uri);
            async move { probe_stellar_provider_health(transport, url, headers).await }
        }))
        .await
    }

    pub(super) async fn probe_ton_provider_health(
        &self,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        let mut probes = Vec::<BoxFuture<'static, ProviderHealthEntry>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            let (report_url, request_url, headers) = ton_v2_provider_uri_parts(uri);
            probes.push(Box::pin(async move {
                probe_ton_v2_provider_health(transport, report_url, request_url, headers).await
            }));
            if let Some((report_url, request_url, headers)) = ton_v3_provider_uri_parts(uri) {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    probe_ton_v3_provider_health(transport, report_url, request_url, headers).await
                }));
            }
        }

        join_all(probes).await
    }

    pub(super) async fn probe_initia_provider_health(
        &self,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        let mut probes = Vec::<BoxFuture<'static, ProviderHealthEntry>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            let (url, headers) = initia_provider_uri_parts(uri);
            probes.push(Box::pin(async move {
                probe_initia_provider_health(transport, url, headers).await
            }));
            if let Some(request) = initia_indexer_provider_health_request(uri) {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    probe_initia_indexer_provider_health(transport, request).await
                }));
            }
        }

        join_all(probes).await
    }

    pub(super) async fn probe_tron_provider_health(
        &self,
        chain_name: &str,
        config: &pillar_config::ProviderConfig,
    ) -> Vec<ProviderHealthEntry> {
        let mut probes = Vec::<BoxFuture<'static, ProviderHealthEntry>>::new();
        for uri in &config.uris {
            let transport = self.transport.clone();
            // Tron is the one family whose probe dials a URL the signing path
            // does not. `tron_json_rpc_provider_uri_parts` moves userinfo into
            // an `Authorization` header and strips the `tron-api-key` and
            // `tron-web-url` parameters, while Tron reaches the signing path as
            // an EVM-shaped chain and dispatches on the configured URI verbatim
            // - so ranking has to be keyed by the latter or `plan_dispatch`
            // never finds it. Every other family's primary probe already dials
            // what dispatch dials.
            let rank_key = rank_key_url(chain_name, uri);
            let (url, headers) = tron_json_rpc_provider_uri_parts(uri);
            probes.push(Box::pin(async move {
                let mut entry = probe_json_rpc_block_number_provider(transport, url, headers).await;
                entry.rank_key = rank_key;
                entry
            }));
            if let Some((report_url, request_url, headers)) = tron_web_provider_uri_parts(uri) {
                let transport = self.transport.clone();
                probes.push(Box::pin(async move {
                    probe_tron_web_provider_health(transport, report_url, request_url, headers)
                        .await
                }));
            }
        }

        join_all(probes).await
    }
}
