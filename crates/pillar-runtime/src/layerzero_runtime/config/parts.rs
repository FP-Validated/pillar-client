use crate::provider_health::JsonRpcTransport;

use super::*;

pub struct RuntimeLayerZeroDependencyInputs<C>
where
    C: RuntimeValidationChecks,
{
    pub uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder>,
    pub read_payload_resolver: Arc<dyn ReadPayloadResolver>,
    pub validation_checks: Arc<C>,
    pub legacy_chain_name_resolver: Arc<dyn LegacyChainNameResolver>,
    /// The registry `/metrics` renders. Provider failures recorded by the
    /// resolver must land here, not in a registry nobody scrapes.
    pub metrics: Arc<tokio::sync::Mutex<PillarMetrics>>,
}

pub fn runtime_layerzero_parts_from_evm_config<T, C>(
    providers: &crate::provider_snapshot::ProviderSnapshotHandle,
    transport: T,
    environment: &str,
    chain_names: &[String],
    inputs: RuntimeLayerZeroDependencyInputs<C>,
) -> Result<RuntimeLayerZeroDependencyParts<C>, ConfigError>
where
    T: JsonRpcTransport,
    C: RuntimeValidationChecks,
{
    let evm_config = runtime_evm_layerzero_config(environment, chain_names)?;
    let evm_payload_builder = Arc::new(EvmUlnPayloadBuilder::new(
        evm_config.receive_contracts_by_chain_name,
    ));
    let evm_uln_v3_payload_builder: Arc<dyn UlnV3PayloadBuilder> = evm_payload_builder.clone();
    let evm_uln_read_payload_builder: Arc<dyn UlnReadV1PayloadBuilder> =
        evm_payload_builder.clone();
    let aptos_config = runtime_aptos_layerzero_config(environment, chain_names)?;
    let mut routed_payload_builder = DestinationUlnPayloadBuilderRouter::new(
        inputs.uln_v2_payload_builder,
        evm_uln_v3_payload_builder,
        evm_uln_read_payload_builder,
    );
    let mut non_evm_builder_chain_names = HashSet::<String>::new();
    if !aptos_config.receive_contracts_by_chain_name.is_empty() {
        let aptos_chain_names = aptos_config
            .receive_contracts_by_chain_name
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        non_evm_builder_chain_names.extend(aptos_chain_names.iter().cloned());
        let aptos_payload_builder = Arc::new(AptosUlnPayloadBuilder::new(
            aptos_config.receive_contracts_by_chain_name,
        ));
        let aptos_uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder> =
            aptos_payload_builder.clone();
        let aptos_uln_v3_payload_builder: Arc<dyn UlnV3PayloadBuilder> =
            aptos_payload_builder.clone();
        let aptos_uln_read_payload_builder: Arc<dyn UlnReadV1PayloadBuilder> =
            aptos_payload_builder.clone();
        for chain_name in aptos_chain_names {
            routed_payload_builder = routed_payload_builder.with_chain_builder(
                chain_name,
                aptos_uln_v2_payload_builder.clone(),
                aptos_uln_v3_payload_builder.clone(),
                aptos_uln_read_payload_builder.clone(),
            );
        }
    }
    let sui_config = runtime_sui_layerzero_config(environment, chain_names)?;
    if !sui_config.receive_contracts_by_chain_name.is_empty() {
        non_evm_builder_chain_names
            .extend(sui_config.receive_contracts_by_chain_name.keys().cloned());
        let chain_names = sui_config
            .receive_contracts_by_chain_name
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let sui_payload_builder = Arc::new(SuiUlnPayloadBuilder::new(
            sui_config.receive_contracts_by_chain_name,
        ));
        let sui_uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder> = sui_payload_builder.clone();
        let sui_uln_v3_payload_builder: Arc<dyn UlnV3PayloadBuilder> = sui_payload_builder.clone();
        let sui_uln_read_payload_builder: Arc<dyn UlnReadV1PayloadBuilder> =
            sui_payload_builder.clone();
        for chain_name in chain_names {
            routed_payload_builder = routed_payload_builder.with_chain_builder(
                chain_name,
                sui_uln_v2_payload_builder.clone(),
                sui_uln_v3_payload_builder.clone(),
                sui_uln_read_payload_builder.clone(),
            );
        }
    }
    if chain_names.iter().any(|chain_name| chain_name == "solana") {
        non_evm_builder_chain_names.insert("solana".to_string());
        let solana_payload_builder = Arc::new(SolanaUlnPayloadBuilder);
        routed_payload_builder = routed_payload_builder.with_chain_builder(
            "solana",
            solana_payload_builder.clone(),
            solana_payload_builder.clone(),
            solana_payload_builder,
        );
    }
    if chain_names
        .iter()
        .any(|chain_name| chain_name == "starknet")
    {
        non_evm_builder_chain_names.insert("starknet".to_string());
        let starknet_payload_builder = Arc::new(StarknetUlnPayloadBuilder::new(
            starknet_uln_302_for_environment(environment)?,
        ));
        routed_payload_builder = routed_payload_builder.with_chain_builder(
            "starknet",
            starknet_payload_builder.clone(),
            starknet_payload_builder.clone(),
            starknet_payload_builder,
        );
    }
    if chain_names.iter().any(|chain_name| chain_name == "stellar") {
        let address = stellar_uln_302_for_environment(environment)?;
        non_evm_builder_chain_names.insert("stellar".to_string());
        // Every other chain trusts the pinned upstream table. Stellar cannot:
        // the pinned ids were confirmed on chain to be a superseded generation,
        // and this id is hashed into the attestation rather than merely
        // addressed by it, so a build would emit an attestation no live
        // verifier reads. Refuse per request rather than at assembly, so one
        // unconfirmed chain does not stop the service serving the others.
        // Derived from the disagreement rather than hardcoded, so re-pinning
        // the table above reopens the chain with no further change here.
        let unconfirmed = stellar_uln_302_published_for_environment(environment)
            .filter(|published| *published != address)
            .map(|published| ConfigError::UnconfirmedDeploymentGeneration {
                environment: environment.to_string(),
                chain_name: "stellar".to_string(),
                pinned: address.to_string(),
                published: published.to_string(),
                confirmed_on: "2026-08-28".to_string(),
            });
        if let Some(unconfirmed) = unconfirmed {
            let refuse = Arc::new(UnavailableUlnPayloadBuilder::new(unconfirmed.to_string()));
            routed_payload_builder = routed_payload_builder.with_chain_builder(
                "stellar",
                refuse.clone(),
                refuse.clone(),
                refuse,
            );
        } else {
            let stellar_payload_builder =
                Arc::new(StellarUlnPayloadBuilder::new(address).map_err(|_| {
                    ConfigError::InvalidNonEvmUlnAddress {
                        environment: environment.to_string(),
                        chain_name: "stellar".to_string(),
                        address: address.to_string(),
                    }
                })?);
            routed_payload_builder = routed_payload_builder.with_chain_builder(
                "stellar",
                stellar_payload_builder.clone(),
                stellar_payload_builder.clone(),
                stellar_payload_builder,
            );
        }
    }
    if chain_names.iter().any(|chain_name| chain_name == "ton") {
        if let Some(ton_config) = runtime_ton_layerzero_config(environment) {
            non_evm_builder_chain_names.insert("ton".to_string());
            let ton_unsupported = Arc::new(TonUlnPayloadBuilder);
            let ton_v3: Arc<dyn UlnV3PayloadBuilder> = Arc::new(RuntimeTonUlnPayloadBuilder::new(
                providers,
                transport.clone(),
                ton_config.code,
                ton_config.uln_manager_address,
                ton_config.deprecated_code,
                ton_config.deprecated_uln_manager_address,
            ));
            routed_payload_builder = routed_payload_builder.with_chain_builder(
                "ton",
                ton_unsupported.clone(),
                ton_v3,
                ton_unsupported,
            );
        }
    }
    routed_payload_builder = routed_payload_builder.with_unsupported_non_evm_destinations(
        unsupported_layerzero_destination_chains(chain_names, &non_evm_builder_chain_names)?,
    );
    let routed_payload_builder = Arc::new(routed_payload_builder);
    let routed_uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder> =
        routed_payload_builder.clone();
    let routed_uln_v3_payload_builder: Arc<dyn UlnV3PayloadBuilder> =
        routed_payload_builder.clone();
    let routed_uln_read_payload_builder: Arc<dyn UlnReadV1PayloadBuilder> =
        routed_payload_builder.clone();
    let sent_event_resolver: Arc<dyn SentEventResolver> = Arc::new(
        EvmPacketSentResolver::new(providers, transport, evm_config.packet_sent_resolver_config)
            .with_metrics(inputs.metrics.clone()),
    );
    Ok(RuntimeLayerZeroDependencyParts {
        uln_v2_payload_builder: routed_uln_v2_payload_builder,
        uln_v3_payload_builder: routed_uln_v3_payload_builder,
        uln_read_v1_payload_builder: routed_uln_read_payload_builder,
        read_payload_resolver: inputs.read_payload_resolver,
        sent_event_resolver,
        validation_checks: inputs.validation_checks,
        legacy_chain_name_resolver: inputs.legacy_chain_name_resolver,
    })
}
