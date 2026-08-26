use super::*;

pub struct RuntimeCoreAppDependencies {
    pub hash_call_data_builders: HashMap<String, Arc<dyn HashCallDataBuilder>>,
    pub sent_event_resolver: Arc<dyn SentEventResolver>,
    pub validator: Arc<dyn AppValidator>,
    pub legacy_chain_name_resolver: Arc<dyn LegacyChainNameResolver>,
}

pub struct RuntimeLayerZeroDependencyParts<C> {
    pub uln_v2_payload_builder: Arc<dyn UlnV2PayloadBuilder>,
    pub uln_v3_payload_builder: Arc<dyn UlnV3PayloadBuilder>,
    pub uln_read_v1_payload_builder: Arc<dyn UlnReadV1PayloadBuilder>,
    pub read_payload_resolver: Arc<dyn ReadPayloadResolver>,
    pub sent_event_resolver: Arc<dyn SentEventResolver>,
    pub validation_checks: Arc<C>,
    pub legacy_chain_name_resolver: Arc<dyn LegacyChainNameResolver>,
}

#[derive(Debug, Clone)]
pub struct EvmPacketSentResolverConfig {
    pub chain_name_by_eid: HashMap<u32, String>,
    pub uln_version_by_send_library_address_by_chain_name: HashMap<String, HashMap<String, String>>,
    pub trusted_packet_emitters_by_chain_name: HashMap<String, HashSet<String>>,
    pub trusted_solana_endpoint_program_ids: HashSet<String>,
    pub trusted_solana_send_library_addresses: HashSet<String>,
    pub trusted_starknet_endpoint_addresses: HashSet<String>,
    pub trusted_stellar_endpoint_addresses: HashSet<String>,
    pub trusted_ton_packet_emitters_by_chain_name: HashMap<String, HashSet<String>>,
    pub trusted_move_packet_emitters_by_chain_name: HashMap<String, HashSet<String>>,
}

pub struct RuntimeEvmLayerZeroConfig {
    pub packet_sent_resolver_config: EvmPacketSentResolverConfig,
    pub receive_contracts_by_chain_name: HashMap<String, EvmReceiveContracts>,
}

pub struct RuntimeAptosLayerZeroConfig {
    pub receive_contracts_by_chain_name: HashMap<String, AptosReceiveContracts>,
}

pub struct RuntimeSuiLayerZeroConfig {
    pub receive_contracts_by_chain_name: HashMap<String, SuiReceiveContracts>,
}

#[derive(Clone)]
pub struct RuntimeRpcValidationChecks<T> {
    pub(super) providers: crate::provider_snapshot::ProviderSnapshotHandle,
    pub(super) transport: T,
    pub(super) evm_receive_contracts_by_chain_name: HashMap<String, EvmReceiveContracts>,
    pub(super) evm_chain_name_by_eid: HashMap<u32, String>,
    pub(super) starknet_uln_302: Option<String>,
    pub(super) move_endpoint_v2_by_chain_name: HashMap<String, String>,
    pub(super) move_uln_302_by_chain_name: HashMap<String, String>,
    pub(super) move_views_by_chain_name: HashMap<String, String>,
    pub(super) sui_payload_contracts: HashMap<String, SuiPayloadContracts>,
    pub(super) ton_payload_config: Option<Arc<RuntimeTonLayerZeroConfig>>,
    pub(super) extra_context: RuntimeExtraContextConfig,
    pub(super) extra_context_lambda_client: Option<Arc<dyn AwsLambdaInvokeClient>>,
    pub(super) rank_tracker: Arc<ProviderRankTracker>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeExtraContextConfig {
    pub request_url: Option<String>,
    pub request_auth_token: Option<String>,
    pub aws_lambda_name: Option<String>,
}

impl RuntimeExtraContextConfig {
    pub fn from_runtime_config(config: &RuntimeConfig) -> Self {
        Self {
            request_url: config.extra_context_request_url.clone(),
            request_auth_token: config.extra_context_request_auth_token.clone(),
            aws_lambda_name: config.extra_context_aws_lambda_name.clone(),
        }
    }
}

impl<T> RuntimeRpcValidationChecks<T>
where
    T: JsonRpcTransport,
{
    pub fn from_getter(
        providers: &crate::provider_snapshot::ProviderSnapshotHandle,
        transport: T,
    ) -> Self {
        Self {
            providers: providers.clone(),
            transport,
            evm_receive_contracts_by_chain_name: HashMap::new(),
            evm_chain_name_by_eid: HashMap::new(),
            starknet_uln_302: None,
            move_endpoint_v2_by_chain_name: HashMap::new(),
            move_uln_302_by_chain_name: HashMap::new(),
            move_views_by_chain_name: HashMap::new(),
            sui_payload_contracts: HashMap::new(),
            ton_payload_config: None,
            extra_context: RuntimeExtraContextConfig::default(),
            extra_context_lambda_client: None,
            rank_tracker: Arc::new(ProviderRankTracker::new()),
        }
    }

    /// Shares one rank tracker across validation checks and the background
    /// reprobe loop (see server_app) instead of each keeping its own state.
    pub(crate) fn with_rank_tracker(mut self, rank_tracker: Arc<ProviderRankTracker>) -> Self {
        self.rank_tracker = rank_tracker;
        self
    }

    pub fn with_evm_receive_contracts(
        mut self,
        contracts_by_chain_name: HashMap<String, EvmReceiveContracts>,
    ) -> Self {
        self.evm_receive_contracts_by_chain_name = contracts_by_chain_name;
        self
    }

    pub fn with_evm_chain_names(mut self, chain_name_by_eid: HashMap<u32, String>) -> Self {
        self.evm_chain_name_by_eid = chain_name_by_eid;
        self
    }

    pub fn with_starknet_uln_302(mut self, address: impl Into<String>) -> Self {
        self.starknet_uln_302 = Some(address.into());
        self
    }

    pub fn with_move_payload_contracts(
        mut self,
        endpoint_v2_by_chain_name: HashMap<String, String>,
        uln_302_by_chain_name: HashMap<String, String>,
        views_by_chain_name: HashMap<String, String>,
    ) -> Self {
        self.move_endpoint_v2_by_chain_name = endpoint_v2_by_chain_name;
        self.move_uln_302_by_chain_name = uln_302_by_chain_name;
        self.move_views_by_chain_name = views_by_chain_name;
        self
    }

    /// Sui and IOTA need the endpoint / views / verification ids on top of the
    /// ULN 302 package to reproduce the upstream view calls.
    pub fn with_sui_payload_contracts(
        mut self,
        contracts_by_chain_name: HashMap<String, SuiPayloadContracts>,
    ) -> Self {
        self.sui_payload_contracts = contracts_by_chain_name;
        self
    }

    /// TON needs the ULN manager addresses and compiled code cells to derive
    /// the `Uln`/`UlnConnection` contracts whose storage the payload-signed
    /// check reads.
    pub fn with_ton_payload_contracts(mut self, config: Arc<RuntimeTonLayerZeroConfig>) -> Self {
        self.ton_payload_config = Some(config);
        self
    }

    pub fn with_extra_context(mut self, extra_context: RuntimeExtraContextConfig) -> Self {
        self.extra_context = extra_context;
        self
    }

    pub fn with_extra_context_lambda_client(
        mut self,
        client: Arc<dyn AwsLambdaInvokeClient>,
    ) -> Self {
        self.extra_context_lambda_client = Some(client);
        self
    }
}
