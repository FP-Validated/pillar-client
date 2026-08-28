use async_trait::async_trait;
use futures::future::try_join_all;
use futures::{stream::FuturesUnordered, StreamExt};
use indexmap::IndexMap;
use pillar_api::{CoreApiApp, SignerInfo};
use pillar_config::{
    layerzero_available_chain_names, layerzero_chain_name_by_evm_endpoint_id,
    layerzero_contract_address, layerzero_evm_endpoint_id, layerzero_evm_endpoint_id_for_version,
    static_chain_type_by_chain_name, ConfigError, RuntimeConfig,
};
use pillar_core::{
    AppCoreError, AppValidator, HashCallDataBuilder, LegacyChainNameResolver, LzMessageId,
    LzSentEvent, PathwayId, PillarApp, ProviderHealthSnapshot, ResolvedTimestampTimeMarker,
    SentEventResolver, SignerGetter, SigningContext, WalletRef,
    PAYLOAD_ALREADY_SIGNED_ERROR_PREFIX,
};
use pillar_layerzero::{
    build_evm_lz_map_call_data, build_evm_lz_reduce_call_data, build_hash_call_data_builders,
    compute_lz_packet_v1_proof_from_event, decode_evm_bytes_result, decode_evm_packet_sent_log,
    decode_evm_read_command, decode_lz_packet_v1, decode_ton_relayer_options,
    derive_evm_feather_hash_info, evm_address_from_pathway_value,
    extract_evm_read_resolved_time_markers, is_lz_read_endpoint_id, solana_message_library_address,
    AptosReceiveContracts, AptosUlnPayloadBuilder, DestinationUlnPayloadBuilderRouter,
    EvmPacketSent, EvmReadCompute, EvmReadComputeSetting, EvmReadRequest, EvmReceiveContracts,
    EvmUlnPayloadBuilder, LzPacketV1, ReadPayloadResolver, ReadResolvedTimeMarker, ReadTimeMarker,
    SolanaUlnPayloadBuilder, StarknetUlnPayloadBuilder, StellarUlnPayloadBuilder,
    SuiReceiveContracts, SuiUlnPayloadBuilder, TonUlnPayloadBuilder, UlnReadV1PayloadBuilder,
    UlnV2HashInfo, UlnV2PayloadBuilder, UlnV3PayloadBuilder, ULN_VERSION_READ_V1002,
    ULN_VERSION_V2, ULN_VERSION_V301, ULN_VERSION_V302,
};
use pillar_metrics::{PillarMetrics, PillarMetricsStageObserver};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::Semaphore;

use crate::provider_health::{
    block_matches_resolved_timestamp, eth_call_at_block, extra_context_sent_event_payload,
    json_value_is_truthy, lz_message_id_matches, normalize_address, normalize_address_map,
    numeric_response, observe_block_confirmations, observe_block_time, observe_payload_signed,
    observe_solana_transaction_from, observe_transaction_from, observe_uln_v2_inbound_proof_type,
    observe_uln_v2_mpt_hash_info, parse_block_timestamp_seconds, pathway_extra_string_value,
    pathway_extra_u32, pathway_extra_u64, plan_dispatch, provider_uri_parts,
    required_provider_quorum, resolve_provider_quorum, strip_hex_prefix, timestamp_validity,
    ton_v3_provider_uri_parts, uln_version_value, AwsLambdaInvokeClient,
    BlockConfirmationObservation, BlockConfirmationValidity, BlockTime, DispatchEntry,
    EvmPayloadSignedObservation, EvmReceiptLog, EvmTransactionReceipt, ExactQuorumAccumulator,
    JsonRpcTransport, PayloadSignedValidity, ProviderRankTracker, TimestampValidity,
};
use crate::provider_snapshot::ChainDispatch;
use crate::validation::{ExpirationValidRange, RuntimeAppValidator, RuntimeValidationChecks};

pub(crate) mod config;
mod core_app;
mod legacy_resolver;
mod source_events_move;
mod source_events_sui;

pub(crate) use source_events_sui::{
    decode_sui_packet_sent_events, observe_sui_block_confirmations_rpc, observe_sui_block_time_rpc,
    sui_rpc_method, SuiBlockConfirmationValidity,
};
mod source_events_starknet;
mod source_events_stellar;
mod source_events_ton;
pub(crate) use source_events_ton::{decode_ton_packet_sent_events, normalize_ton_address};
mod packet_resolver;
pub(crate) use source_events_move::{
    decode_move_packet_sent_events, fetch_move_transaction, move_provider_uri_parts,
    observe_move_block_confirmations, observe_move_block_time, MovePacketSentEvent,
};
pub(crate) use source_events_starknet::{
    decode_starknet_packet_sent_events, starknet_packet_to_lz_sent_event,
};
pub(crate) use source_events_stellar::{
    decode_stellar_packet_sent_events, normalize_stellar_address, stellar_packet_to_lz_sent_event,
};
mod read_payload;
mod ton_v3_builder;
mod types;
mod uln_v2_builder;
mod validation_extra_context;
mod validation_impl;
mod validation_payload;
mod validation_payload_solana;
mod validation_payload_sui;
mod validation_payload_ton;
mod validation_read_markers;
mod validation_readiness;
mod validation_timestamp;

pub use config::{
    runtime_aptos_layerzero_config, runtime_chain_name_by_endpoint_id,
    runtime_evm_layerzero_config, runtime_evm_uln_payload_builder,
    runtime_layerzero_parts_from_evm_config, runtime_rpc_validation_checks_from_evm_config,
    runtime_v_id_by_chain_name, RuntimeLayerZeroDependencyInputs, RuntimeTonLayerZeroConfig,
    SuiPayloadContracts,
};
pub use core_app::{
    core_api_app_from_runtime_parts, runtime_core_dependencies_from_layerzero_parts,
    RuntimeCoreAppParts,
};
pub(crate) use legacy_resolver::RuntimeLegacyChainNameResolver;
pub use packet_resolver::EvmPacketSentResolver;
pub(crate) use read_payload::RuntimeEvmReadPayloadResolver;
pub(crate) use ton_v3_builder::RuntimeTonUlnPayloadBuilder;
pub use types::EvmPacketSentResolverConfig;
pub use types::{
    RuntimeAptosLayerZeroConfig, RuntimeCoreAppDependencies, RuntimeEvmLayerZeroConfig,
    RuntimeExtraContextConfig, RuntimeLayerZeroDependencyParts, RuntimeRpcValidationChecks,
    RuntimeSuiLayerZeroConfig,
};
pub(crate) use uln_v2_builder::RuntimeEvmUlnV2PayloadBuilder;
