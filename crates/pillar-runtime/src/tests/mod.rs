use super::*;
use crate::{config_loader::*, layerzero_runtime::*, provider_health::*, signer_runtime::*};
use async_trait::async_trait;
use indexmap::IndexMap;
use pillar_api::{CoreApiApp, ServerApp, SignerInfo};
use pillar_config::{
    KmsSignerAdapterFactoryOptions, ProviderConfig, ProviderUri, RuntimeConfig,
    StaticProviderConfig, LZ_CDK_DEPLOY_REGION, LZ_ENV, LZ_PROVIDER_CONFIG,
    LZ_PROVIDER_CONFIG_TYPE, LZ_WALLETS_FILE_PATH, LZ_WALLET_MNEMONIC_MAPPING_FILE_PATH,
    SERVER_PORT, SIGNER_TYPE,
};
use pillar_core::{
    AppCoreError, AppValidator, HashCallDataBuilder, HashCallDataResult, LegacyChainNameResolver,
    LzMessageId, LzSentEvent, PathwayId, PillarApiRequestV1, PillarApiRequestV2, PillarApp,
    ProviderHealthSnapshot, ProviderHealthSource, ResolvedTimestampTimeMarker, SentEventResolver,
    Signature, SignerGetter, SigningContext, WalletRef,
};
use pillar_layerzero::{
    build_evm_uln_v2_get_app_config_call_data, build_evm_uln_v2_inbound_proof_library_call_data,
    build_evm_validation_library_get_proof_type_call_data,
    build_evm_validation_library_get_utils_version_call_data, build_hash_call_data_builders,
    EvmReceiveContracts, EvmUlnPayloadBuilder, ReadPayloadResolver, UlnReadV1PayloadBuilder,
    UlnV2PayloadBuilder, UlnV3PayloadBuilder, ULN_VERSION_V302,
};
use pillar_signer::{
    ChainType, ChainTypeWalletDefinition, KmsProvider, LocalMnemonic as SignerLocalMnemonic,
    PublicKeyRequest, RawSignerAdapter, RawSignerAdapterFactory, SignRequest, SignatureType,
    SignerError, WalletSignerKind,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

type RecordedJsonCall = (String, HashMap<String, String>, Value);
type RecordedJsonCalls = Arc<Mutex<Vec<RecordedJsonCall>>>;

mod stellar_provenance_tests;
mod support_app;
mod support_core;
mod support_packets;
mod support_rpc;
mod support_transports;
mod support_validation_layerzero;

use support_app::*;
use support_core::*;
use support_packets::*;
use support_rpc::*;
use support_transports::*;
use support_validation_layerzero::*;

mod core_app_tests;
mod gasolina_parity_tests;
mod layerzero_config_tests;
mod layerzero_packet_resolver_tests;
mod layerzero_parts_non_evm_wiring_tests;
#[path = "layerzero_parts_rejection_tests/mod.rs"]
mod layerzero_parts_rejection_tests;
mod layerzero_parts_wiring_tests;
mod layerzero_read_payload_tests;
mod layerzero_uln_v2_feather_tests;
mod layerzero_uln_v2_mpt_tests;
mod payload_signed_family_tests;
mod provider_config_refresh_tests;
mod provider_health_aptos_tests;
mod provider_health_common_tests;
mod provider_health_evm_tests;
mod provider_health_initia_tests;
mod provider_health_solana_concurrency_tests;
mod provider_health_stellar_solana_probe_tests;
mod provider_health_sui_starknet_tests;
mod provider_health_ton_tests;
mod provider_health_tron_tests;
mod read_time_marker_resolver_tests;
mod server_app_tests;
mod signer_config_tests;
mod signer_kms_config_tests;
mod signer_kms_wallet_policy_tests;
mod signer_local_tests;
mod startup_report_tests;
mod validation_app_tests;
mod validation_payload_receive_library_tests;
mod validation_payload_sui_tests;
mod validation_payload_tests;
mod validation_payload_ton_tests;
mod validation_read_markers_tests;
mod validation_readiness_tests;
mod validation_timestamp_tests;

use signer_config_tests::*;
use validation_readiness_tests::*;

/// The real startup vId table, so these tests sign with the same verifier id
/// production would rather than a literal that could drift from the deployment
/// tables.
fn test_v_ids(environment: &str) -> HashMap<String, String> {
    let chain_names = pillar_config::layerzero_available_chain_names(environment).unwrap();
    runtime_v_id_by_chain_name(environment, &chain_names).unwrap()
}
