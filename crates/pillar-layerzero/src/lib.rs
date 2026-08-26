mod abi;
mod aptos;
mod builders;
mod evm;
mod evm_v2;
mod evm_v3;
mod other_non_evm;
mod packet;
mod read_v1002;
mod router;
mod solana;
mod sui;
mod sui_bcs;
mod types;

pub use abi::{
    build_evm_dvn_call_data_result, build_evm_get_receive_library_call_data,
    build_evm_get_uln_config_call_data, build_evm_hash_lookup_call_data,
    build_evm_is_valid_receive_library_call_data, build_evm_lz_map_call_data,
    build_evm_lz_reduce_call_data, build_evm_uln_v2_get_app_config_call_data,
    build_evm_uln_v2_inbound_proof_library_call_data,
    build_evm_v1_get_receive_library_address_call_data,
    build_evm_validation_library_get_proof_type_call_data,
    build_evm_validation_library_get_utils_version_call_data, build_evm_verifiable_call_data,
    decode_evm_address_result, decode_evm_bool_result, decode_evm_bytes_result,
    decode_evm_hash_lookup_result, decode_evm_receive_library_result, decode_evm_uint64_result,
    decode_evm_uln_config_confirmations, decode_evm_uln_v2_app_config,
    decode_evm_verification_state, evm_address_from_pathway_value, evm_hash_lookup_is_confirmed,
    keccak256_hex, pack_dvn_call_data,
};
pub use aptos::{
    aptos_hash_propose, aptos_hash_verify, AptosReceiveContracts, AptosUlnPayloadBuilder,
};
pub use builders::{
    build_hash_call_data_builders, UlnReadV1HashCallDataBuilder, UlnV2HashCallDataBuilder,
    UlnV3HashCallDataBuilder,
};
pub use evm::{
    evm_receive_contract_for_uln_version, evm_receive_version_from_dst_eid,
    evm_uln_version_from_receive_library, EvmReceiveContracts, EvmUlnPayloadBuilder,
};
pub use evm_v2::build_evm_uln_v2_verify_call_data;
pub use evm_v3::build_evm_uln_v3_verify_call_data;
pub use other_non_evm::{
    boc_from_base64, build_ton_dvn_verify, committable_view_is_signed, decode_proxy_admin_target,
    decode_ton_relayer_options, derive_uln_addresses, dvn_attestation,
    stellar_contract_id_from_strkey, ton_address_to_be32, ton_boc_to_base64,
    ton_payload_signed_targets, uln_default_receive_config, DerivedAddresses, DvnAttestation,
    StarknetUlnPayloadBuilder, StellarUlnPayloadBuilder, TonContractCodeCells, TonDvnVerifyOutput,
    TonDvnVerifyRequest, TonPathway, TonPayloadSignedRequest, TonPayloadSignedTargets,
    TonStorageCell, TonUlnPayloadBuilder, LIVE_TON_PACKET_BOC,
};
pub use packet::{
    build_evm_feather_proof, build_evm_lz_v1_packet_payload_v2,
    build_evm_lz_v1_packet_payload_v2_from_event, compute_lz_packet_v1_proof,
    compute_lz_packet_v1_proof_from_event, decode_evm_legacy_packet_v2_payload,
    decode_evm_packet_sent_log, decode_lz_packet_v1, derive_evm_feather_hash_info,
    encode_lz_packet_v1, native_hash_by_chain_name, EvmPacketSent, EvmUlnProof, LzPacketV1,
};
pub use read_v1002::{
    build_evm_uln_read_v1_verify_call_data, decode_evm_read_command,
    extract_evm_read_resolved_time_markers,
};
pub use router::DestinationUlnPayloadBuilderRouter;
pub use solana::{
    solana_message_library_address, solana_payload_is_signed, solana_payload_signed_accounts,
    solana_payload_signed_request, SolanaFetchedPayloadSignedAccounts, SolanaPayloadSignedAccounts,
    SolanaPayloadSignedRequest, SolanaUlnPayloadBuilder,
};
pub use sui::{SuiReceiveContracts, SuiUlnPayloadBuilder};
pub use sui_bcs::{
    decode_sui_address, decode_sui_u64, decode_sui_u8, decode_sui_uln_config,
    encode_sui_transaction_kind, sui_address_from_hex, sui_pure_address, sui_pure_bytes,
    sui_pure_u32, SuiArgument, SuiCallArg, SuiMoveCall, SuiSharedObject, SuiUlnConfig,
    SUI_DEV_INSPECT_MOCK_SENDER,
};
pub use types::*;

#[cfg(test)]
#[test]
fn rejects_malformed_packet_header() {
    let short_err = decode_lz_packet_v1("0x010203").unwrap_err();
    assert_eq!(short_err.to_string(), "invalid packet length: 3");

    let version_err = decode_lz_packet_v1(&format!("0x02{}", "00".repeat(112))).unwrap_err();
    assert_eq!(version_err.to_string(), "unsupported packet version: 2");
}

#[cfg(test)]
mod tests;
