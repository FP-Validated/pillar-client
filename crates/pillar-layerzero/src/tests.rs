use super::*;
use crate::abi::{
    decode_hex_32, decode_hex_bytes, function_selector, solidity_address_word,
    solidity_dynamic_bytes, solidity_uint256,
};
use crate::aptos::aptos_function_signature_hash;
use crate::read_v1002::resolved_payload_hash;
use async_trait::async_trait;
use indexmap::IndexMap;
use pillar_core::{
    AppCoreError, HashCallDataResult, LzMessageId, LzSentEvent, PathwayId,
    ResolvedTimestampTimeMarker, SigningContext,
};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[path = "tests/non_evm_vectors/mod.rs"]
mod non_evm_vectors;
#[path = "tests/official_vectors.rs"]
mod official_vectors;
#[path = "tests/solana_builder_tests.rs"]
mod solana_builder_tests;
#[path = "tests/solana_payload_signed_tests.rs"]
mod solana_payload_signed_tests;

#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl UlnV2PayloadBuilder for Recorder {
    async fn build_uln_v2_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.calls
            .lock()
            .await
            .push(format!("v2:{block_confirmation}:{expiration}:{v_id}"));
        Ok(result("0xv2"))
    }
}

#[async_trait]
impl UlnV3PayloadBuilder for Recorder {
    async fn build_uln_v3_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        block_confirmation: i64,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.calls.lock().await.push(format!(
            "v3:{block_confirmation}:{expiration}:{v_id}:{}",
            dvn_address.unwrap_or_default()
        ));
        Ok(result("0xv3"))
    }
}

#[async_trait]
impl UlnReadV1PayloadBuilder for Recorder {
    async fn build_uln_read_v1_verify_payload(
        &self,
        _sent_event: &LzSentEvent,
        resolved_payload: String,
        expiration: i64,
        v_id: String,
        dvn_address: Option<&str>,
    ) -> Result<HashCallDataResult, AppCoreError> {
        self.calls.lock().await.push(format!(
            "read:{resolved_payload}:{expiration}:{v_id}:{}",
            dvn_address.unwrap_or_default()
        ));
        Ok(result("0xread"))
    }
}

#[async_trait]
impl ReadPayloadResolver for Recorder {
    async fn resolve_payload(
        &self,
        _sent_event: &LzSentEvent,
        _signing_context: &SigningContext,
    ) -> Result<String, AppCoreError> {
        Ok("0xresolved".to_string())
    }
}

fn result(payload: &str) -> HashCallDataResult {
    HashCallDataResult {
        hash_call_data: payload.to_string(),
        details: serde_json::json!({ "proof": { "payload": payload } }),
    }
}

fn sent_event() -> LzSentEvent {
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "bsc".to_string(),
                extra: IndexMap::new(),
            },
            nonce: 1,
            uln_send_version: Value::from("V302"),
        },
        message: "0xabc".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: IndexMap::new(),
    }
}

fn evm_sent_event() -> LzSentEvent {
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(30_101_u64));
    pathway_extra.insert("dstEid".to_string(), Value::from(30_101_u64));
    pathway_extra.insert(
        "sender".to_string(),
        Value::from("0x1111111111111111111111111111111111111111"),
    );
    pathway_extra.insert(
        "receiver".to_string(),
        Value::from("0x2222222222222222222222222222222222222222"),
    );
    let mut event_extra = IndexMap::new();
    event_extra.insert(
        "guid".to_string(),
        Value::from("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    );
    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: "ethereum".to_string(),
                dst_chain_name: "ethereum".to_string(),
                extra: pathway_extra,
            },
            nonce: 7,
            uln_send_version: Value::from(ULN_VERSION_V302),
        },
        message: "0xdeadbeef".to_string(),
        tx_hash: "0xtx".to_string(),
        extra: event_extra,
    }
}

fn evm_payload_builder() -> EvmUlnPayloadBuilder {
    EvmUlnPayloadBuilder::new(HashMap::from([(
        "ethereum".to_string(),
        EvmReceiveContracts {
            endpoint_v2: "0x5555555555555555555555555555555555555555".to_string(),
            endpoint_v1: None,
            uln_v2: "0x4444444444444444444444444444444444444444".to_string(),
            receive_uln_301: "0x1111111111111111111111111111111111111111".to_string(),
            receive_uln_301_view: "0x1111111111111111111111111111111111111112".to_string(),
            receive_uln_302: "0x2222222222222222222222222222222222222222".to_string(),
            receive_uln_302_view: "0x2222222222222222222222222222222222222223".to_string(),
            read_lib_1002: Some("0x3333333333333333333333333333333333333333".to_string()),
            read_lib_1002_view: Some("0x3333333333333333333333333333333333333334".to_string()),
        },
    )]))
}

fn evm_corpus_payload_builder() -> EvmUlnPayloadBuilder {
    EvmUlnPayloadBuilder::new(HashMap::from([
        (
            "base".to_string(),
            EvmReceiveContracts {
                endpoint_v2: "0x5555555555555555555555555555555555555555".to_string(),
                endpoint_v1: None,
                uln_v2: "0x38dE71124f7a447a01D67945a51eDcE9FF491251".to_string(),
                receive_uln_301: "0x58D53a2d6a08B72a15137F3381d21b90638bd753".to_string(),
                receive_uln_301_view: "0xbfde77038B91a7c772034f0Fe60b6C5f8578a5ad".to_string(),
                receive_uln_302: "0xc70AB6f32772f59fBfc23889Caf4Ba3376C84bAf".to_string(),
                receive_uln_302_view: "0xA4ab842be43aC4De9f4bD2D063eC0479fFDD3A9b".to_string(),
                read_lib_1002: Some("0x1273141a3f7923AA2d9edDfA402440cE075ed8Ff".to_string()),
                read_lib_1002_view: Some("0xFDac1618FdcD0e96CCF6c14B6eFA55Aa1D0aD483".to_string()),
            },
        ),
        (
            "ethereum".to_string(),
            EvmReceiveContracts {
                endpoint_v2: "0x5555555555555555555555555555555555555555".to_string(),
                endpoint_v1: None,
                uln_v2: "0x4D73AdB72bC3DD368966edD0f0b2148401A178E2".to_string(),
                receive_uln_301: "0x245B6e8FFE9ea5Fc301e32d16F66bD4C2123eEfC".to_string(),
                receive_uln_301_view: "0x0330f95a5110E9F72fe0776A1291834FfEACB1e0".to_string(),
                receive_uln_302: "0xc02Ab410f0734EFa3F14628780e6e695156024C2".to_string(),
                receive_uln_302_view: "0xcc0de82D7d520d8d5897d23cf961867Bc16Fd346".to_string(),
                read_lib_1002: Some("0x74F55Bc2a79A27A0bF1D1A35dB5d0Fc36b9FDB9D".to_string()),
                read_lib_1002_view: Some("0x60adfF2ADb728f7D3029e43dEA8c212f31c2962c".to_string()),
            },
        ),
    ]))
}

struct EvmFixture {
    src_eid: u64,
    src_chain_name: &'static str,
    dst_eid: u64,
    dst_chain_name: &'static str,
    sender: &'static str,
    receiver: &'static str,
    nonce: u64,
    message: &'static str,
    block_confirmation: i64,
    expiration: i64,
    guid: &'static str,
    v_id: &'static str,
    expected_hash: &'static str,
    expected_target: &'static str,
}

fn evm_sent_event_from_fixture(fixture: &EvmFixture) -> LzSentEvent {
    let mut pathway_extra = IndexMap::new();
    pathway_extra.insert("srcEid".to_string(), Value::from(fixture.src_eid));
    pathway_extra.insert("dstEid".to_string(), Value::from(fixture.dst_eid));
    pathway_extra.insert("sender".to_string(), Value::from(fixture.sender));
    pathway_extra.insert("receiver".to_string(), Value::from(fixture.receiver));
    let mut event_extra = IndexMap::new();
    event_extra.insert("guid".to_string(), Value::from(fixture.guid));

    LzSentEvent {
        lz_message_id: LzMessageId {
            pathway_id: PathwayId {
                src_chain_name: fixture.src_chain_name.to_string(),
                dst_chain_name: fixture.dst_chain_name.to_string(),
                extra: pathway_extra,
            },
            nonce: fixture.nonce,
            uln_send_version: Value::from(ULN_VERSION_V302),
        },
        message: fixture.message.to_string(),
        tx_hash: "0xtx".to_string(),
        extra: event_extra,
    }
}

fn aptos_sent_event() -> LzSentEvent {
    let mut event = evm_sent_event();
    event.lz_message_id.pathway_id.dst_chain_name = "aptos".to_string();
    event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(30_108_u64));
    event
}

fn aptos_payload_builder() -> AptosUlnPayloadBuilder {
    AptosUlnPayloadBuilder::new(HashMap::from([(
        "aptos".to_string(),
        AptosReceiveContracts {
            v1_oracle: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            v1_uln_301: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            uln_302: "0x3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
        },
    )]))
}

#[tokio::test]
async fn factory_matches_typescript_uln_version_mapping() {
    let recorder = Arc::new(Recorder::default());
    let builders = build_hash_call_data_builders(
        recorder.clone(),
        recorder.clone(),
        recorder.clone(),
        recorder,
        "mainnet",
    );
    assert!(builders.contains_key(ULN_VERSION_V2));
    assert!(builders.contains_key(ULN_VERSION_V301));
    assert!(builders.contains_key(ULN_VERSION_V302));
    assert!(builders.contains_key(ULN_VERSION_READ_V1002));
    assert_eq!(builders.len(), 4);
}

#[tokio::test]
async fn destination_router_keeps_default_builder_for_unregistered_chain() {
    let recorder = Arc::new(Recorder::default());
    let router = Arc::new(DestinationUlnPayloadBuilderRouter::new(
        recorder.clone(),
        recorder.clone(),
        recorder.clone(),
    ));
    let builders = build_hash_call_data_builders(
        router.clone(),
        router.clone(),
        router,
        recorder.clone(),
        "mainnet",
    );

    let result = builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &sent_event(),
            &SigningContext::Message {
                expiration: 2,
                skip_v_id: Some(true),
                dvn_address: Some("0xdvn".to_string()),
                block_confirmation: 1,
            },
        )
        .await
        .unwrap();

    assert_eq!(result.hash_call_data, "0xv3");
    assert_eq!(
        recorder.calls.lock().await.as_slice(),
        &["v3:1:2::0xdvn".to_string()]
    );
}

#[tokio::test]
async fn uln_v3_rejects_read_context_like_typescript() {
    let recorder = Arc::new(Recorder::default());
    let builders = build_hash_call_data_builders(
        recorder.clone(),
        recorder.clone(),
        recorder.clone(),
        recorder,
        "mainnet",
    );
    let err = builders[ULN_VERSION_V302]
        .build_dvn_hash_call_data(
            &sent_event(),
            &SigningContext::Read {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                resolved_timestamp_time_markers: vec![ResolvedTimestampTimeMarker {
                    block_confirmation: 1,
                    is_block_number: false,
                    chain_name: "ethereum".to_string(),
                    block_number: 1,
                    timestamp: 1,
                }],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Invalid protocol type for ULN V3");
}

#[tokio::test]
async fn uln_read_rejects_message_context_with_existing_error_text() {
    let recorder = Arc::new(Recorder::default());
    let builders = build_hash_call_data_builders(
        recorder.clone(),
        recorder.clone(),
        recorder.clone(),
        recorder,
        "mainnet",
    );
    let err = builders[ULN_VERSION_READ_V1002]
        .build_dvn_hash_call_data(
            &sent_event(),
            &SigningContext::Message {
                expiration: 1,
                skip_v_id: None,
                dvn_address: None,
                block_confirmation: 1,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "Invalid protocol type for ULN V3");
}

#[test]
fn pack_dvn_call_data_matches_v_id_branch_shape() {
    let packed = pack_dvn_call_data(
        "0x1111111111111111111111111111111111111111",
        "0xaabb",
        7,
        "9",
    )
    .unwrap();
    assert_eq!(&packed[..4], 9u32.to_be_bytes());
    assert_eq!(packed.len(), 4 + 20 + 32 + 2);
    assert_eq!(&packed[24..56], solidity_uint256(7));
    assert_eq!(&packed[56..], &[0xaa, 0xbb]);
}

#[test]
fn pack_dvn_call_data_matches_no_v_id_branch_shape() {
    let packed = pack_dvn_call_data(
        "0x1111111111111111111111111111111111111111",
        "0xaabb",
        7,
        "",
    )
    .unwrap();
    assert_eq!(packed.len(), 20 + 32 + 2);
    assert_eq!(&packed[20..52], solidity_uint256(7));
    assert_eq!(&packed[52..], &[0xaa, 0xbb]);
}

#[test]
fn evm_receive_version_matches_ts_convenience_logic() {
    assert_eq!(
        evm_receive_version_from_dst_eid(30_184, ULN_VERSION_READ_V1002),
        ULN_VERSION_READ_V1002
    );
    assert_eq!(
        evm_receive_version_from_dst_eid(101, ULN_VERSION_V302),
        ULN_VERSION_V301
    );
    assert_eq!(
        evm_receive_version_from_dst_eid(30_101, ULN_VERSION_V302),
        ULN_VERSION_V302
    );
}

#[test]
fn evm_read_command_decoder_matches_layerzero_utility_encoding() {
    let command = decode_evm_read_command(concat!(
        "0x",
        "000100010001",
        "01000100010027",
        "00007596",
        "00",
        "000000006553f100",
        "000c",
        "1111111111111111111111111111111111111111",
        "deadbeef",
    ))
    .unwrap();

    assert_eq!(command.global_version, 1);
    assert_eq!(command.app_command_label, "0001");
    assert_eq!(command.requests.len(), 1);
    assert_eq!(command.compute, None);
    assert_eq!(command.requests[0].target_eid, 30_102);
    assert_eq!(
        command.requests[0].marker,
        ReadTimeMarker::Timestamp {
            timestamp: 1_700_000_000
        }
    );
    assert_eq!(command.requests[0].block_confirmation, 12);
    assert_eq!(
        command.requests[0].to,
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(command.requests[0].calldata, "0xdeadbeef");
    assert_eq!(
        command.requests[0].request,
        concat!(
            "0x",
            "01000100010027",
            "00007596",
            "00",
            "000000006553f100",
            "000c",
            "1111111111111111111111111111111111111111",
            "deadbeef",
        )
    );
}

#[test]
fn evm_read_command_rejects_unbounded_request_fanout_before_decoding_bodies() {
    let error = decode_evm_read_command("0x000100000101").unwrap_err();

    assert!(error
        .to_string()
        .contains("read request count 257 exceeds limit 256"));
}

#[test]
fn evm_read_command_extracts_request_and_compute_time_markers() {
    let markers = extract_evm_read_resolved_time_markers(concat!(
        "0x",
        "000100010001",
        "01000100010027",
        "00007596",
        "00",
        "000000006553f100",
        "000c",
        "1111111111111111111111111111111111111111",
        "deadbeef",
        "01000101",
        "00007596",
        "01",
        "0000000000003039",
        "0007",
        "2222222222222222222222222222222222222222",
    ))
    .unwrap();

    assert_eq!(
        markers,
        vec![
            ReadResolvedTimeMarker {
                target_eid: 30_102,
                marker: ReadTimeMarker::Timestamp {
                    timestamp: 1_700_000_000,
                },
                block_confirmation: 12,
            },
            ReadResolvedTimeMarker {
                target_eid: 30_102,
                marker: ReadTimeMarker::BlockNumber {
                    block_number: 12_345,
                },
                block_confirmation: 7,
            },
        ]
    );
}

#[test]
fn evm_read_command_rejects_zero_block_number_marker() {
    let err = extract_evm_read_resolved_time_markers(concat!(
        "0x",
        "000100010001",
        "01000100010023",
        "00007596",
        "01",
        "0000000000000000",
        "000c",
        "1111111111111111111111111111111111111111",
    ))
    .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Malformed command: Block number cannot be zero!"
    );
}

#[test]
fn evm_read_compute_call_data_matches_ethers_abi_shape() {
    assert_eq!(
        build_evm_lz_map_call_data("0x0102", "0xaabbcc").unwrap(),
        concat!(
            "0xe60c287c",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0102000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "aabbcc0000000000000000000000000000000000000000000000000000000000",
        )
    );
    assert_eq!(
        build_evm_lz_reduce_call_data(
            "0xdeadbeef",
            &["0x1122".to_string(), "0x334455".to_string()],
        )
        .unwrap(),
        concat!(
            "0xeba1cf08",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000004",
            "deadbeef00000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "1122000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "3344550000000000000000000000000000000000000000000000000000000000",
        )
    );
}

#[test]
fn evm_read_compute_decodes_bytes_return_value() {
    assert_eq!(
        decode_evm_bytes_result(concat!(
            "0x",
            "0000000000000000000000000000000000000000000000000000000000000020",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "cafe000000000000000000000000000000000000000000000000000000000000",
        ))
        .unwrap(),
        "0xcafe"
    );
}

#[test]
fn unsupported_receive_contract_error_text_matches_ts() {
    let err = evm_receive_contract_for_uln_version(ULN_VERSION_V2).unwrap_err();
    assert_eq!(err.to_string(), "Unsupported UlnVersion");
}

#[test]
fn pack_dvn_call_data_matches_known_solidity_pack_hex() {
    let packed = pack_dvn_call_data(
        "0x1111111111111111111111111111111111111111",
        "0xaabb",
        7,
        "9",
    )
    .unwrap();
    assert_eq!(
            format!("0x{}", hex::encode(packed)),
            "0x0000000911111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000007aabb"
        );
}

#[test]
fn evm_uln_v2_update_hash_call_data_matches_ethers_abi_shape() {
    let hash_info = UlnV2HashInfo {
        lookup_hash: "0x0202020202020202020202020202020202020202020202020202020202020202"
            .to_string(),
        block_data: "0x0303030303030303030303030303030303030303030303030303030303030303"
            .to_string(),
    };
    let call_data = build_evm_uln_v2_verify_call_data(30_101, &hash_info, 64).unwrap();
    let bytes = decode_hex_bytes(&call_data).unwrap();

    assert_eq!(
        &bytes[..4],
        function_selector("updateHash(uint16,bytes32,uint256,bytes32)")
    );
    assert_eq!(&bytes[4..36], solidity_uint256(30_101));
    assert_eq!(
        &bytes[36..68],
        decode_hex_32(&hash_info.lookup_hash).unwrap()
    );
    assert_eq!(&bytes[68..100], solidity_uint256(64));
    assert_eq!(
        &bytes[100..132],
        decode_hex_32(&hash_info.block_data).unwrap()
    );
}

#[test]
fn evm_lz_v1_packet_payload_v2_matches_typescript_solidity_pack_shape() {
    let payload = build_evm_lz_v1_packet_payload_v2(
        7,
        101,
        "0x1111111111111111111111111111111111111111",
        102,
        "0x2222222222222222222222222222222222222222",
        "0xdeadbeef",
    )
    .unwrap();

    assert_eq!(
        payload,
        concat!(
            "0x",
            "0000000000000007",
            "0065",
            "1111111111111111111111111111111111111111",
            "0066",
            "2222222222222222222222222222222222222222",
            "deadbeef",
        )
    );
}

#[test]
fn evm_feather_proof_prefixes_packet_emitter_as_bytes32() {
    let proof = build_evm_feather_proof(
            "0x3333333333333333333333333333333333333333",
            "0x00000000000000070065111111111111111111111111111111111111111100662222222222222222222222222222222222222222deadbeef",
        )
        .unwrap();

    assert_eq!(
        proof,
        concat!(
            "0x",
            "0000000000000000000000003333333333333333333333333333333333333333",
            "0000000000000007",
            "0065",
            "1111111111111111111111111111111111111111",
            "0066",
            "2222222222222222222222222222222222222222",
            "deadbeef",
        )
    );
}

#[test]
fn native_hash_by_chain_name_matches_typescript_aptos_vector() {
    assert_eq!(
            native_hash_by_chain_name(
                "0x00000000000000014e3e88a546769667f6b3d199c9c3ef92136d1f26776682c4deaf36e26d00273426bf4e3e88a546769667f6b3d199c9c3ef92136d1f26776682c4deaf36e26d00273426bf01020304",
                "aptos",
            )
            .unwrap(),
            "bd3544561da899f88d9ce7a0834b4b3dc82769915aaec23d9df4f57364c36e5d"
        );
}

#[test]
fn aptos_hashes_match_typescript_hashes_ts_vectors() {
    assert_eq!(
        hex::encode(aptos_function_signature_hash("propose")),
        "6738b0a1"
    );
    assert_eq!(
        hex::encode(aptos_function_signature_hash("verify")),
        "7c40a351"
    );
    assert_eq!(
        aptos_hash_propose(
            "6d5004021f122bb2f06b8e2daf4c17a6de56e9a5b147ade87b433fa352885962",
            15,
            1_712_345_678,
        )
        .unwrap(),
        "bbf736b0be58c1990db270268d9558ca62f3f8c0ba4cdf22a354cac8e3658449"
    );
    assert_eq!(
            aptos_hash_verify(
                "0x010000000000000007000075950000000000000000000000001111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222",
                "0x08eed9e984b654cded42042a70953b0e5c143f47cb44b60296d86f5345656887",
                20,
                "0x00000000000000000000000000000000000000000000000000000000abc123",
                7,
                1_712_345_678,
            )
            .unwrap(),
            "eee9498acfac99a0d3f43f5d00c6819d34277063fed195466935151ad1d39fd3"
        );
}

#[tokio::test]
async fn aptos_payload_builder_builds_v2_hash_propose_like_typescript() {
    let mut sent_event = aptos_sent_event();
    sent_event.lz_message_id.uln_send_version = Value::from(ULN_VERSION_V2);
    let builder = aptos_payload_builder();
    let hash_info = UlnV2HashInfo {
        lookup_hash: "6d5004021f122bb2f06b8e2daf4c17a6de56e9a5b147ade87b433fa352885962".to_string(),
        block_data: "6d5004021f122bb2f06b8e2daf4c17a6de56e9a5b147ade87b433fa352885962".to_string(),
    };

    let result = builder
        .build_uln_v2_verify_payload_from_hash_info(&sent_event, hash_info, 15, 1_712_345_678, "")
        .unwrap();

    assert_eq!(
        result.hash_call_data,
        "bbf736b0be58c1990db270268d9558ca62f3f8c0ba4cdf22a354cac8e3658449"
    );
    assert_eq!(
        result.details["dvnHashCallData"]["dvnCallData"],
        "unknown in aptos"
    );
    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "hashPropose");
}

#[tokio::test]
async fn aptos_payload_builder_rejects_v_id_for_v2_like_typescript() {
    let sent_event = aptos_sent_event();
    let builder = aptos_payload_builder();
    let err = builder
        .build_uln_v2_verify_payload_from_hash_info(
            &sent_event,
            UlnV2HashInfo {
                lookup_hash: "6d5004021f122bb2f06b8e2daf4c17a6de56e9a5b147ade87b433fa352885962"
                    .to_string(),
                block_data: "6d5004021f122bb2f06b8e2daf4c17a6de56e9a5b147ade87b433fa352885962"
                    .to_string(),
            },
            15,
            1_712_345_678,
            "108",
        )
        .unwrap_err();

    assert_eq!(err.to_string(), "VId is not supported on aptos yet");
}

#[tokio::test]
async fn aptos_payload_builder_builds_v3_hash_verify_like_typescript() {
    let mut sent_event = aptos_sent_event();
    sent_event.lz_message_id.uln_send_version = Value::from(ULN_VERSION_V302);
    let builder = aptos_payload_builder();

    let result = builder
            .build_uln_v3_verify_payload_from_proof(
                &sent_event,
                EvmUlnProof {
                    packet_header: "0x010000000000000007000075950000000000000000000000001111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222".to_string(),
                    payload_hash: "0x08eed9e984b654cded42042a70953b0e5c143f47cb44b60296d86f5345656887".to_string(),
                },
                20,
                1_712_345_678,
                "108",
            )
            .unwrap();

    assert_eq!(
        result.hash_call_data,
        "f831206174c85447b0b2a2460cd10ad25a1b2b37bc67968227bb8317f5da81a0"
    );
    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "hashPropose");
}

#[tokio::test]
async fn aptos_payload_builder_rejects_read_v1_without_placeholder_text() {
    let builder = aptos_payload_builder();

    let err = builder
        .build_uln_read_v1_verify_payload(
            &aptos_sent_event(),
            "0xresolved".to_string(),
            1_712_345_678,
            "1".to_string(),
            None,
        )
        .await
        .unwrap_err();

    assert_eq!(
        err.to_string(),
        "Unsupported LayerZero read destination chain type for aptos"
    );
    assert!(!err.to_string().contains("Not implemented"));
}

#[test]
fn evm_feather_hash_info_uses_native_hash_for_lookup_and_block_data() {
    let mut sent_event = evm_sent_event();
    sent_event.lz_message_id.uln_send_version = Value::from(ULN_VERSION_V2);
    sent_event
        .lz_message_id
        .pathway_id
        .extra
        .insert("srcEid".to_string(), Value::from(101_u64));
    sent_event
        .lz_message_id
        .pathway_id
        .extra
        .insert("dstEid".to_string(), Value::from(102_u64));
    let hash_info =
        derive_evm_feather_hash_info(&sent_event, "0x3333333333333333333333333333333333333333")
            .unwrap();

    assert_eq!(hash_info.lookup_hash, hash_info.block_data);
    assert!(hash_info.lookup_hash.starts_with("0x"));
    assert_eq!(decode_hex_32(&hash_info.lookup_hash).unwrap().len(), 32);
}

#[test]
fn evm_payload_builder_builds_v2_dvn_result_with_uln_v2_target() {
    let builder = evm_payload_builder();
    let mut sent_event = evm_sent_event();
    sent_event.lz_message_id.uln_send_version = Value::from(ULN_VERSION_V2);
    let result = builder
        .build_uln_v2_verify_payload_from_hash_info(
            &sent_event,
            UlnV2HashInfo {
                lookup_hash: "0x0202020202020202020202020202020202020202020202020202020202020202"
                    .to_string(),
                block_data: "0x0303030303030303030303030303030303030303030303030303030303030303"
                    .to_string(),
            },
            64,
            1,
            "101",
        )
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x4444444444444444444444444444444444444444"
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "updateHash");
    assert_eq!(result.details["ulnCallData"]["blockConfirmation"], 64);
    assert_eq!(
        result.details["ulnCallData"]["proof"]["lookupHash"],
        "0x0202020202020202020202020202020202020202020202020202020202020202"
    );
    assert_eq!(result.details["proof"]["payload"], "0xdeadbeef");
}

#[test]
fn evm_dvn_result_matches_ts_details_shape() {
    let result = build_evm_dvn_call_data_result(
        "0x1111111111111111111111111111111111111111",
        "0xaabb",
        7,
        "9",
        serde_json::json!({
            "ulnCallData": { "methodName": "verify" },
            "proof": { "payload": "0xpayload" }
        }),
    )
    .unwrap();
    assert!(result.hash_call_data.starts_with("0x"));
    assert_eq!(result.hash_call_data.len(), 66);
    assert_eq!(
        result.details["dvnCallData"],
        serde_json::json!({
            "expiration": 7,
            "vid": "9",
            "targetContract": "0x1111111111111111111111111111111111111111",
            "ulnCallData": "0xaabb"
        })
    );
    assert_eq!(
            result.details["dvnHashCallData"]["dvnCallData"],
            "0x0000000911111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000007aabb"
        );
    assert_eq!(result.details["proof"]["payload"], "0xpayload");
}

#[test]
fn evm_uln_v3_verify_call_data_matches_ethers_abi_shape() {
    let proof = EvmUlnProof {
        packet_header: "0x010203".to_string(),
        payload_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
    };
    let call_data = build_evm_uln_v3_verify_call_data(&proof, 64).unwrap();
    assert_eq!(&call_data[..10], "0x0223536e");
    assert_eq!(
        call_data,
        concat!(
            "0x0223536e",
            "0000000000000000000000000000000000000000000000000000000000000060",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0102030000000000000000000000000000000000000000000000000000000000"
        )
    );
}

#[test]
fn compute_lz_packet_v1_proof_matches_layerzero_packet_codec() {
    let packet = LzPacketV1 {
        nonce: 7,
        src_eid: 30_101,
        sender: "0x1111111111111111111111111111111111111111".to_string(),
        dst_eid: 30_102,
        receiver: "0x2222222222222222222222222222222222222222".to_string(),
        guid: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        message: "0xdeadbeef".to_string(),
    };
    assert_eq!(
            format!("0x{}", hex::encode(encode_lz_packet_v1(&packet).unwrap())),
            "0x010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef"
        );
    assert_eq!(
            compute_lz_packet_v1_proof(&packet).unwrap(),
            EvmUlnProof {
                packet_header: "0x010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222".to_string(),
                payload_hash: "0x08eed9e984b654cded42042a70953b0e5c143f47cb44b60296d86f5345656887".to_string(),
            }
        );
    assert_eq!(decode_lz_packet_v1("0x010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef").unwrap(), LzPacketV1 {
            nonce: 7,
            src_eid: 30_101,
            sender: "0x0000000000000000000000001111111111111111111111111111111111111111".to_string(),
            dst_eid: 30_102,
            receiver: "0x0000000000000000000000002222222222222222222222222222222222222222".to_string(),
            guid: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            message: "0xdeadbeef".to_string(),
        });
}

#[test]
fn decode_endpoint_v2_packet_sent_log_matches_ethers_event_data() {
    let decoded = decode_evm_packet_sent_log(
            &[ENDPOINT_V2_PACKET_SENT_TOPIC.to_string()],
            concat!(
                "0x",
                "0000000000000000000000000000000000000000000000000000000000000060",
                "0000000000000000000000000000000000000000000000000000000000000100",
                "0000000000000000000000003333333333333333333333333333333333333333",
                "0000000000000000000000000000000000000000000000000000000000000075",
                "010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef",
                "0000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "1234000000000000000000000000000000000000000000000000000000000000",
            ),
        )
        .unwrap();

    assert_eq!(decoded.options, "0x1234");
    assert_eq!(
        decoded.send_library.as_deref(),
        Some("0x3333333333333333333333333333333333333333")
    );
    assert_eq!(decoded.packet.nonce, 7);
    assert_eq!(decoded.packet.src_eid, 30_101);
    assert_eq!(decoded.packet.dst_eid, 30_102);
    assert_eq!(decoded.packet.message, "0xdeadbeef");
    assert_eq!(
        decoded.packet.sender,
        "0x0000000000000000000000001111111111111111111111111111111111111111"
    );
}

#[test]
fn decode_uln301_packet_sent_log_matches_ethers_event_data() {
    let decoded = decode_evm_packet_sent_log(
            &[ULN_301_PACKET_SENT_TOPIC.to_string()],
            concat!(
                "0x",
                "0000000000000000000000000000000000000000000000000000000000000080",
                "0000000000000000000000000000000000000000000000000000000000000120",
                "0000000000000000000000000000000000000000000000000000000000000005",
                "0000000000000000000000000000000000000000000000000000000000000006",
                "0000000000000000000000000000000000000000000000000000000000000075",
                "010000000000000007000075950000000000000000000000001111111111111111111111111111111111111111000075960000000000000000000000002222222222222222222222222222222222222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbdeadbeef",
                "0000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "1234000000000000000000000000000000000000000000000000000000000000",
            ),
        )
        .unwrap();

    assert_eq!(decoded.options, "0x1234");
    assert_eq!(decoded.send_library, None);
    assert_eq!(decoded.packet.nonce, 7);
    assert_eq!(
        decoded.packet.guid,
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

#[test]
fn decode_legacy_uln_v2_packet_log_matches_typescript_payload_decoder() {
    let payload = concat!(
        "0x",
        "0000000000000007",
        "0065",
        "1111111111111111111111111111111111111111",
        "0066",
        "2222222222222222222222222222222222222222",
        "deadbeef",
    );
    let mut data = Vec::new();
    data.extend_from_slice(&solidity_uint256(32));
    data.extend_from_slice(&solidity_dynamic_bytes(payload).unwrap());
    let decoded = decode_evm_packet_sent_log(
        &[LEGACY_ULN_V2_PACKET_TOPIC.to_string()],
        &format!("0x{}", hex::encode(data)),
    )
    .unwrap();

    assert_eq!(decoded.packet.nonce, 7);
    assert_eq!(decoded.packet.src_eid, 101);
    assert_eq!(decoded.packet.dst_eid, 102);
    assert_eq!(
        decoded.packet.sender,
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(
        decoded.packet.receiver,
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(decoded.packet.message, "0xdeadbeef");
    assert_eq!(
        decoded.packet.guid,
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(decoded.options, "0x");
    assert_eq!(decoded.send_library, None);
}

#[test]
fn evm_read_v1_verify_call_data_hashes_resolved_payload_like_typescript() {
    let proof = EvmUlnProof {
        packet_header: "0x010203".to_string(),
        payload_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
    };
    let resolved_hash = resolved_payload_hash(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "0x1234",
    )
    .unwrap();
    assert_eq!(
        resolved_hash,
        "0xf88abc595e28aef608f02e2cb392ee165d48839a586a039288a41fb611bfb7db"
    );
    let call_data = build_evm_uln_read_v1_verify_call_data(&proof, &resolved_hash).unwrap();
    assert_eq!(&call_data[..10], "0xab750e75");
    assert!(call_data.contains("f88abc595e28aef608f02e2cb392ee165d48839a586a039288a41fb611bfb7db"));
}

#[test]
fn evm_receive_lookup_call_data_and_decoders_match_abi_shapes() {
    assert_eq!(
        function_selector("verify(bytes,bytes32,uint64)"),
        RECEIVE_ULN_302_VERIFY_SELECTOR
    );
    assert_eq!(
        function_selector("verify(bytes,bytes32,bytes32)"),
        READ_LIB_1002_VERIFY_SELECTOR
    );
    let proof = EvmUlnProof {
        packet_header: "0x010203".to_string(),
        payload_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
    };

    let hash_lookup =
        build_evm_hash_lookup_call_data(&proof, "0x3333333333333333333333333333333333333333")
            .unwrap();
    let packet_header_hash = Keccak256::digest([1u8, 2, 3]);
    assert_eq!(&hash_lookup[..10], "0x3c782a52");
    assert_eq!(
        &hash_lookup[10..74],
        hex::encode(packet_header_hash).as_str()
    );
    assert_eq!(
        &hash_lookup[74..138],
        "2222222222222222222222222222222222222222222222222222222222222222"
    );
    assert_eq!(
        &hash_lookup[138..],
        "0000000000000000000000003333333333333333333333333333333333333333"
    );

    let verifiable = build_evm_verifiable_call_data(&proof).unwrap();
    assert_eq!(&verifiable[..10], "0x27d12cd9");
    assert_eq!(
        verifiable,
        concat!(
            "0x27d12cd9",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0000000000000000000000000000000000000000000000000000000000000003",
            "0102030000000000000000000000000000000000000000000000000000000000",
        )
    );

    let get_config =
        build_evm_get_uln_config_call_data("0x3333333333333333333333333333333333333333", 30_101)
            .unwrap();
    assert_eq!(&get_config[..10], "0x43ea4fa9");
    assert_eq!(
        &get_config[10..74],
        "0000000000000000000000003333333333333333333333333333333333333333"
    );
    assert_eq!(
        &get_config[74..],
        "0000000000000000000000000000000000000000000000000000000000007595"
    );

    let app_config_result = format!(
        "0x{}{}{}{}{}{}",
        hex::encode(solidity_uint256(2)),
        hex::encode(solidity_uint256(64)),
        hex::encode(solidity_address_word("0x1111111111111111111111111111111111111111").unwrap()),
        hex::encode(solidity_uint256(1)),
        hex::encode(solidity_uint256(12)),
        hex::encode(solidity_address_word("0x2222222222222222222222222222222222222222").unwrap()),
    );
    assert_eq!(
        decode_evm_uln_v2_app_config(&app_config_result).unwrap(),
        EvmUlnV2AppConfig {
            inbound_proof_library_version: 2,
            inbound_block_confirmations: 64,
            relayer: "0x1111111111111111111111111111111111111111".to_string(),
            outbound_proof_type: 1,
            outbound_block_confirmations: 12,
            oracle: "0x2222222222222222222222222222222222222222".to_string(),
        }
    );
    assert_eq!(
        decode_evm_address_result(&format!(
            "0x{}",
            hex::encode(
                solidity_address_word("0x3333333333333333333333333333333333333333").unwrap()
            )
        ))
        .unwrap(),
        "0x3333333333333333333333333333333333333333"
    );

    let message_result = format!(
        "0x{}{}",
        hex::encode(solidity_uint256(1)),
        hex::encode(solidity_uint256(64))
    );
    assert_eq!(
        decode_evm_hash_lookup_result(ULN_VERSION_V302, &message_result).unwrap(),
        EvmHashLookupResult::Message {
            submitted: true,
            confirmations: 64
        }
    );
    assert!(evm_hash_lookup_is_confirmed(
        64,
        &decode_evm_hash_lookup_result(ULN_VERSION_V302, &message_result).unwrap()
    ));
    assert!(!evm_hash_lookup_is_confirmed(
        65,
        &decode_evm_hash_lookup_result(ULN_VERSION_V302, &message_result).unwrap()
    ));

    let read_result = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_eq!(
        decode_evm_hash_lookup_result(ULN_VERSION_READ_V1002, read_result).unwrap(),
        EvmHashLookupResult::Read {
            payload_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string()
        }
    );
    assert!(evm_hash_lookup_is_confirmed(
        0,
        &decode_evm_hash_lookup_result(ULN_VERSION_READ_V1002, read_result).unwrap()
    ));
    assert!(!evm_hash_lookup_is_confirmed(
        0,
        &decode_evm_hash_lookup_result(
            ULN_VERSION_READ_V1002,
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        )
        .unwrap()
    ));

    assert_eq!(
        decode_evm_verification_state(
            ULN_VERSION_V302,
            &format!("0x{}", hex::encode(solidity_uint256(2)))
        )
        .unwrap(),
        EvmVerificationState::Verified
    );
    assert_eq!(
        decode_evm_verification_state(
            ULN_VERSION_READ_V1002,
            &format!("0x{}", hex::encode(solidity_uint256(4)))
        )
        .unwrap(),
        EvmVerificationState::Reorged
    );
}

#[test]
fn evm_uln_config_confirmations_decoder_handles_dynamic_tuple_offset() {
    let result = format!(
        "0x{}{}{}{}{}{}{}{}",
        hex::encode(solidity_uint256(32)),
        hex::encode(solidity_uint256(64)),
        hex::encode(solidity_uint256(1)),
        hex::encode(solidity_uint256(2)),
        hex::encode(solidity_uint256(1)),
        hex::encode(solidity_uint256(192)),
        hex::encode(solidity_uint256(256)),
        hex::encode(solidity_uint256(0)),
    );
    assert_eq!(decode_evm_uln_config_confirmations(&result).unwrap(), 64);
    assert_eq!(
        decode_evm_uln_config_confirmations(&format!("0x{}", hex::encode(solidity_uint256(7))))
            .unwrap(),
        7
    );
}

#[tokio::test]
async fn evm_payload_builder_builds_v3_dvn_result_from_event_proof() {
    let result = evm_payload_builder()
        .build_uln_v3_verify_payload(&evm_sent_event(), 64, 1_900_000_000, "9".to_string(), None)
        .await
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x2222222222222222222222222222222222222222"
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "verify");
    assert_eq!(result.details["ulnCallData"]["blockConfirmation"], 64);
    assert_eq!(
        result.details["ulnCallData"]["proof"]["payloadHash"],
        "0x08eed9e984b654cded42042a70953b0e5c143f47cb44b60296d86f5345656887"
    );
    assert_eq!(result.details["proof"]["payload"], "0xdeadbeef");
    assert!(result.hash_call_data.starts_with("0x"));
    assert_eq!(result.hash_call_data.len(), 66);
}

#[tokio::test]
async fn evm_v302_builder_matches_upstream_base_route_corpus() {
    let fixtures = [
        EvmFixture {
            src_eid: 30_101,
            src_chain_name: "ethereum",
            dst_eid: 30_184,
            dst_chain_name: "base",
            sender: "0x5555555555555555555555555555555555555555",
            receiver: "0x6666666666666666666666666666666666666666",
            nonce: 1,
            message: "0x",
            block_confirmation: 10,
            expiration: 1_781_082_000,
            guid: "0x564d6f7b7af13684c0a0e5c6be90f27d92fea817f9469ca742e5e69e55c73b3c",
            v_id: "184",
            expected_hash: "0x754e00c4e8c2e841de9599a14a18554ef748169aab9f64241f36319afa99948f",
            expected_target: "0xc70ab6f32772f59fbfc23889caf4ba3376c84baf",
        },
        EvmFixture {
            src_eid: 30_184,
            src_chain_name: "base",
            dst_eid: 30_101,
            dst_chain_name: "ethereum",
            sender: "0x7777777777777777777777777777777777777777",
            receiver: "0x8888888888888888888888888888888888888888",
            nonce: 101,
            message: "0xa1b2c3d4",
            block_confirmation: 32,
            expiration: 1_781_082_000,
            guid: "0xfd9ab947aa82cf0c219437babf411223296316cbb130f835d839bde8b0218bc9",
            v_id: "101",
            expected_hash: "0xbed70a115f8d9237e15329532b634d9fc8f0edee2ccbd0214b47364106f3a504",
            expected_target: "0xc02ab410f0734efa3f14628780e6e695156024c2",
        },
    ];
    let builder = evm_corpus_payload_builder();

    for fixture in fixtures {
        let result = builder
            .build_uln_v3_verify_payload(
                &evm_sent_event_from_fixture(&fixture),
                fixture.block_confirmation,
                fixture.expiration,
                fixture.v_id.to_string(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(result.hash_call_data, fixture.expected_hash);
        assert!(result.details["dvnCallData"]["targetContract"]
            .as_str()
            .unwrap()
            .eq_ignore_ascii_case(fixture.expected_target));
    }
}

#[tokio::test]
async fn evm_payload_builder_builds_read_dvn_result_with_read_target() {
    let mut sent_event = evm_sent_event();
    sent_event.lz_message_id.uln_send_version = Value::from(ULN_VERSION_READ_V1002);
    let result = evm_payload_builder()
        .build_uln_read_v1_verify_payload(
            &sent_event,
            "0x1234".to_string(),
            1_900_000_000,
            "9".to_string(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        result.details["dvnCallData"]["targetContract"],
        "0x3333333333333333333333333333333333333333"
    );
    assert_eq!(result.details["ulnCallData"]["methodName"], "verify");
    assert_eq!(result.details["proof"]["resolvedPayload"], "0x1234");
    assert_eq!(
        result.details["ulnCallData"]["resolvedPayloadHash"],
        "0xf88abc595e28aef608f02e2cb392ee165d48839a586a039288a41fb611bfb7db"
    );
}

/// `ChannelId` in `@layerzerolabs/lz-definitions@3.1.2` (`dist/index.d.ts:2982-2994`)
/// declares exactly ten read channels, 4_294_967_295 down to 4_294_967_286. Upstream
/// tests membership with `Object.values(ChannelId).includes(Number(endpointId))`
/// (TS: `packages/common-model/src/utils/index.ts:38-40`), so the boundaries below are
/// the whole contract: one past either end is an ordinary chain endpoint.
#[test]
fn read_channel_endpoint_ids_match_ts_channel_id_enum() {
    assert!(is_lz_read_endpoint_id(4_294_967_295));
    assert!(is_lz_read_endpoint_id(4_294_967_286));
    assert!(!is_lz_read_endpoint_id(4_294_967_285));
    assert!(!is_lz_read_endpoint_id(30_101));
    assert!(!is_lz_read_endpoint_id(0));
}

fn packet_with_src_eid(src_eid: u32) -> LzPacketV1 {
    LzPacketV1 {
        nonce: 7,
        src_eid,
        sender: "0x1111111111111111111111111111111111111111".to_string(),
        dst_eid: 30_101,
        receiver: "0x2222222222222222222222222222222222222222".to_string(),
        guid: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        message: "0xdeadbeef".to_string(),
    }
}

fn keccak_hex(parts: &[&str]) -> String {
    let mut pre_image = Vec::new();
    for part in parts {
        pre_image.extend_from_slice(&decode_hex_bytes(part).expect("hex part"));
    }
    format!("0x{}", hex::encode(Keccak256::digest(&pre_image)))
}

/// Upstream: `isLzReadEndpointId(srcEid) ? keccak256(codec.message()) : codec.payloadHash()`
/// (TS: `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:68-72`). A read source hashes
/// the message alone, so the guid is excluded from the signed payload hash.
#[test]
fn read_channel_source_hashes_the_message_alone_like_typescript() {
    let proof = compute_lz_packet_v1_proof(&packet_with_src_eid(4_294_967_295)).expect("proof");
    assert_eq!(proof.payload_hash, keccak_hex(&["0xdeadbeef"]));
}

/// The non-read arm of the same upstream expression: `codec.payloadHash()` is
/// `keccak(guid || message)`.
#[test]
fn non_read_source_hashes_guid_and_message_like_typescript() {
    let proof = compute_lz_packet_v1_proof(&packet_with_src_eid(30_101)).expect("proof");
    assert_eq!(
        proof.payload_hash,
        keccak_hex(&[
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0xdeadbeef",
        ])
    );
}

/// The two proof fields are the only chain-derived inputs to the signed ULN call data,
/// so a caller must never be able to supply them. `LzSentEvent.extra` accepts unknown
/// keys, and an earlier revision short-circuited to `extra.packetHeader` /
/// `extra.payloadHash` when both were present. Upstream never does this:
/// `computeLZMessageV2Proof` always re-encodes
/// (TS: `packages/sdks/lz-v2-sdk/src/utils/common/index.ts:63-78`).
#[test]
fn proof_ignores_a_precomputed_proof_supplied_in_the_event_extra() {
    let derived = compute_lz_packet_v1_proof_from_event(&evm_sent_event()).expect("derived proof");

    let mut event = evm_sent_event();
    event.extra.insert(
        "packetHeader".to_string(),
        Value::from("0xdeadbeefdeadbeef"),
    );
    event.extra.insert(
        "payloadHash".to_string(),
        Value::from("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    );

    let observed = compute_lz_packet_v1_proof_from_event(&event).expect("proof");
    assert_eq!(observed.packet_header, derived.packet_header);
    assert_eq!(observed.payload_hash, derived.payload_hash);
    assert_ne!(observed.packet_header, "0xdeadbeefdeadbeef");
}
