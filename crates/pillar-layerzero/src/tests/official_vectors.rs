use std::path::PathBuf;

use super::*;

const OFFICIAL_LAYERZERO_V2_SHA: &str = "9c741e7f9790639537b1710a203bcdfd73b0b9ac";

fn official_vector_hex(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("official_vectors");
    path.push(name);
    let content = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing official LayerZero vector fixture {} for SHA {}: {}",
            path.display(),
            OFFICIAL_LAYERZERO_V2_SHA,
            error
        )
    });
    let hex = content
        .lines()
        .filter_map(|line| line.split('#').next())
        .flat_map(str::split_whitespace)
        .collect::<String>();
    if hex.starts_with("0x") {
        hex
    } else {
        format!("0x{hex}")
    }
}

#[test]
fn official_vectors_read_cmd_codec_v1_request_and_compute_layout_matches_sha_pinned_source() {
    let command_hex = official_vector_hex("read_cmd_codec_v1_request_compute.hex");
    let command = decode_evm_read_command(&command_hex).unwrap();

    assert_eq!(command.global_version, 1);
    assert_eq!(command.app_command_label, "0042");
    assert_eq!(command.requests.len(), 1);
    assert_eq!(
        command.requests[0].request,
        official_vector_hex("read_cmd_codec_v1_request.hex")
    );
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
        command.compute,
        Some(EvmReadCompute {
            target_eid: 30_102,
            marker: ReadTimeMarker::BlockNumber {
                block_number: 12_345
            },
            block_confirmation: 7,
            to: "0x2222222222222222222222222222222222222222".to_string(),
            setting: EvmReadComputeSetting::MapReduce,
        })
    );
}

#[test]
fn official_vectors_receive_uln_verify_call_data_matches_sha_pinned_source() {
    let proof = EvmUlnProof {
        packet_header: official_vector_hex("packet_v1_header.hex"),
        payload_hash: official_vector_hex("packet_v1_payload_hash.hex"),
    };

    assert_eq!(
        build_evm_uln_v3_verify_call_data(&proof, 64).unwrap(),
        official_vector_hex("receive_uln_verify_calldata.hex")
    );
}

#[test]
fn official_vectors_packet_v1_header_and_payload_hash_match_sha_pinned_source() {
    let packet = LzPacketV1 {
        nonce: 7,
        src_eid: 30_101,
        sender: "0x1111111111111111111111111111111111111111".to_string(),
        dst_eid: 30_102,
        receiver: "0x2222222222222222222222222222222222222222".to_string(),
        guid: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        message: "0xdeadbeef".to_string(),
    };
    let proof = compute_lz_packet_v1_proof(&packet).unwrap();

    assert_eq!(
        format!("0x{}", hex::encode(encode_lz_packet_v1(&packet).unwrap())),
        official_vector_hex("packet_v1_encoded.hex")
    );
    assert_eq!(
        proof.packet_header,
        official_vector_hex("packet_v1_header.hex")
    );
    assert_eq!(
        proof.payload_hash,
        official_vector_hex("packet_v1_payload_hash.hex")
    );
}

#[test]
fn official_vectors_read_lib1002_verify_call_data_matches_sha_pinned_source() {
    let proof = EvmUlnProof {
        packet_header: official_vector_hex("packet_v1_header.hex"),
        payload_hash: official_vector_hex("read_cmd_hash.hex"),
    };

    assert_eq!(
        build_evm_uln_read_v1_verify_call_data(
            &proof,
            &official_vector_hex("read_resolved_payload_hash.hex"),
        )
        .unwrap(),
        official_vector_hex("read_lib1002_verify_calldata.hex")
    );
}
