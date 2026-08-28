//! LayerZero TON class builders for the DVN verify path, ported from
//! the upstream LayerZero TypeScript implementation.
//!
//! Each function assembles one class cell via [`cl_declare`], with fields in
//! schema-index order, from the pinned `@layerzerolabs/lz-ton-sdk-v2`
//! `tonResolvedObjects` schema.

use ton_core::cell::TonCell;

use super::cell::{build, builder, map_err};
use super::cl_declare::{cl_declare, ClField, T_UINT256, T_UINT32, T_UINT64};
use pillar_core::AppCoreError;

/// `Uln_OP_ULN_VERIFY` opcode (from `OPCODES`; cross-checked against the
/// recorded vector's `methodName`).
pub const OP_ULN_VERIFY: u64 = 2_571_808_590;

/// Convert a signed count/timestamp to `u64`, rejecting negatives (the TS
/// `BigInt(...)` throws on negative inputs rather than taking the absolute value).
fn require_nonneg(value: i64, field: &str) -> Result<u64, AppCoreError> {
    u64::try_from(value).map_err(|_| {
        AppCoreError::Internal(format!("TON {field} must be non-negative, got {value}"))
    })
}

/// `hexToCells`: encode an arbitrary-length hex payload into a chain of cells,
/// each holding up to 1023 bits, the first cell being the root.
pub fn hex_to_cells(hex: &str) -> Result<TonCell, AppCoreError> {
    let body = hex.strip_prefix("0x").unwrap_or(hex);
    let total_bits = body.len() * 4;
    if total_bits == 0 {
        return build(builder());
    }
    let bytes = hex::decode(body)
        .map_err(|e| AppCoreError::Internal(format!("TON message hex decode: {e}")))?;

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut offset = 0;
    while offset < total_bits {
        let bits = std::cmp::min(1023, total_bits - offset);
        spans.push((offset, bits));
        offset += 1023;
    }

    let mut acc: Option<TonCell> = None;
    for (bit_offset, bits) in spans.into_iter().rev() {
        let mut b = builder();
        b.write_bits_with_offset(&bytes, bit_offset, bits)
            .map_err(map_err)?;
        if let Some(child) = acc.take() {
            b.write_ref(child).map_err(map_err)?;
        }
        acc = Some(build(b)?);
    }
    Ok(acc.expect("at least one cell"))
}

/// `lz::Attestation { hash, confirmations }`.
pub fn build_attestation(hash_be: &[u8; 32], confirmations: i64) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "Attest",
        vec![
            ClField::u256_be(T_UINT256, hash_be),
            ClField::uint(T_UINT64, require_nonneg(confirmations, "confirmations")?),
        ],
    )
}

/// `md::UlnVerification { nonce, attestation }`.
pub fn build_uln_verification(nonce: u64, attestation: TonCell) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "UlnVerify",
        vec![ClField::uint(T_UINT64, nonce), ClField::Ref(attestation)],
    )
}

/// `md::MdAddress { md, address }`.
pub fn build_md_address(md: TonCell, address_be: &[u8; 32]) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "MdAddr",
        vec![ClField::Ref(md), ClField::u256_be(T_UINT256, address_be)],
    )
}

/// `buildULNCallData`: `md::MdAddress` wrapping `md::UlnVerification` /
/// `lz::Attestation`, using the UlnConnection address and the packet hash.
pub fn build_uln_call_data(
    uln_connection_address_be: &[u8; 32],
    nonce: u64,
    block_confirmation: i64,
    packet_hash_be: &[u8; 32],
) -> Result<TonCell, AppCoreError> {
    let attestation = build_attestation(packet_hash_be, block_confirmation)?;
    let uln_verification = build_uln_verification(nonce, attestation)?;
    build_md_address(uln_verification, uln_connection_address_be)
}

/// `lz::Path { srcEid, srcOApp, dstEid, dstOApp }`.
pub fn build_lz_path(
    src_eid: u32,
    src_oapp_be: &[u8; 32],
    dst_eid: u32,
    dst_oapp_be: &[u8; 32],
) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "path",
        vec![
            ClField::uint(T_UINT32, src_eid),
            ClField::u256_be(T_UINT256, src_oapp_be),
            ClField::uint(T_UINT32, dst_eid),
            ClField::u256_be(T_UINT256, dst_oapp_be),
        ],
    )
}

/// `lz::Packet { path, message, nonce, guid }`.
pub fn build_lz_packet(
    path: TonCell,
    message_hex: &str,
    nonce: u64,
    guid_be: &[u8; 32],
) -> Result<TonCell, AppCoreError> {
    let message = hex_to_cells(message_hex)?;
    cl_declare(
        "Packet",
        vec![
            ClField::Ref(path),
            ClField::Ref(message),
            ClField::uint(T_UINT64, nonce),
            ClField::u256_be(T_UINT256, guid_be),
        ],
    )
}

/// `md::ExecuteParams { target, callData, expiration, opcode, forwardingAddress }`.
pub fn build_execute_params(
    target_be: &[u8; 32],
    call_data: TonCell,
    expiration: i64,
    opcode: u64,
    forwarding_address_be: &[u8; 32],
) -> Result<TonCell, AppCoreError> {
    cl_declare(
        "execParams",
        vec![
            ClField::u256_be(T_UINT256, target_be),
            ClField::Ref(call_data),
            ClField::uint(T_UINT64, require_nonneg(expiration, "expiration")?),
            ClField::uint(T_UINT32, opcode),
            ClField::u256_be(T_UINT256, forwarding_address_be),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::super::cell::{boc_to_hex, repr_hash_hex};
    use super::*;

    fn to_32(hex: &str) -> [u8; 32] {
        let bytes = hex::decode(hex.trim_start_matches("0x")).unwrap();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    fn ton_vectors() -> Vec<serde_json::Value> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("gasolina_parity");
        path.push("ton_dvn_verify.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("missing {}: {error}", path.display()));
        let fixture: serde_json::Value = serde_json::from_str(&raw).expect("parses");
        fixture["vectors"].as_array().expect("vectors").clone()
    }

    /// The two cell encoders, checked one level below `build_ton_dvn_verify`: the
    /// opaque addresses and the packet hash are supplied rather than derived, so a
    /// failure here is the encoder rather than the address derivation. Every
    /// expected value is upstream's, taken from the same parity fixture
    /// `payload.rs` uses.
    #[test]
    fn uln_and_execute_params_encoders_match_upstream_from_semantic_inputs() {
        for vector in ton_vectors() {
            let id = vector["id"].as_str().unwrap();
            let input = &vector["input"];
            let nonce = input["nonce"].as_u64().unwrap();
            let confirmations = input["blockConfirmation"].as_i64().unwrap();
            let expiration = input["expiration"].as_i64().unwrap();

            let uln_call_data = build_uln_call_data(
                &to_32(vector["ulnConnectionAddress"].as_str().unwrap()),
                nonce,
                confirmations,
                &to_32(vector["packetHash"].as_str().unwrap()),
            )
            .unwrap();
            assert_eq!(
                boc_to_hex(&uln_call_data).unwrap(),
                vector["ulnCallDataBoc"].as_str().unwrap(),
                "{id}: md::MdAddress"
            );

            let dvn = build_execute_params(
                &to_32(
                    input["dvnImplementation"]
                        .as_str()
                        .unwrap()
                        .split(':')
                        .nth(1)
                        .unwrap(),
                ),
                uln_call_data,
                expiration,
                OP_ULN_VERIFY,
                &to_32(vector["targetContract"].as_str().unwrap()),
            )
            .unwrap();
            assert_eq!(
                boc_to_hex(&dvn).unwrap(),
                vector["dvnCallDataBoc"].as_str().unwrap(),
                "{id}: md::ExecuteParams"
            );
            assert_eq!(
                repr_hash_hex(&dvn).unwrap(),
                vector["hashCallData"].as_str().unwrap(),
                "{id}: signed hash"
            );
        }
    }

    #[test]
    fn hex_to_cells_single_chunk_round_trips() {
        // 32-bit payload fits one cell with no refs.
        let cell = hex_to_cells("0xdeadbeef").unwrap();
        assert_eq!(cell.refs().len(), 0);
        assert_eq!(cell.data_len_bits(), 32);
    }
}
