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
    use super::super::cell::{boc_from_hex, boc_to_hex, repr_hash_hex};
    use super::super::cl_declare::cl_get_uint_be;
    use super::*;

    const ULN_CALL_DATA_BOC: &str = "b5ee9c724101030100dc000197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0ac9e984a38af418a0481fd5fe59f44be3e53ad657c9d296f40be4fddaec930201016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000001e0200a700000000417474657374815ed897bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8561f69eed245ee440b8e885dc3d2c3cf862d6dd7edec8ec57fa2a6e9ae0db40000000000000010207a1486a";
    const DVN_CALL_DATA_BOC: &str = "b5ee9c72410204010001570001ef65786563506172616d73815ee4ffc625ed4a7b82befffffffffffffffffffffffffffffffffffffffffffffccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc00000001c4fecc02652abd38461e7f7e3139969b96902727f10fbc612990b3ad243f4a6c8e3e6724f9a7973e010197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0ac9e984a38af418a0481fd5fe59f44be3e53ad657c9d296f40be4fddaec930202016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000001e0300a700000000417474657374815ed897bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8561f69eed245ee440b8e885dc3d2c3cf862d6dd7edec8ec57fa2a6e9ae0db4000000000000001021da1ae04";
    const DVN_CALL_DATA_HASH: &str =
        "ed48fa88b46b0044f359a8ee91c5e12772bf731eb09ce22837f6a7965fa0607d";
    const PACKET_HASH: &str = "e1587da7bb4917b9102e3a21770f4b0f3e18b5b75fb7b23b15fe8a9ba6b836d0";
    const TARGET: &str = "11879fdf8c4e65a6e5a409c9fc43ef184a642ceb490fd29b238f99c93e69e5cf";
    const NONCE: u64 = 7;
    const CONFIRMATIONS: i64 = 64;
    const EXPIRATION: i64 = 1_900_000_000;

    fn to_32(hex: &str) -> [u8; 32] {
        let bytes = hex::decode(hex.trim_start_matches("0x")).unwrap();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    #[test]
    fn uln_call_data_matches_recorded_vector() {
        // Extract the opaque UlnConnection address embedded in the recorded vector
        // (md::MdAddress field 1) and rebuild from semantic inputs.
        let golden = boc_from_hex(ULN_CALL_DATA_BOC).unwrap();
        let uln_conn_addr: [u8; 32] = cl_get_uint_be(&golden, 1, 256).unwrap().try_into().unwrap();

        let rebuilt =
            build_uln_call_data(&uln_conn_addr, NONCE, CONFIRMATIONS, &to_32(PACKET_HASH)).unwrap();
        assert_eq!(boc_to_hex(&rebuilt).unwrap(), ULN_CALL_DATA_BOC);
    }

    #[test]
    fn dvn_call_data_matches_recorded_vector() {
        let golden_uln = boc_from_hex(ULN_CALL_DATA_BOC).unwrap();
        let uln_conn_addr: [u8; 32] = cl_get_uint_be(&golden_uln, 1, 256)
            .unwrap()
            .try_into()
            .unwrap();
        let golden_dvn = boc_from_hex(DVN_CALL_DATA_BOC).unwrap();
        // Opaque, on-chain / derivation-supplied inputs, extracted from the vector:
        // field 0 = target (dvnAddressImplementation), field 4 = forwardingAddress (uln.address).
        let target: [u8; 32] = cl_get_uint_be(&golden_dvn, 0, 256)
            .unwrap()
            .try_into()
            .unwrap();
        let uln_addr: [u8; 32] = cl_get_uint_be(&golden_dvn, 4, 256)
            .unwrap()
            .try_into()
            .unwrap();
        // forwardingAddress equals the details targetContract (0x11879fdf... = uln.address).
        assert_eq!(hex::encode(uln_addr), TARGET);
        // Semantic fields must decode to the known values.
        let exp = u64::from_be_bytes(
            cl_get_uint_be(&golden_dvn, 2, 64)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let op = u32::from_be_bytes(
            cl_get_uint_be(&golden_dvn, 3, 32)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(exp, EXPIRATION as u64);
        assert_eq!(op as u64, OP_ULN_VERIFY);

        let uln_call_data =
            build_uln_call_data(&uln_conn_addr, NONCE, CONFIRMATIONS, &to_32(PACKET_HASH)).unwrap();
        let dvn =
            build_execute_params(&target, uln_call_data, EXPIRATION, OP_ULN_VERIFY, &uln_addr)
                .unwrap();

        assert_eq!(boc_to_hex(&dvn).unwrap(), DVN_CALL_DATA_BOC);
        assert_eq!(repr_hash_hex(&dvn).unwrap(), DVN_CALL_DATA_HASH);
    }

    #[test]
    fn hex_to_cells_single_chunk_round_trips() {
        // 32-bit payload fits one cell with no refs.
        let cell = hex_to_cells("0xdeadbeef").unwrap();
        assert_eq!(cell.refs().len(), 0);
        assert_eq!(cell.data_len_bits(), 32);
    }
}
