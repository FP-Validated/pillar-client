//! Standard TON cell primitives, adapted from `ton_core` behind a thin interface.
//!
//! This module centralizes the higher-level `ton_core` operations —
//! representation hashing, BOC (de)serialization, StateInit address derivation —
//! that the LayerZero-specific `clDeclare` encoding builds on. The sibling
//! modules (`cl_declare`, `builders`, `address`) also use `ton_core`'s
//! `CellBuilder`/`CellParser`/`TonAddress` directly, so replacing `ton_core`
//! would touch those too — this file just keeps the cross-cutting conversions
//! in one place.

use pillar_core::AppCoreError;
use ton_core::cell::{BoC, CellBuilder, TonCell};
use ton_core::types::TonAddress;

pub fn builder() -> CellBuilder {
    TonCell::builder()
}

pub fn map_err(err: impl std::fmt::Display) -> AppCoreError {
    AppCoreError::Internal(format!("TON cell error: {err}"))
}

pub fn build(builder: CellBuilder) -> Result<TonCell, AppCoreError> {
    builder.build().map_err(map_err)
}

pub fn boc_from_hex(hex: &str) -> Result<TonCell, AppCoreError> {
    BoC::from_hex(hex.trim_start_matches("0x"))
        .map_err(map_err)?
        .single_root()
        .map_err(map_err)
}

/// Parse a single-root BOC from a base64 string (toncenter `data` field).
pub fn boc_from_base64(data: &str) -> Result<TonCell, AppCoreError> {
    BoC::from_base64(data)
        .map_err(map_err)?
        .single_root()
        .map_err(map_err)
}

/// Serialize a cell to a BOC hex string (with CRC32C, `b5ee9c72` magic) as the
/// TypeScript `Cell.toBoc().toString('hex')` does.
pub fn boc_to_hex(cell: &TonCell) -> Result<String, AppCoreError> {
    BoC::new(cell.clone()).to_hex(true).map_err(map_err)
}

/// Serialize a cell to a BOC base64 string, as the TypeScript
/// `cell.toBoc().toString('base64')` does for `runGetMethod` `tvm.Cell` stack
/// arguments (`serializeStack`, TS:
/// `packages/common-ton/src/TonV2Wrapper.ts:44-70`).
pub fn boc_to_base64(cell: &TonCell) -> Result<String, AppCoreError> {
    BoC::new(cell.clone()).to_base64(true).map_err(map_err)
}

/// Representation hash of a cell as a lowercase hex string (no `0x`), matching
/// the TypeScript `Cell.hash().toString('hex')`.
pub fn repr_hash_hex(cell: &TonCell) -> Result<String, AppCoreError> {
    Ok(cell.hash().map_err(map_err)?.to_hex())
}

/// Derive the standard TON address of a contract from its StateInit
/// (`split_depth`/`special` absent, `code` and `data` present, empty library),
/// matching `@ton/ton` `contractAddress(workchain, { code, data })`.
pub fn state_init_address(
    workchain: i32,
    code: &TonCell,
    data: &TonCell,
) -> Result<TonAddress, AppCoreError> {
    let mut b = builder();
    // Maybe split_depth = 0, Maybe special = 0, Maybe code = 1, Maybe data = 1, library HashmapE = 0
    b.write_bit(false).map_err(map_err)?;
    b.write_bit(false).map_err(map_err)?;
    b.write_bit(true).map_err(map_err)?;
    b.write_ref(code.clone()).map_err(map_err)?;
    b.write_bit(true).map_err(map_err)?;
    b.write_ref(data.clone()).map_err(map_err)?;
    b.write_bit(false).map_err(map_err)?;
    let state_init = build(b)?;
    let hash = state_init.hash().map_err(map_err)?.clone();
    Ok(TonAddress::new(workchain, hash))
}
#[cfg(test)]
mod tests {
    use super::*;

    // Recorded `md::ExecuteParams` fixture for the DVN verify path, pinning this
    // crate's BOC codec: the hex is the cell upstream signs over and the hash is
    // that cell's representation hash.
    //
    // Upstream shape — TS: `buildULNV3VerifyPayload` at
    // `apps/gasolina/src/app/sdks/gasolinaSdk/ton/index.ts:97`, which returns
    // `dvnVerifyCallData.hash().toString('hex')` as `hashCallData` (`:162`) and
    // `dvnVerifyCallData.toBoc().toString('hex')` as
    // `details.dvnHashCallData.dvnCallData` (`:165`). The cell is built by
    // `packages/contracts/lz-ton-contracts/src/dvn.ts:25-31`
    // (`lzEncodeClass('md::ExecuteParams', { opcode: Uln_OP_ULN_VERIFY,
    // forwardingAddress: uln.address, callData: ulnCallData, expiration,
    // target: dvnAddressImplementation })`), encoder at
    // `packages/contracts/lz-ton-contracts/src/classes/index.ts:103`.
    //
    // Evidence limit: neither constant has a source-backed reproduction. The
    // corpus entry `ton-uln-v3-boc-dvn-verify-cell` carries `upstreamBehavior`
    // only — not the `sourceBackedExpected` block that
    // `solana-uln-v3-execute-transaction-digest` has — and the upstream fixture
    // extractor covers sui/starknet/solana. These tests therefore lock the codec
    // against a recorded value; they do not prove byte parity with a TS run.
    const DVN_CALL_DATA_BOC: &str = "b5ee9c72410204010001570001ef65786563506172616d73815ee4ffc625ed4a7b82befffffffffffffffffffffffffffffffffffffffffffffccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc00000001c4fecc02652abd38461e7f7e3139969b96902727f10fbc612990b3ad243f4a6c8e3e6724f9a7973e010197000000004d644164647293ff2057bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0ac9e984a38af418a0481fd5fe59f44be3e53ad657c9d296f40be4fddaec930202016700556c6e566572696679615ee4ffcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000001e0300a700000000417474657374815ed897bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8561f69eed245ee440b8e885dc3d2c3cf862d6dd7edec8ec57fa2a6e9ae0db4000000000000001021da1ae04";
    const DVN_CALL_DATA_HASH: &str =
        "ed48fa88b46b0044f359a8ee91c5e12772bf731eb09ce22837f6a7965fa0607d";

    #[test]
    fn repr_hash_matches_recorded_execute_params_cell() {
        let cell = boc_from_hex(DVN_CALL_DATA_BOC).expect("parse recorded BOC");
        assert_eq!(repr_hash_hex(&cell).unwrap(), DVN_CALL_DATA_HASH);
    }

    #[test]
    fn boc_round_trip_is_byte_identical() {
        let cell = boc_from_hex(DVN_CALL_DATA_BOC).expect("parse recorded BOC");
        assert_eq!(boc_to_hex(&cell).unwrap(), DVN_CALL_DATA_BOC);
    }
}
