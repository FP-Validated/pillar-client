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
    // The BOC and its representation hash come from the parity fixture: upstream
    // parsed this exact BOC with `@ton/core` and reported both its hash and its
    // re-serialized bytes, so neither constant is this port checking itself.
    // `payload.rs`'s `build_matches_gasolina_for_every_ton_vector` covers the
    // built payloads; these two cover the primitives underneath them.
    fn codec_lock() -> (String, String) {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("gasolina_parity");
        path.push("ton_dvn_verify.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("missing {}: {error}", path.display()));
        let fixture: serde_json::Value = serde_json::from_str(&raw).expect("parses");
        let lock = &fixture["codecLock"];
        assert_eq!(
            lock["boc"], lock["reserializedBoc"],
            "upstream's own round trip must be byte-identical for this to mean anything"
        );
        (
            lock["boc"].as_str().unwrap().to_string(),
            lock["reprHash"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn repr_hash_matches_upstream_for_the_execute_params_cell() {
        let (boc, expected_hash) = codec_lock();
        let cell = boc_from_hex(&boc).expect("parse BOC");
        assert_eq!(repr_hash_hex(&cell).unwrap(), expected_hash);
    }

    #[test]
    fn boc_round_trip_is_byte_identical() {
        let (boc, _) = codec_lock();
        let cell = boc_from_hex(&boc).expect("parse BOC");
        assert_eq!(boc_to_hex(&cell).unwrap(), boc);
    }
}
