//! Standard TON cell primitives, adapted from `ton_core` behind a thin interface.
//!
//! This module centralizes the higher-level `ton_core` operations —
//! representation hashing, BOC (de)serialization, StateInit address derivation —
//! that the LayerZero-specific `clDeclare` encoding builds on. The sibling
//! modules (`cl_declare`, `builders`, `address`) also use `ton_core`'s
//! `CellBuilder`/`CellParser`/`TonAddress` directly, so replacing `ton_core`
//! would touch those too — this file just keeps the cross-cutting conversions
//! in one place.

use base64::Engine;
use pillar_core::AppCoreError;
use std::panic::{catch_unwind, AssertUnwindSafe};
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
    let bytes = hex::decode(hex.trim_start_matches("0x")).map_err(map_err)?;
    boc_from_bytes(bytes)
}

/// Parse a single-root BOC from a base64 string (toncenter `data` field).
pub fn boc_from_base64(data: &str) -> Result<TonCell, AppCoreError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(map_err)?;
    boc_from_bytes(bytes)
}

pub fn boc_from_bytes(bytes: Vec<u8>) -> Result<TonCell, AppCoreError> {
    if !boc_header_is_safe(&bytes) {
        return Err(map_err("invalid BOC header"));
    }
    catch_unwind(AssertUnwindSafe(|| {
        BoC::from_bytes(std::sync::Arc::new(bytes))
            .map_err(map_err)?
            .single_root()
            .map_err(map_err)
    }))
    .unwrap_or_else(|_| Err(map_err("BOC parser panicked")))
}

fn boc_header_is_safe(bytes: &[u8]) -> bool {
    if bytes.len() < 10 || bytes[..4] != [0xb5, 0xee, 0x9c, 0x72] {
        return false;
    }
    let flags = bytes[4];
    let has_idx = flags & 0x80 != 0;
    let has_crc32c = flags & 0x40 != 0;
    let size_bytes = (flags & 7) as usize;
    let offset_bytes = bytes[5] as usize;
    if size_bytes == 0 || size_bytes > 4 || offset_bytes == 0 || offset_bytes > 8 {
        return false;
    }
    let mut cursor = 6;
    let Some(cells) = read_boc_uint(bytes, &mut cursor, size_bytes) else {
        return false;
    };
    let Some(roots) = read_boc_uint(bytes, &mut cursor, size_bytes) else {
        return false;
    };
    let Some(absent) = read_boc_uint(bytes, &mut cursor, size_bytes) else {
        return false;
    };
    let Some(data_size) = read_boc_uint(bytes, &mut cursor, offset_bytes) else {
        return false;
    };
    if cells == 0
        || cells > data_size / 2
        || roots == 0
        || roots.checked_add(absent).is_none_or(|n| n > cells)
    {
        return false;
    }
    for _ in 0..roots {
        let Some(root) = read_boc_uint(bytes, &mut cursor, size_bytes) else {
            return false;
        };
        if root >= cells {
            return false;
        }
    }
    let index_size = if has_idx {
        let Some(size) = cells.checked_mul(offset_bytes) else {
            return false;
        };
        size
    } else {
        0
    };
    let Some(data_start) = cursor.checked_add(index_size) else {
        return false;
    };
    let Some(data_end) = data_start.checked_add(data_size) else {
        return false;
    };
    let crc_size = if has_crc32c { 4 } else { 0 };
    data_end
        .checked_add(crc_size)
        .is_some_and(|end| end <= bytes.len())
}

fn read_boc_uint(bytes: &[u8], cursor: &mut usize, width: usize) -> Option<usize> {
    let end = cursor.checked_add(width)?;
    let value = bytes
        .get(*cursor..end)?
        .iter()
        .try_fold(0usize, |n, byte| {
            n.checked_mul(256)?.checked_add(usize::from(*byte))
        })?;
    *cursor = end;
    Some(value)
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
    #[test]
    fn malformed_boc_indices_do_not_panic() {
        let root_index = [0xb5, 0xee, 0x9c, 0x72, 1, 1, 1, 1, 0, 2, 5, 0, 0];
        let has_index_overflow = [
            0xb5, 0xee, 0x9c, 0x72, 0x84, 8, 0x20, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0,
        ];
        for boc in [&root_index[..], &has_index_overflow[..]] {
            let result = catch_unwind(AssertUnwindSafe(|| boc_from_bytes(boc.to_vec())));
            assert!(
                result.is_ok_and(|parsed| parsed.is_err()),
                "malformed BOC must fail without unwinding"
            );
        }
    }
}
