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
use ton_core::cell::{BoC, CellBuilder, CellType, TonCell, TonHash};
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
    boc_from_bytes_with_limits(bytes, MAX_MESSAGE_CELLS, true)
}

pub fn boc_from_base64_with_limits(
    data: &str,
    max_cells: usize,
    reject_exotic: bool,
) -> Result<TonCell, AppCoreError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(map_err)?;
    boc_from_bytes_with_limits(bytes, max_cells, reject_exotic)
}

pub fn boc_from_bytes_with_limits(
    bytes: Vec<u8>,
    max_cells: usize,
    reject_exotic: bool,
) -> Result<TonCell, AppCoreError> {
    if !boc_header_is_safe(&bytes, max_cells) {
        return Err(map_err("invalid BOC header"));
    }
    if boc_max_depth(&bytes).is_none_or(|depth| depth > MAX_CELL_DEPTH) {
        return Err(map_err("TON cell depth exceeds protocol limit"));
    }
    catch_unwind(AssertUnwindSafe(|| {
        let root = BoC::from_bytes(std::sync::Arc::new(bytes))
            .map_err(map_err)?
            .single_root()
            .map_err(map_err)?;
        root.hash().map_err(map_err)?;
        root.depth().map_err(map_err)?;
        let mut cells = vec![root.clone()];
        let mut visited = std::collections::HashSet::new();
        while let Some(cell) = cells.pop() {
            if reject_exotic
                && (cell.cell_type() != CellType::Ordinary || cell.level_mask().mask() != 0)
            {
                return Err(map_err("exotic TON cells are not supported"));
            }
            let refs = cell.refs();
            // Refs are inline in each Arc-backed cell; their address identifies the node.
            if refs.is_empty() || !visited.insert(refs.as_ptr() as usize) {
                continue;
            }
            cells.extend(refs.iter().cloned());
        }
        Ok(root)
    }))
    .unwrap_or_else(|_| Err(map_err("BOC parser panicked")))
}

pub const MAX_MESSAGE_CELLS: usize = 1 << 13;
pub const MAX_ACCOUNT_STATE_CELLS: usize = 1 << 16;
pub const MAX_CELL_DEPTH: usize = 1024;

fn boc_header_is_safe(bytes: &[u8], max_cells: usize) -> bool {
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
        || cells > max_cells
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
// Bound every declared cell, reachable or not, before constructing TonCells: the parser
// builds and drops all of them, so one deep unreachable chain would recurse on drop.
fn boc_max_depth(bytes: &[u8]) -> Option<usize> {
    let flags = *bytes.get(4)?;
    let has_idx = flags & 0x80 != 0;
    let size_bytes = usize::from(flags & 7);
    let offset_bytes = usize::from(*bytes.get(5)?);
    let mut cursor = 6;
    let cells = read_boc_uint(bytes, &mut cursor, size_bytes)?;
    let roots = read_boc_uint(bytes, &mut cursor, size_bytes)?;
    read_boc_uint(bytes, &mut cursor, size_bytes)?;
    let data_size = read_boc_uint(bytes, &mut cursor, offset_bytes)?;
    if roots != 1 {
        return None;
    }
    let root = read_boc_uint(bytes, &mut cursor, size_bytes)?;
    if root >= cells {
        return None;
    }
    let index_size = if has_idx {
        cells.checked_mul(offset_bytes)?
    } else {
        0
    };
    cursor = cursor.checked_add(index_size)?;
    let data_end = cursor.checked_add(data_size)?;
    if data_end > bytes.len() {
        return None;
    }
    let mut refs_by_cell = Vec::with_capacity(cells);
    for index in 0..cells {
        let d1 = *bytes.get(cursor)?;
        let d2 = *bytes.get(cursor + 1)?;
        cursor += 2;
        if d1 & 0x10 != 0 {
            let hash_count = (d1 >> 5).count_ones() as usize + 1;
            cursor = cursor.checked_add(hash_count * (32 + 2))?;
        }
        cursor = cursor.checked_add(usize::from(d2 / 2 + d2 % 2))?;
        let refs_count = usize::from(d1 & 7);
        let mut refs = Vec::with_capacity(refs_count);
        for _ in 0..refs_count {
            let reference = read_boc_uint(bytes, &mut cursor, size_bytes)?;
            if reference <= index || reference >= cells {
                return None;
            }
            refs.push(reference);
        }
        refs_by_cell.push(refs);
    }
    if cursor != data_end {
        return None;
    }
    let mut depths = vec![0usize; cells];
    for index in (0..cells).rev() {
        for &reference in &refs_by_cell[index] {
            depths[index] = depths[index].max(depths[reference].checked_add(1)?);
        }
    }
    depths.into_iter().max()
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
    Ok(hex::encode(serialize_boc(cell)?))
}

/// Serialize a cell to a BOC base64 string, as the TypeScript
/// `cell.toBoc().toString('base64')` does for `runGetMethod` `tvm.Cell` stack
/// arguments (`serializeStack`, TS:
/// `packages/common-ton/src/TonV2Wrapper.ts:44-70`).
pub fn boc_to_base64(cell: &TonCell) -> Result<String, AppCoreError> {
    Ok(base64::engine::general_purpose::STANDARD.encode(serialize_boc(cell)?))
}

/// `@ton/core` `serializeBoc(root, { idx: false, crc32: true })`, cell order included.
/// `ton_core` orders shared cells by `HashMap` iteration, so its bytes varied between runs.
fn serialize_boc(root: &TonCell) -> Result<Vec<u8>, AppCoreError> {
    // `topologicalSort`: unique cells in breadth-first order, by representation hash.
    let mut cells: Vec<&TonCell> = Vec::new();
    let mut id_by_hash: std::collections::HashMap<TonHash, usize> =
        std::collections::HashMap::new();
    let mut level = vec![root];
    while !level.is_empty() {
        let mut next = Vec::new();
        for cell in level {
            let hash = *cell.hash().map_err(map_err)?;
            if id_by_hash.contains_key(&hash) {
                continue;
            }
            id_by_hash.insert(hash, cells.len());
            cells.push(cell);
            next.extend(cell.refs());
        }
        level = next;
    }
    let refs = cells
        .iter()
        .map(|cell| {
            cell.refs()
                .iter()
                .map(|child| Ok(id_by_hash[child.hash().map_err(map_err)?]))
                .collect::<Result<Vec<usize>, AppCoreError>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Postorder over refs last-to-first, from each unvisited cell in breadth-first order;
    // the serialized order is that postorder reversed.
    let mut visited = vec![false; cells.len()];
    let mut postorder = Vec::with_capacity(cells.len());
    for start in 0..cells.len() {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        let mut stack = vec![(start, refs[start].len())];
        while let Some((id, remaining)) = stack.last_mut() {
            if *remaining == 0 {
                postorder.push(*id);
                stack.pop();
                continue;
            }
            *remaining -= 1;
            let child = refs[*id][*remaining];
            if !visited[child] {
                visited[child] = true;
                stack.push((child, refs[child].len()));
            }
        }
    }
    let mut position = vec![0; cells.len()];
    for (index, &id) in postorder.iter().rev().enumerate() {
        position[id] = index;
    }

    let byte_width = |n: usize| (usize::BITS - n.leading_zeros()).div_ceil(8).max(1) as usize;
    let size_bytes = byte_width(cells.len());
    let cell_size =
        |id: usize| 2 + cells[id].data_len_bits().div_ceil(8) + refs[id].len() * size_bytes;
    let total_cell_size: usize = (0..cells.len()).map(cell_size).sum();
    let offset_bytes = byte_width(total_cell_size);
    let mut out = Vec::with_capacity(4 + 2 + 4 * size_bytes + offset_bytes + total_cell_size + 4);
    let push_uint = |out: &mut Vec<u8>, value: usize, width: usize| {
        out.extend_from_slice(&value.to_be_bytes()[std::mem::size_of::<usize>() - width..]);
    };
    out.extend_from_slice(&[
        0xb5,
        0xee,
        0x9c,
        0x72,
        0x40 | size_bytes as u8,
        offset_bytes as u8,
    ]);
    push_uint(&mut out, cells.len(), size_bytes);
    push_uint(&mut out, 1, size_bytes);
    push_uint(&mut out, 0, size_bytes);
    push_uint(&mut out, total_cell_size, offset_bytes);
    push_uint(&mut out, 0, size_bytes);
    for &id in postorder.iter().rev() {
        let cell = cells[id];
        let bits = cell.data_len_bits();
        let exotic = if cell.cell_type() == CellType::Ordinary {
            0
        } else {
            8
        };
        out.push(refs[id].len() as u8 + exotic + cell.level_mask().mask() * 32);
        out.push((bits / 8 + bits.div_ceil(8)) as u8);
        let mut data = cell.parser().read_bits(bits).map_err(map_err)?;
        if !bits.is_multiple_of(8) {
            // Completion tag: a 1 bit right after the data, as `bitsToPaddedBuffer` writes.
            data[bits / 8] |= 0x80 >> (bits % 8);
        }
        out.extend_from_slice(&data);
        for &child in &refs[id] {
            push_uint(&mut out, position[child], size_bytes);
        }
    }
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
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
    let hash = *state_init.hash().map_err(map_err)?;
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
    #[test]
    fn rejects_pruned_branch_boc_without_panicking() {
        let boc = [
            0xb5, 0xee, 0x9c, 0x72, 1, 1, 1, 1, 0, 3, 0, 0x28, 0x02, 0x01,
        ];
        let result = catch_unwind(AssertUnwindSafe(|| boc_from_bytes(boc.to_vec())));
        assert!(result.is_ok_and(|cell| cell.is_err()));
    }

    /// Built with ton_core 0.3.7; pytoniq-core parses it to the same representation hash.
    const NESTED_SPARSE_PRUNED_BODY: &str = "te6cckEBBAEAdwAJRgOcbabPbAuhOG9pT3KgrlvYhSHQNNMrvecHNF/OArueOAAJASlGAzuQksw/c9hMQbR+1wEJSlYAr+sbWjJjVTAxuzpVMblbAAgCQQSrzQNISAECEREREREREREREREREREREREREREREREREREREREREREAB+Yx3Ug=";

    /// A pruned branch storing one hash and depth per set bit of `mask`, as the TON node does.
    fn pruned_branch_boc(mask: u8) -> Vec<u8> {
        let count = mask.count_ones() as u8;
        let mut data = vec![1, mask];
        for index in 0..count {
            data.extend_from_slice(&[0x11 + index; 32]);
        }
        for index in 0..count {
            data.extend_from_slice(&u16::from(7 + index).to_be_bytes());
        }
        let mut boc = vec![
            0xb5,
            0xee,
            0x9c,
            0x72,
            1,
            1,
            1,
            1,
            0,
            data.len() as u8 + 2,
            0,
        ];
        boc.extend_from_slice(&[(mask << 5) | 0x08, data.len() as u8 * 2]);
        boc.extend(data);
        boc
    }

    #[test]
    fn hashes_pruned_branches_of_every_level_mask_like_an_independent_parser() {
        // pytoniq-core's representation hashes; it refuses mask 0b110, so that one has none.
        let independent = [
            (
                1,
                "d9baec4b7133705dc349538ad043e76d5b3152b4b90f25fed0cd601b43619f3b",
            ),
            (
                2,
                "b73237a06deaa4eb8796c20038e5950419e5c11b35d983fef9e452c48445aaa8",
            ),
            (
                3,
                "3af442f8ad8b37c3ed7ca688f4729df05e8c77c440bbced95521be1585dc1131",
            ),
            (
                4,
                "818d3050bfe39a60a0cf55a523bccc19edffd07c113927a3f6ca6ea8b06b517a",
            ),
            (
                5,
                "3539ab6bf3318a67833b7cb035010c4bf0b5c7aeafc1c9b9e249440eaae73fa2",
            ),
            (
                7,
                "fd0f1f33b619e688b1dc30737d2d48e74264cde7ad7da33c75e9f468ecbae2a1",
            ),
        ];
        for mask in 1u8..=7 {
            let cell =
                boc_from_bytes_with_limits(pruned_branch_boc(mask), MAX_MESSAGE_CELLS, false)
                    .unwrap_or_else(|error| panic!("mask {mask:#05b}: {error}"));
            if let Some((_, hash)) = independent.iter().find(|(known, _)| *known == mask) {
                assert_eq!(repr_hash_hex(&cell).unwrap(), *hash, "mask {mask:#05b}");
            }
            assert!(
                boc_from_bytes_with_limits(pruned_branch_boc(mask), MAX_MESSAGE_CELLS, true)
                    .is_err(),
                "mask {mask:#05b}: exotic cells stay refused where the caller requires it"
            );
        }
    }

    #[test]
    fn parses_a_level_zero_body_holding_a_sparse_pruned_branch() {
        // MerkleProof(MerkleProof(ordinary -> pruned branch, mask 0b010)): a body TON accepts.
        let body = base64::engine::general_purpose::STANDARD
            .decode(NESTED_SPARSE_PRUNED_BODY)
            .unwrap();
        let cell = boc_from_bytes_with_limits(body, MAX_MESSAGE_CELLS, false).unwrap();
        assert_eq!(cell.level_mask().mask(), 0);
        assert_eq!(
            repr_hash_hex(&cell).unwrap(),
            "d56d25bc265ab408feb6359de03d9197fc572ae3eb0e3a49653c29e677bb3383"
        );
    }

    #[test]
    fn serializes_shared_cells_in_ton_core_js_order_on_every_run() {
        // `@ton/core` 0.63.1 `toBoc({ idx: false, crc32: true })` bytes: a DAG whose shared
        // cells sit at different depths, and a body holding a Merkle proof and pruned branch.
        let expected = [
            "b5ee9c7241010601001a000302010401020202b005030202c003040001e80102a0050002d0c119982f",
            "b5ee9c7241010501005a000202020104094603608f1a3b91fc10c48c50f5a59f87ac8de53213a0b7cd25bf5515349d90b17be00008022204abcd030428480101111111111111111111111111111111111111111111111111111111111111111100070001e8a54777b4",
        ];
        for boc in expected {
            let cell =
                boc_from_bytes_with_limits(hex::decode(boc).unwrap(), MAX_MESSAGE_CELLS, false)
                    .unwrap();
            for _ in 0..64 {
                assert_eq!(boc_to_hex(&cell).unwrap(), boc);
            }
        }
    }

    #[test]
    fn serializes_a_mainnet_cell_ton_core_reordered_as_ton_core_js_does() {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/gasolina_parity/ton_shared_cell_boc.json");
        let fixture: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let cell = boc_from_base64_with_limits(
            fixture["input"].as_str().unwrap(),
            MAX_MESSAGE_CELLS,
            false,
        )
        .unwrap();
        assert_eq!(repr_hash_hex(&cell).unwrap(), fixture["reprHash"]);
        for _ in 0..64 {
            assert_eq!(boc_to_hex(&cell).unwrap(), fixture["tonCoreJs"]);
        }
    }

    #[test]
    fn rejects_cell_count_over_limit_in_header() {
        let mut boc = vec![
            0xb5, 0xee, 0x9c, 0x72, 2, 2, 0x20, 0x01, 0, 1, 0, 0, 0x40, 0x02, 0, 0,
        ];
        boc.resize(16 + 0x4002, 0);
        assert!(!boc_header_is_safe(&boc, MAX_MESSAGE_CELLS));
    }
    #[test]
    fn rejects_account_state_cell_count_over_protocol_limit() {
        let mut boc = vec![
            0xb5, 0xee, 0x9c, 0x72, 3, 3, 0x01, 0x00, 0x01, 0, 0, 1, 0, 0, 0, 2, 0, 2, 0, 0, 0,
        ];
        boc.resize(21 + 0x2_0002, 0);
        assert!(!boc_header_is_safe(&boc, MAX_ACCOUNT_STATE_CELLS));
    }
    #[test]
    fn refuses_a_chain_that_would_overflow_ton_cell_depth() {
        let boc = make_deep_chain(MAX_CELL_DEPTH + 2);
        assert_eq!(boc_max_depth(&boc), Some(MAX_CELL_DEPTH + 1));
        assert!(boc_from_bytes_with_limits(boc, MAX_ACCOUNT_STATE_CELLS, true).is_err());
    }

    #[test]
    fn refuses_an_unreachable_chain_deeper_than_ton_cell_depth() {
        let at_limit = make_unreachable_chain(MAX_CELL_DEPTH + 1);
        assert_eq!(boc_max_depth(&at_limit), Some(MAX_CELL_DEPTH));
        assert!(boc_from_bytes_with_limits(at_limit, MAX_MESSAGE_CELLS, true).is_ok());
        let deeper = make_unreachable_chain(MAX_CELL_DEPTH + 2);
        assert_eq!(boc_max_depth(&deeper), Some(MAX_CELL_DEPTH + 1));
        assert!(boc_from_bytes_with_limits(deeper, MAX_MESSAGE_CELLS, false).is_err());
    }

    #[test]
    fn rejects_chains_at_the_cell_limits_in_two_mib_worker() {
        const CHILD: &str = "PILLAR_TON_DEEP_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let cases = [
                (
                    make_deep_chain(MAX_ACCOUNT_STATE_CELLS - 1),
                    MAX_ACCOUNT_STATE_CELLS,
                    true,
                ),
                (
                    make_unreachable_chain(MAX_MESSAGE_CELLS - 1),
                    MAX_MESSAGE_CELLS,
                    false,
                ),
                (
                    make_unreachable_chain(MAX_ACCOUNT_STATE_CELLS - 1),
                    MAX_ACCOUNT_STATE_CELLS,
                    true,
                ),
            ];
            for (boc, max_cells, reject_exotic) in cases {
                let worker = std::thread::Builder::new()
                    .stack_size(2 * 1024 * 1024)
                    .spawn(move || boc_from_bytes_with_limits(boc, max_cells, reject_exotic))
                    .unwrap();
                assert!(worker.join().expect("worker must return normally").is_err());
            }
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "other_non_evm::ton::cell::tests::rejects_chains_at_the_cell_limits_in_two_mib_worker", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child test failed: {}",
            output.status
        );
        // An `--exact` filter that matches nothing also exits 0.
        assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"));
    }

    /// A chain of `chain_len` cells nothing references, rooted at one more empty cell.
    fn make_unreachable_chain(chain_len: usize) -> Vec<u8> {
        let be3 = |n: usize| [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let mut boc = vec![0xb5, 0xee, 0x9c, 0x72, 3, 3];
        boc.extend_from_slice(&be3(chain_len + 1));
        boc.extend_from_slice(&be3(1));
        boc.extend_from_slice(&be3(0));
        boc.extend_from_slice(&be3((chain_len - 1) * 5 + 4));
        boc.extend_from_slice(&be3(chain_len));
        for index in 0..chain_len {
            if index + 1 == chain_len {
                boc.extend_from_slice(&[0, 0]);
            } else {
                boc.extend_from_slice(&[1, 0]);
                boc.extend_from_slice(&be3(index + 1));
            }
        }
        boc.extend_from_slice(&[0, 0]);
        boc
    }

    fn make_deep_chain(cell_count: usize) -> Vec<u8> {
        let data_size = (cell_count - 1) * 5 + 2;
        let mut boc = vec![
            0xb5,
            0xee,
            0x9c,
            0x72,
            3,
            3,
            ((cell_count >> 16) & 0xff) as u8,
            ((cell_count >> 8) & 0xff) as u8,
            (cell_count & 0xff) as u8,
            0,
            0,
            1,
            0,
            0,
            0,
            ((data_size >> 16) & 0xff) as u8,
            ((data_size >> 8) & 0xff) as u8,
            (data_size & 0xff) as u8,
            0,
            0,
            0,
        ];
        for index in 0..cell_count {
            if index + 1 == cell_count {
                boc.extend_from_slice(&[0, 0]);
            } else {
                boc.extend_from_slice(&[1, 0]);
                let next = (index + 1) as u32;
                boc.extend_from_slice(&next.to_be_bytes()[1..]);
            }
        }
        boc
    }

    #[test]
    fn parses_maximal_account_state_boc() {
        let boc = make_flat_boc(MAX_ACCOUNT_STATE_CELLS);
        assert!(boc_from_bytes_with_limits(boc, MAX_ACCOUNT_STATE_CELLS, true).is_ok());
    }

    #[test]
    fn parses_maximal_message_boc() {
        let boc = make_flat_boc(MAX_MESSAGE_CELLS);
        assert!(boc_from_bytes_with_limits(boc, MAX_MESSAGE_CELLS, true).is_ok());
    }

    fn make_flat_boc(cell_count: usize) -> Vec<u8> {
        let data_size = cell_count * 2;
        let mut boc = vec![
            0xb5,
            0xee,
            0x9c,
            0x72,
            3,
            3,
            ((cell_count >> 16) & 0xff) as u8,
            ((cell_count >> 8) & 0xff) as u8,
            (cell_count & 0xff) as u8,
            0,
            0,
            1,
            0,
            0,
            0,
            ((data_size >> 16) & 0xff) as u8,
            ((data_size >> 8) & 0xff) as u8,
            (data_size & 0xff) as u8,
            0,
            0,
            0,
        ];
        boc.resize(21 + data_size, 0);
        boc
    }
    #[test]
    fn refuses_deep_chain_on_message_cell_cap_path() {
        let boc = make_deep_chain(MAX_MESSAGE_CELLS + 1);
        assert!(boc_from_bytes(boc).is_err());
    }
    #[test]
    fn refuses_forged_level_mask_pruned_branch_boc() {
        let mut c_builder = TonCell::builder();
        c_builder.write_bits([0xcd], 8).unwrap();
        let c = c_builder.build().unwrap();
        let hash = c.hash().unwrap();
        let depth = c.depth().unwrap();

        let mut boc = vec![
            0xb5, 0xee, 0x9c, 0x72, 3, 3, 0, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 61, 0, 0, 0, 2, 0, 0, 0,
            1, 0, 0, 2, 1, 2, 0xab, 0, 0, 3, 1, 2, 0xab, 0, 0, 4, 0x28, 72, 1, 1,
        ];
        boc.extend_from_slice(hash.as_slice());
        boc.extend_from_slice(&depth.to_be_bytes());
        boc.extend_from_slice(&[0, 2, 0xcd]);
        assert_eq!(boc.len(), 21 + 61);
        assert!(boc_from_bytes_with_limits(boc, MAX_MESSAGE_CELLS, true).is_err());
    }

    #[test]
    fn accepts_boc_cells_that_store_their_hashes() {
        let plain = vec![
            0xb5, 0xee, 0x9c, 0x72, 1, 1, 2, 1, 0, 7, 0, 0x01, 0x02, 0xab, 1, 0x00, 0x02, 0xcd,
        ];
        let root = boc_from_bytes(plain).expect("plain BoC");
        let leaf = &root.refs()[0];
        let mut with_hashes = vec![0xb5, 0xee, 0x9c, 0x72, 1, 1, 2, 1, 0, 75, 0, 0x11, 0x02];
        with_hashes.extend_from_slice(root.hash().unwrap().as_slice());
        with_hashes.extend_from_slice(&root.depth().unwrap().to_be_bytes());
        with_hashes.extend_from_slice(&[0xab, 1, 0x10, 0x02]);
        with_hashes.extend_from_slice(leaf.hash().unwrap().as_slice());
        with_hashes.extend_from_slice(&leaf.depth().unwrap().to_be_bytes());
        with_hashes.push(0xcd);
        assert_eq!(boc_max_depth(&with_hashes), Some(1));
        let parsed = boc_from_bytes(with_hashes).expect("BoC with stored hashes");
        assert_eq!(parsed.hash().unwrap(), root.hash().unwrap());
    }

    #[test]
    fn validates_repeated_reference_dag_in_linear_time() {
        let mut boc = vec![0xb5, 0xee, 0x9c, 0x72, 1, 1, 40, 1, 0, 236, 0];
        for index in 0..40 {
            if index == 39 {
                boc.extend_from_slice(&[0, 0]);
            } else {
                boc.extend_from_slice(&[4, 0]);
                boc.extend_from_slice(&[(index + 1) as u8; 4]);
            }
        }
        assert_eq!(boc.len(), 247);
        assert!(boc_from_bytes(boc).is_ok());
    }
}
