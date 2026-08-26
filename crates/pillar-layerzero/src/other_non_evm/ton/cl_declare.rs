//! Port of LayerZero's TON `clDeclare` class encoding (upstream TypeScript
//! `common-ton/src/class/index.ts`). This is a LayerZero-proprietary layout on
//! top of standard TON cells (NOT standard TL-B), so it is hand-ported rather
//! than derived from a schema macro.
//!
//! Layout of an encoded class cell:
//! `[ 80-bit class name ][ 15 x 18-bit field-info ][ all-ones padding to 350 ]
//!  [ root data-cell numeric bits ][ refs... ]`

use num_bigint::BigUint;
use ton_core::cell::{CellBuilder, TonCell};

use super::cell::{build, builder, map_err};
use pillar_core::AppCoreError;

// `cl.t` type codes used by the ported LayerZero TON schemas (type code 0 = bool
// / uint1; the bit width is `1 << type_code` for codes 0..=8).
pub const T_UINT8: u8 = 3;
pub const T_UINT16: u8 = 4;
pub const T_UINT32: u8 = 5;
pub const T_UINT64: u8 = 6;
pub const T_UINT256: u8 = 8; // also address
pub const T_REF: u8 = 9; // cellRef / objRef / dict256 / addressList

const NAME_WIDTH: usize = 80;
const FIELD_TYPE_WIDTH: usize = 4;
const CELL_ID_WIDTH: usize = 2;
const DATA_OFFSET_WIDTH: usize = 10;
const REF_OFFSET_WIDTH: usize = 2;
const FIELD_INFO_WIDTH: usize =
    FIELD_TYPE_WIDTH + CELL_ID_WIDTH + DATA_OFFSET_WIDTH + REF_OFFSET_WIDTH; // 18
const MAX_CLASS_FIELDS: usize = 15;
const BASIC_HEADER_WIDTH: usize = NAME_WIDTH;
const HEADER_WIDTH: usize = BASIC_HEADER_WIDTH + MAX_CLASS_FIELDS * FIELD_INFO_WIDTH; // 350
const MAX_CELL_BITS: usize = 1023;
const MAX_CELL_REFS: usize = 4;

/// A single field of a class, already resolved to its wire representation.
pub enum ClField {
    /// Numeric field. `type_code` is the `cl.t` uint code (0..=8); the bit width
    /// is derived from it. `value` is the absolute integer to store.
    Num { type_code: u8, value: BigUint },
    /// Reference field (`objRef`/`cellRef`/`dict256`/`addressList`).
    Ref(TonCell),
}

impl ClField {
    pub fn uint(type_code: u8, value: impl Into<BigUint>) -> Self {
        ClField::Num {
            type_code,
            value: value.into(),
        }
    }

    /// A 256-bit field (address / uint256) from a 32-byte big-endian buffer.
    pub fn u256_be(type_code: u8, be: &[u8]) -> Self {
        ClField::Num {
            type_code,
            value: BigUint::from_bytes_be(be),
        }
    }
}

fn type_width(type_code: u8) -> usize {
    if type_code <= T_UINT256 {
        1usize << type_code
    } else {
        0
    }
}

/// `asciiStringToBigint`: the class name's ASCII bytes as a big-endian integer.
pub fn ascii_name(name: &str) -> BigUint {
    BigUint::from_bytes_be(name.as_bytes())
}

fn write_uint(builder: &mut CellBuilder, value: &BigUint, bits: usize) -> Result<(), AppCoreError> {
    builder.write_num(value, bits).map_err(map_err)
}

/// Encode a class into a cell, replicating `clDeclare(name, fields)`.
pub fn cl_declare(name: &str, fields: Vec<ClField>) -> Result<TonCell, AppCoreError> {
    if fields.len() > MAX_CLASS_FIELDS {
        return Err(AppCoreError::Internal("INVALID_CLASS".to_string()));
    }

    // `cells[1]` is the root data cell (TS `classBuilder[1]`); index 0 is unused.
    let mut cells: Vec<Option<CellBuilder>> = vec![None, Some(builder())];
    let mut header = builder();
    write_uint(&mut header, &ascii_name(name), NAME_WIDTH)?;

    let mut cur_data_cell = 1usize;
    let mut cur_ref_cell = 1usize;
    let mut cur_cell_max_refs = 2usize;
    let mut cur_data_offset = HEADER_WIDTH;
    let mut cur_ref_offset = 0usize;

    for field in fields {
        let field_bits = match &field {
            ClField::Num { type_code, .. } => type_width(*type_code),
            ClField::Ref(_) => 0,
        };

        if cur_data_offset + field_bits > MAX_CELL_BITS {
            cur_data_cell += 1;
            cur_data_offset = 0;
            if cur_data_cell >= cells.len() {
                cells.push(Some(builder()));
            }
        }
        if field_bits == 0 && cur_ref_offset + 1 > cur_cell_max_refs {
            cur_ref_cell += 1;
            cur_ref_offset = 0;
            cur_cell_max_refs = MAX_CELL_REFS;
            if cur_ref_cell >= cells.len() {
                cells.push(Some(builder()));
            }
        }

        let field_type: u8 = match &field {
            ClField::Num { type_code, .. } => *type_code,
            ClField::Ref(_) => T_REF,
        };

        match field {
            ClField::Num { value, .. } => {
                let cell = cells[cur_data_cell].as_mut().expect("data cell present");
                write_uint(cell, &value, field_bits)?;
            }
            ClField::Ref(cell_ref) => {
                let cell = cells[cur_ref_cell].as_mut().expect("ref cell present");
                cell.write_ref(cell_ref).map_err(map_err)?;
            }
        }

        write_uint(&mut header, &BigUint::from(field_type), FIELD_TYPE_WIDTH)?;
        if field_bits > 0 {
            let cell_id = if cur_data_cell == 1 { 0 } else { cur_data_cell };
            write_uint(&mut header, &BigUint::from(cell_id), CELL_ID_WIDTH)?;
            write_uint(
                &mut header,
                &BigUint::from(cur_data_offset),
                DATA_OFFSET_WIDTH,
            )?;
            write_uint(&mut header, &BigUint::from(3u32), REF_OFFSET_WIDTH)?;
            cur_data_offset += field_bits;
        } else {
            let cell_id = if cur_ref_cell == 1 { 0 } else { cur_ref_cell };
            write_uint(&mut header, &BigUint::from(cell_id), CELL_ID_WIDTH)?;
            write_uint(
                &mut header,
                &BigUint::from(MAX_CELL_BITS),
                DATA_OFFSET_WIDTH,
            )?;
            write_uint(
                &mut header,
                &BigUint::from(cur_ref_offset),
                REF_OFFSET_WIDTH,
            )?;
            cur_ref_offset += 1;
        }
    }

    let mut root = cells[1].take().expect("root cell present");
    let num_cells = cells.len() - 1;

    // Reserve empty ref slots so extra data cells land at ref indices 2/3.
    if num_cells > 1 {
        while (MAX_CELL_REFS - root.refs_left()) < 2 {
            root.write_ref(TonCell::empty().clone()).map_err(map_err)?;
        }
    }

    let header_bits_used = MAX_CELL_BITS - header.data_bits_left();
    let trailing_ones = HEADER_WIDTH - header_bits_used;
    for _ in 0..trailing_ones {
        header.write_bit(true).map_err(map_err)?;
    }

    let root_cell = build(root)?;
    header.write_cell(&root_cell).map_err(map_err)?;

    for extra in cells.iter_mut().take(num_cells + 1).skip(2) {
        let extra = extra.take().expect("extra data cell present");
        header.write_ref(build(extra)?).map_err(map_err)?;
    }

    build(header)
}

fn field_info(cell: &TonCell, field_index: usize) -> Result<(usize, usize, usize), AppCoreError> {
    let mut parser = cell.parser();
    let field_info_offset = BASIC_HEADER_WIDTH + field_index * FIELD_INFO_WIDTH;
    parser
        .read_bits(field_info_offset + FIELD_TYPE_WIDTH)
        .map_err(map_err)?;
    let cell_index = parser.read_num::<u64>(CELL_ID_WIDTH).map_err(map_err)? as usize;
    let offset = parser.read_num::<u64>(DATA_OFFSET_WIDTH).map_err(map_err)? as usize;
    let ref_idx = parser.read_num::<u64>(REF_OFFSET_WIDTH).map_err(map_err)? as usize;
    Ok((cell_index, offset, ref_idx))
}

/// Read a numeric field as a big-endian byte vector (`clGetUint`).
pub fn cl_get_uint_be(
    cell: &TonCell,
    field_index: usize,
    width: usize,
) -> Result<Vec<u8>, AppCoreError> {
    let (cell_index, offset, _) = field_info(cell, field_index)?;
    let value: BigUint = if cell_index == 0 {
        let mut parser = cell.parser();
        parser.read_bits(offset).map_err(map_err)?;
        parser.read_num(width).map_err(map_err)?
    } else {
        let mut parser = cell.parser();
        for _ in 0..cell_index {
            parser.read_next_ref().map_err(map_err)?;
        }
        let target = parser.read_next_ref().map_err(map_err)?.clone();
        let mut inner = target.parser();
        inner.read_bits(offset).map_err(map_err)?;
        inner.read_num(width).map_err(map_err)?
    };
    let mut be = value.to_bytes_be();
    let byte_len = width.div_ceil(8);
    while be.len() < byte_len {
        be.insert(0, 0);
    }
    Ok(be)
}

/// Read a reference field (`clGetCellRef`).
pub fn cl_get_ref(cell: &TonCell, field_index: usize) -> Result<TonCell, AppCoreError> {
    let (cell_index, _, ref_idx) = field_info(cell, field_index)?;
    let mut parser = cell.parser();
    if cell_index == 0 {
        for _ in 0..ref_idx {
            parser.read_next_ref().map_err(map_err)?;
        }
        return parser.read_next_ref().map_err(map_err).cloned();
    }
    for _ in 0..cell_index {
        parser.read_next_ref().map_err(map_err)?;
    }
    let nested = parser.read_next_ref().map_err(map_err)?.clone();
    let mut inner = nested.parser();
    for _ in 0..ref_idx {
        inner.read_next_ref().map_err(map_err)?;
    }
    inner.read_next_ref().map_err(map_err).cloned()
}

/// `getCellName`: the class name stored in the first 80 bits, as ASCII.
pub fn cell_name(cell: &TonCell) -> Result<String, AppCoreError> {
    let mut parser = cell.parser();
    let value: BigUint = parser.read_num(NAME_WIDTH).map_err(map_err)?;
    // `to_bytes_be` strips leading zero bytes, matching `bigintToAsciiString`.
    String::from_utf8(value.to_bytes_be())
        .map_err(|e| AppCoreError::Internal(format!("TON cell name not ASCII: {e}")))
}
