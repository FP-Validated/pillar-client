//! Direct `HashmapE` (TON `dict256`) lookup, ported from the upstream
//! LayerZero TypeScript implementation's dictionary loading.
//!
//! Every LayerZero TON dictionary reachable from contract storage is loaded as
//! `loadDictDirect(Dictionary.Keys.BigUint(256), Dictionary.Values.Cell())`:
//! the storage field cell *is* the hashmap root (no `Maybe` prefix bit), keys
//! are fixed 256-bit unsigned integers and values are stored as cell
//! references.
//!
//! * TS: `packages/common-ton/src/class/generators.ts:493-505`
//!   (`enhancedLoadDict`: an empty cell becomes
//!   `Dictionary.empty(Dictionary.Keys.BigUint(256), value)`, otherwise
//!   `rawCell.beginParse().loadDictDirect(Dictionary.Keys.BigUint(256), value)`)
//! * TS: `packages/sdks/lz-v2-sdk/src/uln/ton/index.ts:162-200`
//!   (`hashLookups.getDict(Dictionary.Values.Cell())` keyed by the message
//!   nonce, then the nested `loadDictDirect(Dictionary.Keys.BigUint(256),
//!   Dictionary.Values.Cell())` keyed by the verifier address)
//!
//! `Dictionary.Values.Cell()` in `@ton/core` serializes with `storeRef` and
//! parses with `loadRef`, so a leaf's value is the leaf node's next reference,
//! not its remaining bits.
//!
//! `ton_core` has no hashmap support, so the TL-B `HashmapE` label encoding
//! (`hml_short$0` / `hml_long$10` / `hml_same$11`) is decoded here.

use pillar_core::AppCoreError;
use ton_core::cell::TonCell;

use super::cell::map_err;

/// `Dictionary.Keys.BigUint(256)`.
pub const DICT_KEY_BITS: usize = 256;

/// Bits needed for a TL-B `#<= m` field: `ceil(log2(m + 1))`.
fn bounded_uint_bits(m: usize) -> usize {
    usize::BITS as usize - m.leading_zeros() as usize
}

/// Bit `index` of a 256-bit big-endian key, most significant bit first.
fn key_bit(key_be: &[u8; 32], index: usize) -> bool {
    (key_be[index / 8] >> (7 - index % 8)) & 1 == 1
}

/// One step down the hashmap tree.
enum Descent {
    /// The key's label was fully matched: this is the leaf's value reference.
    Value(TonCell),
    /// The branch to continue in.
    Node(TonCell),
    /// The stored label diverges from the key, so the key is not in the tree.
    Absent,
}

/// Read one node's label, match it against the key and either resolve the leaf
/// value or pick the branch to descend into.
fn descend(
    node: &TonCell,
    key_be: &[u8; 32],
    remaining: &mut usize,
    consumed: &mut usize,
) -> Result<Descent, AppCoreError> {
    let mut parser = node.parser();
    let (label_len, same_bit) = if !parser.read_bit().map_err(map_err)? {
        // hml_short$0 len:(Unary ~n) s:(n * Bit)
        let mut len = 0usize;
        while parser.read_bit().map_err(map_err)? {
            len += 1;
        }
        (len, None)
    } else if !parser.read_bit().map_err(map_err)? {
        // hml_long$10 n:(#<= m) s:(n * Bit)
        let len = parser
            .read_num::<u64>(bounded_uint_bits(*remaining))
            .map_err(map_err)? as usize;
        (len, None)
    } else {
        // hml_same$11 v:Bit n:(#<= m)
        let bit = parser.read_bit().map_err(map_err)?;
        let len = parser
            .read_num::<u64>(bounded_uint_bits(*remaining))
            .map_err(map_err)? as usize;
        (len, Some(bit))
    };

    if label_len > *remaining {
        return Err(AppCoreError::Internal(
            "TON dictionary label is longer than the remaining key".to_string(),
        ));
    }

    for offset in 0..label_len {
        // `hml_same` stores the repeated bit once; the other two forms spell
        // every label bit out.
        let label_bit = match same_bit {
            Some(bit) => bit,
            None => parser.read_bit().map_err(map_err)?,
        };
        if label_bit != key_bit(key_be, *consumed + offset) {
            return Ok(Descent::Absent);
        }
    }
    *consumed += label_len;
    *remaining -= label_len;

    if *remaining == 0 {
        return Ok(Descent::Value(
            parser.read_next_ref().map_err(map_err)?.clone(),
        ));
    }

    // hmn_fork: left holds the keys whose next bit is 0, right the 1s.
    let branch = key_bit(key_be, *consumed);
    *consumed += 1;
    *remaining -= 1;
    let left = parser.read_next_ref().map_err(map_err)?.clone();
    let right = parser.read_next_ref().map_err(map_err)?.clone();
    Ok(Descent::Node(if branch { right } else { left }))
}

/// Look up a 256-bit key in a directly-serialized `HashmapE` whose values are
/// cell references. Returns `None` for an empty dictionary, for a key absent
/// from the tree and for a diverging label — the three cases where the upstream
/// `Dictionary.has(key)` is `false`.
pub fn dict256_get_ref(root: &TonCell, key_be: &[u8; 32]) -> Result<Option<TonCell>, AppCoreError> {
    // `rawCell.bits.length === 0` -> `Dictionary.empty(...)`, which has no keys.
    if root.data_len_bits() == 0 {
        return Ok(None);
    }

    let mut node = root.clone();
    let mut remaining = DICT_KEY_BITS;
    let mut consumed = 0usize;
    loop {
        match descend(&node, key_be, &mut remaining, &mut consumed)? {
            Descent::Value(value) => return Ok(Some(value)),
            Descent::Absent => return Ok(None),
            Descent::Node(next) => node = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cell::{build, builder};
    use super::*;
    use num_bigint::BigUint;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn value_cell(tag: u64) -> TonCell {
        let mut b = builder();
        b.write_num(&BigUint::from(tag), 64).unwrap();
        build(b).unwrap()
    }

    /// A one-key dictionary: the root's label spells the whole 256-bit key with
    /// `hml_long$10`, and the leaf's value is its single reference.
    fn single_key_dict(key_be: &[u8; 32], value: TonCell) -> TonCell {
        let mut b = builder();
        b.write_bit(true).unwrap(); // hml_long$10
        b.write_bit(false).unwrap();
        b.write_num(&BigUint::from(256u32), bounded_uint_bits(256))
            .unwrap();
        b.write_bits(key_be, 256).unwrap();
        b.write_ref(value).unwrap();
        build(b).unwrap()
    }

    /// A branch node holding the last `label_len` key bits, then the value.
    fn leaf_after_fork(key_be: &[u8; 32], label_len: usize, value: TonCell) -> TonCell {
        let mut b = builder();
        b.write_bit(true).unwrap(); // hml_long$10
        b.write_bit(false).unwrap();
        b.write_num(
            &BigUint::from(label_len as u64),
            bounded_uint_bits(label_len),
        )
        .unwrap();
        // The fork consumed the first bit, so the label is the tail of the key.
        let mut tail = Vec::with_capacity(label_len);
        for index in 0..label_len {
            tail.push(key_bit(key_be, DICT_KEY_BITS - label_len + index));
        }
        for bit in tail {
            b.write_bit(bit).unwrap();
        }
        b.write_ref(value).unwrap();
        build(b).unwrap()
    }

    /// A two-key dictionary whose keys differ in their first bit: the root has
    /// an empty `hml_short$0` label and forks immediately.
    fn forked_dict(zero_branch: TonCell, one_branch: TonCell) -> TonCell {
        let mut b = builder();
        b.write_bit(false).unwrap(); // hml_short$0
        b.write_bit(false).unwrap(); // unary length 0
        b.write_ref(zero_branch).unwrap();
        b.write_ref(one_branch).unwrap();
        build(b).unwrap()
    }

    #[test]
    fn empty_dictionary_has_no_keys() {
        let empty = build(builder()).unwrap();
        assert!(dict256_get_ref(&empty, &key(0x11)).unwrap().is_none());
    }

    #[test]
    fn resolves_single_key_leaf_value_from_its_reference() {
        let dict = single_key_dict(&key(0x11), value_cell(0xabc));
        let found = dict256_get_ref(&dict, &key(0x11)).unwrap().unwrap();
        assert_eq!(
            found.parser().read_num::<u64>(64).unwrap(),
            0xabc,
            "leaf value must come from the leaf's reference, like Values.Cell()"
        );
    }

    #[test]
    fn absent_key_diverging_from_the_label_is_none() {
        let dict = single_key_dict(&key(0x11), value_cell(0xabc));
        assert!(dict256_get_ref(&dict, &key(0x12)).unwrap().is_none());
    }

    #[test]
    fn forked_dictionary_selects_the_branch_by_key_bit() {
        // 0x11.. starts with bit 0, 0xff.. starts with bit 1.
        let zero_key = key(0x11);
        let one_key = key(0xff);
        let dict = forked_dict(
            leaf_after_fork(&zero_key, 255, value_cell(1)),
            leaf_after_fork(&one_key, 255, value_cell(2)),
        );

        let zero = dict256_get_ref(&dict, &zero_key).unwrap().unwrap();
        assert_eq!(zero.parser().read_num::<u64>(64).unwrap(), 1);
        let one = dict256_get_ref(&dict, &one_key).unwrap().unwrap();
        assert_eq!(one.parser().read_num::<u64>(64).unwrap(), 2);
        // Same leading bit as `zero_key`, but the tail label diverges.
        assert!(dict256_get_ref(&dict, &key(0x13)).unwrap().is_none());
    }

    #[test]
    fn same_bit_label_matches_only_a_run_of_that_bit() {
        // hml_same$11 with v=0 and n=256 encodes the all-zero key.
        let mut b = builder();
        b.write_bit(true).unwrap();
        b.write_bit(true).unwrap();
        b.write_bit(false).unwrap(); // v = 0
        b.write_num(&BigUint::from(256u32), bounded_uint_bits(256))
            .unwrap();
        b.write_ref(value_cell(7)).unwrap();
        let dict = build(b).unwrap();

        let found = dict256_get_ref(&dict, &key(0x00)).unwrap().unwrap();
        assert_eq!(found.parser().read_num::<u64>(64).unwrap(), 7);
        assert!(dict256_get_ref(&dict, &key(0x01)).unwrap().is_none());
    }

    #[test]
    fn bounded_uint_bits_matches_tlb_bound() {
        assert_eq!(bounded_uint_bits(0), 0);
        assert_eq!(bounded_uint_bits(1), 1);
        assert_eq!(bounded_uint_bits(255), 8);
        assert_eq!(bounded_uint_bits(256), 9);
    }
}
