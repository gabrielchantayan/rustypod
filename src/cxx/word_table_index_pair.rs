//! Indexed word-table pair construction — original: `FUN_083d2244` @
//! `0x083d2244` (36 bytes, `0x083d2244..0x083d2268`; the next real function
//! begins with `push {r0-r8,lr}` at `0x083d2268`).
//!
//! Decoding the nine raw ARM words establishes three inbound plain `bl` call
//! sites (0x082690f8, 0x08269374, and 0x08269620) and no predicated `bl`
//! calls. The function has no calls of its own. It reads the target-width table
//! pointer at +0x14 and index at +0x18, computes `table + index * 4` with
//! wrapping ARM address arithmetic, and stores `{slot, *slot}` in `out_pair`.
//! Deliberate deviations: the redundant stack copies emitted by ADS are not
//! represented; they have no observable effect.

/// Target-width table descriptor consumed by [`word_table_index_pair`].
///
/// Only the table pointer and index are known; the preceding words remain
/// opaque. Keeping every field a `u32` preserves target offsets on hosts.
#[repr(C)]
pub struct WordTableIndex {
    opaque_prefix: [u32; 5],
    table: u32,
    index: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(WordTableIndex, table)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(WordTableIndex, index)];

/// The target-width `{slot_address, slot_value}` result written by the helper.
#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
pub struct WordTableIndexPair {
    pub slot: u32,
    pub value: u32,
}

/// word_table_index_pair — original: `FUN_083d2244` @ `0x083d2244` (36 bytes;
/// 3 direct plain `bl` call sites, no predicated calls). See the module header.
///
/// # Safety
///
/// `table_index` must be readable and its selected target address must name a
/// readable aligned word. `out_pair` must be writable. As in retailOS, neither
/// pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_table_index_pair(
    out_pair: *mut WordTableIndexPair,
    table_index: *const WordTableIndex,
) {
    let table = unsafe { (*table_index).table };
    let index = unsafe { (*table_index).index };
    let slot = table.wrapping_add(index.wrapping_mul(4));
    let value = unsafe { core::ptr::read(slot as usize as *const u32) };

    unsafe {
        (*out_pair).slot = slot;
        (*out_pair).value = value;
    }
}

#[cfg(test)]
mod tests {
    use super::{word_table_index_pair, WordTableIndex, WordTableIndexPair};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn selects_indexed_word_and_overwrites_both_result_words() {
        let Some(slab) = try_map_u32_slab(hints::WORD_TABLE_INDEX_PAIR, 0x1000) else {
            return;
        };
        let words = slab.cast::<u32>();
        unsafe {
            *words.add(0) = 0x1122_3344;
            *words.add(1) = 0x5566_7788;
            *words.add(2) = 0x99aa_bbcc;
            *words.add(3) = 0xddee_ff00;
        }
        let table = words as usize as u32;
        let descriptor = WordTableIndex {
            opaque_prefix: [0; 5],
            table,
            index: 0,
        };
        let mut out = WordTableIndexPair { slot: 0, value: 0 };

        unsafe { word_table_index_pair(&mut out, &descriptor) };
        assert_eq!(out, WordTableIndexPair { slot: table, value: 0x1122_3344 });

        let descriptor = WordTableIndex { index: 3, ..descriptor };
        out = WordTableIndexPair { slot: u32::MAX, value: u32::MAX };
        unsafe { word_table_index_pair(&mut out, &descriptor) };
        assert_eq!(out, WordTableIndexPair { slot: table + 12, value: 0xddee_ff00 });
    }
}
