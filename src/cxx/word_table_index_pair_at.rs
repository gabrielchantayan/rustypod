//! Indexed word-table pair construction — original: `FUN_083d21a4` @
//! `0x083d21a4` (36 bytes, `0x083d21a4..0x083d21c8`; the next real function
//! begins with `push {r0-r8,lr}` at `0x083d21c8`).
//!
//! Decoding the nine raw ARM words establishes three inbound plain `bl` call
//! sites and no predicated `bl` calls. The function has no calls of its own.
//! It reads the target-width table pointer at +0x14 and index at +0x18,
//! computes `table + index * 4` with wrapping ARM address arithmetic, and
//! stores `{slot, *slot}` in `out_pair`. Deliberate deviations: the redundant
//! stack copies emitted by ADS are not represented; they have no observable
//! effect.

/// Target-width table descriptor consumed by [`word_table_index_pair_at`].
///
/// Only the table pointer and index are known; the preceding words remain
/// opaque. Keeping every field a `u32` preserves target offsets on hosts.
#[repr(C)]
pub struct WordTableIndexAt {
    opaque_prefix: [u32; 5],
    table: u32,
    index: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(WordTableIndexAt, table)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(WordTableIndexAt, index)];

/// The target-width `{slot_address, slot_value}` result written by the helper.
#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
pub struct WordTableIndexAtPair {
    pub slot: u32,
    pub value: u32,
}

/// word_table_index_pair_at — original: `FUN_083d21a4` @ `0x083d21a4` (36
/// bytes; 3 direct plain `bl` call sites, no predicated calls). See the module
/// header.
///
/// # Safety
///
/// `table_index` must be readable and its selected target address must name a
/// readable aligned word. `out_pair` must be writable. As in retailOS, neither
/// pointer is NULL-checked.
#[cfg_attr(target_os = "none", link_section = ".text.word_table_index_pair_at")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_table_index_pair_at(
    out_pair: *mut WordTableIndexAtPair,
    table_index: *const WordTableIndexAt,
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
    use super::{word_table_index_pair_at, WordTableIndexAt, WordTableIndexAtPair};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn selects_indexed_word_and_overwrites_both_result_words() {
        let Some(slab) = try_map_u32_slab(hints::WORD_TABLE_INDEX_PAIR_AT, 0x1000) else {
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
        let descriptor = WordTableIndexAt {
            opaque_prefix: [0; 5],
            table,
            index: 0,
        };
        let mut out = WordTableIndexAtPair { slot: 0, value: 0 };

        unsafe { word_table_index_pair_at(&mut out, &descriptor) };
        assert_eq!(out, WordTableIndexAtPair { slot: table, value: 0x1122_3344 });

        let descriptor = WordTableIndexAt { index: 3, ..descriptor };
        out = WordTableIndexAtPair { slot: u32::MAX, value: u32::MAX };
        unsafe { word_table_index_pair_at(&mut out, &descriptor) };
        assert_eq!(out, WordTableIndexAtPair { slot: table + 12, value: 0xddee_ff00 });
    }
}
