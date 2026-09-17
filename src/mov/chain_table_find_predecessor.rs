//! MOV chain predecessor search port.
//!
//! Original: `FUN_0820c8f4` at 0x0820c8f4. Raw `osos.dec` establishes a
//! 100-byte extent (0x0820c8f4..0x0820c958): 25 ARM instructions followed by
//! the separately linked function at 0x0820c958. Decoding every ARM B/BL word
//! in the image found four direct plain `bl` call sites (0x081e46e4,
//! 0x081e4a4c, 0x081e4e94, and 0x081e4f98), zero predicated `bl` call sites,
//! and its sole internal unconditional `bl` is to the established
//! `mov_chain_table_next` seam at 0x0820c8a0.
//!
//! Starting at `head`, follows next-slot links until `target` is reached. It
//! writes `u32::MAX` first, then writes the prior link before each next-link
//! lookup. Thus finding `target` at the head is an error (there is no
//! predecessor), while a later match returns its predecessor. Link-read errors
//! propagate after preserving the last predecessor written to `out`.
//!
//! # Deliberate deviations
//!
//! None. The stock routine has no NULL checks and does not detect cycles; this
//! port preserves both properties.

use super::chain_table::{mov_chain_table_next, MovChainTable, MOV_CHAIN_TABLE_ERR, MOV_CHAIN_TABLE_OK};

/// Finds the chain slot immediately preceding `target`.
///
/// Returns [`MOV_CHAIN_TABLE_OK`] and writes that predecessor when `target`
/// occurs after `head`. Returns [`MOV_CHAIN_TABLE_ERR`] when `head` is the end
/// marker, `target == head`, or [`mov_chain_table_next`] reports an invalid
/// link. The stock routine writes `u32::MAX` before examining `head`; a failed
/// subsequent link lookup leaves the most recently traversed predecessor in
/// `out`.
///
/// # Safety
///
/// `table` must identify a readable [`MovChainTable`] for each chain index
/// traversed, and `out` must be writable. Neither is NULL-checked; cyclic
/// chains that omit `target` do not terminate, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_find_predecessor")]
pub unsafe extern "C" fn mov_chain_table_find_predecessor(
    table: *const MovChainTable,
    head: u32,
    target: u32,
    out: *mut u32,
) -> i32 {
    unsafe { core::ptr::write(out, u32::MAX) };
    if head == u32::MAX {
        return MOV_CHAIN_TABLE_ERR;
    }

    let mut current = head;
    loop {
        if current == target {
            return if unsafe { core::ptr::read(out) } == u32::MAX {
                MOV_CHAIN_TABLE_ERR
            } else {
                MOV_CHAIN_TABLE_OK
            };
        }

        unsafe { core::ptr::write(out, current) };
        let mut next = 0;
        if unsafe { mov_chain_table_next(table, current, &mut next) } != MOV_CHAIN_TABLE_OK {
            return MOV_CHAIN_TABLE_ERR;
        }
        current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mov::chain_table::{MovChainEntry, MOV_CHAIN_TABLE_SLOTS};

    const POISON: u32 = 0xdead_beef;

    fn fresh_table() -> MovChainTable {
        MovChainTable {
            entries: [const {
                MovChainEntry { field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 0, field_10: 0 }
            }; MOV_CHAIN_TABLE_SLOTS],
        }
    }

    #[test]
    fn finds_predecessor_after_head() {
        let mut table = fresh_table();
        table.entries[4].next = 23;
        table.entries[23].next = 91;
        table.entries[91].next = u32::MAX;
        let mut out = POISON;

        assert_eq!(unsafe { mov_chain_table_find_predecessor(&table, 4, 91, &mut out) }, MOV_CHAIN_TABLE_OK);
        assert_eq!(out, 23);
    }

    #[test]
    fn head_and_end_marker_have_no_predecessor() {
        let mut table = fresh_table();
        table.entries[7].next = u32::MAX;

        let mut out = POISON;
        assert_eq!(unsafe { mov_chain_table_find_predecessor(&table, 7, 7, &mut out) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(out, u32::MAX);

        let mut out = POISON;
        assert_eq!(unsafe { mov_chain_table_find_predecessor(&table, u32::MAX, 7, &mut out) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(out, u32::MAX);
    }

    #[test]
    fn invalid_link_preserves_last_predecessor() {
        let mut table = fresh_table();
        table.entries[3].next = 128;
        let mut out = POISON;

        assert_eq!(unsafe { mov_chain_table_find_predecessor(&table, 3, 99, &mut out) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(out, 3);
    }
}
