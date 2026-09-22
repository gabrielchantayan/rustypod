//! Counts MOV chain links between two table slots.
//!
//! Original: `FUN_0820c9ec` at 0x0820c9ec. Raw `osos.dec` establishes the
//! exact 96-byte extent (0x0820c9ec..0x0820ca4b): the next function starts
//! with `push {r4,r5,r6,r7,r8,lr}` at 0x0820ca4c. Whole-image A32 decoding
//! finds three inbound plain `bl` calls (0x081e4c40, 0x081e4c64, and
//! 0x081e4d4c), zero predicated `bl` calls, and one outbound unconditional
//! `bl` to the established `mov_chain_table_next` seam at 0x0820c8a0.
//!
//! The routine clears `*count`, then follows next-slot links from `start`
//! until it reaches `end`. Each successful link read increments `*count`.
//! Link-read failure, or a 129th successful read, returns status 2; reaching
//! `end` first returns status 0. Deliberate deviations: none.

use super::chain_table::{mov_chain_table_next, MovChainTable, MOV_CHAIN_TABLE_ERR, MOV_CHAIN_TABLE_OK};

/// Counts links from `start` until `end` is reached.
///
/// # Safety
///
/// `table` must identify readable entries for every traversed slot and `count`
/// must be writable. Neither pointer is NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_count_steps")]
pub unsafe extern "C" fn mov_chain_table_count_steps(
    table: *const MovChainTable,
    start: u32,
    end: u32,
    count: *mut u32,
) -> i32 {
    unsafe { core::ptr::write(count, 0) };
    let mut current = start;

    loop {
        if current == end {
            return MOV_CHAIN_TABLE_OK;
        }

        let mut next = 0;
        if unsafe { mov_chain_table_next(table, current, &mut next) } != MOV_CHAIN_TABLE_OK {
            return MOV_CHAIN_TABLE_ERR;
        }

        let updated_count = unsafe { core::ptr::read(count) } + 1;
        unsafe { core::ptr::write(count, updated_count) };
        if updated_count > 128 {
            return MOV_CHAIN_TABLE_ERR;
        }
        current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mov::chain_table::{MovChainEntry, MOV_CHAIN_TABLE_SLOTS};

    fn fresh_table() -> MovChainTable {
        MovChainTable {
            entries: [const {
                MovChainEntry { field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3], next: 0, field_10: 0 }
            }; MOV_CHAIN_TABLE_SLOTS],
        }
    }

    #[test]
    fn zeroes_count_when_start_is_end() {
        let table = fresh_table();
        let mut count = 0xdead_beef;

        assert_eq!(unsafe { mov_chain_table_count_steps(&table, 7, 7, &mut count) }, MOV_CHAIN_TABLE_OK);
        assert_eq!(count, 0);
    }

    #[test]
    fn counts_every_successful_link_before_end() {
        let mut table = fresh_table();
        table.entries[4].next = 23;
        table.entries[23].next = 91;
        let mut count = 0;

        assert_eq!(unsafe { mov_chain_table_count_steps(&table, 4, 91, &mut count) }, MOV_CHAIN_TABLE_OK);
        assert_eq!(count, 2);
    }

    #[test]
    fn propagates_invalid_link_after_zeroing_count() {
        let mut table = fresh_table();
        table.entries[6].next = MOV_CHAIN_TABLE_SLOTS as u32;
        let mut count = 0xdead_beef;

        assert_eq!(unsafe { mov_chain_table_count_steps(&table, 6, 7, &mut count) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(count, 0);
    }

    #[test]
    fn rejects_the_129th_successful_link_and_records_it() {
        let mut table = fresh_table();
        table.entries[0].next = 0;
        let mut count = 0;

        assert_eq!(unsafe { mov_chain_table_count_steps(&table, 0, 1, &mut count) }, MOV_CHAIN_TABLE_ERR);
        assert_eq!(count, 129);
    }
}
