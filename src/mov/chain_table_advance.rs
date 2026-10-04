//! Advances a MOV chain by a signed number of links.
//!
//! Original: `FUN_0820c818` @ 0x0820c818, true size 84 bytes
//! (0x0820c818..0x0820c86c; the next entry starts with `mov r3,#0`).
//! Whole-image raw A32 decoding verifies two inbound plain BLs at
//! 0x081e4cbc and 0x081e533c, zero predicated inbound BLs, and one
//! outbound plain BL at 0x0820c838 to `mov_chain_table_next` (0x0820c8a0).
//! Follow exactly `steps` links when positive, keeping the cursor local.
//! Nonpositive counts copy `start` without reading the table. Publish the
//! final cursor only on success; any failed read returns 2 without storing
//! to `out`. An end marker can be the final result, but cannot be traversed.
//! Cycles are allowed and bounded only by the requested count. Deliberate
//! deviations: none; no added cycle limit, pointer checks, or callee seam.

use super::chain_table::{mov_chain_table_next, MovChainTable, MOV_CHAIN_TABLE_ERR, MOV_CHAIN_TABLE_OK};

/// Advance `steps` links and store the resulting slot only on success.
///
/// # Safety
/// `table` must provide readable entries for traversed valid indices; it is
/// unused for nonpositive counts. `out` must be writable on success and may
/// alias a table field. Neither pointer is NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mov_chain_table_advance")]
pub unsafe extern "C" fn mov_chain_table_advance(
    table: *const MovChainTable,
    steps: i32,
    start: u32,
    out: *mut u32,
) -> i32 {
    let mut current = start;
    let mut completed = 0;
    while completed < steps {
        if unsafe { mov_chain_table_next(table, current, &mut current) } != MOV_CHAIN_TABLE_OK {
            return MOV_CHAIN_TABLE_ERR;
        }
        completed += 1;
    }
    unsafe { core::ptr::write(out, current) };
    MOV_CHAIN_TABLE_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mov::chain_table::{MovChainEntry, MOV_CHAIN_TABLE_SLOTS};

    fn table() -> MovChainTable {
        MovChainTable {
            entries: core::array::from_fn(|index| MovChainEntry {
                field_00: 0, field_04: 0, tag: 0, pad_09: [0; 3],
                next: (index as u32 + 1) % MOV_CHAIN_TABLE_SLOTS as u32, field_10: 0,
            }),
        }
    }

    fn reference(table: &MovChainTable, steps: i32, start: u32) -> Result<u32, i32> {
        let mut cursor = start;
        for _ in 0..steps {
            if cursor >= 128 { return Err(2); }
            cursor = table.entries[cursor as usize].next;
            if cursor >= 128 && cursor != u32::MAX { return Err(2); }
        }
        Ok(cursor)
    }

    #[test]
    fn signed_nonpositive_counts_do_not_read_table_or_validate_start() {
        for steps in [i32::MIN, -1, 0] {
            for start in [0, 127, 128, u32::MAX] {
                let mut out = 42;
                assert_eq!(unsafe { mov_chain_table_advance(core::ptr::null(), steps, start, &mut out) }, 0);
                assert_eq!(out, start);
            }
        }
    }

    #[test]
    fn matches_reference_for_cycles_boundaries_and_corrupt_links() {
        let mut table = table();
        for link in [0, 127, 128, 129, 0x8000_0000, u32::MAX] {
            table.entries[127].next = link;
            for start in [0, 126, 127, 128, 0x8000_0000, u32::MAX] {
                for steps in [1, 2, 3, 127, 128, 129, 257] {
                    let mut out = 0xdead_beef;
                    let expected = reference(&table, steps, start);
                    let status = unsafe { mov_chain_table_advance(&table, steps, start, &mut out) };
                    match expected {
                        Ok(cursor) => { assert_eq!(status, 0); assert_eq!(out, cursor); }
                        Err(error) => { assert_eq!(status, error); assert_eq!(out, 0xdead_beef); }
                    }
                }
            }
        }
    }

    #[test]
    fn aliased_output_is_published_only_after_traversal() {
        let mut table = table();
        let raw = core::ptr::addr_of_mut!(table);
        let out = unsafe { core::ptr::addr_of_mut!((*raw).entries[0].next) };
        assert_eq!(unsafe { mov_chain_table_advance(raw, 129, 0, out) }, 0);
        assert_eq!(table.entries[0].next, 1);
        assert_eq!(unsafe { mov_chain_table_advance(raw, 2, 0, out) }, 0);
        assert_eq!(table.entries[0].next, 2);
        table.entries[2].next = 128;
        assert_eq!(unsafe { mov_chain_table_advance(raw, 2, 0, out) }, 2);
        assert_eq!(table.entries[0].next, 2);
    }
}
