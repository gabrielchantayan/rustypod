//! First matching tag lookup in the MOV manager's fixed chain table.
//!
//! Original: `FUN_0820c86c` @ `0x0820c86c`, true size 52 bytes
//! (`0x0820c86c..0x0820c8a0`, next entry starts with `cmp r1,#128`).
//! Whole-image raw A32 decoding verifies two inbound plain BLs at
//! `0x0820c99c` and `0x0820ce20`, zero predicated inbound BLs, and zero
//! outbound BLs of either kind. Scan 128 entries of 20 bytes, comparing
//! the byte at +8 to the full u32 query. On the first match write its
//! index and return zero; otherwise return two without writing output.
//! Callers search for tag zero to allocate and tag two to retrieve a value.
//! Deliberate deviations: none; no narrowing of the query or NULL guards.

use super::chain_table::{MovChainTable, MOV_CHAIN_TABLE_SLOTS, MOV_CHAIN_TABLE_OK, MOV_CHAIN_TABLE_ERR};

/// # Safety
/// `table` must point to a readable table. `out` must be writable when a
/// matching entry exists; it may alias table storage. No pointers are
/// NULL-checked, matching stock.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mov_chain_table_find_tag(
    table: *const MovChainTable, out: *mut u32, tag: u32,
) -> i32 {
    let entries = unsafe { core::ptr::addr_of!((*table).entries).cast::<super::chain_table::MovChainEntry>() };
    let mut index = 0;
    while index < MOV_CHAIN_TABLE_SLOTS {
        let entry_tag = unsafe { core::ptr::addr_of!((*entries.add(index)).tag).read() };
        if entry_tag as u32 == tag {
            unsafe { out.write(index as u32); }
            return MOV_CHAIN_TABLE_OK;
        }
        index += 1;
    }
    MOV_CHAIN_TABLE_ERR
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::chain_table::MovChainEntry;

    fn table() -> MovChainTable {
        MovChainTable { entries: core::array::from_fn(|_| MovChainEntry {
            field_00: 0xfeedbeef, field_04: 0, tag: 1, pad_09: [0; 3],
            next: u32::MAX, field_10: 0,
        }) }
    }

    #[test]
    fn every_slot_and_byte_tag_matches_without_changing_entries() {
        let mut table = table();
        for index in 0..MOV_CHAIN_TABLE_SLOTS {
            for tag in [0, 2, 127, 255] {
                table.entries[index].tag = tag;
                let mut out = u32::MAX;
                assert_eq!(unsafe { mov_chain_table_find_tag(&table, &mut out, tag as u32) }, 0);
                assert_eq!(out, index as u32);
                assert_eq!(table.entries[index].tag, tag);
                assert_eq!(table.entries[index].field_00, 0xfeedbeef);
                table.entries[index].tag = 1;
            }
        }
    }

    #[test]
    fn duplicates_choose_first_and_allow_output_aliasing() {
        let mut table = table();
        table.entries[3].tag = 2;
        table.entries[127].tag = 2;
        let out = core::ptr::addr_of_mut!(table.entries[3].field_00);
        assert_eq!(unsafe { mov_chain_table_find_tag(&table, out, 2) }, 0);
        assert_eq!(table.entries[3].field_00, 3);
        assert_eq!(table.entries[127].tag, 2);
    }

    #[test]
    fn missing_and_full_width_queries_preserve_output() {
        let mut table = table();
        table.entries[0].tag = 0;
        table.entries[127].tag = 255;
        for tag in [2, 256, 511, 0x10000, u32::MAX] {
            let mut out = 0x12345678;
            assert_eq!(unsafe { mov_chain_table_find_tag(&table, &mut out, tag) }, 2);
            assert_eq!(out, 0x12345678);
            assert_eq!(unsafe { mov_chain_table_find_tag(&table, core::ptr::null_mut(), tag) }, 2);
        }
    }
}
