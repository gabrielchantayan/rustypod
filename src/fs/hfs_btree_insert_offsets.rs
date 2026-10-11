//! HFS B-tree offset-table insertion — `FUN_0805945c` @ `0x0805945c`.
//! True extent: `0x0805945c..0x080594b0` (84 bytes), ending immediately
//! before the next independently called function's PUSH prologue. Raw A32
//! verifies two incoming plain BLs (0x08058df8, 0x08059524), no predicated
//! incoming BLs, and zero outgoing plain or predicated BLs.
//!
//! Increment numRecords, then copy the descending table's old end-of-data
//! entry and subsequent record offsets one halfword toward lower addresses,
//! adding the inserted record's byte length modulo 65536. The inclusive
//! loop copies `(old_count - index) mod 65536 + 1` entries, even when index
//! equals old_count. The caller moves record bytes separately.
//! Deliberate deviations: none; native-endian aligned halfword accesses,
//! wrapping count, displacement and loop arithmetic match the firmware.

use super::hfs_btree_get_node::BTreeControlBlock;
use super::hfs_btree_get_record::NUM_RECORDS_OFFSET;

/// Insert a slot in the descending record-offset table.
///
/// # Safety
/// `btree` must be readable, and `node` must be halfword-aligned and writable.
/// The count field and every source/destination halfword of the inclusive
/// wrapping loop must lie within the allocation. Normal callers provide
/// `index <= numRecords` and room for the additional offset-table entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_insert_offsets(
    btree: *const BTreeControlBlock,
    node: *mut u8,
    index: u32,
    record_size: u32,
) {
    let count_ptr = node.add(NUM_RECORDS_OFFSET).cast::<u16>();
    let old_count = count_ptr.read();
    let node_size = (*btree).node_size as usize;
    count_ptr.write(old_count.wrapping_add(1));
    let mut remaining = (old_count as u32).wrapping_sub(index) as u16;
    let mut source = node.add(node_size).cast::<u16>().sub(old_count as usize + 1);
    let mut destination = source.sub(1);
    loop {
        destination.write(source.read().wrapping_add(record_size as u16));
        source = source.add(1);
        destination = destination.add(1);
        let previous = remaining;
        remaining = remaining.wrapping_sub(1);
        if previous == 0 { break; }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn inserts_at_every_position_and_preserves_unaffected_bytes() {
        for count in 0..=8u16 {
            for index in 0..=count {
                for delta in [0u32, 2, 65535, 65536, 0xffff_fff0] {
                    let mut tree: BTreeControlBlock = unsafe { core::mem::zeroed() };
                    tree.node_size = 128;
                    let mut node = [0xa55au16; 64];
                    node[NUM_RECORDS_OFFSET / 2] = count;
                    for record in 0..=count as usize {
                        node[63 - record] = (record as u16).wrapping_mul(0x4001).wrapping_add(0xfff0);
                    }
                    let before = node;
                    let mut expected = before;
                    expected[NUM_RECORDS_OFFSET / 2] = count + 1;
                    for record in index as usize..=count as usize {
                        expected[62 - record] = before[63 - record].wrapping_add(delta as u16);
                    }
                    unsafe { hfs_btree_insert_offsets(&tree, node.as_mut_ptr().cast(), index as u32, delta); }
                    assert_eq!(node, expected, "count={count} index={index} delta={delta}");
                }
            }
        }
    }

    #[test]
    fn count_wraps_and_equal_index_still_moves_sentinel() {
        let mut tree: BTreeControlBlock = unsafe { core::mem::zeroed() };
        tree.node_size = 0;
        let mut storage = vec![0xa55au16; 65544];
        // Headroom keeps the original's negative table offset in-bounds.
        let node_index = 65537;
        storage[node_index + NUM_RECORDS_OFFSET / 2] = 65535;
        storage[1] = 0xfffe;
        let mut expected = storage.clone();
        expected[node_index + NUM_RECORDS_OFFSET / 2] = 0;
        expected[0] = 1;
        unsafe { hfs_btree_insert_offsets(&tree, storage.as_mut_ptr().add(node_index).cast(), 65535, 3); }
        assert_eq!(storage, expected);
    }
}
