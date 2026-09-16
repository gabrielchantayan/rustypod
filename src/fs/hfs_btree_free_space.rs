//! `hfs_btree_free_space` — original: `FUN_08053e14` @ `0x08053e14`
//! (44 bytes, `0x08053e14..0x08053e40`; 5 verified direct `bl` call
//! sites, all unconditional; a leaf with zero calls of its own).
//!
//! # What it is
//!
//! The HFS B-tree node free-space probe — Apple's `FreeSpace` from the
//! classic `hfs` `BTreeIO.c`. The five callers (`0x08058d88`,
//! `0x080594c8`, `0x08064d3c`, `0x08064d50`, `0x0806b808`) all sit in
//! record-insert/split paths: `0x0806b808` compares the result plus the
//! space reclaimed by a record move against a new record's length to
//! decide whether the node must split, which is exactly how the classic
//! code uses `FreeSpace`.
//!
//! # Algorithm
//!
//! 1. `node_size` is the u16 at `btree + 0x1c` — the control block's
//!    `node_size` field, the same field [`crate::fs::hfs_btree_get_node`]
//!    publishes into each block descriptor.
//! 2. `num_records` is the u16 at `node + 0x0a` (the node descriptor's
//!    `numRecords`).
//! 3. The offset table grows down from the end of the node, so
//!    `*(u16 *)(node + node_size - 2 * num_records - 2)` is the
//!    one-past-the-end offset of record data (the table entry for
//!    "record" `num_records`).
//! 4. Return `node_size - that_offset - 2 * num_records - 2`: the gap
//!    between the end of record data and the start of the offset table,
//!    i.e. the bytes free for another record plus its table entry. The
//!    final result is truncated to a u16 by the original's
//!    `mov r0, r0, lsl #16` / `lsr #16` pair.
//!
//! # Deliberate deviations
//!
//! None. The original performs three `ldrh`s and pure arithmetic; the
//! port performs the same native-endian (little-endian on target) u16
//! reads at the same offsets and the same wrapping u32 subtraction
//! chain, with the same final 16-bit truncation.

use super::hfs_btree_get_node::BTreeControlBlock;
use super::hfs_btree_get_record::NUM_RECORDS_OFFSET;

/// Byte length of one entry in the node's descending offset table.
const OFFSET_TABLE_ENTRY_SIZE: usize = 2;

/// Free bytes in an HFS B-tree node: the gap between the end of record
/// data and the descending record-offset table, already net of the table
/// entry a new record would consume. Original: `FUN_08053e14`.
///
/// # Safety
///
/// `btree` must point to a valid [`BTreeControlBlock`] and `node` to a
/// readable node buffer of at least `btree.node_size` bytes whose
/// descriptor and offset-table entries are in range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_free_space(
    btree: *const BTreeControlBlock,
    node: *const u8,
) -> u16 {
    let node_size = u32::from((*btree).node_size);
    let num_records = u32::from((node.add(NUM_RECORDS_OFFSET) as *const u16).read());
    let table_entry = node
        .add(node_size as usize)
        .sub(OFFSET_TABLE_ENTRY_SIZE * num_records as usize + OFFSET_TABLE_ENTRY_SIZE)
        as *const u16;
    let data_end_offset = u32::from(table_entry.read());
    (node_size
        .wrapping_sub(data_end_offset)
        .wrapping_sub(OFFSET_TABLE_ENTRY_SIZE as u32 * num_records)
        .wrapping_sub(OFFSET_TABLE_ENTRY_SIZE as u32)) as u16
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::hfs_btree_get_node::BTreeControlBlock;
    use std::vec::Vec;

    const NODE_SIZE: usize = 512;

    struct Fixture {
        btree: BTreeControlBlock,
        node: Vec<u8>,
    }

    fn control_block(node_size: u16) -> BTreeControlBlock {
        BTreeControlBlock {
            reserved_00: [0; 2],
            tree_depth: 0,
            fork: 0,
            reserved_08: [0; 0x14],
            node_size,
            max_key_length: 0,
            total_nodes: 0,
            reserved_24: [0; 0x0c],
            attributes: 0,
            reserved_34: [0; 8],
            get_block_proc: 0,
            release_block_proc: 0,
            reserved_44: 0,
            num_get_nodes: 0,
            reserved_4c: 0,
            num_release_nodes: 0,
        }
    }

    /// Builds a node whose `record_offsets` (ascending, one per record,
    /// plus the mandatory end-of-data entry) are published into the
    /// descending table at the tail, exactly as on disk. Two headroom
    /// bytes are prepended so a zero `node_size` fixture keeps the
    /// end-of-data entry read inside the allocation.
    fn fixture(node_size: u16, record_offsets: &[u16]) -> Fixture {
        let mut node = std::vec![0u8; (node_size as usize).max(14) + 2];
        let num_records = record_offsets.len() - 1;
        node[2 + NUM_RECORDS_OFFSET..2 + NUM_RECORDS_OFFSET + 2]
            .copy_from_slice(&(num_records as u16).to_le_bytes());
        for (i, &off) in record_offsets.iter().enumerate() {
            let at = 2 + node_size as usize - 2 * (i + 1);
            node[at..at + 2].copy_from_slice(&off.to_le_bytes());
        }
        Fixture { btree: control_block(node_size), node }
    }

    unsafe fn free_space(f: &Fixture) -> u16 {
        hfs_btree_free_space(&f.btree, f.node.as_ptr().add(2))
    }

    /// Native u16 arithmetic, mirroring the ARM `sub` chain.
    fn reference(node_size: u16, num_records: u16, data_end_offset: u16) -> u16 {
        (node_size as u32)
            .wrapping_sub(data_end_offset as u32)
            .wrapping_sub(2 * num_records as u32)
            .wrapping_sub(2) as u16
    }

    #[test]
    fn empty_node_reports_node_size_minus_one_table_entry() {
        // Header-node layout: no records, offset table has just the
        // end-of-data entry at offset 14 (a bare node descriptor).
        let f = fixture(NODE_SIZE as u16, &[14]);
        let free = unsafe { free_space(&f) };
        assert_eq!(free, NODE_SIZE as u16 - 14 - 2);
        assert_eq!(free, reference(NODE_SIZE as u16, 0, 14));
    }

    #[test]
    fn fullish_node_leaves_only_the_record_gap() {
        // Three records ending at offset 400 in a 512-byte node.
        let f = fixture(NODE_SIZE as u16, &[14, 100, 250, 400]);
        let free = unsafe { free_space(&f) };
        // 512 - 400 - 3*2 - 2 = 104.
        assert_eq!(free, 104);
        assert_eq!(free, reference(NODE_SIZE as u16, 3, 400));
    }

    #[test]
    fn packed_node_reports_zero_free() {
        // Records run right up to the offset table:
        // 4 records => table occupies the last 10 bytes, data ends at
        // NODE_SIZE - 10.
        let data_end = (NODE_SIZE - 10) as u16;
        let f = fixture(NODE_SIZE as u16, &[14, 100, 200, 300, data_end]);
        let free = unsafe { free_space(&f) };
        assert_eq!(free, 0);
    }

    #[test]
    fn result_is_truncated_to_a_u16_like_the_original() {
        // The original's final mov-pair keeps only the low 16 bits. Feed
        // a node_size of 0 (a degenerate control block) so the
        // subtraction chain underflows; the result must wrap, not panic.
        let f = fixture(0, &[0]);
        let free = unsafe { free_space(&f) };
        assert_eq!(free, reference(0, 0, 0));
        assert_eq!(free, 0xfffe);
    }

    #[test]
    fn matches_reference_across_a_sweep_of_layouts() {
        for num_records in 0u16..8 {
            for data_end in (14u16..200).step_by(17) {
                let mut offsets = std::vec![14u16; num_records as usize + 1];
                *offsets.last_mut().unwrap() = data_end;
                let f = fixture(NODE_SIZE as u16, &offsets);
                let free = unsafe { free_space(&f) };
                assert_eq!(free, reference(NODE_SIZE as u16, num_records, data_end));
            }
        }
    }
}
