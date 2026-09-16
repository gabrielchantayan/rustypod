//! `hfs_btree_get_record` — original: `FUN_08054a04` @ `0x08054a04`
//! (140 bytes, `0x08054a04..0x08054a90`; 5 verified direct `bl` call
//! sites, all unconditional: `0x080416f8`, `0x08041f04`, `0x08048d80`,
//! `0x08058fc8`, `0x080662ec`; no outgoing calls — a leaf).
//!
//! # What it is
//!
//! Apple's `GetRecord` from the classic `hfs` `BTreeNodeOps.c`: given a
//! B-tree node buffer and a record index, hand back the record's key
//! pointer, data pointer, and data length. The control block is the same
//! [`BTreeControlBlock`] used by [`crate::fs::hfs_btree_get_node`]
//! (`GetNode`): the node size lives at `+0x1c` and the attributes word at
//! `+0x30`, whose bit 1 is Apple's `kBTBigKeysMask` (set on HFS+:
//! two-byte key length; clear on plain HFS: one-byte key length).
//!
//! # Algorithm
//!
//! 1. `num_records` is the u16 at `node + 0x0a` (the node descriptor's
//!    `numRecords`). If `index >= num_records` — an *unsigned*
//!    `cmp`/`bls` — return [`BTREE_INVALID_INDEX_STATUS`] (0x20).
//! 2. The record-offset table grows downward from the end of the node:
//!    `record_offset = ldrh(node + node_size - 2*(index + 1))`.
//!    `*key_ptr = node + record_offset`.
//! 3. The data follows the key, padded to an even offset:
//!    `data_offset = record_offset + key_length + 1` (small keys, the
//!    length byte counts itself) or `+ key_length + 2` (big keys). If the
//!    sum is odd, add 1.
//! 4. `*data_ptr = node + data_offset`.
//! 5. `*data_size = next_record_offset - data_offset`, where
//!    `next_record_offset = ldrh(node + node_size - 2*(index + 2))`; the
//!    difference is truncated to a u16 by the original's `strh`.
//! 6. Return 0.
//!
//! # Deliberate deviations
//!
//! None semantic. The original's `bic r3, r3, #0x10000` after each
//! addition — clearing bit 16 of the 32-bit accumulator, an artifact of
//! its source's 16-bit arithmetic carried in a 32-bit register — is
//! preserved literally. Struct field offsets are asserted at compile time
//! via [`BTreeControlBlock`]. LLVM codegen differences (folded address
//! arithmetic, a different predicate split) are expected under match.py;
//! the control flow and field offsets are identical.

use super::hfs_btree_get_node::BTreeControlBlock;

/// Status returned when `index` is not a live record of the node: the
/// firmware's stand-in for Apple's `fsBTInvalidNodeErr`. Distinct from
/// `CheckNode`'s 36 (`hfs_btree_get_node::BTREE_INVALID_NODE_STATUS`).
pub const BTREE_INVALID_INDEX_STATUS: i32 = 0x20;

/// Apple's `kBTBigKeysMask` in the control block's attributes word: set
/// when record keys carry a two-byte length (HFS+), clear for a one-byte
/// length (HFS).
pub const BIG_KEYS_ATTRIBUTE: u32 = 0x2;

/// Byte offset of the node descriptor's `numRecords` field.
pub const NUM_RECORDS_OFFSET: usize = 0x0a;

/// Locates record `index` of the node at `node` and publishes its key
/// pointer, data pointer, and data length.
///
/// # Safety
/// `btree` must point to a valid [`BTreeControlBlock`] (only
/// `node_size` and `attributes` are read). `node` must point to a valid
/// node buffer of `node_size` bytes whose descriptor and offset table are
/// consistent with `index`. All reads are naturally aligned halfword or
/// byte reads, matching the original; `key_ptr`, `data_ptr`, and
/// `data_size` must be valid for writes of a u32, a u32, and a u16.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_get_record(
    btree: *const BTreeControlBlock,
    node: *const u8,
    index: u32,
    key_ptr: *mut u32,
    data_ptr: *mut u32,
    data_size: *mut u16,
) -> i32 {
    let num_records = (node.add(NUM_RECORDS_OFFSET) as *const u16).read() as u32;
    if num_records <= index {
        return BTREE_INVALID_INDEX_STATUS;
    }
    let node_size = (*btree).node_size as usize;
    let table_entry = node.add(node_size).sub(2 * index as usize + 2) as *const u16;
    let record_offset = table_entry.read() as u32;
    let key = node.add(record_offset as usize);
    key_ptr.write(key as u32);

    let attributes = (*btree).attributes;
    let mut data_offset: u32 = if attributes & BIG_KEYS_ATTRIBUTE == 0 {
        (key as *const u8).read() as u32 + 1
    } else {
        (key as *const u16).read() as u32 + 2
    };
    data_offset &= 0xfffe_ffff;
    if data_offset & 1 != 0 {
        data_offset = (data_offset + 1) & 0xfffe_ffff;
    }
    data_offset = (record_offset + data_offset) & 0xfffe_ffff;
    data_ptr.write(node.add(data_offset as usize) as u32);

    let next_record_offset = table_entry.sub(1).read() as u32;
    data_size.write(next_record_offset.wrapping_sub(data_offset) as u16);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    /// Build a control block and a node buffer holding `records` records
    /// (key bytes, data bytes). Key bytes include their own length prefix:
    /// one byte when `big_keys` is clear, two little-endian bytes when
    /// set. Returns (btree, node) with a well-formed descriptor and
    /// offset table.
    fn fixture(records: &[(std::vec::Vec<u8>, std::vec::Vec<u8>)], big_keys: bool) -> (BTreeControlBlock, Vec<u8>) {
        const NODE_SIZE: usize = 0x200;
        let mut node = std::vec![0u8; NODE_SIZE];
        // Node descriptor: numRecords at +0x0a.
        node[NUM_RECORDS_OFFSET..NUM_RECORDS_OFFSET + 2]
            .copy_from_slice(&(records.len() as u16).to_le_bytes());

        let mut offsets = std::vec::Vec::new();
        let mut pos = 0x0eusize; // records start after the descriptor
        for (key, data) in records {
            offsets.push(pos as u16);
            let len_prefix = if big_keys { 2 } else { 1 };
            node[pos..pos + len_prefix].copy_from_slice(
                &(key.len() as u16).to_le_bytes()[..len_prefix],
            );
            node[pos + len_prefix..pos + len_prefix + key.len()].copy_from_slice(key);
            let mut data_pos = pos + len_prefix + key.len();
            if data_pos & 1 != 0 {
                data_pos += 1;
            }
            node[data_pos..data_pos + data.len()].copy_from_slice(data);
            pos = data_pos + data.len();
            if pos & 1 != 0 {
                pos += 1;
            }
        }
        offsets.push(pos as u16);
        // Offset table grows downward from the end of the node:
        // entry[i] at NODE_SIZE - 2*(i+1).
        for (i, off) in offsets.iter().enumerate() {
            let at = NODE_SIZE - 2 * (i + 1);
            node[at..at + 2].copy_from_slice(&off.to_le_bytes());
        }

        let btree = BTreeControlBlock {
            reserved_00: [0; 2],
            tree_depth: 0,
            fork: 0,
            reserved_08: [0; 0x14],
            node_size: NODE_SIZE as u16,
            max_key_length: 0,
            total_nodes: 0,
            reserved_24: [0; 0x0c],
            attributes: if big_keys { BIG_KEYS_ATTRIBUTE } else { 0 },
            reserved_34: [0; 8],
            get_block_proc: 0,
            release_block_proc: 0,
            reserved_44: 0,
            num_get_nodes: 0,
            reserved_4c: 0,
            num_release_nodes: 0,
        };
        (btree, node)
    }

    /// Independent reference for one record, straight from the algorithm
    /// description.
    fn reference(node: &[u8], index: usize, big_keys: bool) -> (usize, usize, u16) {
        let record_offset =
            u16::from_le_bytes([node[node.len() - 2 * (index + 1)], node[node.len() - 2 * (index + 1) + 1]])
                as usize;
        let key = record_offset;
        let mut data_offset = if big_keys {
            record_offset + u16::from_le_bytes([node[key], node[key + 1]]) as usize + 2
        } else {
            record_offset + node[key] as usize + 1
        };
        if data_offset & 1 != 0 {
            data_offset += 1;
        }
        let next = u16::from_le_bytes([node[node.len() - 2 * (index + 2)], node[node.len() - 2 * (index + 2) + 1]])
            as usize;
        (key, data_offset, (next - data_offset) as u16)
    }

    fn call(
        btree: &BTreeControlBlock,
        node: &[u8],
        index: u32,
    ) -> (i32, u32, u32, u16) {
        let mut key_ptr = 0u32;
        let mut data_ptr = 0u32;
        let mut data_size = 0u16;
        let status = unsafe {
            hfs_btree_get_record(
                btree,
                node.as_ptr(),
                index,
                &mut key_ptr,
                &mut data_ptr,
                &mut data_size,
            )
        };
        (status, key_ptr, data_ptr, data_size)
    }

    #[test]
    fn index_at_num_records_is_rejected() {
        let records = [(std::vec![0xAAu8, 0xBB], std::vec![1u8, 2, 3, 4])];
        let (btree, node) = fixture(&records, false);
        let base = node.as_ptr() as usize as u32;
        let (status, key_ptr, _, _) = call(&btree, &node, 1);
        assert_eq!(status, BTREE_INVALID_INDEX_STATUS);
        // Index 0 is live; index 1 is exactly numRecords and fails.
        let (status0, key_ptr0, _, _) = call(&btree, &node, 0);
        assert_eq!(status0, 0);
        assert!(key_ptr0 >= base);
        let _ = key_ptr;
    }

    #[test]
    fn small_keys_record_layout() {
        let records = [
            (std::vec![0x10u8, 0x20, 0x30], std::vec![0xDEu8, 0xAD]),
            (std::vec![0x44u8], std::vec![9u8, 8, 7]),
        ];
        let (btree, node) = fixture(&records, false);
        let base = node.as_ptr() as usize as u32;
        for index in 0..records.len() {
            let (status, key_ptr, data_ptr, data_size) = call(&btree, &node, index as u32);
            assert_eq!(status, 0);
            let (r_key, r_data, r_size) = reference(&node, index, false);
            assert_eq!(key_ptr - base, r_key as u32, "key offset, index {index}");
            assert_eq!(data_ptr - base, r_data as u32, "data offset, index {index}");
            assert_eq!(data_size, r_size, "data size, index {index}");
            assert_eq!(r_data & 1, 0, "data pointer must be even");
        }
    }

    #[test]
    fn big_keys_record_layout() {
        let records = [
            (std::vec![0x11u8, 0x22, 0x33, 0x44, 0x55], std::vec![0xABu8, 0xCD, 0xEF]),
            (std::vec![0x66u8, 0x77], std::vec![0x01u8]),
        ];
        let (btree, node) = fixture(&records, true);
        let base = node.as_ptr() as usize as u32;
        for index in 0..records.len() {
            let (status, key_ptr, data_ptr, data_size) = call(&btree, &node, index as u32);
            assert_eq!(status, 0);
            let (r_key, r_data, r_size) = reference(&node, index, true);
            assert_eq!(key_ptr - base, r_key as u32, "key offset, index {index}");
            assert_eq!(data_ptr - base, r_data as u32, "data offset, index {index}");
            assert_eq!(data_size, r_size, "data size, index {index}");
        }
    }

    #[test]
    fn odd_data_offset_is_padded_to_even() {
        // One-byte length 1 + one key byte lands the data on an odd
        // offset; the original pads by one.
        let records = [(std::vec![0x42u8], std::vec![0xEEu8, 0xEE])];
        let (btree, node) = fixture(&records, false);
        let base = node.as_ptr() as usize as u32;
        let (status, _, data_ptr, _) = call(&btree, &node, 0);
        assert_eq!(status, 0);
        assert_eq!((data_ptr - base) & 1, 0);
        // Record starts at 0x0e: len at 0x0e, key byte at 0x0f,
        // data padded to 0x10.
        assert_eq!(data_ptr - base, 0x10);
    }

    #[test]
    fn data_size_uses_next_table_entry() {
        // Last record's size runs to the trailing table entry (end of
        // used space), not to node_size.
        let records = [(std::vec![0x01u8, 0x02], std::vec![0x77u8, 0x88, 0x99, 0xAA])];
        let (btree, node) = fixture(&records, false);
        let (status, _, _, data_size) = call(&btree, &node, 0);
        assert_eq!(status, 0);
        assert_eq!(data_size, 4);
    }

    #[test]
    fn index_far_past_end_is_rejected_unsigned() {
        // The original's cmp/bls is unsigned: 0xffff_ffff is "greater".
        let records = [(std::vec![0x01u8], std::vec![0x02u8])];
        let (btree, node) = fixture(&records, false);
        let (status, _, _, _) = call(&btree, &node, 0xffff_ffff);
        assert_eq!(status, BTREE_INVALID_INDEX_STATUS);
    }
}
