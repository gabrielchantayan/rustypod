//! Byte-key red-black-tree predecessor lookup.
//!
//! `byte_key_tree_find_predecessor` — original: `FUN_083d7248` @
//! `0x083d7248` (**180 bytes**, `0x083d7248..0x083d72fc`; the next separately
//! linked function begins at `0x083d72fc`). The body has four plain `bl`
//! instructions (`0x083d727c` and `0x083d72cc` to
//! `less_unsigned_byte_alias_73ec`, `0x083d72ac` to `equal_deref_f788_copy`,
//! and `0x083d72bc` to the node-key accessor `FUN_083b6a54`) and no predicated
//! BL instructions. Two inbound plain BL sites are `0x0829e31c` and
//! `0x0829e330`; there are no predicated inbound BL sites.
//!
//! Starting at the header's root link (`tree + 0x10`, then `header + 0x04`),
//! walk toward the right child when `node.key < key`, retaining that node as
//! the candidate; otherwise walk left. If the candidate is the header, or the
//! final `key < candidate.key` recheck holds, return the header. The result is
//! therefore the greatest node whose byte key is strictly less than `key`,
//! with the header as the no-result sentinel.
//!
//! # Deliberate deviations
//!
//! Target pointers are 32-bit words. This port retains the raw-word layout
//! instead of Rust pointer fields, so target offsets remain exact and host
//! fixtures can use a below-4-GiB slab. The node-key accessor is inlined as
//! its verified `node + 0x10` body; all other behavior is unchanged.

use crate::cxx::templates::less_unsigned_byte_alias_73ec;

const TREE_HEADER_OFFSET: usize = 0x10;
const HEADER_ROOT_OFFSET: usize = 0x04;
const NODE_RIGHT_OFFSET: usize = 0x08;
const NODE_LEFT_OFFSET: usize = 0x0c;
const NODE_KEY_OFFSET: usize = 0x10;

#[inline(always)]
unsafe fn raw_pointer(word: u32) -> *mut u8 {
    word as usize as *mut u8
}

#[inline(always)]
unsafe fn pointer_word(address: *const u8) -> u32 {
    address.cast::<u32>().read()
}

/// # Safety
///
/// `tree`, its header, every traversed node, and `key` must be readable. All
/// stored pointer words must be valid target addresses. As in retailOS, no
/// pointer or tree-invariant checks are performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_find_predecessor(
    tree: *const u8,
    key: *const u8,
) -> *mut u8 {
    let header = raw_pointer(pointer_word(tree.add(TREE_HEADER_OFFSET)));
    let mut candidate = header;
    let mut node = raw_pointer(pointer_word(header.add(HEADER_ROOT_OFFSET)));

    while !node.is_null() {
        if less_unsigned_byte_alias_73ec(tree.add(0x19), node.add(NODE_KEY_OFFSET), key) == 0 {
            node = raw_pointer(pointer_word(node.add(NODE_LEFT_OFFSET)));
        } else {
            candidate = node;
            node = raw_pointer(pointer_word(node.add(NODE_RIGHT_OFFSET)));
        }
    }

    if candidate != header
        && less_unsigned_byte_alias_73ec(tree.add(0x19), key, candidate.add(NODE_KEY_OFFSET)) == 0
    {
        return candidate;
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const TREE_OFFSET: usize = 0x00;
    const HEADER_OFFSET: usize = 0x40;
    const NODE_FIVE_OFFSET: usize = 0x80;
    const NODE_THREE_OFFSET: usize = 0xc0;
    const NODE_SEVEN_OFFSET: usize = 0x100;
    const SLAB_SIZE: usize = 0x200;

    unsafe fn word_at(base: *mut u8, offset: usize) -> *mut u32 {
        base.add(offset).cast()
    }

    unsafe fn node(base: *mut u8, offset: usize, key: u8, right: u32, left: u32) {
        word_at(base, offset + NODE_RIGHT_OFFSET).write(right);
        word_at(base, offset + NODE_LEFT_OFFSET).write(left);
        base.add(offset + NODE_KEY_OFFSET).write(key);
    }

    #[test]
    fn finds_predecessors_and_returns_header_for_below_minimum() {
        let Some(base) = try_map_u32_slab(hints::BYTE_KEY_TREE_FIND_PREDECESSOR, SLAB_SIZE) else {
            return;
        };
        unsafe {
            base.write_bytes(0, SLAB_SIZE);
            let tree = base.add(TREE_OFFSET);
            let header = base.add(HEADER_OFFSET);
            let five = base.add(NODE_FIVE_OFFSET);
            let three = base.add(NODE_THREE_OFFSET);
            let seven = base.add(NODE_SEVEN_OFFSET);
            word_at(tree, TREE_HEADER_OFFSET).write(header as usize as u32);
            word_at(header, HEADER_ROOT_OFFSET).write(five as usize as u32);
            node(base, NODE_FIVE_OFFSET, 5, seven as usize as u32, three as usize as u32);
            node(base, NODE_THREE_OFFSET, 3, 0, 0);
            node(base, NODE_SEVEN_OFFSET, 7, 0, 0);

            for (key, expected) in [(0, header), (3, header), (4, three), (5, three), (6, five), (7, five), (255, seven)] {
                assert_eq!(byte_key_tree_find_predecessor(tree, &key), expected, "key={key}");
            }
        }
    }

    #[test]
    fn empty_tree_returns_its_header_without_reading_a_node() {
        let Some(base) = try_map_u32_slab(hints::BYTE_KEY_TREE_FIND_PREDECESSOR_EMPTY, SLAB_SIZE) else {
            return;
        };
        unsafe {
            base.write_bytes(0, SLAB_SIZE);
            let tree = base.add(TREE_OFFSET);
            let header = base.add(HEADER_OFFSET);
            word_at(tree, TREE_HEADER_OFFSET).write(header as usize as u32);
            let key = 42;
            assert_eq!(byte_key_tree_find_predecessor(tree, &key), header);
        }
    }
}
