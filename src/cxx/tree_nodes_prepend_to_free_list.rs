//! `tree_nodes_prepend_to_free_list` — originals: `FUN_083bd1b0` @
//! `0x083bd1b0`, `FUN_083cf444` @ `0x083cf444`, `FUN_083cea00` @
//! `0x083cea00`, and `FUN_083c81f0` @ `0x083c81f0`.
//!
//! Each is 60 bytes: `0x083bd1b0..0x083bd1ec`, `0x083cf444..0x083cf480`,
//! `0x083cea00..0x083cea3c`, and `0x083c81f0..0x083c822c`; a `push` begins
//! the next separately linked function at each endpoint. Raw A32 decoding
//! verifies one plain direct recursive `bl` in each body and no predicated
//! `bl` instructions. Whole-image decoding finds two inbound plain `bl`
//! calls for `FUN_083bd1b0` (`0x083bcfb0` and its recursive call at
//! `0x083bd1c8`), with no predicated inbound calls.
//! `FUN_083cea00` and `FUN_083c81f0` are deliberate shared-symbol aliases
//! rather than duplicate implementations; whole-image aligned A32 decoding
//! finds two inbound unconditional plain BL sites for `FUN_083c81f0`
//! (`0x083c7ee4`, `0x083c8208`) and no predicated direct callers.
//!
//! Walks a binary tree whose link words are at node+8 and node+12. It visits
//! each node+12 subtree first, pushes the node onto owner+4, then continues
//! along node+8. The node+12 word becomes the free-list link.
//!
//! Deliberate deviations: none.

const OWNER_FREE_LIST_WORD: usize = 0x04 / 4;
const NODE_NEXT_SUBTREE_WORD: usize = 0x08 / 4;
const NODE_RECURSIVE_SUBTREE_WORD: usize = 0x0c / 4;

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut u32 { word as usize as *mut u32 }

/// Moves a tree's nodes onto the owner free list.
///
/// # Safety
///
/// `owner` must have a writable target-width free-list word at +4. Every
/// nonzero link in `node`'s tree must identify a writable four-word node at a
/// target-width address.
#[cfg_attr(target_os = "none", link_section = ".text.tree_nodes_prepend_to_free_list")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_nodes_prepend_to_free_list(owner: *mut u32, mut node: *mut u32) {
    unsafe {
        while !node.is_null() {
            tree_nodes_prepend_to_free_list(owner, node_from_word(node.add(NODE_RECURSIVE_SUBTREE_WORD).read()));
            let free_list = owner.add(OWNER_FREE_LIST_WORD).read();
            let next = node_from_word(node.add(NODE_NEXT_SUBTREE_WORD).read());
            node.add(NODE_RECURSIVE_SUBTREE_WORD).write(free_list);
            owner.add(OWNER_FREE_LIST_WORD).write(node as usize as u32);
            node = next;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    unsafe fn node(slab: *mut u8, offset: usize) -> *mut u32 { unsafe { slab.add(offset).cast() } }

    #[test]
    fn preserves_existing_free_list_for_an_empty_tree() {
        let Some(slab) = try_map_u32_slab(hints::TREE_NODES_PREPEND_TO_FREE_LIST, 0x1000) else {
            note_missing_u32_fixture("cxx/tree_nodes_prepend_to_free_list");
            return;
        };
        unsafe {
            let owner = slab.cast::<u32>();
            owner.add(OWNER_FREE_LIST_WORD).write(0x1234_5678);
            tree_nodes_prepend_to_free_list(owner, ptr::null_mut());
            assert_eq!(owner.add(OWNER_FREE_LIST_WORD).read(), 0x1234_5678);
        }
    }

    #[test]
    fn visits_recursive_subtrees_before_next_subtrees() {
        let Some(slab) = try_map_u32_slab(hints::TREE_NODES_PREPEND_TO_FREE_LIST, 0x2000) else {
            note_missing_u32_fixture("cxx/tree_nodes_prepend_to_free_list");
            return;
        };
        unsafe {
            let owner = slab.cast::<u32>();
            let root = node(slab, 0x100);
            let left = node(slab, 0x120);
            let right = node(slab, 0x140);
            let right_child = node(slab, 0x160);
            let existing = node(slab, 0x180);
            ptr::write_bytes(slab, 0, 0x2000);
            owner.add(OWNER_FREE_LIST_WORD).write(existing as usize as u32);
            root.add(NODE_NEXT_SUBTREE_WORD).write(left as usize as u32);
            root.add(NODE_RECURSIVE_SUBTREE_WORD).write(right as usize as u32);
            right.add(NODE_RECURSIVE_SUBTREE_WORD).write(right_child as usize as u32);

            tree_nodes_prepend_to_free_list(owner, root);

            assert_eq!(owner.add(OWNER_FREE_LIST_WORD).read(), left as usize as u32);
            assert_eq!(left.add(NODE_RECURSIVE_SUBTREE_WORD).read(), root as usize as u32);
            assert_eq!(root.add(NODE_RECURSIVE_SUBTREE_WORD).read(), right as usize as u32);
            assert_eq!(right.add(NODE_RECURSIVE_SUBTREE_WORD).read(), right_child as usize as u32);
            assert_eq!(right_child.add(NODE_RECURSIVE_SUBTREE_WORD).read(), existing as usize as u32);
        }
    }

    #[test]
    fn processes_each_next_subtree_after_its_recursive_subtree() {
        let Some(slab) = try_map_u32_slab(hints::TREE_NODES_PREPEND_TO_FREE_LIST, 0x2000) else {
            note_missing_u32_fixture("cxx/tree_nodes_prepend_to_free_list");
            return;
        };
        unsafe {
            let owner = slab.cast::<u32>();
            let root = node(slab, 0x100);
            let root_next = node(slab, 0x120);
            let recursive = node(slab, 0x140);
            let recursive_next = node(slab, 0x160);
            let recursive_child = node(slab, 0x180);
            let existing = node(slab, 0x1a0);
            ptr::write_bytes(slab, 0, 0x2000);
            owner.add(OWNER_FREE_LIST_WORD).write(existing as usize as u32);
            root.add(NODE_NEXT_SUBTREE_WORD).write(root_next as usize as u32);
            root.add(NODE_RECURSIVE_SUBTREE_WORD).write(recursive as usize as u32);
            recursive.add(NODE_NEXT_SUBTREE_WORD).write(recursive_next as usize as u32);
            recursive.add(NODE_RECURSIVE_SUBTREE_WORD).write(recursive_child as usize as u32);

            tree_nodes_prepend_to_free_list(owner, root);

            assert_eq!(owner.add(OWNER_FREE_LIST_WORD).read(), root_next as usize as u32);
            assert_eq!(root_next.add(NODE_RECURSIVE_SUBTREE_WORD).read(), root as usize as u32);
            assert_eq!(root.add(NODE_RECURSIVE_SUBTREE_WORD).read(), recursive as usize as u32);
            assert_eq!(recursive.add(NODE_RECURSIVE_SUBTREE_WORD).read(), recursive_next as usize as u32);
            assert_eq!(recursive_next.add(NODE_RECURSIVE_SUBTREE_WORD).read(), recursive_child as usize as u32);
            assert_eq!(recursive_child.add(NODE_RECURSIVE_SUBTREE_WORD).read(), existing as usize as u32);
        }
    }
}
