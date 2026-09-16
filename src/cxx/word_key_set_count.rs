//! Count equivalent keys in the word-keyed red-black tree.
//!
//! [`word_key_set_count`] — original: `FUN_083d72fc` @ `0x083d72fc`.
//! Raw `osos.dec` establishes the 60-byte extent `0x083d72fc..0x083d7338`;
//! `ldr r0,[r0]` at `0x083d7338` starts the independently linked successor.
//! The body has two direct outgoing `bl` instructions, both unconditional
//! (`0x083d730c` to lower/upper-bound helper `0x083d6644`, and `0x083d7328`
//! to iterator distance `0x083e7c14`); it has no predicated `bl` instructions.
//!
//! The stock code obtains the equal range with unsigned-word lower and upper
//! bounds, then counts successor steps from the lower bound to the upper bound.
//! This port inlines those two unported, verified helpers rather than creating
//! exports for them. No deliberate behavioral deviations.

use super::word_key_set::{WordKeySet, WordKeySetNode};

unsafe fn lower_bound(tree: *const WordKeySet, key: u32) -> *mut WordKeySetNode {
    let mut node = (*(*tree).header).parent;
    let mut result = (*tree).header;

    while !node.is_null() {
        if (*node).key < key {
            node = (*node).right;
        } else {
            result = node;
            node = (*node).left;
        }
    }
    result
}

unsafe fn upper_bound(tree: *const WordKeySet, key: u32) -> *mut WordKeySetNode {
    let mut node = (*(*tree).header).parent;
    let mut result = (*tree).header;

    while !node.is_null() {
        if key < (*node).key {
            result = node;
            node = (*node).left;
        } else {
            node = (*node).right;
        }
    }
    result
}

unsafe fn successor(mut node: *mut WordKeySetNode) -> *mut WordKeySetNode {
    if !(*node).right.is_null() {
        node = (*node).right;
        while !(*node).left.is_null() {
            node = (*node).left;
        }
        return node;
    }

    let mut parent = (*node).parent;
    while (*parent).right == node {
        node = parent;
        parent = (*parent).parent;
    }
    parent
}

/// Count elements whose unsigned 32-bit key equals `*key`.
///
/// # Safety
/// `tree` must be a live [`WordKeySet`] with a libstdc++-style header node,
/// and `key` must point to a readable word. Tree links must form a valid
/// ordered red-black tree.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_key_set_count(tree: *const WordKeySet, key: *const u32) -> u32 {
    let key = *key;
    let mut node = lower_bound(tree, key);
    let upper = upper_bound(tree, key);
    let mut count: u32 = 0;

    while node != upper {
        count = count.wrapping_add(1);
        node = successor(node);
    }
    count
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::null_mut;
    use std::{boxed::Box, vec::Vec};

    fn node(key: u32) -> Box<WordKeySetNode> {
        Box::new(WordKeySetNode {
            color: 0,
            _pad: [0; 3],
            parent: null_mut(),
            left: null_mut(),
            right: null_mut(),
            key,
        })
    }

    unsafe fn tree_with_sorted_keys(keys: &[u32]) -> (WordKeySet, Box<WordKeySetNode>, Vec<Box<WordKeySetNode>>) {
        let mut nodes: Vec<_> = keys.iter().copied().map(node).collect();
        let mut header = node(0);
        let header_ptr = header.as_mut() as *mut _;
        let root = if nodes.is_empty() { null_mut() } else { nodes[0].as_mut() as *mut _ };
        header.parent = root;
        header.left = nodes.first_mut().map_or(header_ptr, |node| node.as_mut());
        header.right = nodes.last_mut().map_or(header_ptr, |node| node.as_mut());

        for index in 0..nodes.len() {
            let current: *mut WordKeySetNode = nodes[index].as_mut();
            (*current).parent = if index == 0 { header_ptr } else { nodes[index - 1].as_mut() };
            (*current).right = if index + 1 == nodes.len() { null_mut() } else { nodes[index + 1].as_mut() };
        }

        (WordKeySet {
            _opaque: [0; core::mem::size_of::<super::super::word_key_set::WordKeySetNodePool>()],
            header: header_ptr,
            node_count: keys.len() as u32,
            multi_insert: 1,
            comparator: 0,
        }, header, nodes)
    }

    #[test]
    fn counts_empty_and_missing_keys() {
        unsafe {
            let (tree, _header, _nodes) = tree_with_sorted_keys(&[]);
            assert_eq!(word_key_set_count(&tree, &7), 0);
            let (tree, _header, _nodes) = tree_with_sorted_keys(&[1, 3, 5]);
            assert_eq!(word_key_set_count(&tree, &0), 0);
            assert_eq!(word_key_set_count(&tree, &4), 0);
            assert_eq!(word_key_set_count(&tree, &6), 0);
        }
    }

    #[test]
    fn counts_runs_at_tree_edges_and_middle() {
        unsafe {
            let (tree, _header, _nodes) = tree_with_sorted_keys(&[1, 1, 2, 3, 3, 3]);
            assert_eq!(word_key_set_count(&tree, &1), 2);
            assert_eq!(word_key_set_count(&tree, &2), 1);
            assert_eq!(word_key_set_count(&tree, &3), 3);
        }
    }
}
