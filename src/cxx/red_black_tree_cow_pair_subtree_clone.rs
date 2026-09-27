//! Red-black-tree COW-pair subtree clone — retailOS `FUN_083c4a10` at load
//! address `0x083c4a10` (116 bytes).
//!
//! Raw `osos.dec` establishes the exact 29-word A32 extent from `push
//! {r4-r8,lr}` at `0x083c4a10` through `pop {r4-r8,pc}` at `0x083c4a80`;
//! `0x083c4a84` begins the next real function. The body has two unconditional
//! plain `bl` instructions, to the node-and-COW-pair clone helper
//! `FUN_083c411c` at `0x083c411c` and recursively to itself; it has no
//! predicated `bl` instructions.
//!
//! recursively, preserving each node's color and setting each clone's parent
//! link. Node allocation and COW payload construction are delegated to
//! [`red_black_tree_node_cow_pair_clone`].

use super::red_black_tree_node_cow_pair_clone::red_black_tree_node_cow_pair_clone;

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut u8 { word as usize as *mut u8 }

#[inline(always)]
unsafe fn node_word(node: *mut u8, offset: usize) -> u32 { unsafe { node.add(offset).cast::<u32>().read() } }

#[inline(always)]
unsafe fn write_node_word(node: *mut u8, offset: usize, value: *mut u8) {
    unsafe { node.add(offset).cast::<u32>().write(value as usize as u32) }
}

/// Clones `source` below `parent`, returning the first clone.
///
/// # Safety
///
/// `pool`, `parent`, and every nonzero source link must identify valid
/// target-layout tree storage. The retail node clone helper must return a
/// writable node with four link words followed by its COW-pair payload.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_cow_pair_subtree_clone(
    pool: *mut u8,
    mut source: *mut u8,
    mut parent: *mut u8,
) -> *mut u8 {
    let first = source;
    let mut result = source;
    while !source.is_null() {
        let clone = unsafe { red_black_tree_node_cow_pair_clone(pool, source.add(0x10)) };
        unsafe {
            write_node_word(parent, 0x08, clone);
            write_node_word(clone, 0x04, parent);
            clone.add(0).write(source.read());
        }
        if first == source { result = clone; }
        let right = unsafe { node_from_word(node_word(source, 0x0c)) };
        let cloned_right = unsafe { red_black_tree_cow_pair_subtree_clone(pool, right, clone) };
        unsafe { write_node_word(clone, 0x0c, cloned_right); }
        parent = clone;
        source = unsafe { node_from_word(node_word(source, 0x08)) };
    }
    unsafe { write_node_word(parent, 0x08, core::ptr::null_mut()); }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    const NODE_SIZE: usize = 0x18;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut NEXT_NODE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn acquire_fixture(_pool: *mut u8) -> *mut u8 {
        let node = unsafe { NEXT_NODE };
        unsafe { NEXT_NODE = NEXT_NODE.add(NODE_SIZE); }
        node
    }

    unsafe fn word(node: *mut u8, offset: usize) -> u32 { unsafe { node.add(offset).cast::<u32>().read() } }
    unsafe fn put_word(node: *mut u8, offset: usize, value: *mut u8) { unsafe { node.add(offset).cast::<u32>().write(value as usize as u32) } }

    #[test]
    fn clones_left_spine_and_right_subtrees_with_parent_links() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_COW_PAIR_SUBTREE_CLONE, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/red_black_tree_cow_pair_subtree_clone"));
            return;
        };
        unsafe {
            let parent = slab;
            let root = slab.add(0x40);
            let left = slab.add(0x80);
            let right = slab.add(0xc0);
            let clones = slab.add(0x200);
            for (node, color) in [(root, 1), (left, 2), (right, 3)] {
                node.write(color);
            }
            let string_data = slab.add(0x700);
            string_data.sub(12).cast::<u32>().write(0);
            for node in [root, left, right] {
                put_word(node, 0x10, string_data);
                put_word(node, 0x14, string_data);
            }
            put_word(root, 0x08, left); put_word(root, 0x0c, right);
            NEXT_NODE = clones;
            let previous = super::super::red_black_tree_node_cow_pair_clone::NODE_POOL_ACQUIRE;
            super::super::red_black_tree_node_cow_pair_clone::NODE_POOL_ACQUIRE = acquire_fixture;
            let result = red_black_tree_cow_pair_subtree_clone(slab.add(0x20), root, parent);
            super::super::red_black_tree_node_cow_pair_clone::NODE_POOL_ACQUIRE = previous;
            let root_clone = clones;
            let right_clone = clones.add(NODE_SIZE);
            let left_clone = clones.add(NODE_SIZE * 2);
            assert_eq!(result, root_clone);
            assert_eq!(root_clone.read(), 1); assert_eq!(right_clone.read(), 3); assert_eq!(left_clone.read(), 2);
            assert_eq!(word(parent, 0x08) as usize, root_clone as usize);
            assert_eq!(word(root_clone, 0x04) as usize, parent as usize);
            assert_eq!(word(root_clone, 0x0c) as usize, right_clone as usize);
            assert_eq!(word(root_clone, 0x08) as usize, left_clone as usize);
            assert_eq!(word(right_clone, 0x04) as usize, root_clone as usize);
            assert_eq!(word(left_clone, 0x04) as usize, root_clone as usize);
            assert_eq!(word(right_clone, 0x08), 0); assert_eq!(word(right_clone, 0x0c), 0);
            assert_eq!(word(left_clone, 0x08), 0); assert_eq!(word(left_clone, 0x0c), 0);
            assert_eq!(word(root_clone, 0x10) as usize, string_data as usize);
            assert_eq!(word(root_clone, 0x14) as usize, string_data as usize);
        }
    }

    #[test]
    fn null_source_clears_parent_left_and_returns_null() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_COW_PAIR_SUBTREE_CLONE_NULL, 0x1000) else { return; };
        unsafe {
            put_word(slab, 0x08, slab.add(0x40));
            assert!(red_black_tree_cow_pair_subtree_clone(slab.add(0x20), core::ptr::null_mut(), slab).is_null());
            assert_eq!(word(slab, 0x08), 0);
        }
    }
}
