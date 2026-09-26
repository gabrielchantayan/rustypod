//! Red-black-tree word-subtree clone — original: `FUN_083bfdbc` at load
//! address `0x083bfdbc`.
//!
//! Raw `osos.dec` establishes the exact 116-byte extent: 29 ARM words from
//! `push {r4-r8,lr}` at `0x083bfdbc` through `pop {r4-r8,pc}` at
//! `0x083bfe2c`; the next real function starts at `0x083bfe30`. The body has
//! two unconditional `bl` instructions, to
//! `red_black_tree_word_node_pool_acquire` at `0x083bf4dc` and recursively to
//! itself, and no predicated `bl` instructions.
//!
//! Clones a red-black subtree into `pool`, preserving each node's color and
//! word payload. It iterates down the source left links, recursively clones
//! each source right subtree, and sets every clone's parent link to its
//! destination parent.
//!
//! Deliberate deviations: none.

use super::red_black_tree_word_node_pool_acquire::{
    RedBlackTreeWordNode, RedBlackTreeWordNodePool,
};
use super::red_black_tree_word_node_pool_acquire_with_payload::red_black_tree_word_node_pool_acquire_with_payload;

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreeWordNode {
    word as usize as *mut RedBlackTreeWordNode
}

/// Clones `source` below `parent`, returning the first cloned node.
///
/// # Safety
/// `pool`, `parent`, and every nonzero source link must identify writable,
/// target-width tree nodes. The pool allocator must provide enough storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_word_subtree_clone(
    pool: *mut RedBlackTreeWordNodePool,
    mut source: *mut RedBlackTreeWordNode,
    mut parent: *mut RedBlackTreeWordNode,
) -> *mut RedBlackTreeWordNode {
    let first = source;
    let mut result = source;
    while !source.is_null() {
        let clone = red_black_tree_word_node_pool_acquire_with_payload(pool, &(*source).payload);
        (*parent).left = pointer_word(clone.cast());
        (*clone).parent = pointer_word(parent.cast());
        if source == first {
            result = clone;
        }
        (*clone).color = (*source).color;
        (*clone).right = pointer_word(red_black_tree_word_subtree_clone(
            pool,
            node_from_word((*source).right),
            clone,
        ).cast());
        source = node_from_word((*source).left);
        parent = clone;
    }
    (*parent).left = 0;
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut ALLOCATIONS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut CURSOR: usize = 0;

    unsafe extern "C" fn alloc(_: *mut HeapDescriptorDescriptor, _: usize, _: usize) -> *mut u8 {
        let allocation = ALLOCATIONS[CURSOR];
        CURSOR += 1;
        allocation
    }

    unsafe fn node(slab: *mut u8, offset: usize) -> *mut RedBlackTreeWordNode {
        slab.add(offset).cast()
    }

    #[test]
    fn clones_empty_and_mixed_subtree() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_WORD_SUBTREE_CLONE, 0x6000) else {
            note_missing_u32_fixture("cxx/red_black_tree_word_subtree_clone");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x6000);
            ALLOCATIONS = [slab.add(0x2000), slab.add(0x3000)];
            CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let sentinel = node(slab, 0x000);
            let root = node(slab, 0x100);
            let left = node(slab, 0x140);
            let right = node(slab, 0x180);
            let left_right = node(slab, 0x1c0);
            ptr::write(sentinel, RedBlackTreeWordNode { color: 0, _pad: [0; 3], parent: 0, left: 0xdead_beef, right: 0, payload: 0 });
            ptr::write(root, RedBlackTreeWordNode { color: 1, _pad: [0; 3], parent: 0, left: pointer_word(left.cast()), right: pointer_word(right.cast()), payload: 10 });
            ptr::write(left, RedBlackTreeWordNode { color: 0, _pad: [0; 3], parent: 0, left: 0, right: pointer_word(left_right.cast()), payload: 20 });
            ptr::write(right, RedBlackTreeWordNode { color: 1, _pad: [0; 3], parent: 0, left: 0, right: 0, payload: 30 });
            ptr::write(left_right, RedBlackTreeWordNode { color: 1, _pad: [0; 3], parent: 0, left: 0, right: 0, payload: 40 });

            let mut pool = RedBlackTreeWordNodePool::default();
            assert!(red_black_tree_word_subtree_clone(&mut pool, ptr::null_mut(), sentinel).is_null());
            assert_eq!((*sentinel).left, 0);

            let cloned_root = red_black_tree_word_subtree_clone(&mut pool, root, sentinel);
            let cloned_left = node_from_word((*cloned_root).left);
            let cloned_right = node_from_word((*cloned_root).right);
            let cloned_left_right = node_from_word((*cloned_left).right);
            assert_eq!((*sentinel).left, pointer_word(cloned_root.cast()));
            assert_eq!((*cloned_root).parent, pointer_word(sentinel.cast()));
            assert_eq!((*cloned_left).parent, pointer_word(cloned_root.cast()));
            assert_eq!((*cloned_right).parent, pointer_word(cloned_root.cast()));
            assert_eq!((*cloned_left_right).parent, pointer_word(cloned_left.cast()));
            assert_eq!([(*cloned_root).payload, (*cloned_left).payload, (*cloned_right).payload, (*cloned_left_right).payload], [10, 20, 30, 40]);
            assert_eq!([(*cloned_root).color, (*cloned_left).color, (*cloned_right).color, (*cloned_left_right).color], [1, 0, 1, 1]);
            assert_eq!((*cloned_left_right).left, 0);
            assert_eq!((*cloned_right).left, 0);
        }
    }
}
