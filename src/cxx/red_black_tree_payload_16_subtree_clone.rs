//! Red-black-tree 16-byte-payload subtree clone — original: `FUN_083c5628`
//! at load address `0x083c5628`.
//!
//! Raw `osos.dec` establishes the exact 144-byte extent: 36 ARM words from
//! `push {r4-r9,sl,lr}` at `0x083c5628` through `pop {r4-r9,sl,pc}` at
//! `0x083c56b4`; the next independently entered function starts at
//! `0x083c56b8`. The body has four unconditional `bl` instructions: node-pool
//! acquire at `0x083c4d30`, string copy construction at `0x083d8c30`, vector
//! copy construction at `0x083e5b00`, and its recursive call. It has no
//! predicated `bl` instructions.
//!
//! Clones a red-black subtree into `pool`, preserving each node's color and
//! 16-byte `{COW string, string vector}` payload. It iterates down source left
//! links, recursively clones each source right subtree, and sets every clone's
//! parent link to its destination parent.
//!
//! Deliberate deviations: none.
#[cfg(not(test))]
use super::string::{cxx_string_copy_ctor, cxx_string_vector_copy_ctor};
use super::red_black_tree_payload_16_node_pool_acquire::{
    red_black_tree_payload_16_node_pool_acquire, RedBlackTreePayload16Node,
    RedBlackTreePayload16NodePool,
};

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]

#[cfg(not(test))]
unsafe fn clone_payload(destination: *mut u8, source: *const u8) {
    cxx_string_copy_ctor(destination.cast(), source.cast());
    cxx_string_vector_copy_ctor(destination.add(4).cast(), source.add(4).cast());
}

#[cfg(test)]
unsafe fn clone_payload(destination: *mut u8, source: *const u8) {
    unsafe fn copy_string(destination: *mut u8, source: *const u8) {
        let string = core::ptr::read_unaligned(source.cast::<u32>());
        core::ptr::write_unaligned(destination.cast(), string);
        if string != 0 {
            let rep = string.wrapping_sub(12) as usize as *mut i32;
            *rep += 1;
        }
    }

    copy_string(destination, source);
    let source_begin = core::ptr::read_unaligned(source.add(4).cast::<u32>());
    let source_end = core::ptr::read_unaligned(source.add(8).cast::<u32>());
    let length = source_end.wrapping_sub(source_begin) / 4;
    let allocation = crate::heap::veneers::operator_new_checked((length.min(32) * 4) as usize);
    let allocation_word = allocation as usize as u32;
    core::ptr::write_unaligned(destination.add(4).cast(), allocation_word);
    core::ptr::write_unaligned(destination.add(8).cast(), allocation_word.wrapping_add(length * 4));
    core::ptr::write_unaligned(destination.add(12).cast(), allocation_word.wrapping_add(length.min(32) * 4));
    let mut input = source_begin;
    let mut output = allocation;
    while input != source_end {
        copy_string(output, input as usize as *const u8);
        input = input.wrapping_add(4);
        output = output.add(4);
    }
}
#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreePayload16Node {
    word as usize as *mut RedBlackTreePayload16Node
}

/// Clones `source` below `parent`, returning the first cloned node.
///
/// # Safety
///
/// `pool`, `parent`, and every nonzero source link must identify writable,
/// target-width tree nodes. The pool allocator and payload constructors must
/// provide enough storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_16_subtree_clone(
    pool: *mut RedBlackTreePayload16NodePool,
    mut source: *mut RedBlackTreePayload16Node,
    mut parent: *mut RedBlackTreePayload16Node,
) -> *mut RedBlackTreePayload16Node {
    let first = source;
    let mut result = source;
    while !source.is_null() {
        let clone = red_black_tree_payload_16_node_pool_acquire(pool);
        (*parent).left = pointer_word(clone.cast());
        (*clone).parent = pointer_word(parent.cast());
        if source == first {
            result = clone;
        }
        (*clone).color = (*source).color;
        clone_payload((*clone).payload.as_mut_ptr(), (*source).payload.as_ptr());
        (*clone).right = pointer_word(red_black_tree_payload_16_subtree_clone(
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

    static mut VECTOR_ALLOCATION: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn alloc(_: *mut HeapDescriptorDescriptor, _: usize, _: usize) -> *mut u8 {
        VECTOR_ALLOCATION
    }

    unsafe fn node(slab: *mut u8, offset: usize) -> *mut RedBlackTreePayload16Node {
        slab.add(offset).cast()
    }

    unsafe fn set_payload(node: *mut RedBlackTreePayload16Node, string: u32, vector_empty: u32) {
        ptr::write_unaligned((*node).payload.as_mut_ptr().cast(), string);
        ptr::write_unaligned((*node).payload.as_mut_ptr().add(4).cast(), vector_empty);
        ptr::write_unaligned((*node).payload.as_mut_ptr().add(8).cast(), vector_empty);
        ptr::write_unaligned((*node).payload.as_mut_ptr().add(12).cast(), vector_empty);
    }

    #[test]
    fn clones_empty_and_mixed_subtree_with_payloads() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_16_SUBTREE_CLONE, 0x6000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_16_subtree_clone");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x6000);
            VECTOR_ALLOCATION = slab.add(0x5000);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let sentinel = node(slab, 0x000);
            let root = node(slab, 0x100);
            let left = node(slab, 0x140);
            let right = node(slab, 0x180);
            let free_root = node(slab, 0x200);
            let free_left = node(slab, 0x240);
            let free_right = node(slab, 0x280);
            let rep = slab.add(0x4000);
            let string = rep.add(12) as usize as u32;
            ptr::write_unaligned(rep.cast::<i32>(), 0);
            ptr::write(sentinel, RedBlackTreePayload16Node { color: 0, _pad: [0; 3], parent: 0, left: 0xdead_beef, right: 0, payload: [0; 16] });
            ptr::write(root, RedBlackTreePayload16Node { color: 1, _pad: [0; 3], parent: 0, left: pointer_word(left.cast()), right: pointer_word(right.cast()), payload: [0; 16] });
            ptr::write(left, RedBlackTreePayload16Node { color: 0, _pad: [0; 3], parent: 0, left: 0, right: 0, payload: [0; 16] });
            set_payload(root, string, string);
            set_payload(left, string, string);
            set_payload(right, string, string);
            ptr::write(free_root, RedBlackTreePayload16Node { color: 0, _pad: [0; 3], parent: 0, left: 0, right: pointer_word(free_left.cast()), payload: [0; 16] });
            ptr::write(free_left, RedBlackTreePayload16Node { color: 0, _pad: [0; 3], parent: 0, left: 0, right: pointer_word(free_right.cast()), payload: [0; 16] });
            ptr::write(free_right, RedBlackTreePayload16Node { color: 0, _pad: [0; 3], parent: 0, left: 0, right: 0, payload: [0; 16] });
            let mut pool = RedBlackTreePayload16NodePool { chunks: 0, free: pointer_word(free_root.cast()), next: 0, end: 0 };

            assert!(red_black_tree_payload_16_subtree_clone(&mut pool, ptr::null_mut(), sentinel).is_null());
            assert_eq!((*sentinel).left, 0);

            let cloned_root = red_black_tree_payload_16_subtree_clone(&mut pool, root, sentinel);
            let cloned_left = node_from_word((*cloned_root).left);
            let cloned_right = node_from_word((*cloned_root).right);
            assert_eq!((*sentinel).left, pointer_word(cloned_root.cast()));
            assert_eq!((*cloned_root).parent, pointer_word(sentinel.cast()));
            assert_eq!((*cloned_left).parent, pointer_word(cloned_root.cast()));
            assert_eq!((*cloned_right).parent, pointer_word(cloned_root.cast()));
            assert_eq!([(*cloned_root).color, (*cloned_left).color, (*cloned_right).color], [1, 0, 0]);
            assert_eq!(
                [
                    ptr::read_unaligned((*cloned_root).payload.as_ptr().cast::<u32>()),
                    ptr::read_unaligned((*cloned_left).payload.as_ptr().cast::<u32>()),
                    ptr::read_unaligned((*cloned_right).payload.as_ptr().cast::<u32>()),
                ],
                [string; 3],
            );
            assert_eq!(
                [
                    ptr::read_unaligned((*cloned_root).payload.as_ptr().add(4).cast::<u32>()),
                    ptr::read_unaligned((*cloned_left).payload.as_ptr().add(4).cast::<u32>()),
                    ptr::read_unaligned((*cloned_right).payload.as_ptr().add(4).cast::<u32>()),
                ],
                [VECTOR_ALLOCATION as usize as u32; 3],
            );
            assert_eq!((*cloned_left).left, 0);
            assert_eq!((*cloned_right).left, 0);
            assert_eq!(*(rep.cast::<i32>()), 3);
        }
    }
}
