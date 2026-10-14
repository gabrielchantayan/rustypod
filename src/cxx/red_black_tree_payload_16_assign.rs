//! Tree copy assignment — retailOS `FUN_083c58d8` @ `0x083c58d8`.
//!
//! True extent: 164 bytes, through `pop {r1-r5,pc}` at 0x083c5978;
//! the next function starts at 0x083c597c. Raw branch decoding verifies
//! four outbound unconditional BLs, zero predicated BLs, and one inbound
//! unconditional BL (0x081dfa84). Erase the destination range, clone the
//! source beneath the destination header, rebuild cached extrema, and copy
//! the count. Self-assignment does nothing. Only r0 is a return value.
//!
//! Deliberate deviations: reuse the identical leftmost walker at 0x083b6a80
//! rather than its 0x083b6ae8 twin; retain target pointers as u32 words.
//! Range erase at 0x083c53c8 remains a retail seam, not a second port.
use super::red_black_tree_payload_16_node_pool_acquire::{RedBlackTreePayload16Node as Node, RedBlackTreePayload16NodePool as Pool};
use super::red_black_tree_payload_16_subtree_clone::red_black_tree_payload_16_subtree_clone;
use super::red_black_tree_leftmost_descendant::red_black_tree_leftmost_descendant;
use super::red_black_tree_rightmost_descendant::red_black_tree_rightmost_descendant;

#[repr(C)]
pub struct RedBlackTreePayload16 {
    pub pool: Pool,
    pub header: u32,
    pub count: u32,
}

type EraseRange = unsafe extern "C" fn(*mut u32, *mut RedBlackTreePayload16, *const u32, *const u32);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_erase(_: *mut u32, _: *mut RedBlackTreePayload16, _: *const u32, _: *const u32) {
    panic!("tree assignment requires retail range erase or host operations")
}
#[cfg(not(target_os = "none"))]
pub static mut PAYLOAD_16_ASSIGN_ERASE_RANGE: EraseRange = unavailable_erase;

/// # Safety
/// Both trees must be valid target-layout trees with disjoint owned nodes
/// (or the same tree). The destination pool and payload constructors must
/// satisfy the subtree clone contract; the retail erase helper must be live.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_16_assign(
    destination: *mut RedBlackTreePayload16,
    source: *const RedBlackTreePayload16,
) -> *mut RedBlackTreePayload16 {
    if core::ptr::eq(destination, source) { return destination; }
    let last = (*destination).header;
    let first = (*(last as usize as *const Node)).left;
    let mut result = 0;
    #[cfg(target_os = "none")]
    let erase: EraseRange = core::mem::transmute(0x083c_53c8usize);
    #[cfg(not(target_os = "none"))]
    let erase = PAYLOAD_16_ASSIGN_ERASE_RANGE;
    erase(&mut result, destination, &first, &last);
    let source_header = (*source).header as usize as *const Node;
    let root = red_black_tree_payload_16_subtree_clone(
        core::ptr::addr_of_mut!((*destination).pool),
        (*source_header).parent as usize as *mut Node,
        (*destination).header as usize as *mut Node,
    ) as usize as u32;
    let header = (*destination).header as usize as *mut Node;
    (*header).parent = root;
    if root == 0 {
        (*header).left = (*destination).header;
        (*header).right = (*destination).header;
    } else {
        (*header).left = red_black_tree_leftmost_descendant(root);
        (*header).right = red_black_tree_rightmost_descendant(root);
    }
    (*destination).count = (*source).count;
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;

    // Restricted host model: fixtures begin empty, so retail erase has no
    // payload destruction to perform. No substitute cloning implementation.
    unsafe extern "C" fn erase_empty(out: *mut u32, tree: *mut RedBlackTreePayload16, first: *const u32, last: *const u32) {
        assert_eq!(*first, *last);
        assert_eq!((*tree).count, 0);
        *out = *last;
    }

    #[test]
    fn self_empty_and_branched_copy_preserve_source_and_rebuild_extrema() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let slab = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_16_ASSIGN, 0x1000).expect("low tree fixture");
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let dst = slab.cast::<RedBlackTreePayload16>();
            let src = slab.add(0x40).cast::<RedBlackTreePayload16>();
            let dh = slab.add(0x100).cast::<Node>();
            let sh = slab.add(0x140).cast::<Node>();
            (*dst).header = dh as usize as u32;
            (*src).header = sh as usize as u32;
            (*dh).left = (*dst).header; (*dh).right = (*dst).header;
            (*sh).left = (*src).header; (*sh).right = (*src).header;
            // Invalid header is safe for self-assignment: no dereference.
            let mut alias = RedBlackTreePayload16 { pool: Pool::default(), header: 1, count: 73 };
            assert_eq!(red_black_tree_payload_16_assign(&mut alias, &alias), &mut alias as *mut _);
            assert_eq!((alias.header, alias.count), (1, 73));
            let old = PAYLOAD_16_ASSIGN_ERASE_RANGE;
            PAYLOAD_16_ASSIGN_ERASE_RANGE = erase_empty;
            assert_eq!(red_black_tree_payload_16_assign(dst, src), dst);
            assert_eq!(((*dh).parent, (*dh).left, (*dh).right, (*dst).count), (0, (*dst).header, (*dst).header, 0));
            let root = slab.add(0x200).cast::<Node>();
            let left = slab.add(0x240).cast::<Node>();
            let right = slab.add(0x280).cast::<Node>();
            (*sh).parent = root as usize as u32;
            (*root).left = left as usize as u32; (*root).right = right as usize as u32;
            (*root).color = 1;
            (*src).count = 3;
            let free = slab.add(0x300).cast::<Node>();
            (*free).right = slab.add(0x340) as usize as u32;
            (*free.add(2)).right = slab.add(0x380) as usize as u32;
            (*dst).pool.free = free as usize as u32;
            red_black_tree_payload_16_assign(dst, src);
            let cloned = (*dh).parent as usize as *const Node;
            assert_eq!(cloned, free);
            assert_eq!((*cloned).parent, (*dst).header);
            assert_eq!((*cloned).color, 1);
            assert_eq!((*dh).left, (*cloned).left);
            assert_eq!((*dh).right, (*cloned).right);
            assert_ne!((*cloned).left, left as usize as u32);
            assert_ne!((*cloned).right, right as usize as u32);
            assert_eq!((*dst).count, 3);
            assert_eq!(((*root).left, (*root).right, (*src).count), (left as usize as u32, right as usize as u32, 3));
            PAYLOAD_16_ASSIGN_ERASE_RANGE = old;
        }
    }
}
