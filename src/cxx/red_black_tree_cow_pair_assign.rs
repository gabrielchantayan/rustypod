//! COW-string-pair tree copy assignment — retailOS `FUN_083c4c8c` @
//! `0x083c4c8c` (164 bytes, ending at `0x083c4d30`, the next real function).
//!
//! Raw A32 decoding verifies four outbound plain BLs, no predicated BLs,
//! and one inbound plain BL at `0x08101ec0`. Erase the destination range,
//! clone the source beneath its header, rebuild cached extrema, copy the
//! count, and return the destination. Self-assignment touches no fields.
//!
//! Deliberate deviations: reuse the equivalent existing extrema walkers
//! instead of the identical loops at `0x083b6ab8` and `0x083b6aa4`. Retain
//! target pointers as u32 words. Range erase at `0x083c4698` remains a retail
//! seam. Ghidra's extra arguments and undefined8 return are artifacts: the
//! original restores saved r1 rather than returning a second result.

use super::red_black_tree_node_cow_pair_pool_acquire::{RedBlackTreeNodeCowPair as Node, RedBlackTreeNodeCowPairPool as Pool};
use super::red_black_tree_cow_pair_subtree_clone::red_black_tree_cow_pair_subtree_clone;
use super::red_black_tree_leftmost_descendant::red_black_tree_leftmost_descendant;
use super::red_black_tree_rightmost_descendant::red_black_tree_rightmost_descendant;

#[repr(C)]
pub struct RedBlackTreeCowPair {
    pub pool: Pool,
    pub header: u32,
    pub count: u32,
}

type EraseRange = unsafe extern "C" fn(*mut u32, *mut RedBlackTreeCowPair, *const u32, *const u32);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_erase(_: *mut u32, _: *mut RedBlackTreeCowPair, _: *const u32, _: *const u32) {
    panic!("COW tree assignment requires retail range erase or host operations")
}
#[cfg(not(target_os = "none"))]
pub static mut COW_PAIR_ASSIGN_ERASE_RANGE: EraseRange = unavailable_erase;

/// # Safety
/// Both trees must be valid target-layout trees with disjoint owned nodes
/// (or the same object). The destination pool must satisfy the subtree clone
/// contract, and the retail range-erase helper must be available.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_cow_pair_assign(
    destination: *mut RedBlackTreeCowPair,
    source: *const RedBlackTreeCowPair,
) -> *mut RedBlackTreeCowPair {
    if core::ptr::eq(destination, source) { return destination; }
    let last = (*destination).header;
    let first = (*(last as usize as *const Node)).left;
    let mut result = 0;
    #[cfg(target_os = "none")]
    let erase: EraseRange = core::mem::transmute(0x083c_4698usize);
    #[cfg(not(target_os = "none"))]
    let erase = COW_PAIR_ASSIGN_ERASE_RANGE;
    erase(&mut result, destination, &first, &last);
    let source_header = (*source).header as usize as *const Node;
    let root = red_black_tree_cow_pair_subtree_clone(
        core::ptr::addr_of_mut!((*destination).pool),
        (*source_header).parent as usize as *mut u8,
        (*destination).header as usize as *mut u8,
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

    // Restricted model: destinations start empty; no payload destruction is
    // replaced. Cloning, pool acquisition, and COW construction run for real.
    unsafe extern "C" fn erase_empty(out: *mut u32, tree: *mut RedBlackTreeCowPair, first: *const u32, last: *const u32) {
        assert_eq!(*first, *last);
        assert_eq!((*tree).count, 0);
        *out = *last;
    }
    struct Reset(EraseRange);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { COW_PAIR_ASSIGN_ERASE_RANGE = self.0; } }
    }

    #[test]
    fn self_empty_single_and_branched_assignment() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let slab = try_map_u32_slab(hints::RED_BLACK_TREE_COW_PAIR_ASSIGN, 0x1000).expect("low tree fixture");
        unsafe {
            let mut alias = RedBlackTreeCowPair { pool: Pool::default(), header: 1, count: 73 };
            assert_eq!(red_black_tree_cow_pair_assign(&mut alias, &alias), &mut alias as *mut _);
            assert_eq!((alias.header, alias.count), (1, 73));
            let _reset = Reset(COW_PAIR_ASSIGN_ERASE_RANGE);
            COW_PAIR_ASSIGN_ERASE_RANGE = erase_empty;
            for count in [0, 1, 3] {
                ptr::write_bytes(slab, 0, 0x1000);
                let dst = slab.cast::<RedBlackTreeCowPair>();
                let src = slab.add(0x40).cast::<RedBlackTreeCowPair>();
                let dh = slab.add(0x100).cast::<Node>();
                let sh = slab.add(0x140).cast::<Node>();
                (*dst).header = dh as usize as u32;
                (*src).header = sh as usize as u32;
                (*dh).left = (*dst).header; (*dh).right = (*dst).header;
                let root = slab.add(0x200).cast::<Node>();
                let left = slab.add(0x240).cast::<Node>();
                let right = slab.add(0x280).cast::<Node>();
                let data = slab.add(0x700);
                data.sub(12).cast::<u32>().write(0);
                if count != 0 {
                    (*sh).parent = root as usize as u32;
                    (*root).parent = (*src).header;
                    if count == 3 {
                        (*root).left = left as usize as u32;
                        (*root).right = right as usize as u32;
                        (*left).parent = root as usize as u32;
                        (*right).parent = root as usize as u32;
                    }
                    for (node, color) in [(root, 1), (left, 2), (right, 3)] {
                        (*node).color = color;
                        (*node).payload = [data as usize as u32; 2];
                    }
                }
                (*src).count = count;
                let saved = core::slice::from_raw_parts(slab.add(0x140), 0x160).to_vec();
                let clones = slab.add(0x300).cast::<Node>();
                (*dst).pool.next = clones as usize as u32;
                (*dst).pool.end = clones.add(3) as usize as u32;
                assert_eq!(red_black_tree_cow_pair_assign(dst, src), dst);
                assert_eq!((*dst).count, count);
                assert_eq!(core::slice::from_raw_parts(slab.add(0x140), 0x160), saved);
                if count == 0 {
                    assert_eq!(((*dh).parent, (*dh).left, (*dh).right), (0, (*dst).header, (*dst).header));
                } else {
                    assert_eq!((*dh).parent, clones as usize as u32);
                    assert_eq!((*clones).parent, (*dst).header);
                    assert_eq!((*clones).color, 1);
                    assert_eq!((*clones).payload, (*root).payload);
                    if count == 1 {
                        assert_eq!(((*dh).left, (*dh).right), (clones as usize as u32, clones as usize as u32));
                    } else {
                        assert_eq!((*dh).left, clones.add(2) as usize as u32);
                        assert_eq!((*dh).right, clones.add(1) as usize as u32);
                        assert_eq!((*clones).left, (*dh).left);
                        assert_eq!((*clones).right, (*dh).right);
                        for (node, color) in [(clones.add(1), 3), (clones.add(2), 2)] {
                            assert_eq!((*node).parent, clones as usize as u32);
                            assert_eq!((*node).color, color);
                            assert_eq!(((*node).left, (*node).right), (0, 0));
                            assert_eq!((*node).payload, (*root).payload);
                        }
                    }
                    assert_eq!(data.sub(12).cast::<u32>().read(), count * 2);
                }
            }
        }
    }
}
