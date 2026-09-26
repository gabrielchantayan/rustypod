//! Recycle every live node in a pooled doubly-linked list.
//!
//! `list_node_pool_recycle_all` — original: `FUN_083dd844` @ `0x083dd844`
//! (180 bytes; 45 ARM words). Raw `osos.dec` establishes the exact extent
//! `0x083dd844..0x083dd8f8`; `0x083dd8f8` begins the next independently
//! entered function with `push {r4-r6,lr}`. Whole-image A32 decoding finds
//! two inbound plain `bl` calls (`0x08292868` and `0x083dd910`) and no
//! predicated `bl` calls. The body has no `bl` instructions.
//!
//! Algorithm: walk the intrusive ring from `sentinel.next` until the sentinel,
//! unlinking each live node, decrementing the count, and pushing the node onto
//! the pool free list through its `next` word. The sentinel ring is empty when
//! complete. Deliberate deviation: target pointers remain `u32` words, so the
//! 24-byte target layout is preserved on hosts with native-width pointers.

use crate::cxx::list_node_pool_acquire::{ListNode, ListNodePool};

/// The target's 24-byte pooled-list header.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNodePoolList {
    pub pool: ListNodePool,
    /// Target +0x10: intrusive-ring sentinel node address.
    pub sentinel: u32,
    /// Target +0x14: number of live nodes in the ring.
    pub count: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(ListNodePoolList, sentinel)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(ListNodePoolList, count)];
const _: [u8; 0x18] = [0; core::mem::size_of::<ListNodePoolList>()];

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut ListNode {
    word as usize as *mut ListNode
}

/// Moves all live nodes from `list`'s intrusive ring to its node-pool free
/// list. RetailOS does not NULL-check `list` or any linked node.
///
/// # Safety
///
/// `list` must be a valid pooled-list header whose sentinel and live nodes form
/// a writable, valid intrusive ring at target-width addresses.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_recycle_all(list: *mut ListNodePoolList) {
    let sentinel = unsafe { (*list).sentinel };
    let mut node_word = unsafe { (*node_from_word(sentinel)).next };

    while node_word != sentinel {
        let node = unsafe { node_from_word(node_word) };
        let next = unsafe { (*node).next };
        let previous = unsafe { (*node).prev };

        unsafe {
            (*node_from_word(previous)).next = next;
            (*node_from_word(next)).prev = previous;
            (*list).count = (*list).count.wrapping_sub(1);
            (*node).next = (*list).pool.free;
            (*list).pool.free = node_word;
        }
        node_word = next;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    const SENTINEL: usize = 0x1000;
    const FIRST: usize = 0x2000;
    const SECOND: usize = 0x2400;
    const THIRD: usize = 0x2800;
    const FREE: usize = 0x2c00;
    const FREE_NEXT: usize = 0x3000;

    unsafe fn word(base: *mut u8, offset: usize) -> u32 {
        base.add(offset) as usize as u32
    }

    unsafe fn node(base: *mut u8, offset: usize) -> *mut ListNode {
        base.add(offset).cast()
    }

    #[test]
    fn recycles_empty_and_populated_rings() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_RECYCLE_ALL, 0x4000) else {
            note_missing_u32_fixture("cxx/list_node_pool_recycle_all");
            return;
        };

        unsafe {
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = word(slab, SENTINEL);
            ptr::write(node(slab, SENTINEL), ListNode { next: sentinel, prev: sentinel, payload: [0; 3] });
            ptr::write(list, ListNodePoolList { pool: ListNodePool::default(), sentinel, count: 0 });
            list_node_pool_recycle_all(list);
            assert_eq!((*list).count, 0);
            assert_eq!((*list).pool.free, 0);
            assert_eq!((*node(slab, SENTINEL)).next, sentinel);
            assert_eq!((*node(slab, SENTINEL)).prev, sentinel);

            let first = word(slab, FIRST);
            let second = word(slab, SECOND);
            let third = word(slab, THIRD);
            let free = word(slab, FREE);
            let free_next = word(slab, FREE_NEXT);
            ptr::write(node(slab, SENTINEL), ListNode { next: first, prev: third, payload: [0; 3] });
            ptr::write(node(slab, FIRST), ListNode { next: second, prev: sentinel, payload: [1, 2, 3] });
            ptr::write(node(slab, SECOND), ListNode { next: third, prev: first, payload: [4, 5, 6] });
            ptr::write(node(slab, THIRD), ListNode { next: sentinel, prev: second, payload: [7, 8, 9] });
            ptr::write(node(slab, FREE), ListNode { next: free_next, prev: 0, payload: [0; 3] });
            ptr::write(node(slab, FREE_NEXT), ListNode::default());
            ptr::write(list, ListNodePoolList {
                pool: ListNodePool { chunks: 0, free, next: 0, end: 0 }, sentinel, count: 3,
            });

            list_node_pool_recycle_all(list);

            assert_eq!((*list).count, 0);
            assert_eq!((*node(slab, SENTINEL)).next, sentinel);
            assert_eq!((*node(slab, SENTINEL)).prev, sentinel);
            assert_eq!((*list).pool.free, third);
            assert_eq!((*node(slab, THIRD)).next, second);
            assert_eq!((*node(slab, SECOND)).next, first);
            assert_eq!((*node(slab, FIRST)).next, free);
            assert_eq!((*node(slab, FIRST)).payload, [1, 2, 3]);
            assert_eq!((*node(slab, SECOND)).payload, [4, 5, 6]);
            assert_eq!((*node(slab, THIRD)).payload, [7, 8, 9]);
        }
    }
}
