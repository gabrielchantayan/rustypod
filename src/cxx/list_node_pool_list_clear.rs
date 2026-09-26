//! `list_node_pool_list_clear` — original: `FUN_083dd584` @ `0x083dd584`
//! (112 bytes; 28 A32 words through `pop {r4,r5,r6,pc}` at `0x083dd5f0`; the
//! next function begins at `0x083dd5f4`). Raw decoding finds two plain
//! outgoing `bl` calls, to `list_node_pool_list_erase` at `0x083dd5c4` and
//! `not_equal_deref_alias_6f94` at `0x083dd5d8`, and no predicated `bl`.
//!
//! Starts at the sentinel's successor and erases each non-sentinel node from
//! the target-width intrusive ring, leaving the sentinel self-linked and all
//! removed nodes on the pool free list. Deliberate deviation: the retail
//! epilogue writes its final local node word into dead stack storage; Rust
//! omits that unobservable store.

use super::list_node_pool_list_erase::list_node_pool_list_erase;
use super::list_node_pool_list_init::{ListNode, ListNodePoolList};
use super::templates::not_equal_deref;

/// Removes every non-sentinel node from `list` and returns them to its pool.
///
/// # Safety
///
/// `list` must identify a valid target-layout owner whose sentinel and every
/// reachable successor form an intrusive ring.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_clear(list: *mut ListNodePoolList) {
    unsafe {
        let sentinel = (*list).sentinel;
        let mut node = (*(sentinel as usize as *mut ListNode)).next;

        while not_equal_deref(&node, &sentinel) != 0 {
            let mut successor = 0;
            list_node_pool_list_erase(&mut successor, list, &mut node);
            node = successor;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn clears_nodes_in_successor_order_and_leaves_empty_list_unchanged() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_CLEAR, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_clear");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            let first = slab.add(0x120).cast::<ListNode>();
            let second = slab.add(0x140).cast::<ListNode>();
            let free = slab.add(0x160).cast::<ListNode>();
            let sentinel_word = sentinel as usize as u32;
            let first_word = first as usize as u32;
            let second_word = second as usize as u32;
            let free_word = free as usize as u32;

            (*list).sentinel = sentinel_word;
            (*list).free = free_word;
            (*list).state = 2;
            (*sentinel).next = first_word;
            (*sentinel).previous = second_word;
            (*first).next = second_word;
            (*first).previous = sentinel_word;
            (*second).next = sentinel_word;
            (*second).previous = first_word;

            list_node_pool_list_clear(list);

            assert_eq!((*list).state, 0);
            assert_eq!((*list).free, second_word);
            assert_eq!((*second).next, first_word);
            assert_eq!((*first).next, free_word);
            assert_eq!((*sentinel).next, sentinel_word);
            assert_eq!((*sentinel).previous, sentinel_word);
            assert_eq!((*list).chunks, 0xa5a5_a5a5);
            assert_eq!((*list).next, 0xa5a5_a5a5);
            assert_eq!((*list).end, 0xa5a5_a5a5);

            (*list).free = first_word;
            (*list).state = 0;
            list_node_pool_list_clear(list);
            assert_eq!((*list).free, first_word);
            assert_eq!((*list).state, 0);
            assert_eq!((*sentinel).next, sentinel_word);
            assert_eq!((*sentinel).previous, sentinel_word);
        }
    }
}
