//! `word_list_node_pool_list_recycle_all` — original: `FUN_083dd39c` @
//! `0x083dd39c` (180 bytes; 45 A32 words through `bx lr` at `0x083dd44c`;
//! the next function begins at `0x083dd450`). Raw decoding finds no outgoing
//! plain or predicated `bl`; it has two inbound plain `bl` calls, at
//! `0x082928c8` and `0x083dd468`.
//!
//! Walks the intrusive ring from `sentinel.next`, unlinking each live node,
//! decrementing `state`, and pushing it onto the target-width free list. The
//! sentinel is left self-linked. Deliberate deviation: Rust omits the retail
//! stack-local stores, which are dead on return.

use super::list_node_pool_list_init::{ListNode, ListNodePoolList};

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut ListNode {
    word as usize as *mut ListNode
}

/// Moves all live word-list nodes from the intrusive ring onto the free list.
///
/// # Safety
///
/// `list` must identify a valid target-layout list whose sentinel and live
/// nodes form a writable intrusive ring at target-width addresses.
#[cfg_attr(target_os = "none", link_section = ".text.word_list_node_pool_list_recycle_all")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_node_pool_list_recycle_all(list: *mut ListNodePoolList) {
    unsafe {
        let sentinel = (*list).sentinel;
        let mut node_word = (*node_from_word(sentinel)).next;

        while node_word != sentinel {
            let node = node_from_word(node_word);
            let next = (*node).next;
            let previous = (*node).previous;

            (*node_from_word(previous)).next = next;
            (*node_from_word(next)).previous = previous;
            (*list).state = (*list).state.wrapping_sub(1);
            (*node).next = (*list).free;
            (*list).free = node_word;
            node_word = next;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn recycles_empty_and_populated_word_list_rings() {
        let Some(slab) = try_map_u32_slab(hints::WORD_LIST_NODE_POOL_LIST_RECYCLE_ALL, 0x1000) else {
            note_missing_u32_fixture("cxx/word_list_node_pool_list_recycle_all");
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
            (*list).state = 0;
            (*sentinel).next = sentinel_word;
            (*sentinel).previous = sentinel_word;
            word_list_node_pool_list_recycle_all(list);
            assert_eq!((*list).state, 0);
            assert_eq!((*list).free, free_word);

            (*list).state = 2;
            (*sentinel).next = first_word;
            (*sentinel).previous = second_word;
            (*first).next = second_word;
            (*first).previous = sentinel_word;
            (*second).next = sentinel_word;
            (*second).previous = first_word;
            (*free).next = 0xfeed_face;
            word_list_node_pool_list_recycle_all(list);

            assert_eq!((*list).state, 0);
            assert_eq!((*sentinel).next, sentinel_word);
            assert_eq!((*sentinel).previous, sentinel_word);
            assert_eq!((*list).free, second_word);
            assert_eq!((*second).next, first_word);
            assert_eq!((*first).next, free_word);
            assert_eq!((*list).chunks, 0xa5a5_a5a5);
            assert_eq!((*list).next, 0xa5a5_a5a5);
            assert_eq!((*list).end, 0xa5a5_a5a5);
        }
    }
}
