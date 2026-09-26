//! `two_word_list_node_pool_list_recycle_all` — retailOS `FUN_083dca68` @
//! `0x083dca68`.
//!
//! Load address: `0x083dca68`; true size: 180 bytes (`0xb4`), from `ldr r1,
//! [r0,#0x10]` through `bx lr` at `0x083dcb18`; `push {r4-r6,lr}` at
//! `0x083dcb1c` begins the next real function. Raw ARM decoding verifies zero
//! outgoing plain `bl` instructions and zero predicated `bl` instructions. It
//! has two inbound unconditional plain `bl` call sites and no predicated inbound
//! `bl` calls.
//!
//! Walks the intrusive ring from `sentinel.next`, unlinks each live 16-byte
//! node, decrements `state`, and pushes it onto the target-width free list. The
//! sentinel is left self-linked. Deliberate deviation: Rust omits the retail
//! stack-local stores, which are dead on return.

use super::two_word_list_node_pool_acquire::TwoWordListNode;

/// The complete 24-byte owner: a 16-byte node pool, the intrusive-ring
/// sentinel, and the live-node count.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TwoWordListNodePoolList {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
    pub sentinel: u32,
    pub state: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(TwoWordListNodePoolList, sentinel)];
const _: [u8; 0x18] = [0; core::mem::size_of::<TwoWordListNodePoolList>()];

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut TwoWordListNode {
    word as usize as *mut TwoWordListNode
}

/// Moves all live two-word list nodes from the intrusive ring onto the free
/// list.
///
/// # Safety
///
/// `list` must identify a valid target-layout list whose sentinel and live
/// nodes form a writable intrusive ring at target-width addresses.
#[cfg_attr(target_os = "none", link_section = ".text.two_word_list_node_pool_list_recycle_all")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_word_list_node_pool_list_recycle_all(
    list: *mut TwoWordListNodePoolList,
) {
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
    fn recycles_empty_and_populated_two_word_list_rings() {
        let Some(slab) = try_map_u32_slab(hints::TWO_WORD_LIST_NODE_POOL_LIST_RECYCLE_ALL, 0x1000) else {
            note_missing_u32_fixture("cxx/two_word_list_node_pool_list_recycle_all");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<TwoWordListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<TwoWordListNode>();
            let first = slab.add(0x120).cast::<TwoWordListNode>();
            let second = slab.add(0x140).cast::<TwoWordListNode>();
            let free = slab.add(0x160).cast::<TwoWordListNode>();
            let sentinel_word = sentinel as usize as u32;
            let first_word = first as usize as u32;
            let second_word = second as usize as u32;
            let free_word = free as usize as u32;

            (*list).sentinel = sentinel_word;
            (*list).free = free_word;
            (*list).state = 0;
            (*sentinel).next = sentinel_word;
            (*sentinel).previous = sentinel_word;
            two_word_list_node_pool_list_recycle_all(list);
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
            two_word_list_node_pool_list_recycle_all(list);

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
