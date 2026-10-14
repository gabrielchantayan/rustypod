//! Clears a pooled two-word intrusive list — retailOS `FUN_083dcbcc`.
//!
//! Load address: `0x083dcbcc`; true size: 180 bytes, ending in `bx lr` at
//! `0x083dcc7c`, before the next function's push at `0x083dcc80`. Raw A32
//! decoding verifies zero outgoing plain BLs and zero predicated BLs; one
//! inbound plain BL at `0x0812d954`, no predicated inbound BLs. The bytes are
//! identical to the recycle-all body at `0x083dca68`. Unlinks each live node,
//! decrements the live count with wrapping arithmetic, and prepends the node
//! to the free list, reversing ring order ahead of any existing free nodes.
//! Returns the sentinel left in retail r0. Deliberate deviation: omits dead
//! stack-local iterator stores and the unreachable sentinel-removal branch
//! for a valid, exclusively accessed ring. All pointer fields remain u32.

use super::two_word_list_node_pool_acquire::TwoWordListNode;
use super::two_word_list_node_pool_list_recycle_all::TwoWordListNodePoolList;

/// # Safety
/// `list` and its target-width sentinel/node pointers must designate writable,
/// aligned objects forming a valid ring, exclusively accessed during this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.two_word_list_node_pool_list_clear")]
#[inline(never)]
pub unsafe extern "C" fn two_word_list_node_pool_list_clear(
    list: *mut TwoWordListNodePoolList,
) -> *mut TwoWordListNode {
    let sentinel = (*list).sentinel;
    let mut current = (*(sentinel as usize as *mut TwoWordListNode)).next;
    while current != sentinel {
        let node = current as usize as *mut TwoWordListNode;
        let next = (*node).next;
        let previous = (*node).previous;
        (*(previous as usize as *mut TwoWordListNode)).next = next;
        (*(next as usize as *mut TwoWordListNode)).previous = previous;
        (*list).state = (*list).state.wrapping_sub(1);
        (*node).next = (*list).free;
        (*list).free = current;
        current = next;
    }
    sentinel as usize as *mut TwoWordListNode
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn clears_empty_single_and_multiple_nodes_preserving_payloads_and_old_free_tail() {
        let Some(slab) = try_map_u32_slab(hints::TWO_WORD_LIST_NODE_POOL_LIST_CLEAR, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/two_word_list_node_pool_list_clear"));
            return;
        };
        unsafe {
            let list = slab.cast::<TwoWordListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<TwoWordListNode>();
            let nodes = slab.add(0x120).cast::<TwoWordListNode>();
            let old_free = slab.add(0x200).cast::<TwoWordListNode>();
            let word = |p: *mut TwoWordListNode| p as usize as u32;
            for (length, count) in [(0usize, 7u32), (1, 1), (3, 3), (3, 0)] {
                list.write(TwoWordListNodePoolList {
                    chunks: 0x1234, free: word(old_free), next: 0x5678,
                    end: 0x9abc, sentinel: word(sentinel), state: count,
                });
                sentinel.write(TwoWordListNode {
                    next: if length == 0 { word(sentinel) } else { word(nodes) },
                    previous: if length == 0 { word(sentinel) } else { word(nodes.add(length - 1)) },
                    first: 91, second: 92,
                });
                old_free.write(TwoWordListNode { next: 0, previous: 93, first: 94, second: 95 });
                for index in 0..length {
                    nodes.add(index).write(TwoWordListNode {
                        next: if index + 1 == length { word(sentinel) } else { word(nodes.add(index + 1)) },
                        previous: if index == 0 { word(sentinel) } else { word(nodes.add(index - 1)) },
                        first: index as u32 + 100, second: index as u32 + 200,
                    });
                }
                assert_eq!(two_word_list_node_pool_list_clear(list), sentinel);
                assert_eq!((*sentinel).next, word(sentinel));
                assert_eq!((*sentinel).previous, word(sentinel));
                assert_eq!(((*sentinel).first, (*sentinel).second), (91, 92));
                assert_eq!((*list).state, count.wrapping_sub(length as u32));
                assert_eq!(((*list).chunks, (*list).next, (*list).end), (0x1234, 0x5678, 0x9abc));
                let mut free = (*list).free;
                for index in (0..length).rev() {
                    assert_eq!(free, word(nodes.add(index)));
                    let node = free as usize as *mut TwoWordListNode;
                    assert_eq!(((*node).first, (*node).second), (index as u32 + 100, index as u32 + 200));
                    assert_eq!((*node).previous, word(sentinel));
                    free = (*node).next;
                }
                assert_eq!(free, word(old_free));
                assert_eq!(((*old_free).next, (*old_free).previous, (*old_free).first, (*old_free).second), (0, 93, 94, 95));
                assert_eq!(two_word_list_node_pool_list_clear(list), sentinel);
                assert_eq!((*list).state, count.wrapping_sub(length as u32));
                assert_eq!((*list).free, if length == 0 { word(old_free) } else { word(nodes.add(length - 1)) });
            }
        }
    }
}
