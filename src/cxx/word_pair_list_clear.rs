//! `word_pair_list_clear` — original: `FUN_083dcf94` @ `0x083dcf94`.
//!
//! True extent: 180 bytes (45 A32 words), ending with `bx lr` at
//! `0x083dd044`; the next function begins at `0x083dd048`. Raw decoding
//! verifies zero plain or predicated outgoing BL calls and one inbound plain
//! BL at `0x083dd184` (no predicated inbound calls).
//!
//! Walk the intrusive ring from its first node to the saved sentinel, unlink
//! each node, decrement the count, and push it onto the pool free chain.
//! Payloads, sentinel storage, and chunk/bump allocation state are preserved.
//! Deliberate deviation: omit dead stack iterator temporaries and the redundant
//! current-sentinel check for a valid ring. Target pointers remain u32 words.
//! LLVM intentionally folds this body into `list_node_pool_recycle_all`:
//! both exported symbols resolve to the same 80-byte ARM section. `match.py`
//! requires that canonical symbol for its diff; the loop remains call-free.

use super::word_pair_list_copy_construct::{WordPairList, WordPairListNode};

/// Recycles every value node without releasing pool storage or the sentinel.
///
/// # Safety
/// `list` must be writable, with a valid non-null sentinel and a finite,
/// writable doubly linked ring of target-addressable `WordPairListNode`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_pair_list_clear(list: *mut WordPairList) {
    let sentinel = (*list).sentinel;
    let mut current = (*(sentinel as usize as *mut WordPairListNode)).next;
    while current != sentinel {
        let node = current as usize as *mut WordPairListNode;
        let next = (*node).next;
        let previous = (*node).previous;
        (*(previous as usize as *mut WordPairListNode)).next = next;
        (*(next as usize as *mut WordPairListNode)).previous = previous;
        (*list).state = (*list).state.wrapping_sub(1);
        (*node).next = (*list).free;
        (*list).free = current;
        current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn empty_single_and_multiple_nodes_preserve_storage_and_reverse_free_order() {
        let Some(slab) = try_map_u32_slab(hints::WORD_PAIR_LIST_CLEAR, 0x1000) else {
            note_missing_u32_fixture("cxx/word_pair_list_clear");
            return;
        };
        unsafe {
            let nodes = slab.cast::<WordPairListNode>();
            let word = |index: usize| nodes.add(index) as usize as u32;
            for count in [0usize, 1, 4] {
                for initial_state in [count as u32, 0, u32::MAX] {
                    for index in 0..=count {
                        nodes.add(index).write(WordPairListNode {
                            next: word(if index == count { 0 } else { index + 1 }),
                            previous: word(if index == 0 { count } else { index - 1 }),
                            first: 0x100 + index as u32,
                            second: 0x200 + index as u32,
                        });
                    }
                    nodes.add(8).write(WordPairListNode {
                        next: word(9), previous: 0x1234, first: 0x5678, second: 0x9abc,
                    });
                    let mut list = WordPairList {
                        chunks: 0x1111, free: word(8), next: 0x2222, end: 0x3333,
                        sentinel: word(0), state: initial_state,
                    };
                    word_pair_list_clear(&mut list);
                    assert_eq!(((*nodes).next, (*nodes).previous), (word(0), word(0)));
                    assert_eq!(list.state, initial_state.wrapping_sub(count as u32));
                    assert_eq!((list.chunks, list.next, list.end, list.sentinel),
                        (0x1111, 0x2222, 0x3333, word(0)));
                    assert_eq!(list.free, word(if count == 0 { 8 } else { count }));
                    for index in 1..=count {
                        let node = &*nodes.add(index);
                        assert_eq!(node.next, word(if index == 1 { 8 } else { index - 1 }));
                        assert_eq!(node.previous, word(0));
                        assert_eq!((node.first, node.second), (0x100 + index as u32, 0x200 + index as u32));
                    }
                    assert_eq!(((*nodes).first, (*nodes).second), (0x100, 0x200));
                    let tail = &*nodes.add(8);
                    assert_eq!((tail.next, tail.previous, tail.first, tail.second),
                        (word(9), 0x1234, 0x5678, 0x9abc));
                    let free = list.free;
                    word_pair_list_clear(&mut list);
                    assert_eq!(list.free, free);
                    assert_eq!(list.state, initial_state.wrapping_sub(count as u32));
                }
            }
        }
    }
}
