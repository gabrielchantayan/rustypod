//! Merges two sorted intrusive linked lists by their word at offset `+0x04`.

/// `linked_list_merge_by_word_4` — original: `FUN_082d9538` @ `0x082d9538`
/// (100 bytes).
///
/// Raw ARM words establish the exact body at `0x082d9538..0x082d9598`; the
/// next independently linked function begins with `push {r3-r9,sl,fp,lr}` at
/// `0x082d959c`. Whole-image decoding finds three inbound plain `bl` calls
/// (`0x083698c4`, `0x083698e8`, and `0x08369904`), no predicated `bl` calls,
/// and no outbound calls. It merges two singly linked lists sorted by the
/// unsigned word at `+0x04`, relinking nodes through their target-width `+0x24`
/// next field. Equal keys select the right list first.
///
/// Deliberate deviation: target pointers remain `u32` words rather than host
/// pointers, preserving the retailOS `+0x24` field offset on 64-bit hosts.
///
/// # Safety
/// Each nonzero argument and every nonzero `+0x24` link must be a valid,
/// aligned target-width node address. Nodes must provide readable words at
/// `+0x04` and writable links at `+0x24`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_list_merge_by_word_4(mut left: u32, mut right: u32) -> u32 {
    let mut merged_head = 0;
    let mut tail_link = &mut merged_head as *mut u32;

    while left != 0 {
        if right == 0 {
            break;
        }

        let left_words = left as usize as *mut u32;
        let right_words = right as usize as *mut u32;
        if *left_words.add(1) < *right_words.add(1) {
            *tail_link = left;
            tail_link = left_words.add(9);
            left = *tail_link;
        } else {
            *tail_link = right;
            tail_link = right_words.add(9);
            right = *tail_link;
        }
    }

    *tail_link = if left == 0 { right } else { left };
    merged_head
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::linked_list_merge_by_word_4;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const NODE_WORDS: usize = 10;
    const FIXTURE_BYTES: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LINKED_LIST_MERGE_BY_WORD_4, FIXTURE_BYTES).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn node(base: *mut u8, index: usize) -> *mut u32 {
        base.add(index * NODE_WORDS * core::mem::size_of::<u32>()).cast()
    }

    unsafe fn initialize_node(base: *mut u8, index: usize, key: u32, next: u32) -> u32 {
        let node = node(base, index);
        ptr::write_bytes(node, 0, NODE_WORDS);
        *node.add(1) = key;
        *node.add(9) = next;
        node as usize as u32
    }

    unsafe fn keys(mut head: u32) -> std::vec::Vec<u32> {
        let mut result = std::vec::Vec::new();
        while head != 0 {
            let current = head as usize as *mut u32;
            result.push(*current.add(1));
            head = *current.add(9);
        }
        result
    }

    #[test]
    fn merges_sorted_lists_and_takes_equal_keys_from_right_first() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/linked_list_merge_by_word_4"));
            return;
        };
        let base = base as *mut u8;
        unsafe {
            let left_second = initialize_node(base, 1, 4, 0);
            let left_first = initialize_node(base, 0, 1, left_second);
            let right_third = initialize_node(base, 4, 5, 0);
            let right_second = initialize_node(base, 3, 4, right_third);
            let right_first = initialize_node(base, 2, 2, right_second);

            let merged = linked_list_merge_by_word_4(left_first, right_first);
            assert_eq!(keys(merged), [1, 2, 4, 4, 5]);
            assert_eq!(*(right_second as usize as *mut u32).add(9), left_second);
        }
    }

    #[test]
    fn returns_the_nonempty_list_without_reading_a_null_side() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/linked_list_merge_by_word_4"));
            return;
        };
        let base = base as *mut u8;
        unsafe {
            let second = initialize_node(base, 1, 9, 0);
            let first = initialize_node(base, 0, 3, second);
            assert_eq!(linked_list_merge_by_word_4(0, first), first);
            assert_eq!(linked_list_merge_by_word_4(0, 0), 0);
        }
    }
}
