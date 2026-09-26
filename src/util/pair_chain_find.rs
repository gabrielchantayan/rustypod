//! Finds a node in a singly linked chain by its preceding two-word key.

/// `pair_chain_find` — original: `FUN_083d6dc8` @ `0x083d6dc8` (72 bytes).
///
/// Raw A32 establishes the exact extent `0x083d6dc8..0x083d6e0f`; the next
/// independently entered function begins with `push {r4,lr}` at `0x083d6e10`.
/// Whole-image decoding finds two inbound plain `bl` sites (`0x083d2ec0` and
/// `0x083d6ce0`) and no predicated inbound `bl` sites. The body has one plain
/// `bl` to `FUN_083d7b88` and no predicated calls. It starts at `*head_link`,
/// compares the two words immediately before each node against `key`, and
/// follows the node's target-width `+0x00` link until a match or NULL.
///
/// Deliberate deviation: `FUN_083d7b88` is an unported, verified equality
/// helper whose raw body only compares those two words; its body is inlined
/// here rather than creating an invented seam. `comparison_context` is still
/// accepted to preserve the retail ABI, but its computed `+4`-relative address
/// is unused by that helper.
///
/// # Safety
/// `head_link`, `key`, every nonzero node, and each node's preceding two words
/// must be valid aligned target-width addresses. `comparison_context` is not
/// dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pair_chain_find(
    _comparison_context: u32,
    head_link: u32,
    key: u32,
) -> u32 {
    let key = key as usize as *const u32;
    let mut node = *(head_link as usize as *const u32);

    while node != 0 {
        let candidate = (node as usize - 8) as *const u32;
        if *key == *candidate && *key.add(1) == *candidate.add(1) {
            return node;
        }
        node = *(node as usize as *const u32);
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::pair_chain_find;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_BYTES: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PAIR_CHAIN_FIND, FIXTURE_BYTES).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn word(base: *mut u8, byte_offset: usize) -> *mut u32 {
        base.add(byte_offset).cast()
    }

    unsafe fn initialize_node(base: *mut u8, byte_offset: usize, pair: [u32; 2], next: u32) -> u32 {
        let node = word(base, byte_offset);
        *node.sub(2) = pair[0];
        *node.sub(1) = pair[1];
        *node = next;
        node as usize as u32
    }

    #[test]
    fn finds_head_middle_and_tail_by_complete_pair() {
        let _lock = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("util/pair_chain_find"));
            return;
        };
        unsafe {
            let base = base as *mut u8;
            let key = word(base, 0x20);
            *key = 0xaaaa_5555;
            *key.add(1) = 0x0123_4567;
            let tail = initialize_node(base, 0x100, [7, 9], 0);
            let middle = initialize_node(base, 0x140, [0xaaaa_5555, 0x0123_4567], tail);
            let head = initialize_node(base, 0x180, [1, 2], middle);
            let head_link = word(base, 0x60);
            *head_link = head;

            assert_eq!(pair_chain_find(0, head_link as usize as u32, key as usize as u32), middle);
            *key = 1;
            *key.add(1) = 2;
            assert_eq!(pair_chain_find(0, head_link as usize as u32, key as usize as u32), head);
            *key = 7;
            *key.add(1) = 9;
            assert_eq!(pair_chain_find(0, head_link as usize as u32, key as usize as u32), tail);
        }
    }

    #[test]
    fn returns_null_for_empty_chain_and_partial_pair_match() {
        let _lock = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("util/pair_chain_find"));
            return;
        };
        unsafe {
            let base = base as *mut u8;
            let key = word(base, 0x20);
            *key = 3;
            *key.add(1) = 5;
            let head_link = word(base, 0x60);
            *head_link = 0;
            assert_eq!(pair_chain_find(0, head_link as usize as u32, key as usize as u32), 0);

            *head_link = initialize_node(base, 0x100, [3, 4], 0);
            assert_eq!(pair_chain_find(0, head_link as usize as u32, key as usize as u32), 0);
        }
    }
}
