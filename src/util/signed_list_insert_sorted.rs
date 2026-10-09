//! Stable signed-key list insertion @ `0x080e86b8`.
//!
//! True extent: 56 bytes, `0x080e86b8..0x080e86f0`; final `bx lr` at
//! `0x080e86ec`, followed by the next function's word loads at `0x080e86f0`.
//! Raw aligned A32 decoding finds two plain incoming BLs (`0x08073ed0`,
//! `0x08073fb0`), zero predicated incoming BLs and zero outgoing calls.
//! Walk pointer-to-link slots while the current signed key is <= the cached
//! new key, then store the successor into the new node and publish it in the
//! slot. Equal keys retain insertion order. No target behavioral deviations;
//! repr(C) pointer fields widen on hosts but remain key +0, next +4 on ARM.

#[repr(C)]
pub struct SignedListNode {
    pub key: i32,
    pub next: *mut SignedListNode,
}

/// # Safety
/// `link` must be a valid writable link slot. Its chain must be finite with
/// valid aligned nodes, and traversed next slots must be writable. `node`
/// must be a valid writable node; existing membership is not checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn signed_list_insert_sorted(
    mut link: *mut *mut SignedListNode,
    node: *mut SignedListNode,
) {
    unsafe {
        let mut current = *link;
        let key = (*node).key;
        while !current.is_null() {
            if (*current).key > key {
                break;
            }
            link = core::ptr::addr_of_mut!((*current).next);
            current = *link;
        }
        (*node).next = current;
        *link = node;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn signed_boundaries_positions_and_equal_key_stability() {
        // Includes empty, head, middle, tail and repeated equal-key insertions.
        let keys = [0, i32::MAX, i32::MIN, -1, 0, i32::MAX, i32::MIN, 1];
        let mut nodes = keys.map(|key| SignedListNode { key, next: null_mut() });
        let mut head = null_mut();
        let mut expected = std::vec::Vec::new();
        for index in 0..nodes.len() {
            // A stale link must be overwritten even for insertion at the tail.
            nodes[index].next = &mut nodes[index];
            unsafe { signed_list_insert_sorted(&mut head, &mut nodes[index]) };
            expected.push(index);
            expected.sort_by_key(|&i| keys[i]);
            let mut current = head;
            for &i in &expected {
                assert_eq!(current, &mut nodes[i] as *mut SignedListNode);
                unsafe {
                    assert_eq!((*current).key, keys[i]);
                    current = (*current).next;
                }
            }
            assert!(current.is_null());
        }
    }

    #[test]
    fn insertion_at_interior_slot_leaves_prefix_untouched() {
        let mut tail = SignedListNode { key: 4, next: null_mut() };
        let mut prefix = SignedListNode { key: 9, next: &mut tail };
        let mut inserted = SignedListNode { key: -3, next: null_mut() };
        unsafe { signed_list_insert_sorted(&mut prefix.next, &mut inserted) };
        assert_eq!(prefix.key, 9);
        assert_eq!(prefix.next, &mut inserted as *mut SignedListNode);
        assert_eq!(inserted.next, &mut tail as *mut SignedListNode);
        assert_eq!(tail.key, 4);
        assert!(tail.next.is_null());
    }
}
