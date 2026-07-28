//! list_find_by_id16 — original: `FUN_081c8a84` @ 0x081c8a84 (56 bytes;
//! 7 call sites, binary-scanned, all in the MPEG-4 container parser
//! cluster @ 0x081c38e0..0x081c8a38 — the code that owns the
//! "moovmvhdtrakmdiahdlrmdat" atom-name literals; callers look up
//! track-like nodes by a 16-bit id).
//!
//! Node layout: `+0` next pointer, `+4` u16 id (modeled as the
//! `#[repr(C)]` `IdNode`, whose field offsets on the 32-bit target are
//! exactly the original's). Walk the singly-linked list from `head` and
//! return the first node whose id equals `key`. On a miss the fallback
//! depends on the key: 0 and 0xffffffff act as "any/default" and return
//! `head` itself; every other key returns NULL. (A key of 0xffffffff
//! can never match — the id is a 16-bit `ldrh` — so it always means
//! "give me the head".)

use core::ptr;

/// The list node the original walks: next pointer, then a 16-bit id.
#[repr(C)]
pub struct IdNode {
    pub next: *mut IdNode,
    pub id: u16,
}

/// Returns the first node with `id == key` (the key is compared as a
/// full u32 against the zero-extended id); on a miss, `head` when `key`
/// is 0 or 0xffffffff, else NULL. An empty list follows the same
/// fallback.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_find_by_id16(head: *mut IdNode, key: u32) -> *mut IdNode {
    let mut node = head;
    while !node.is_null() {
        if (*node).id as u32 == key {
            return node;
        }
        node = (*node).next;
    }
    if key == 0 || key == 0xffff_ffff {
        head
    } else {
        ptr::null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u16) -> IdNode {
        IdNode { next: ptr::null_mut(), id }
    }

    fn chain(nodes: &mut [IdNode]) {
        for i in 0..nodes.len() - 1 {
            nodes[i].next = &mut nodes[i + 1] as *mut IdNode;
        }
    }

    fn find(head: *mut IdNode, key: u32) -> *mut IdNode {
        unsafe { list_find_by_id16(head, key) }
    }

    #[test]
    fn finds_matching_node_anywhere_in_the_list() {
        let mut nodes = [node(10), node(20), node(30)];
        chain(&mut nodes);
        let head = &mut nodes[0] as *mut IdNode;
        assert_eq!(find(head, 10), head);
        assert_eq!(find(head, 20), &mut nodes[1] as *mut IdNode);
        assert_eq!(find(head, 30), &mut nodes[2] as *mut IdNode);
    }

    #[test]
    fn miss_with_ordinary_key_returns_null() {
        let mut nodes = [node(7)];
        assert!(find(&mut nodes[0], 8).is_null());
    }

    #[test]
    fn miss_with_wildcard_keys_returns_head() {
        let mut nodes = [node(7), node(9)];
        chain(&mut nodes);
        let head = &mut nodes[0] as *mut IdNode;
        assert_eq!(find(head, 0xffff_ffff), head, "-1 never matches a u16 id");
        // Key 0 with no id-0 node: also the head.
        assert_eq!(find(head, 0), head);
    }

    #[test]
    fn key_zero_still_matches_a_real_id_zero_node() {
        let mut nodes = [node(5), node(0)];
        chain(&mut nodes);
        assert_eq!(find(&mut nodes[0], 0), &mut nodes[1] as *mut IdNode);
    }

    #[test]
    fn empty_list_follows_the_same_fallback() {
        assert!(find(ptr::null_mut(), 5).is_null());
        assert!(find(ptr::null_mut(), 0).is_null(), "head is NULL, so fallback is NULL");
        assert!(find(ptr::null_mut(), 0xffff_ffff).is_null());
    }

    #[test]
    fn id_is_zero_extended_before_the_u32_compare() {
        let mut nodes = [node(0x1234)];
        let head = &mut nodes[0] as *mut IdNode;
        assert_eq!(find(head, 0x1234), head);
        assert!(find(head, 0xdead_1234).is_null(), "high key bits must match the zero extension");
    }
}
