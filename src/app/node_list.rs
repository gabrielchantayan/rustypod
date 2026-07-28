//! `list_count_until_match` — original: `FUN_0810fa90` @ 0x0810fa90
//! (84 bytes; 125 `bl` call sites, binary-scanned).
//!
//! Walks the singly-linked node list hanging off a list object and
//! returns how many nodes it visited. When the object carries a nonzero
//! *stop key* the walk ends at (and counts) the first node whose vtable
//! slot +0x68 returns that key, so the result is the node's 1-based
//! position; with a zero stop key nothing can match and the result is
//! the full node count.
//!
//! The list object is a C++ singleton — its accessor `FUN_0810fa30` is
//! a function-local-static initializer (guard word @ 0x089cc834, ADS
//! guard helpers @ 0x082ab31c / 0x082ab338) that returns the fixed
//! object @ 0x08a79c74, and the getter @ 0x0810fa88 hands out its head
//! pointer. The 125 callers are view classes in the 0x0839xxxx block,
//! all of the form `list_walk_begin(); depth = list_count_until_match();
//! this->field_c4 = depth;`. Its sibling `FUN_0810fb48` drains the same
//! list, dispatching the same +0x68 slot against the same stop key.
//!
//! ```text
//! list +0x00  vtable            (dispatched by FUN_0810fb48, not here)
//! list +0x04  head node
//! list +0x08  stop key          0 = walk the whole list
//! node +0x00  vtable            (+0x68 = the node's key accessor)
//! node +0x14  next node
//! ```
//!
//! Faithful details:
//! - The counter is bumped *before* the key test, so a matching node is
//!   included in the result.
//! - The stop key is re-read from the list on both sides of the virtual
//!   call — the original does two `ldr r0, [r5, #8]` — so a callee that
//!   rewrites it is honored. Reproduced.
//! - The dispatch goes through the node's own vtable pointer, not a
//!   crate-level hook table, so subclass (and test) vtables work.
//! - Fields are typed struct members, never literal byte offsets: the
//!   32-bit target layout is exact (asserted in `layout_checks`) while a
//!   64-bit host keeps the fields disjoint.

/// The node's vtable, modeled down to the one slot this walk
/// dispatches (+0x68).
#[repr(C)]
pub struct NodeVtable {
    /// Slots +0x00..+0x64: not dispatched here.
    pub unresolved: [usize; 26],
    /// Slot +0x68: the node's key, compared against the list's stop key.
    pub key: unsafe extern "C" fn(this: *mut Node) -> u32,
}

/// A list node, modeled down to its vtable pointer and its link.
#[repr(C)]
pub struct Node {
    /// +0x00: the node's vtable.
    pub vtable: *const NodeVtable,
    /// +0x04..+0x13: not read by this walk.
    pub opaque: [u32; 4],
    /// +0x14: next node, NULL at the end.
    pub next: *mut Node,
}

/// The list object (the singleton @ 0x08a79c74 on device).
#[repr(C)]
pub struct NodeList {
    /// +0x00: the list's own vtable — dispatched by the drain function
    /// @ 0x0810fb48, never here.
    pub vtable: *const u8,
    /// +0x04: first node.
    pub head: *mut Node,
    /// +0x08: stop key; 0 means "count everything".
    pub stop_key: u32,
}

// Target-exact layout.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x68] = [0; core::mem::offset_of!(NodeVtable, key)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(Node, opaque)];
    const _: [u8; 0x14] = [0; core::mem::offset_of!(Node, next)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(NodeList, head)];
    const _: [u8; 0x08] = [0; core::mem::offset_of!(NodeList, stop_key)];
}

/// list_count_until_match — original: `FUN_0810fa90` @ 0x0810fa90
/// (84 bytes).
///
/// Returns the 1-based position of the node matching the list's stop
/// key, or the total node count when the key is 0 or unmatched.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_count_until_match(list: *mut NodeList) -> u32 {
    let mut node = (*list).head;
    let mut count: u32 = 0;

    while !node.is_null() {
        count = count.wrapping_add(1);
        if (*list).stop_key != 0 {
            let key = ((*(*node).vtable).key)(node);
            // Re-read: the original reloads list + 8 after the call.
            if key == (*list).stop_key {
                break;
            }
        }
        node = (*node).next;
    }
    count
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::vec::Vec;

    /// A node whose key accessor returns a stored value and records the
    /// call.
    #[repr(C)]
    struct TestNode {
        vtable: *const NodeVtable,
        opaque: [u32; 4],
        next: *mut Node,
        key: u32,
        /// Shared visit log (raw pointer so the node stays `repr(C)`
        /// compatible past the fields the port reads).
        visits: *mut Vec<u32>,
    }

    unsafe extern "C" fn test_key(this: *mut Node) -> u32 {
        let node = this as *mut TestNode;
        (*(*node).visits).push((*node).key);
        (*node).key
    }

    static TEST_VTABLE: NodeVtable = NodeVtable { unresolved: [0; 26], key: test_key };

    fn node(key: u32, visits: *mut Vec<u32>) -> TestNode {
        TestNode {
            vtable: &TEST_VTABLE,
            opaque: [0; 4],
            next: ptr::null_mut(),
            key,
            visits,
        }
    }

    /// Links the nodes head-to-tail and returns the head.
    fn chain(nodes: &mut [TestNode]) -> *mut Node {
        for i in 0..nodes.len() - 1 {
            nodes[i].next = &mut nodes[i + 1] as *mut TestNode as *mut Node;
        }
        &mut nodes[0] as *mut TestNode as *mut Node
    }

    fn list(head: *mut Node, stop_key: u32) -> NodeList {
        NodeList { vtable: ptr::null(), head, stop_key }
    }

    #[test]
    fn an_empty_list_counts_zero_and_dispatches_nothing() {
        let mut visits: Vec<u32> = Vec::new();
        let mut list = list(ptr::null_mut(), 7);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 0);
        assert!(visits.is_empty(), "no node, no dispatch");
        let _ = &mut visits;
    }

    #[test]
    fn a_zero_stop_key_counts_every_node_without_dispatching() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits), node(3, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 0);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 3);
        assert!(visits.is_empty(), "a zero key short-circuits before the vtable call");
    }

    #[test]
    fn the_matching_node_is_counted_and_the_walk_stops_there() {
        let mut visits = Vec::new();
        let mut nodes =
            [node(10, &mut visits), node(20, &mut visits), node(30, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 20);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 2, "1-based position");
        assert_eq!(visits, std::vec![10, 20], "the third node is never asked");
    }

    #[test]
    fn the_head_matching_returns_one() {
        let mut visits = Vec::new();
        let mut nodes = [node(5, &mut visits), node(6, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 5);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 1);
        assert_eq!(visits, std::vec![5]);
    }

    #[test]
    fn an_unmatched_key_falls_through_to_the_full_count() {
        let mut visits = Vec::new();
        let mut nodes = [node(1, &mut visits), node(2, &mut visits), node(3, &mut visits)];
        let head = chain(&mut nodes);
        let mut list = list(head, 99);
        assert_eq!(unsafe { list_count_until_match(&mut list) }, 3);
        assert_eq!(visits, std::vec![1, 2, 3], "every node is asked");
    }

    #[test]
    fn a_single_node_list_counts_one_either_way() {
        let mut visits = Vec::new();
        let mut nodes = [node(4, &mut visits)];
        let head = chain_single(&mut nodes);
        let mut with_key = list(head, 4);
        assert_eq!(unsafe { list_count_until_match(&mut with_key) }, 1);
        let mut without = list(head, 0);
        assert_eq!(unsafe { list_count_until_match(&mut without) }, 1);
    }

    /// `chain` needs at least two nodes; this is the one-node case.
    fn chain_single(nodes: &mut [TestNode; 1]) -> *mut Node {
        &mut nodes[0] as *mut TestNode as *mut Node
    }

    #[test]
    fn a_key_accessor_that_clears_the_stop_key_ends_the_matching() {
        // The original reloads list + 8 after the call, so a callee
        // that rewrites the key is honored on the very same iteration.
        static mut LIST_UNDER_TEST: *mut NodeList = ptr::null_mut();

        unsafe extern "C" fn clearing_key(this: *mut Node) -> u32 {
            let node = this as *mut TestNode;
            (*(*node).visits).push((*node).key);
            (*(*core::ptr::addr_of!(LIST_UNDER_TEST))).stop_key = 0;
            (*node).key
        }
        static CLEARING_VTABLE: NodeVtable =
            NodeVtable { unresolved: [0; 26], key: clearing_key };

        let mut visits = Vec::new();
        let mut nodes = [node(8, &mut visits), node(9, &mut visits)];
        nodes[0].vtable = &CLEARING_VTABLE;
        nodes[1].vtable = &CLEARING_VTABLE;
        let head = chain(&mut nodes);
        let mut list = list(head, 8);
        unsafe {
            LIST_UNDER_TEST = &mut list;
            // The first node's key is 8 and would have matched, but the
            // accessor zeroed the stop key first, so the reload sees 0.
            assert_eq!(list_count_until_match(&mut list), 2);
        }
        assert_eq!(visits, std::vec![8], "the second node skips the call: key is now 0");
    }
}
