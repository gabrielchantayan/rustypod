//! Test whether a list's first-word chain is empty.
//!
//! `singly_linked_list_is_empty` — original: `FUN_0839e764` @ 0x0839e764
//! (24 bytes). Raw ARM establishes the exact 24-byte extent
//! 0x0839e764..0x0839e77c: `pop {r4,pc}` ends the body and the next separately
//! linked function begins with `push {r4-r8,lr}`. Whole-image A32 branch
//! decoding finds two direct inbound plain `bl` calls (0x08211ea0 and
//! 0x08211f2c), no predicated inbound `bl` calls, and one outbound plain `bl`
//! to `singly_linked_list_count` @ 0x0807a13c.
//!
//! Algorithm: count nodes starting at list+0x04, then return one only when the
//! count is zero. The list address itself has no NULL guard, as in retailOS.
//!
//! Deliberate deviations: none.

use super::linked_list_count::{singly_linked_list_count, SinglyLinkedNode};

/// Target-layout prefix whose head-link is at +0x04 on ARM.
#[repr(C)]
pub struct SinglyLinkedList {
    /// +0x00 — unrecovered list metadata; this function does not read it.
    pub metadata: u32,
    /// +0x04 on ARM — first node in the intrusive chain, or NULL.
    pub head: *mut SinglyLinkedNode,
}

/// Returns one when `list` has no nodes, otherwise zero.
///
/// `list` must point to a readable, target-layout [`SinglyLinkedList`]. Every
/// non-NULL node must meet [`singly_linked_list_count`]'s alignment and
/// readability requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn singly_linked_list_is_empty(list: *mut SinglyLinkedList) -> u32 {
    let head_link = unsafe { core::ptr::addr_of_mut!((*list).head) };
    (unsafe { singly_linked_list_count(head_link) } == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn empty_list_returns_one() {
        let mut list = SinglyLinkedList { metadata: u32::MAX, head: ptr::null_mut() };

        assert_eq!(unsafe { singly_linked_list_is_empty(&mut list) }, 1);
    }

    #[test]
    fn single_node_returns_zero() {
        let mut node = SinglyLinkedNode { next: ptr::null_mut() };
        let mut list = SinglyLinkedList { metadata: 0, head: &mut node };

        assert_eq!(unsafe { singly_linked_list_is_empty(&mut list) }, 0);
    }

    #[test]
    fn multiple_nodes_return_zero() {
        let mut nodes = [
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
        ];
        nodes[0].next = &mut nodes[1];
        nodes[1].next = &mut nodes[2];
        let mut list = SinglyLinkedList { metadata: 0x1234_5678, head: nodes.as_mut_ptr() };

        assert_eq!(unsafe { singly_linked_list_is_empty(&mut list) }, 0);
    }
}
