//! Count a NULL-terminated singly linked list.
//!
//! `singly_linked_list_count` — original: `FUN_0807a13c` @ 0x0807a13c
//! (28 bytes). Raw ARM spans 0x0807a13c..0x0807a158; 0x0807a15c begins
//! the separately linked next function. Decoding every ARM B/BL word in
//! `osos.dec` finds 11 direct inbound calls, all unconditional `bl`; no
//! predicated calls or tail branches target this entry.
//!
//! Algorithm: load the first link from the supplied head-link address, then
//! repeatedly follow the first word of each node until NULL, incrementing the
//! returned count once per node. As in retailOS, the head-link address itself
//! has no NULL guard and must be readable and word-aligned.
//!
//! Deviation: none. `wrapping_add` explicitly preserves ARM's 32-bit counter
//! wraparound rather than allowing host debug-overflow panics.

/// A singly linked node whose target layout begins with its next pointer.
#[repr(C)]
pub struct SinglyLinkedNode {
    /// +0x00 — next node, or NULL at the end of the chain.
    pub next: *mut SinglyLinkedNode,
}

/// Counts nodes reached from the non-NULL `head_link`.
///
/// `head_link` must point to a readable first-link word; every non-NULL link
/// must point to a readable, word-aligned [`SinglyLinkedNode`]. No cycle guard
/// exists, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.singly_linked_list_count")]
#[inline(never)]
pub unsafe extern "C" fn singly_linked_list_count(head_link: *mut *mut SinglyLinkedNode) -> u32 {
    let mut node = unsafe { head_link.read() };
    let mut count = 0u32;

    while !node.is_null() {
        count = count.wrapping_add(1);
        node = unsafe { node.read().next };
    }

    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn count(head_link: &mut *mut SinglyLinkedNode) -> u32 {
        unsafe { singly_linked_list_count(head_link) }
    }

    #[test]
    fn empty_head_link_returns_zero() {
        let mut head = ptr::null_mut();

        assert_eq!(count(&mut head), 0);
    }

    #[test]
    fn single_node_returns_one() {
        let mut node = SinglyLinkedNode { next: ptr::null_mut() };
        let mut head = &mut node as *mut SinglyLinkedNode;

        assert_eq!(count(&mut head), 1);
    }

    #[test]
    fn counts_every_node_through_the_null_terminator() {
        let mut nodes = [
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
        ];
        nodes[0].next = &mut nodes[1];
        nodes[1].next = &mut nodes[2];
        nodes[2].next = &mut nodes[3];
        let mut head = nodes.as_mut_ptr();

        assert_eq!(count(&mut head), 4);
    }
}
