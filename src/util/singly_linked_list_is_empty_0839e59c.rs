//! Test whether a list's first-word chain is empty.
//!
//! `singly_linked_list_is_empty_0839e59c` — original: `FUN_0839e59c` @
//! **0x0839e59c** (24 bytes, `0x0839e59c..0x0839e5b4`; the next separately
//! linked function begins at `0x0839e5b4`). Raw A32 decoding finds two inbound
//! plain, unconditional `bl` calls (from `0x081ba5d8` and `0x081ba640`), no
//! predicated inbound `bl` calls, and one outbound plain `bl` to
//! `singly_linked_list_count` @ `0x0807a13c`; no predicated outbound calls.
//!
//! Algorithm: count nodes starting at list+0x04, then return one only when the
//! count is zero. The list address itself has no NULL guard, as in retailOS.
//!
//! Deliberate deviations: none.

use super::linked_list_count::singly_linked_list_count;
use super::singly_linked_list_is_empty::SinglyLinkedList;

/// Returns one when `list` has no nodes, otherwise zero.
///
/// # Safety
/// `list` must point to a readable, target-layout [`SinglyLinkedList`]. Every
/// non-NULL node must meet [`singly_linked_list_count`]'s alignment and
/// readability requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.singly_linked_list_is_empty_0839e59c")]
#[inline(never)]
pub unsafe extern "C" fn singly_linked_list_is_empty_0839e59c(list: *mut SinglyLinkedList) -> u32 {
    let head_link = unsafe { core::ptr::addr_of_mut!((*list).head) };
    (unsafe { singly_linked_list_count(head_link) } == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::linked_list_count::SinglyLinkedNode;
    use core::ptr;

    #[test]
    fn empty_list_returns_one() {
        let mut list = SinglyLinkedList { metadata: u32::MAX, head: ptr::null_mut() };

        assert_eq!(unsafe { singly_linked_list_is_empty_0839e59c(&mut list) }, 1);
    }

    #[test]
    fn populated_list_returns_zero_without_reading_metadata() {
        let mut nodes = [
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
        ];
        nodes[0].next = &mut nodes[1];
        nodes[1].next = &mut nodes[2];
        let mut list = SinglyLinkedList { metadata: 0xa5a5_5a5a, head: nodes.as_mut_ptr() };

        assert_eq!(unsafe { singly_linked_list_is_empty_0839e59c(&mut list) }, 0);
        assert_eq!(list.metadata, 0xa5a5_5a5a);
    }
}
