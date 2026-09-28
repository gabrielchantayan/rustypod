//! Test whether a condition queue's item chain is empty.
//!
//! `condition_queue_list_is_empty_0839e348` — original: `FUN_0839e348` @
//! **0x0839e348** (24 bytes, `0x0839e348..0x0839e360`; the next separately
//! linked function begins at `0x0839e360`). Raw A32 decoding finds two inbound
//! plain, unconditional `bl` calls (from `0x08100be4` and `0x0839e378`), no
//! predicated inbound `bl` calls, and one outbound plain `bl` to
//! `singly_linked_list_count` @ `0x0807a13c`; no predicated outbound calls.
//!
//! Algorithm: count the NULL-terminated intrusive item chain beginning at
//! queue+0x04, then return one exactly when that count is zero. The queue
//! pointer itself has no NULL guard, matching retailOS.
//!
//! Deliberate deviations: none.

use crate::cxx::condition_queue_is_empty_0839e670::ConditionQueue;
use crate::util::linked_list_count::singly_linked_list_count;

/// Returns one when `queue` has no item nodes, otherwise zero.
///
/// # Safety
/// `queue` must point to a readable target-layout [`ConditionQueue`]. Every
/// non-NULL node must satisfy `singly_linked_list_count`'s requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.condition_queue_list_is_empty_0839e348")]
#[inline(never)]
pub unsafe extern "C" fn condition_queue_list_is_empty_0839e348(queue: *mut ConditionQueue) -> u32 {
    let head_link = unsafe { core::ptr::addr_of_mut!((*queue).head) };
    (unsafe { singly_linked_list_count(head_link) } == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::linked_list_count::SinglyLinkedNode;
    use core::ptr;

    #[test]
    fn empty_queue_returns_one() {
        let mut queue = ConditionQueue { metadata: u32::MAX, head: ptr::null_mut() };

        assert_eq!(unsafe { condition_queue_list_is_empty_0839e348(&mut queue) }, 1);
    }

    #[test]
    fn nonempty_chain_returns_zero_without_reading_metadata() {
        let mut nodes = [
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
            SinglyLinkedNode { next: ptr::null_mut() },
        ];
        nodes[0].next = &mut nodes[1];
        nodes[1].next = &mut nodes[2];
        let mut queue = ConditionQueue { metadata: 0xa5a5_5a5a, head: nodes.as_mut_ptr() };

        assert_eq!(unsafe { condition_queue_list_is_empty_0839e348(&mut queue) }, 0);
        assert_eq!(queue.metadata, 0xa5a5_5a5a);
    }
}
