//! Test whether a condition queue's item chain is empty.
//!
//! `condition_queue_list_is_empty` — original: `FUN_0839e488` @
//! **0x0839e488** (24 bytes, `0x0839e488..0x0839e4a0`; the next separately
//! linked function begins at `0x0839e4a0`). Raw A32 decoding finds two inbound
//! plain, unconditional `bl` calls (from `0x0839e4ac` and `0x0839e548`), no
//! predicated inbound `bl` calls, and one outbound plain `bl` to
//! `singly_linked_list_count` @ `0x0807a13c`; no predicated outbound calls.
//!
//! Algorithm: count the NULL-terminated intrusive item chain beginning at
//! queue+0x04, then return one exactly when that count is zero. The queue
//! pointer itself has no NULL guard, matching retailOS.
//!
//! Deliberate deviation: host builds traverse target-width `u32` links
//! directly so a target-layout queue remains testable on hosts with 8-byte
//! pointers; target builds directly call the ported count helper.

#[cfg(target_os = "none")]
use crate::util::linked_list_count::{singly_linked_list_count, SinglyLinkedNode};

/// Returns one when `queue` has no item nodes, otherwise zero.
///
/// # Safety
///
/// `queue` must point to a readable target-layout condition queue. Its word at
/// +0x04 and every non-NULL node's first word must be readable and word-aligned.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.condition_queue_list_is_empty")]
#[inline(never)]
pub unsafe extern "C" fn condition_queue_list_is_empty(queue: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let head_link = unsafe { queue.add(4).cast::<*mut SinglyLinkedNode>() };
        return (unsafe { singly_linked_list_count(head_link) } == 0) as u32;
    }

    #[cfg(not(target_os = "none"))]
    {
        let mut node = unsafe { queue.add(4).cast::<u32>().read() as usize as *const u32 };
        let mut count = 0u32;
        while !node.is_null() {
            count = count.wrapping_add(1);
            node = unsafe { node.read() as usize as *const u32 };
        }
        (count == 0) as u32
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn distinguishes_empty_and_multi_item_target_width_chains() {
        let Some(slab) = try_map_u32_slab(hints::CONDITION_QUEUE_LIST_IS_EMPTY, 0x1000) else {
            return;
        };
        unsafe {
            let queue = slab.cast::<u32>();
            let first = slab.add(0x20).cast::<u32>();
            let second = slab.add(0x24).cast::<u32>();
            let third = slab.add(0x28).cast::<u32>();
            queue.write(0xa5a5_5a5a);
            queue.add(1).write(first as usize as u32);
            first.write(second as usize as u32);
            second.write(third as usize as u32);
            third.write(0);

            assert_eq!(condition_queue_list_is_empty(slab), 0);
            assert_eq!(queue.read(), 0xa5a5_5a5a);

            queue.add(1).write(0);
            assert_eq!(condition_queue_list_is_empty(slab), 1);
        }
    }
}
