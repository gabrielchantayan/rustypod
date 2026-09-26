//! `list_node_pool_list_append_value` — original: `FUN_083dd660` @ `0x083dd660`
//! (104 bytes; 26 A32 words through `pop {r2,r3,r4,r5,r6,pc}` at
//! `0x083dd6c4`; the next separately linked function begins at `0x083dd6c8`).
//! Raw decoding finds one plain outgoing `bl` to `list_node_pool_acquire` at
//! `0x083dd4cc`, no predicated `bl`, and two inbound plain `bl` calls at
//! `0x08292800` and `0x08292914`.
//!
//! Acquires a node, conditionally stores the supplied value in its final word,
//! and splices it before the sentinel of the target-width intrusive ring. It
//! then increments the list state word with wrapping arithmetic. Deliberate
//! deviation: none.

use core::ptr::addr_of_mut;

use super::list_node_pool_acquire_083dd4cc::list_node_pool_acquire_083dd4cc;
use super::list_node_pool_list_init::{ListNode, ListNodePoolList};

/// Appends `*value` immediately before `list`'s sentinel.
///
/// # Safety
///
/// `list`, its sentinel ring, and `value` must be live target-layout objects;
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_append_value(
    list: *mut ListNodePoolList,
    value: *const u32,
) {
    let sentinel = (*list).sentinel as usize as *mut ListNode;
    let node = list_node_pool_acquire_083dd4cc(list, 0);

    if (node as usize as u32).wrapping_add(8) != 0 {
        addr_of_mut!((*node).value).write(*value);
    }
    addr_of_mut!((*node).next).write((*list).sentinel);
    let previous = (*sentinel).previous;
    addr_of_mut!((*node).previous).write(previous);
    addr_of_mut!((*(previous as usize as *mut ListNode)).next).write(node as usize as u32);
    addr_of_mut!((*sentinel).previous).write(node as usize as u32);
    addr_of_mut!((*list).state).write((*list).state.wrapping_add(1));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn appends_after_existing_tail_and_preserves_unrelated_pool_words() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_APPEND_VALUE, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_append_value");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            let tail = slab.add(0x120).cast::<ListNode>();
            let node = slab.add(0x140).cast::<ListNode>();
            (*list).sentinel = sentinel as usize as u32;
            (*list).state = u32::MAX;
            (*sentinel).next = tail as usize as u32;
            (*sentinel).previous = tail as usize as u32;
            (*tail).next = sentinel as usize as u32;
            (*tail).previous = sentinel as usize as u32;
            (*node).next = 0;
            (*list).free = node as usize as u32;

            let value = 0xcafe_babe;
            list_node_pool_list_append_value(list, &value);
            assert_eq!((*node).next, sentinel as usize as u32);
            assert_eq!((*node).previous, tail as usize as u32);
            assert_eq!((*node).value, value);
            assert_eq!((*tail).next, node as usize as u32);
            assert_eq!((*sentinel).previous, node as usize as u32);
            assert_eq!((*sentinel).next, tail as usize as u32);
            assert_eq!((*list).state, 0);
            assert_eq!((*list).chunks, 0xa5a5_a5a5);
            assert_eq!((*list).free, 0);
            assert_eq!((*list).next, 0xa5a5_a5a5);
            assert_eq!((*list).end, 0xa5a5_a5a5);
        }
    }
}
