//! `list_node_pool_list_insert_payload_range` — retailOS `FUN_083dc544` @
//! `0x083dc544` (176 bytes).
//!
//! Raw `osos.dec` establishes the exact forty-four-word A32 extent from
//! `push {r0-r8,lr}` at `0x083dc544` through `pop {r0-r8,pc}` at
//! `0x083dc5f0`; the literal word at `0x083dc5f4` is followed by the next
//! separately linked function at `0x083dc5f8`. The body has one unconditional
//! plain `bl`, to `list_node_pool_acquire` @ `0x083dc344`, and no predicated
//! `bl` calls. Whole-image A32 decoding finds two inbound unconditional plain
//! `bl` sites (`0x0811f3c4`, `0x083dc7d4`) and no predicated direct calls.
//!
//! Inserts one freshly allocated node before `*insertion_link` for every node
//! in `[source, end)`. Each new node receives the retail payload tag and words
//! 1 and 2 from its source, then is spliced into the target intrusive ring;
//! the target list count increments with wrapping arithmetic. Deliberate
//! deviation: the unlabelled literal `0x0898ce24` is retained as a named
//! payload tag rather than inventing a callee or type identity.

use core::ptr::addr_of_mut;

use super::list_node_pool_acquire::{list_node_pool_acquire, ListNode};
use super::list_node_pool_list_construct::ListNodePoolList;

const PAYLOAD_TAG: u32 = 0x0898_ce24;

/// Inserts tagged copies of source payload words 1 and 2 before the node word
/// stored at `insertion_link`.
///
/// # Safety
///
/// `list` must be a live target-layout list, `insertion_link` must contain a
/// node in its writable ring, and `[source, end)` must be a next-linked range
/// of readable [`ListNode`]s. The list pool must be valid for acquisition.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_list_insert_payload_range")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_insert_payload_range(
    list: *mut ListNodePoolList,
    insertion_link: *const u32,
    mut source: *const ListNode,
    end: *const ListNode,
) -> *mut ListNode {
    let mut inserted = core::ptr::null_mut();

    while source != end {
        let insertion = *insertion_link as usize as *mut ListNode;
        inserted = list_node_pool_acquire(addr_of_mut!((*list).pool), 0);
        if (inserted as usize as u32).wrapping_add(8) != 0 {
            addr_of_mut!((*inserted).payload[0]).write(PAYLOAD_TAG);
            addr_of_mut!((*inserted).payload[1]).write((*source).payload[1]);
            addr_of_mut!((*inserted).payload[2]).write((*source).payload[2]);
        }
        addr_of_mut!((*inserted).next).write(insertion as usize as u32);
        let previous = (*insertion).prev;
        addr_of_mut!((*inserted).prev).write(previous);
        addr_of_mut!((*(previous as usize as *mut ListNode)).next).write(inserted as usize as u32);
        addr_of_mut!((*insertion).prev).write(inserted as usize as u32);
        addr_of_mut!((*list).count).write((*list).count.wrapping_add(1));
        source = (*source).next as usize as *const ListNode;
    }

    inserted
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inserts_source_range_in_order_before_fixed_link() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_INSERT_PAYLOAD_RANGE, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_insert_payload_range");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            let tail = slab.add(0x120).cast::<ListNode>();
            let first = slab.add(0x140).cast::<ListNode>();
            let second = slab.add(0x160).cast::<ListNode>();
            let source_first = slab.add(0x200).cast::<ListNode>();
            let source_second = slab.add(0x220).cast::<ListNode>();
            let source_end = slab.add(0x240).cast::<ListNode>();

            (*list).sentinel = sentinel as usize as u32;
            (*list).count = u32::MAX;
            (*list).pool.free = first as usize as u32;
            (*first).next = second as usize as u32;
            (*second).next = 0;
            (*sentinel).next = tail as usize as u32;
            (*sentinel).prev = tail as usize as u32;
            (*tail).next = sentinel as usize as u32;
            (*tail).prev = sentinel as usize as u32;
            (*source_first).next = source_second as usize as u32;
            (*source_first).payload = [0x1111_1111, 0x2222_2222, 0x3333_3333];
            (*source_second).next = source_end as usize as u32;
            (*source_second).payload = [0x4444_4444, 0x5555_5555, 0x6666_6666];

            let inserted = list_node_pool_list_insert_payload_range(list, &(*sentinel).next, source_first, source_end);

            assert_eq!(inserted, second);
            assert_eq!((*list).pool.free, 0);
            assert_eq!((*list).count, 1);
            assert_eq!((*sentinel).next, first as usize as u32);
            assert_eq!((*first).prev, sentinel as usize as u32);
            assert_eq!((*first).next, second as usize as u32);
            assert_eq!((*second).prev, first as usize as u32);
            assert_eq!((*second).next, tail as usize as u32);
            assert_eq!((*tail).prev, second as usize as u32);
            assert_eq!((*first).payload, [PAYLOAD_TAG, 0x2222_2222, 0x3333_3333]);
            assert_eq!((*second).payload, [PAYLOAD_TAG, 0x5555_5555, 0x6666_6666]);
            assert_eq!((*list).pool.chunks, 0xa5a5_a5a5);
            assert_eq!((*list).pool.next, 0xa5a5_a5a5);
            assert_eq!((*list).pool.end, 0xa5a5_a5a5);
        }
    }

    #[test]
    fn empty_range_leaves_list_unchanged_and_returns_null() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_INSERT_PAYLOAD_RANGE, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_insert_payload_range");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            (*list).sentinel = sentinel as usize as u32;
            (*list).count = 7;
            (*sentinel).next = sentinel as usize as u32;
            (*sentinel).prev = sentinel as usize as u32;

            let inserted = list_node_pool_list_insert_payload_range(list, &(*sentinel).next, sentinel, sentinel);

            assert!(inserted.is_null());
            assert_eq!((*list).count, 7);
            assert_eq!((*sentinel).next, sentinel as usize as u32);
            assert_eq!((*sentinel).prev, sentinel as usize as u32);
        }
    }
}
