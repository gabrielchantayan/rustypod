//! `list_node_pool_list_erase` — original: `FUN_083dd5f4` @ `0x083dd5f4`
//! (108 bytes; 27 A32 words through `pop {r2,r3,ip,pc}` at `0x083dd65c`; the
//! next function begins at `0x083dd660`). Raw decoding finds no outgoing plain
//! or predicated `bl`, and two inbound plain `bl` calls at `0x08292944` and
//! `0x083dd5c4`.
//!
//! Removes the node selected by `*node_slot` from the target-width intrusive
//! ring, returns its successor through `successor`, decrements the list state,
//! and returns the removed node to the pool free list. Selecting the sentinel
//! only reports the sentinel and leaves the list unchanged. Deliberate
//! deviation: none.

use core::ptr::addr_of_mut;

use super::list_node_pool_list_init::{ListNode, ListNodePoolList};

/// Removes `*node_slot` from `list`, writing its successor to `successor`.
///
/// # Safety
///
/// `list`, `node_slot`, and `successor` must be valid target-layout objects.
/// If `*node_slot` is not the sentinel, it must be linked into `list`'s ring.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_erase(
    successor: *mut u32,
    list: *mut ListNodePoolList,
    node_slot: *mut u32,
) {
    unsafe {
        let node_word = node_slot.read();
        if node_word == (*list).sentinel {
            successor.write((*list).sentinel);
            return;
        }

        let node = node_word as usize as *mut ListNode;
        let next = (*node).next;
        let previous = (*node).previous;
        addr_of_mut!((*(previous as usize as *mut ListNode)).next).write(next);
        addr_of_mut!((*(next as usize as *mut ListNode)).previous).write(previous);
        addr_of_mut!((*list).state).write((*list).state.wrapping_sub(1));
        addr_of_mut!((*node).next).write((*list).free);
        addr_of_mut!((*list).free).write(node_word);
        successor.write(next);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn erases_linked_node_and_preserves_sentinel_case() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_ERASE, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_erase");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            let previous = slab.add(0x120).cast::<ListNode>();
            let node = slab.add(0x140).cast::<ListNode>();
            let next = slab.add(0x160).cast::<ListNode>();
            (*list).sentinel = sentinel as usize as u32;
            (*list).free = 0xfeed_beef;
            (*list).state = 0;
            (*sentinel).next = previous as usize as u32;
            (*sentinel).previous = next as usize as u32;
            (*previous).next = node as usize as u32;
            (*node).previous = previous as usize as u32;
            (*node).next = next as usize as u32;
            (*next).previous = node as usize as u32;

            let mut selected = node as usize as u32;
            let mut successor = 0;
            list_node_pool_list_erase(&mut successor, list, &mut selected);

            assert_eq!(successor, next as usize as u32);
            assert_eq!((*previous).next, next as usize as u32);
            assert_eq!((*next).previous, previous as usize as u32);
            assert_eq!((*node).next, 0xfeed_beef);
            assert_eq!((*list).free, node as usize as u32);
            assert_eq!((*list).state, u32::MAX);
            assert_eq!((*list).chunks, 0xa5a5_a5a5);

            selected = sentinel as usize as u32;
            successor = 0;
            list_node_pool_list_erase(&mut successor, list, &mut selected);
            assert_eq!(successor, selected);
            assert_eq!((*list).free, node as usize as u32);
            assert_eq!((*list).state, u32::MAX);
        }
    }
}
