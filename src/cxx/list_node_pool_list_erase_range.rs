//! `list_node_pool_list_erase_range` — retailOS `FUN_083dc484` @
//! `0x083dc484` (192 bytes).
//!
//! Raw `osos.dec` establishes the exact forty-eight-word A32 extent from
//! `push {r4-r7,lr}` at `0x083dc484` through `pop {r4-r7,pc}` at
//! `0x083dc540`; the next independently linked function starts at
//! `0x083dc544`. Whole-image aligned decoding finds one inbound unconditional
//! plain `bl` at `0x083dc7c0` and no predicated direct calls. The body has no
//! plain `bl` calls and one indirect `blx` through the payload vtable.
//!
//! Erases every node in `[first, end)` from the intrusive ring, invokes each
//! payload's first virtual method with its payload address, and returns each
//! node to the list free chain. It writes the first non-erased node to `out`.
//! Deliberate deviation: host tests replace the target-width virtual call with
//! an injected callback; target builds load and call the retail vtable slot.

use core::ptr::addr_of_mut;

use super::list_node_pool_acquire::ListNode;
use super::list_node_pool_list_construct::ListNodePoolList;

#[cfg(test)]
type HostPayloadDestroy = unsafe extern "C" fn(*mut u8);
#[cfg(test)]
static mut HOST_PAYLOAD_DESTROY: Option<HostPayloadDestroy> = None;

unsafe fn destroy_payload(payload: *mut u8) {
    #[cfg(target_os = "none")]
    {
        type PayloadDestroy = unsafe extern "C" fn(*mut u8);
        let vtable = payload.cast::<u32>().read();
        let destroy: PayloadDestroy = core::mem::transmute((vtable as usize as *const u32).read());
        destroy(payload);
    }
    #[cfg(test)]
    {
        if let Some(destroy) = HOST_PAYLOAD_DESTROY {
            destroy(payload);
        }
    }
    #[cfg(all(not(target_os = "none"), not(test)))]
    {
        let _ = payload;
    }
}

/// Erases nodes in `[first, end)`, storing `end` in `out`.
///
/// # Safety
///
/// `list`, `out`, `first`, and `end` must be valid target-layout objects.
/// Every node from `first` through, but excluding, `end` must be linked in
/// `list` and its payload vtable must provide a valid first virtual method.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_list_erase_range")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_erase_range(
    out: *mut u32,
    list: *mut ListNodePoolList,
    mut first: *mut ListNode,
    end: *const u32,
) {
    let end_word = end.read();
    while first as usize as u32 != end_word {
        let next = (*first).next;
        let previous = (*first).prev;
        addr_of_mut!((*(previous as usize as *mut ListNode)).next).write(next);
        addr_of_mut!((*(next as usize as *mut ListNode)).prev).write(previous);
        addr_of_mut!((*list).count).write((*list).count.wrapping_sub(1));
        destroy_payload(addr_of_mut!((*first).payload).cast());
        addr_of_mut!((*first).next).write((*list).pool.free);
        addr_of_mut!((*list).pool.free).write(first as usize as u32);
        first = next as usize as *mut ListNode;
    }
    out.write(first as usize as u32);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static DESTROYED: Mutex<std::vec::Vec<usize>> = Mutex::new(std::vec::Vec::new());

    unsafe extern "C" fn record_payload_destroy(payload: *mut u8) {
        DESTROYED.lock().push(payload as usize);
    }

    #[test]
    fn erases_half_open_range_dispatches_payloads_and_builds_free_chain() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_ERASE_RANGE, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_erase_range");
            return;
        };
        unsafe {
            HOST_PAYLOAD_DESTROY = Some(record_payload_destroy);
            DESTROYED.lock().clear();
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            let first = slab.add(0x120).cast::<ListNode>();
            let second = slab.add(0x140).cast::<ListNode>();
            let end = slab.add(0x160).cast::<ListNode>();
            (*list).sentinel = sentinel as usize as u32;
            (*list).count = 3;
            (*list).pool.free = 0xfeed_beef;
            (*sentinel).next = first as usize as u32;
            (*first).prev = sentinel as usize as u32;
            (*first).next = second as usize as u32;
            (*second).prev = first as usize as u32;
            (*second).next = end as usize as u32;
            (*end).prev = second as usize as u32;
            (*end).next = sentinel as usize as u32;
            (*sentinel).prev = end as usize as u32;
            let mut out = 0;
            let end_word = end as usize as u32;

            list_node_pool_list_erase_range(&mut out, list, first, &end_word);

            assert_eq!(out, end_word);
            assert_eq!((*list).count, 1);
            assert_eq!((*sentinel).next, end_word);
            assert_eq!((*end).prev, sentinel as usize as u32);
            assert_eq!((*first).next, 0xfeed_beef);
            assert_eq!((*second).next, first as usize as u32);
            assert_eq!((*list).pool.free, second as usize as u32);
            assert_eq!(*DESTROYED.lock(), [addr_of_mut!((*first).payload) as usize, addr_of_mut!((*second).payload) as usize]);
            HOST_PAYLOAD_DESTROY = None;
        }
    }

    #[test]
    fn empty_range_only_writes_cursor() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_ERASE_RANGE, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_erase_range");
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            (*list).count = 7;
            (*list).pool.free = 0xdead_beef;
            let mut out = 0;
            let sentinel_word = sentinel as usize as u32;
            list_node_pool_list_erase_range(&mut out, list, sentinel, &sentinel_word);
            assert_eq!(out, sentinel_word);
            assert_eq!(((*list).count, (*list).pool.free), (7, 0xdead_beef));
        }
    }
}
