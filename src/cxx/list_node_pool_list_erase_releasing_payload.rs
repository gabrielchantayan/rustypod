//! `list_node_pool_list_erase_releasing_payload` — retailOS `FUN_083dc3fc` @
//! `0x083dc3fc` (136 bytes; 34 A32 words through `pop {r4-r6,pc}` at
//! `0x083dc480`; the next independently linked function starts at
//! `0x083dc484`). Raw decoding finds two inbound unconditional plain `bl`
//! sites, no predicated direct callers, no outbound direct `bl`, and one
//! indirect `blx` through the removed node payload's vtable slot +0x00.
//!
//! Erases `*node_slot` from the list's intrusive ring. A sentinel selection
//! only returns the sentinel through `successor`. Otherwise it unlinks the
//! node, decrements the wrapping count, invokes the payload's slot-zero release
//! method with the payload word's address, returns the node to the pool free
//! list, and writes its successor through `successor`. Deliberate deviation:
//! the target's u32 vtable function slot cannot hold a native host callback, so
//! host builds use an explicit release seam; target builds perform the observed
//! vtable dispatch without assigning an identity to that callee.

use core::ptr::addr_of_mut;

use super::list_node_pool_acquire::ListNode;
use super::list_node_pool_list_construct::ListNodePoolList;

#[cfg(not(target_os = "none"))]
pub type PayloadRelease = unsafe extern "C" fn(*mut u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_payload_release(_: *mut u32) {
    panic!("install payload release operation")
}

#[cfg(not(target_os = "none"))]
pub static mut LIST_NODE_POOL_LIST_ERASE_RELEASING_PAYLOAD_RELEASE: PayloadRelease = missing_payload_release;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_payload(payload_slot: *mut u32) {
    let payload = payload_slot.read();
    let vtable = (payload as usize as *const u32).read();
    let release: unsafe extern "C" fn(*mut u32) = core::mem::transmute((vtable as usize as *const u32).read());
    release(payload_slot);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_payload(payload_slot: *mut u32) {
    let release = core::ptr::read_volatile(core::ptr::addr_of!(LIST_NODE_POOL_LIST_ERASE_RELEASING_PAYLOAD_RELEASE));
    release(payload_slot);
}

/// Erases `*node_slot`, releases its payload, and writes its successor.
///
/// # Safety
///
/// `list`, `node_slot`, and `successor` must point to valid target-layout
/// objects. A non-sentinel `*node_slot` must be linked into `list`'s ring and
/// have a payload accepted by its slot-zero release method.
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_list_erase_releasing_payload")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_erase_releasing_payload(
    successor: *mut u32,
    list: *mut ListNodePoolList,
    node_slot: *mut u32,
) {
    let node_word = unsafe { node_slot.read() };
    if node_word == unsafe { (*list).sentinel } {
        unsafe { successor.write(node_word) };
        return;
    }

    let node = node_word as usize as *mut ListNode;
    let next = unsafe { (*node).next };
    let previous = unsafe { (*node).prev };
    unsafe {
        addr_of_mut!((*(previous as usize as *mut ListNode)).next).write(next);
        addr_of_mut!((*(next as usize as *mut ListNode)).prev).write(previous);
        addr_of_mut!((*list).count).write((*list).count.wrapping_sub(1));
        release_payload(addr_of_mut!((*node).payload[0]));
        addr_of_mut!((*node).next).write((*list).pool.free);
        addr_of_mut!((*list).pool.free).write(node_word);
        successor.write(next);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static RELEASE_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED_SLOT: *mut u32 = core::ptr::null_mut();
    static mut RELEASE_CALLS: u32 = 0;

    unsafe extern "C" fn record_release(payload_slot: *mut u32) {
        unsafe {
            RELEASED_SLOT = payload_slot;
            RELEASE_CALLS += 1;
            payload_slot.write(0);
        }
    }

    #[test]
    fn erases_releases_and_recycles_or_reports_the_sentinel() {
        let _lock = RELEASE_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_ERASE_RELEASING_PAYLOAD, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_erase_releasing_payload");
            return;
        };

        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let sentinel = slab.add(0x100).cast::<ListNode>();
            let node = slab.add(0x120).cast::<ListNode>();
            let free = slab.add(0x140).cast::<ListNode>();
            let sentinel_word = sentinel as usize as u32;
            let node_word = node as usize as u32;
            let free_word = free as usize as u32;

            (*list).sentinel = sentinel_word;
            (*list).count = 1;
            (*list).pool.free = free_word;
            (*sentinel).next = node_word;
            (*sentinel).prev = node_word;
            (*node).next = sentinel_word;
            (*node).prev = sentinel_word;
            (*node).payload[0] = 0xfeed_beef;
            let mut selected = node_word;
            let mut successor = 0;
            LIST_NODE_POOL_LIST_ERASE_RELEASING_PAYLOAD_RELEASE = record_release;
            RELEASED_SLOT = core::ptr::null_mut();
            RELEASE_CALLS = 0;

            list_node_pool_list_erase_releasing_payload(&mut successor, list, &mut selected);

            assert_eq!(successor, sentinel_word);
            assert_eq!((*list).count, 0);
            assert_eq!((*sentinel).next, sentinel_word);
            assert_eq!((*sentinel).prev, sentinel_word);
            assert_eq!((*list).pool.free, node_word);
            assert_eq!((*node).next, free_word);
            assert_eq!(RELEASED_SLOT, addr_of_mut!((*node).payload[0]));
            assert_eq!(RELEASE_CALLS, 1);
            assert_eq!((*node).payload[0], 0);

            selected = sentinel_word;
            successor = 0;
            list_node_pool_list_erase_releasing_payload(&mut successor, list, &mut selected);
            assert_eq!(successor, sentinel_word);
            assert_eq!((*list).pool.free, node_word);
            assert_eq!(RELEASE_CALLS, 1);
        }
    }
}
