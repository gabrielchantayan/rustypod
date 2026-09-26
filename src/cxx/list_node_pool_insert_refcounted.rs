//! Inserts a refcounted payload into a pooled doubly linked list.
//!
//! `list_node_pool_insert_refcounted` — original: `FUN_083dc2d0` at load
//! address `0x083dc2d0` (116 bytes, `0x083dc2d0..0x083dc344`). Raw ARM
//! establishes the next real function at `0x083dc344` (`push {r4,r5,r6,lr}`).
//! It has one plain `bl` to the 12-byte node-pool acquire routine at
//! `0x083dc120`, and one predicated `blne` to
//! `refcounted_ptr_copy_construct` @ `0x0839ef3c`.
//!
//! The function acquires a node, copy-constructs its refcounted payload, then
//! inserts it immediately before the sentinel supplied through `node_slot`.
//! The list count at +0x14 increments with ARM wrapping arithmetic and the
//! acquired target pointer is written to `out`. The pool-acquire callee is now
//! the direct port [`refcounted_list_node_pool_acquire`], which preserves the
//! recovered 16-byte pool and 12-byte `{next, previous, value}` layout.

use crate::cxx::handle::{refcounted_ptr_copy_construct, RefcountedBody};
use crate::cxx::refcounted_list_node_pool_acquire::refcounted_list_node_pool_acquire;
use crate::cxx::word_list_node_pool_acquire::{WordListNode, WordListNodePool};

type AcquireNode = unsafe fn(*mut WordListNodePool) -> *mut WordListNode;
type CopyConstruct = unsafe fn(*mut u32, *const u32);

unsafe fn acquire_node(pool: *mut WordListNodePool) -> *mut WordListNode {
    refcounted_list_node_pool_acquire(pool, 0)
}

#[inline(always)]
unsafe fn copy_refcounted_payload(dst: *mut u32, src: *const u32) {
    refcounted_ptr_copy_construct(dst.cast::<*mut RefcountedBody>(), src.cast::<*mut RefcountedBody>());
}

#[inline(always)]
unsafe fn list_node_pool_insert_refcounted_with(
    acquire: AcquireNode,
    copy_construct: CopyConstruct,
    out: *mut u32,
    list: *mut u32,
    node_slot: *const u32,
    payload: *const u32,
) {
    let node = acquire(list.cast::<WordListNodePool>());
    copy_construct((node as *mut u32).add(2), payload);

    let sentinel = node_slot.read();
    (node as *mut u32).write(sentinel);
    (node as *mut u32).add(1).write((sentinel as *const u32).add(1).read());
    (((sentinel as *const u32).add(1).read()) as *mut u32).write(node as usize as u32);
    (sentinel as *mut u32).add(1).write(node as usize as u32);
    list.add(5).write(list.add(5).read().wrapping_add(1));
    out.write(node as usize as u32);
}

/// # Safety
///
/// `out`, `list`, `node_slot`, and `payload` must be valid aligned target-word
/// addresses. `*node_slot` must be a writable list sentinel, and the pool and
/// refcounted-body invariants required by the two recovered callees apply.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_insert_refcounted")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_insert_refcounted(
    out: *mut u32,
    list: *mut u32,
    node_slot: *const u32,
    payload: *const u32,
) {
    list_node_pool_insert_refcounted_with(acquire_node, copy_refcounted_payload, out, list, node_slot, payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut COPY: (usize, usize) = (0, 0);

    unsafe fn acquire(pool: *mut WordListNodePool) -> *mut WordListNode {
        (pool as *mut u8).add(0x100).cast()
    }

    unsafe fn copy_construct(dst: *mut u32, src: *const u32) {
        COPY = (dst as usize, src as usize);
        dst.write(src.read());
    }

    #[test]
    fn inserts_before_sentinel_and_wraps_count() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_INSERT_REFCOUNTED, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/list_node_pool_insert_refcounted"));
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let list = slab.cast::<u32>();
            let sentinel = list.add(0x80);
            let payload = list.add(0xc0);
            let mut out = 0;
            sentinel.write(sentinel as usize as u32);
            sentinel.add(1).write(sentinel as usize as u32);
            list.add(5).write(u32::MAX);
            payload.write(0x1234_5678);
            COPY = (0, 0);

            list_node_pool_insert_refcounted_with(acquire, copy_construct, &mut out, list, sentinel, payload);

            let node = list.add(0x40);
            assert_eq!(out, node as usize as u32);
            assert_eq!(COPY, (node.add(2) as usize, payload as usize));
            assert_eq!(node.read(), sentinel as usize as u32);
            assert_eq!(node.add(1).read(), sentinel as usize as u32);
            assert_eq!(node.add(2).read(), 0x1234_5678);
            assert_eq!(sentinel.read(), node as usize as u32);
            assert_eq!(sentinel.add(1).read(), node as usize as u32);
            assert_eq!(list.add(5).read(), 0);
        }
    }
}
