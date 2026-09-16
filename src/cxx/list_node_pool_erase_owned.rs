//! Doubly-linked-list node erase with owned-payload release — original:
//! `FUN_083dc24c` at load address `0x083dc24c`.
//!
//! Raw `osos.dec` establishes the exact 132-byte extent: 33 ARM words from
//! `push {r1-r7,lr}` at `0x083dc24c` through `pop {r1-r7,pc}` at
//! `0x083dc2cc`; the next separately linked function begins at `0x083dc2d0`.
//! Decoding every aligned ARM B/BL-immediate word in `osos.dec` finds
//! exactly four inbound direct calls, all unconditional `bl` at
//! `0x08133364`, `0x081333b0`, `0x0813356c`, and `0x083dc214`; there are no
//! predicated direct calls and no tail `b` sites. The body itself performs
//! exactly one `bl`, an unconditional call to
//! [`refcounted_body_release_owned_variant`] @ `0x0839cf4c` at `0x083dc2b0`;
//! its only predicated instruction is the `ldreq` that reloads the sentinel
//! for the early-out store.
//!
//! This is the erase sibling of [`list_node_pool_acquire`] over the same
//! ADS `std::list` node (`{next, prev, payload[3]}`, 20 bytes) and 24-byte
//! list header (16-byte pool state, sentinel node word at +0x10, node count
//! at +0x14). If `*node_slot` equals the sentinel it is not unlinked: the
//! routine simply writes the sentinel back to `*out` (erase-at-end is a
//! no-op). Otherwise it splices the node out of the ring
//! (`prev->next = next`, `next->prev = prev`), decrements the count,
//! releases the owned [`RefcountedBody`] handle in `payload[0]`, pushes the
//! node onto the pool free list (the free link lives in `next`), and writes
//! the erased node's `next` to `*out`. The `refcounted_body` slot is NULLed
//! by the callee, exactly as in retail. The clear-loop caller at
//! `0x083dc1d8` iterates `cur = sentinel->next; while cur != sentinel`
//! feeding each node back through this routine.
//!
//! Deliberate deviation: node links and payload words stay `u32` target
//! words so the 20-byte node layout holds on the host, but
//! [`refcounted_body_release_owned_variant`] takes a native
//! `*mut *mut RefcountedBody` slot. Target builds pass `&payload[0]`
//! directly (pointer width matches); host builds bounce the payload word
//! through a native slot and write the (NULLed) result back. This is a
//! pointer-width adaptation only — the observable behavior is identical.

use crate::cxx::handle::{refcounted_body_release_owned_variant, RefcountedBody};
use crate::cxx::list_node_pool_acquire::{ListNode, ListNodePool};

/// The 24-byte list header: 16-byte node-pool state followed by the
/// sentinel node word and the live node count.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct OwnedListHeader {
    pub pool: ListNodePool,
    /// Target +0x10: sentinel ("end") node; `sentinel.next` is the head.
    pub sentinel: u32,
    /// Target +0x14: number of live (non-sentinel) nodes in the ring.
    pub count: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(OwnedListHeader, sentinel)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(OwnedListHeader, count)];
const _: [u8; 0x18] = [0; core::mem::size_of::<OwnedListHeader>()];

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut ListNode {
    word as usize as *mut ListNode
}

/// Releases the owned body handle stored in the node's `payload[0]` word.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_owned_payload(slot: *mut u32) {
    refcounted_body_release_owned_variant(slot.cast());
}

/// Host pointer-width adaptation of [`release_owned_payload`]: the native
/// callee reads and NULLs an 8-byte slot, so the 4-byte target word is
/// bounced through a native temporary.
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_owned_payload(slot: *mut u32) {
    let mut body = slot.read() as usize as *mut RefcountedBody;
    refcounted_body_release_owned_variant(&mut body);
    slot.write(body as usize as u32);
}

/// Erases `*node_slot` from the intrusive ring headed by `header`,
/// releasing the node's owned payload and recycling the node onto the pool
/// free list. Writes the erased node's successor (or the sentinel itself
/// when erasing the sentinel) to `*out`.
///
/// Original: `FUN_083dc24c` at load address `0x083dc24c` (132 bytes; four
/// unconditional inbound `bl` sites, one internal unconditional `bl`).
///
/// # Safety
///
/// `out`, `header`, and `node_slot` must be valid writable pointers.
/// `*node_slot` must name a 20-byte [`ListNode`] currently linked into the
/// ring (or the sentinel itself), and its `payload[0]` word must satisfy
/// the [`refcounted_body_release_owned_variant`] slot contract. The stock
/// function performs no NULL checks on any input.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_erase_owned")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_erase_owned(
    out: *mut u32,
    header: *mut OwnedListHeader,
    node_slot: *mut u32,
) {
    let node_word = node_slot.read();
    let sentinel = (*header).sentinel;
    if node_word == sentinel {
        out.write(sentinel);
        return;
    }

    let node = node_from_word(node_word);
    let next = (*node).next;
    let prev = (*node).prev;
    (prev as usize as *mut u32).write(next);
    (*node_from_word(next)).prev = prev;
    (*header).count = (*header).count.wrapping_sub(1);
    release_owned_payload(core::ptr::addr_of_mut!((*node).payload).cast::<u32>());
    (*node).next = (*header).pool.free;
    (*header).pool.free = node_word;
    out.write(next);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    const NODE_SENTINEL: usize = 0x1000;
    const NODE_A: usize = 0x2000;
    const NODE_B: usize = 0x2400;
    const NODE_C: usize = 0x2800;
    const BODY_B: usize = 0x4000;

    unsafe fn word(base: *mut u8, offset: usize) -> u32 {
        base.add(offset) as usize as u32
    }

    unsafe fn node_at(base: *mut u8, offset: usize) -> *mut ListNode {
        base.add(offset) as *mut ListNode
    }

    /// Builds sentinel <-> A <-> B <-> C ring, count 3, empty free list, and
    /// a refcount-2 body owned by B's payload.
    unsafe fn build_ring(base: *mut u8, header: *mut OwnedListHeader) {
        let sentinel = word(base, NODE_SENTINEL);
        let a = word(base, NODE_A);
        let b = word(base, NODE_B);
        let c = word(base, NODE_C);
        ptr::write(
            node_at(base, NODE_SENTINEL),
            ListNode { next: a, prev: c, payload: [0; 3] },
        );
        ptr::write(
            node_at(base, NODE_A),
            ListNode { next: b, prev: sentinel, payload: [0; 3] },
        );
        ptr::write(
            node_at(base, NODE_B),
            ListNode { next: c, prev: a, payload: [word(base, BODY_B), 0, 0] },
        );
        ptr::write(
            node_at(base, NODE_C),
            ListNode { next: sentinel, prev: b, payload: [0; 3] },
        );
        ptr::write(
            base.add(BODY_B) as *mut RefcountedBody,
            RefcountedBody { opaque0: 0, refcount: 2, mutex: ptr::null_mut() },
        );
        ptr::write(
            header,
            OwnedListHeader {
                pool: ListNodePool::default(),
                sentinel,
                count: 3,
            },
        );
    }

    /// Single entry point: the three phases share one dedicated slab
    /// mapping, so they must run sequentially rather than as parallel tests.
    #[test]
    fn erase_owned_scenarios() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_ERASE_OWNED, 0x8000) else {
            note_missing_u32_fixture("cxx/list_node_pool_erase_owned");
            return;
        };

        unsafe {
            erases_middle_node(slab);
            erasing_sentinel_only_reports_end(slab);
            clear_loop_drains_ring(slab);
        }
    }

    unsafe fn erases_middle_node(slab: *mut u8) {
        {
            let header = slab as *mut OwnedListHeader;
            build_ring(slab, header);
            let mut slot = word(slab, NODE_B);
            let mut out = 0u32;

            list_node_pool_erase_owned(&mut out, header, &mut slot);

            // Successor is reported; neighbors are spliced together.
            assert_eq!(out, word(slab, NODE_C));
            assert_eq!((*node_at(slab, NODE_A)).next, word(slab, NODE_C));
            assert_eq!((*node_at(slab, NODE_C)).prev, word(slab, NODE_A));
            // Count drops by one.
            assert_eq!((*header).count, 2);
            // Owned payload was released: refcount 2 -> 1, slot NULLed.
            let body = slab.add(BODY_B) as *mut RefcountedBody;
            assert_eq!((*body).refcount, 1);
            assert_eq!((*node_at(slab, NODE_B)).payload[0], 0);
            // Node is recycled onto the free list through its `next` word.
            assert_eq!((*header).pool.free, word(slab, NODE_B));
            assert_eq!((*node_at(slab, NODE_B)).next, 0);
            // The slot word itself is not rewritten by the erase.
            assert_eq!(slot, word(slab, NODE_B));
        }
    }

    unsafe fn erasing_sentinel_only_reports_end(slab: *mut u8) {
        {
            let header = slab as *mut OwnedListHeader;
            build_ring(slab, header);
            let mut slot = word(slab, NODE_SENTINEL);
            let mut out = 0u32;

            list_node_pool_erase_owned(&mut out, header, &mut slot);

            assert_eq!(out, word(slab, NODE_SENTINEL));
            // No side effects: ring, count, free list, and payload untouched.
            assert_eq!((*header).count, 3);
            assert_eq!((*header).pool.free, 0);
            assert_eq!((*node_at(slab, NODE_A)).prev, word(slab, NODE_SENTINEL));
            assert_eq!((*node_at(slab, NODE_C)).next, word(slab, NODE_SENTINEL));
            let body = slab.add(BODY_B) as *mut RefcountedBody;
            assert_eq!((*body).refcount, 2);
            assert_eq!((*node_at(slab, NODE_B)).payload[0], word(slab, BODY_B));
        }
    }

    unsafe fn clear_loop_drains_ring(slab: *mut u8) {
        {
            let header = slab as *mut OwnedListHeader;
            build_ring(slab, header);

            // Mirror FUN_083dc1d8: walk from sentinel->next until the
            // sentinel, erasing every node through this routine.
            let sentinel = word(slab, NODE_SENTINEL);
            let mut current = (*node_at(slab, NODE_SENTINEL)).next;
            let mut order = std::vec::Vec::new();
            while current != sentinel {
                let mut slot = current;
                let mut out = 0u32;
                list_node_pool_erase_owned(&mut out, header, &mut slot);
                order.push(current);
                current = out;
            }

            assert_eq!(
                order,
                std::vec![word(slab, NODE_A), word(slab, NODE_B), word(slab, NODE_C)]
            );
            assert_eq!((*header).count, 0);
            // Free list is a LIFO chain through `next`: C -> B -> A -> 0.
            assert_eq!((*header).pool.free, word(slab, NODE_C));
            assert_eq!((*node_at(slab, NODE_C)).next, word(slab, NODE_B));
            assert_eq!((*node_at(slab, NODE_B)).next, word(slab, NODE_A));
            assert_eq!((*node_at(slab, NODE_A)).next, 0);
            let body = slab.add(BODY_B) as *mut RefcountedBody;
            assert_eq!((*body).refcount, 1);
        }
    }
}
