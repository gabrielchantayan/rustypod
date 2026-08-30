//! Shared-cell handle family: intrusive-refcounted polymorphic cells the
//! C++ layer hangs off one-word slots, and the release helper that tears
//! them down.
//!
//! The family (addresses binary-verified against osos.dec):
//!
//! | address      | role                                                        |
//! |--------------|-------------------------------------------------------------|
//! | 0x083b5090   | constructor: 8-byte `operator_new`, `{value, refcount = 1}`  |
//! | 0x083b50c8   | copy-construct: copy the cell pointer, `refcount += 1`       |
//! | 0x083b50e4   | copy-assign: release dst, copy src's cell, `refcount += 1`   |
//! | 0x083b5120   | slot word compare (ported as `cxx::value_compare`)           |
//! | 0x083b524c   | release — this module                                        |
//! | 0x083b52a0   | release, byte-identical save the `bl` displacement (19 sites)|
//! | 0x083b52f4   | release variant with a direct `bl 0x081fc930` value destroy  |
//!
//! A slot is one word holding a cell pointer (or NULL); a cell is two
//! words: the polymorphic payload pointer and a signed refcount. The
//! constructor stores 1, the copy helpers increment, the release helper
//! decrements and destroys on the transition to zero. Destruction is
//! virtual: the payload's deleting destructor runs through vtable word 1
//! (+4), then the cell itself is tag-2 `operator_delete`d. The slot is
//! always cleared, shared reference or not.

use crate::heap::veneers::{operator_delete, operator_new};

/// Two-word shared cell a slot points at. On the ARM target word 0 (+0)
/// is the polymorphic payload pointer — its own first word is the vtable
/// [`shared_cell_release`] dispatches through — and word 1 (+4) is the
/// signed refcount. Host fixtures widen word 0 to `usize`, keeping the
/// fields disjoint on a 64-bit host.
#[repr(C)]
pub struct SharedCell {
    /// Target +0: payload pointer; NULL is legal and skips the virtual
    /// destroy but not the cell delete.
    pub value: usize,
    /// Target +4: intrusive reference count. The constructor stores 1;
    /// a plain ARM `subs` drives the decrement, so it wraps on underflow.
    pub refcount: i32,
}

/// shared_cell_construct — original: `FUN_083b5090` @ `0x083b5090`
/// (56 bytes; 29 `bl` call sites, ALL unconditional — zero predicated
/// forms and zero tail `b`, verified by decoding every B/BL word in
/// osos.dec). Whole body:
///
/// ```text
/// 083b5090: push  {r4, r5, r6, lr}
/// 083b5094: mov   r4, r0
/// 083b5098: mov   r0, #0
/// 083b509c: movs  r5, r1
/// 083b50a0: str   r0, [r4]          @ *slot = NULL
/// 083b50a4: beq   0x083b50c0        @ NULL value: return slot
/// 083b50a8: mov   r0, #8
/// 083b50ac: bl    0x082aadd4        @ operator_new(8)
/// 083b50b0: mov   r1, #1
/// 083b50b4: str   r1, [r0, #4]      @ cell->refcount = 1
/// 083b50b8: str   r5, [r0]          @ cell->value = value
/// 083b50bc: str   r0, [r4]          @ *slot = cell
/// 083b50c0: mov   r0, r4
/// 083b50c4: pop   {r4, r5, r6, pc}
/// ```
///
/// Clears `slot`, then, for a non-NULL polymorphic payload, allocates an
/// 8-byte `{value, refcount}` cell with tag-2 [`operator_new`], sets its
/// reference count to one, and installs it in the slot. It returns `slot`.
/// A NULL payload does not allocate. The original has no allocation-failure
/// guard; its stores through a NULL allocator result fault, so this port
/// likewise requires a non-NULL allocator result for a non-NULL payload.
///
/// Deviation: [`SharedCell::value`] is `usize` on hosts to retain host
/// pointers in tests, while the target field is one 32-bit word; the
/// allocation request remains the raw target size of eight bytes.
///
/// # Safety
/// `slot` must be a valid, aligned writable shared-cell slot. For a
/// non-NULL `value`, `operator_new(8)` must return writable storage for a
/// [`SharedCell`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.shared_cell_construct")]
#[inline(never)]
pub unsafe extern "C" fn shared_cell_construct(
    slot: *mut *mut SharedCell,
    value: *mut u8,
) -> *mut *mut SharedCell {
    slot.write(core::ptr::null_mut());
    if !value.is_null() {
        let cell = operator_new(8).cast::<SharedCell>();
        core::ptr::addr_of_mut!((*cell).refcount).write_volatile(1);
        core::ptr::addr_of_mut!((*cell).value).write_volatile(value as usize);
        slot.write(cell);
    }
    slot
}

/// shared_cell_release — original: `FUN_083b524c` @ `0x083b524c`
/// (84 bytes; 38 `bl` call sites, ALL unconditional — zero predicated
/// forms and zero tail `b`, verified by decoding every B/BL word in
/// osos.dec; the callee's own NULL guard is the only guard). Whole body:
///
/// ```text
/// 083b524c: push  {r4, lr}
/// 083b5250: mov   r4, r0
/// 083b5254: ldr   r0, [r0]          @ cell = *slot
/// 083b5258: cmp   r0, #0
/// 083b525c: popeq {r4, pc}          @ empty slot: no-op, slot untouched
/// 083b5260: ldr   r1, [r0, #4]
/// 083b5264: subs  r1, r1, #1        @ refcount -= 1 (wraps)
/// 083b5268: str   r1, [r0, #4]
/// 083b526c: bne   0x083b5294        @ still shared: skip teardown
/// 083b5270: ldr   r0, [r4]          @ reload cell through the slot
/// 083b5274: ldr   r0, [r0]          @ value = cell->value
/// 083b5278: cmp   r0, #0
/// 083b527c: ldrne r1, [r0]          @ vtable
/// 083b5280: ldrne r1, [r1, #4]      @ vtable[1] = deleting destructor
/// 083b5284: blxne r1                @ value->~T() (deleting)
/// 083b5288: ldr   r0, [r4]          @ RELOAD cell after the virtual call
/// 083b528c: cmp   r0, #0
/// 083b5290: blne  0x082aad24        @ operator_delete(cell)
/// 083b5294: mov   r0, #0
/// 083b5298: str   r0, [r4]          @ *slot = NULL (every non-empty path)
/// 083b529c: pop   {r4, pc}
/// ```
///
/// Drops one reference to the cell in `slot`. A non-final drop only
/// decrements; the final drop (1 -> 0) runs the payload's virtual
/// deleting destructor (ARM EABI vtable slot 1) when the payload pointer
/// is non-NULL, reloads the slot — a destructor that aliased and cleared
/// the slot suppresses the delete — and tag-2 `operator_delete`s the
/// 8-byte cell. Every path that found a non-NULL cell then NULLs the
/// slot; a NULL cell returns early with the slot untouched. Refcount 0
/// underflows to -1 and takes the shared path (no teardown), exactly as
/// the wrapping `subs` encodes.
///
/// The sibling @ 0x083b52a0 is this same body (19 `bl` sites) and may
/// alias this symbol; 0x083b52f4 swaps the virtual dispatch for a direct
/// call and is a distinct port.
///
/// Deviation: the original's predicated `blxne`/`blne` become ordinary
/// guarded calls; the dispatch seam is `heap::veneers::operator_delete`
/// (the ported tag-2 delete @ 0x082aad24).
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot; it is not NULL-checked,
/// as in the original. A non-NULL cell must be readable/writable for two
/// words; on the final drop a non-NULL `value` must point at a live
/// object whose first word names a vtable with a valid function pointer
/// at word 1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_cell_release(slot: *mut *mut SharedCell) {
    let cell = slot.read();
    if cell.is_null() {
        return;
    }

    let remaining = (*cell).refcount.wrapping_sub(1);
    (*cell).refcount = remaining;
    if remaining == 0 {
        // Reloaded through the slot, like the ARM's `ldr r0, [r4]` /
        // `ldr r0, [r0]` pair, though nothing could have changed it yet.
        let value = (*slot.read()).value as *mut u8;
        if !value.is_null() {
            let vtable = (value as *const usize).read() as *const usize;
            let deleting_destructor: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(1).read());
            deleting_destructor(value);
        }

        // The ARM reloads the slot after the virtual call and skips the
        // cell delete when it now holds NULL.
        let cell = slot.read();
        if !cell.is_null() {
            operator_delete(cell.cast());
        }
    }

    slot.write(core::ptr::null_mut());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::vec::Vec;

    /// The crate's test configuration serializes hook-swapping tests;
    /// this atomic also keeps the fixture safe when a runner overrides
    /// that configuration.
    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut EVENTS: Vec<Event> = Vec::new();
    /// Lets a recording destructor alias the caller's slot, proving the
    /// post-destructor reload.
    static mut SLOT_ALIAS: *mut *mut SharedCell = core::ptr::null_mut();
    /// The next allocation returned by the mocked tag-2 allocator.
    static mut NEXT_ALLOCATION: *mut u8 = core::ptr::null_mut();

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Destructor(usize),
        HeapFree(usize, usize),
        HeapAlloc(usize, usize),
    }

    unsafe extern "C" fn recording_destructor(value: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Destructor(value as usize));
    }

    unsafe extern "C" fn slot_clearing_destructor(value: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Destructor(value as usize));
        (*core::ptr::addr_of_mut!(SLOT_ALIAS)).write(core::ptr::null_mut());
    }

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::HeapFree(ptr as usize, tag));
    }

    unsafe extern "C" fn recording_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::HeapAlloc(size, tag));
        core::ptr::read_volatile(core::ptr::addr_of!(NEXT_ALLOCATION))
    }

    struct Bench {
        old_heap: HeapVeneerOps,
    }

    fn bench() -> Bench {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            (*core::ptr::addr_of_mut!(SLOT_ALIAS)) = core::ptr::null_mut();
            (*core::ptr::addr_of_mut!(NEXT_ALLOCATION)) = core::ptr::null_mut();
            let old_heap = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(HEAP_OPS),
                HeapVeneerOps {
                    alloc: recording_alloc,
                    free: recording_free,
                    ..old_heap
                },
            );
            Bench { old_heap }
        }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), self.old_heap);
            }
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// A NULL payload clears an existing slot, returns that same slot, and
    /// takes the early path before the allocator call.
    #[test]
    fn null_payload_clears_slot_without_allocating() {
        let _bench = bench();
        let mut slot = 0x1234usize as *mut SharedCell;

        let result = unsafe { shared_cell_construct(&mut slot, core::ptr::null_mut()) };

        assert_eq!(result, core::ptr::addr_of_mut!(slot));
        assert!(slot.is_null());
        assert!(events().is_empty());
    }

    /// A non-NULL payload requests the raw eight-byte target cell, replaces
    /// the old slot value, and initializes the new cell in store order.
    #[test]
    fn payload_allocates_and_initializes_a_shared_cell() {
        let _bench = bench();
        let mut cell = SharedCell {
            value: 0,
            refcount: -1,
        };
        let cell_ptr = core::ptr::addr_of_mut!(cell);
        unsafe {
            (*core::ptr::addr_of_mut!(NEXT_ALLOCATION)) = cell_ptr.cast();
        }
        let payload = 0x1234_5678usize as *mut u8;
        let mut slot = 0xfeed_faceusize as *mut SharedCell;

        let result = unsafe { shared_cell_construct(&mut slot, payload) };

        assert_eq!(result, core::ptr::addr_of_mut!(slot));
        assert_eq!(slot, cell_ptr);
        assert_eq!(cell.value, payload as usize);
        assert_eq!(cell.refcount, 1);
        assert_eq!(events(), std::vec![Event::HeapAlloc(8, 2)]);
    }

    /// NULL cell: the original returns before touching anything, and the
    /// (already NULL) slot keeps its word.
    #[test]
    fn null_cell_returns_without_touching_anything() {
        let _bench = bench();
        let mut slot: *mut SharedCell = core::ptr::null_mut();

        unsafe { shared_cell_release(&mut slot) };

        assert!(slot.is_null());
        assert!(events().is_empty());
    }

    /// Non-final drop (2 -> 1): the count falls and the slot is cleared,
    /// but neither the destructor nor the cell delete runs.
    #[test]
    fn shared_reference_only_decrements_and_nulls_the_slot() {
        let _bench = bench();
        let mut cell = SharedCell {
            value: 0x1111_2222,
            refcount: 2,
        };
        let mut slot = core::ptr::addr_of_mut!(cell);

        unsafe { shared_cell_release(&mut slot) };

        assert_eq!(cell.refcount, 1);
        assert_eq!(cell.value, 0x1111_2222, "the payload word is not read");
        assert!(slot.is_null(), "the non-final path still clears the slot");
        assert!(events().is_empty());
    }

    /// Final drop (1 -> 0): vtable[1] runs with the payload pointer, then
    /// the reloaded cell is tag-2 deleted, then the slot is cleared.
    #[test]
    fn final_reference_dispatches_vtable1_then_deletes_the_cell() {
        let _bench = bench();
        let mut vtable = [0usize; 2];
        vtable[1] = recording_destructor as usize;
        let mut payload = [vtable.as_mut_ptr() as usize];
        let payload_ptr = payload.as_mut_ptr() as *mut u8;
        let mut cell = SharedCell {
            value: payload_ptr as usize,
            refcount: 1,
        };
        let cell_ptr = core::ptr::addr_of_mut!(cell);
        let mut slot = cell_ptr;

        unsafe { shared_cell_release(&mut slot) };

        assert_eq!(cell.refcount, 0);
        assert!(slot.is_null());
        assert_eq!(
            events(),
            std::vec![
                Event::Destructor(payload_ptr as usize),
                Event::HeapFree(cell_ptr as *mut u8 as usize, 2),
            ],
            "destructor first, then the tag-2 cell delete"
        );
    }

    /// Final drop with a NULL payload: the predicated dispatch is skipped
    /// but the cell is still deleted and the slot cleared.
    #[test]
    fn final_reference_with_null_value_deletes_cell_without_dispatch() {
        let _bench = bench();
        let mut cell = SharedCell {
            value: 0,
            refcount: 1,
        };
        let cell_ptr = core::ptr::addr_of_mut!(cell);
        let mut slot = cell_ptr;

        unsafe { shared_cell_release(&mut slot) };

        assert_eq!(cell.refcount, 0);
        assert!(slot.is_null());
        assert_eq!(
            events(),
            std::vec![Event::HeapFree(cell_ptr as *mut u8 as usize, 2)]
        );
    }

    /// The ARM reloads the slot after the virtual call: a destructor that
    /// cleared the slot suppresses the cell delete, and the final store
    /// just re-clears it.
    #[test]
    fn destructor_that_clears_the_slot_suppresses_the_cell_delete() {
        let _bench = bench();
        let mut vtable = [0usize; 2];
        vtable[1] = slot_clearing_destructor as usize;
        let mut payload = [vtable.as_mut_ptr() as usize];
        let payload_ptr = payload.as_mut_ptr() as *mut u8;
        let mut cell = SharedCell {
            value: payload_ptr as usize,
            refcount: 1,
        };
        let mut slot = core::ptr::addr_of_mut!(cell);
        unsafe { (*core::ptr::addr_of_mut!(SLOT_ALIAS)) = &mut slot };

        unsafe { shared_cell_release(&mut slot) };

        assert!(slot.is_null());
        assert_eq!(
            events(),
            std::vec![Event::Destructor(payload_ptr as usize)],
            "no HeapFree: the reloaded slot was already NULL"
        );
    }

    /// Refcount 0 underflows the wrapping `subs` to -1, which is "still
    /// shared": no teardown, but the slot is still cleared.
    #[test]
    fn zero_refcount_wraps_without_running_cleanup() {
        let _bench = bench();
        let mut cell = SharedCell {
            value: 0,
            refcount: 0,
        };
        let mut slot = core::ptr::addr_of_mut!(cell);

        unsafe { shared_cell_release(&mut slot) };

        assert_eq!(cell.refcount, -1);
        assert!(slot.is_null());
        assert!(events().is_empty());
    }
}
