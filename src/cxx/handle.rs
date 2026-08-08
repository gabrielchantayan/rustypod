//! The NULL-guarded two-level handle accessor the C++ layer instantiates
//! once per wrapped type — 22 byte-identical 16-byte copies in osos.
//!
//! Every copy is exactly these four words:
//!
//! ```text
//! ldr   r0, [r0]      ; cell = *slot
//! cmp   r0, #0
//! ldrne r0, [r0]      ; cell ? *cell : NULL
//! bx    lr
//! ```
//!
//! i.e. `T *get() const { return cell_ ? *cell_ : nullptr; }` on a class
//! whose sole (offset-0) member is a `T **`. The compiler emitted one
//! out-of-line copy per template instantiation instead of sharing them,
//! so the image carries 22 functions that differ only in address. This
//! module is the single port; `names.yaml` records the alias map, and a
//! hook may point every one of the 22 addresses at this symbol.
//!
//! Binary-scanned `bl` call sites (no `b` sites anywhere), 725 in total:
//!
//! | address    | calls | address    | calls | address    | calls |
//! |------------|-------|------------|-------|------------|-------|
//! | 0x083d604c | 253   | 0x083d606c | 69    | 0x083d6190 | 69    |
//! | 0x083d61d0 | 66    | 0x083d64f4 | 97    | 0x083d60bc | 25    |
//! | 0x083d64c4 | 18    | 0x083d64e4 | 18    | 0x083d602c | 17    |
//! | 0x083d61a0 | 16    | 0x083d6180 | 13    | 0x083d64d4 | 9     |
//! | 0x083d607c | 9     | 0x083d603c | 8     | 0x083d609c | 8     |
//! | 0x083d60ac | 7     | 0x083d61b0 | 7     | 0x083d60cc | 5     |
//! | 0x083d608c | 4     | 0x083d605c | 3     | 0x083d61c0 | 2     |
//! | 0x08262b1c | 2     |            |       |            |       |
//!
//! 0x08262b1c is the one copy outside the C++ block (it sits in the
//! application layer); it is the same four words and aliases here too.
//!
//! The 0x083d604c copy is the canonical one (most call sites) and the
//! address this port cites. Note the NULL test is on the *inner* pointer,
//! not on `slot`: a NULL `slot` faults in the original, and does here.
//!
//! Also here: [`refcounted_ptr_assign`], the mutex-guarded shared-body
//! assign that backs the C++ layer's refcounted handles (it sits outside
//! the 0x083c0000-0x083dffff block, at 0x0839eda0, so it is not one of
//! the byte-identical families above), and [`refcounted_body_release`],
//! its refcount-drop teardown @ 0x0839cd98. [`refcounted_ptr_release`]
//! is the thin destroy-and-return-this wrapper @ 0x0816cd44.

use crate::heap::veneers::operator_delete;
use crate::kernel::sync_mutex::{mutex_delete, mutex_lock, mutex_unlock, Mutex};

/// handle_deref_or_null — original: `FUN_083d604c` @ 0x083d604c
/// (16 bytes; 253 `bl` call sites at that address, 725 across all 22
/// byte-identical copies — see the module header for the alias map).
///
/// Loads the handle cell out of `slot` and dereferences it, yielding
/// NULL when the cell is NULL.
///
/// # Safety
/// `slot` must be readable; the cell it holds must be readable when
/// non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_deref_or_null(slot: *const *const *mut u8) -> *mut u8 {
    let cell = slot.read();
    if cell.is_null() {
        return core::ptr::null_mut();
    }
    cell.read()
}

/// handle_deref_field12 — original: `FUN_083d5ea0` @ 0x083d5ea0
/// (20 bytes; 11 `bl` call sites — the only copy of this offset in the
/// image).
///
/// [`handle_deref_or_null`] with the second load at +0xc instead of +0:
/// `cell = *slot; return cell ? cell[3] : NULL`. What the fourth word
/// of the cell holds is not identified.
///
/// The field is addressed by WORD INDEX (3), like the +0 field of the
/// primary port is word 0 — byte-exact +0xc on the 32-bit target,
/// disjoint from the cell's other words on a 64-bit host.
///
/// # Safety
/// `slot` must be readable; the cell it holds must have at least four
/// readable words when non-NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_deref_field12(slot: *const *const *mut u8) -> *mut u8 {
    let cell = slot.read();
    if cell.is_null() {
        return core::ptr::null_mut();
    }
    cell.add(3).read()
}

/// Shared body of the C++ layer's refcounted handles — the object a
/// `*mut RefcountedBody` slot points at. On the ARM target its three words
/// are the implementation pointer (+0), signed reference count (+4), and
/// optional [`Mutex`] pointer (+8). Host fixtures widen each target pointer
/// word to `usize`, keeping pointers intact and the fields disjoint.
#[repr(C)]
pub struct RefcountedBody {
    /// Target +0: implementation pointer. Its first word is the vtable
    /// pointer used by [`refcounted_body_release`] at the final drop.
    pub opaque0: usize,
    /// Target +4: intrusive reference count, changed under the mutex.
    pub refcount: i32,
    /// Target +8: optional mutex guarding the refcount (NULL = unguarded).
    pub mutex: *mut Mutex,
}

/// refcounted_ptr_assign — original: `FUN_0839eda0` @ 0x0839eda0
/// (68 bytes; 78 `bl` call sites).
///
/// The copy-assign of a refcounted handle slot: `obj = *src;
/// *dst = obj`, and when `obj` is non-NULL its refcount (+4) is bumped
/// by one under the mutex at +8. The mutex field is loaded twice —
/// before the lock and again before the unlock — and each load is
/// NULL-checked separately, so a NULL mutex means an unguarded bump.
/// Returns `dst`.
///
/// The lock pair is `kernel::sync_mutex::mutex_lock` /
/// `mutex_unlock` (originals @ 0x0807f5c4 / 0x0807f6a0, now ported);
/// an earlier scouting note deferred this function until those landed.
///
/// Codegen deviation: LLVM inlines the ported lock/unlock (guards and
/// ROM_KERNEL dispatch included) instead of emitting the original's
/// `bl` pair, so the ARM body is larger but structurally the same —
/// both mutex-field loads are NULL-checked, the bump sits between
/// them, and `dst` is returned untouched.
///
/// # Safety
/// `dst` and `src` must be valid, aligned pointer slots; when the
/// loaded body pointer is non-NULL it must point at a readable/writable
/// [`RefcountedBody`]. As in the original, the slot pointers themselves
/// are not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_assign(
    dst: *mut *mut RefcountedBody,
    src: *const *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    let obj = src.read();
    dst.write(obj);
    if !obj.is_null() {
        let mutex = (*obj).mutex;
        if !mutex.is_null() {
            mutex_lock(mutex);
        }
        // Original: `add r0, r0, #1` — a plain wrapping increment.
        (*obj).refcount = (*obj).refcount.wrapping_add(1);
        // Re-loaded, as in the original: a racing release could in
        // principle have torn the object down under us.
        let mutex = (*obj).mutex;
        if !mutex.is_null() {
            mutex_unlock(mutex);
        }
    }
    dst
}

/// refcounted_body_release — original: `FUN_0839cd98` @ 0x0839cd98
/// (144 bytes; called by the refcounted-handle release wrappers).
///
/// Drops the shared body's signed refcount under its optional mutex. A
/// non-final drop simply unlocks and NULLs the caller's slot. On the final
/// transition, it invokes the implementation's virtual destructor at vtable
/// slot 7 (+0x1c), unlocks, deletes the mutex (including its semaphore
/// cell), then tag-2-deletes the mutex object and body. The final slot store
/// happens on every non-NULL-body path. The target's plain `subs` wraps on
/// underflow, so only a result of exactly zero is final.
///
/// The target body layout is documented on [`RefcountedBody`]. `opaque0`
/// must be a valid implementation pointer when nonzero; its first word must
/// be a valid vtable containing a virtual destructor at word index 7.
///
/// # Safety
/// `slot` must be a valid aligned pointer slot. Its non-NULL body, mutex,
/// implementation, vtable, and virtual destructor must all be live and
/// valid for the operations encoded by the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_body_release(slot: *mut *mut RefcountedBody) {
    let body = slot.read();
    if body.is_null() {
        return;
    }

    let mutex = (*body).mutex;
    if !mutex.is_null() {
        mutex_lock(mutex);
    }

    let remaining = (*body).refcount.wrapping_sub(1);
    (*body).refcount = remaining;
    if remaining == 0 {
        let implementation = (*body).opaque0 as *mut u8;
        if !implementation.is_null() {
            let vtable = (implementation as *const usize).read() as *const usize;
            let destructor: unsafe extern "C" fn(*mut u8) =
                core::mem::transmute(vtable.add(7).read());
            destructor(implementation);
        }

        // The original re-reads the slot after the destructor before
        // releasing and destroying the body it still names.
        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_unlock(mutex);
                mutex_delete(mutex);
                // Reload after mutex_delete, exactly as the ARM does before
                // the tag-2 delete, then clear the field after that delete.
                let mutex = (*body).mutex;
                operator_delete(mutex.cast());
                (*body).mutex = core::ptr::null_mut();
            }
            operator_delete(body.cast());
        }
    } else {
        // This helper call is reached with a fresh load from the slot in the
        // ARM body; the mutex helper performs its own NULL guards.
        let body = slot.read();
        if !body.is_null() {
            let mutex = (*body).mutex;
            if !mutex.is_null() {
                mutex_unlock(mutex);
            }
        }
    }

    slot.write(core::ptr::null_mut());
}

/// refcounted_ptr_release — original: `FUN_0816cd44` @ 0x0816cd44
/// (20 bytes; 90 `bl` call sites, mostly the 0x0822xxxx application
/// layer releasing stack- and member-slot handles).
///
/// The drop counterpart of [`refcounted_ptr_assign`]: drops the body in
/// `slot` through [`refcounted_body_release`] and returns `slot` unchanged
/// — the ADS destroy-and-return-this idiom.
///
/// # Safety
/// `slot` must be a valid, aligned pointer slot; when the body pointer
/// it holds is non-NULL it must point at a live [`RefcountedBody`]. As
/// in the original, the slot pointer itself is not NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_ptr_release(
    slot: *mut *mut RefcountedBody,
) -> *mut *mut RefcountedBody {
    refcounted_body_release(slot);
    slot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_both_levels() {
        unsafe {
            let mut target: u8 = 0;
            let mut cell: *mut u8 = &mut target;
            let slot: *const *mut u8 = &mut cell;
            assert_eq!(handle_deref_or_null(&slot), &mut target as *mut u8);
        }
    }

    #[test]
    fn null_cell_yields_null_without_a_second_load() {
        unsafe {
            let slot: *const *mut u8 = core::ptr::null();
            assert!(handle_deref_or_null(&slot).is_null());
        }
    }

    /// The inner pointer is returned verbatim, NULL included — the
    /// original has no second guard.
    #[test]
    fn null_target_is_passed_through() {
        unsafe {
            let mut cell: *mut u8 = core::ptr::null_mut();
            let slot: *const *mut u8 = &mut cell;
            assert!(handle_deref_or_null(&slot).is_null());
        }
    }

    #[test]
    fn field12_reads_the_cells_fourth_word() {
        unsafe {
            let mut target: u8 = 0;
            let mut cell: [*mut u8; 5] = [
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut target,
                0x5555 as *mut u8,
            ];
            let slot: *const *mut u8 = cell.as_mut_ptr();
            assert_eq!(handle_deref_field12(&slot), &mut target as *mut u8);
        }
    }

    #[test]
    fn field12_null_cell_yields_null_without_a_second_load() {
        unsafe {
            let slot: *const *mut u8 = core::ptr::null();
            assert!(handle_deref_field12(&slot).is_null());
        }
    }

    #[test]
    fn field12_null_field_is_passed_through() {
        unsafe {
            let mut cell: [*mut u8; 4] = [core::ptr::null_mut(); 4];
            let slot: *const *mut u8 = cell.as_mut_ptr();
            assert!(handle_deref_field12(&slot).is_null());
        }
    }

    /// NULL source body: the slot is overwritten with NULL, nothing
    /// else is touched, and `dst` comes back.
    #[test]
    fn assign_null_body_stores_null_and_returns_dst() {
        unsafe {
            let mut slot: *mut RefcountedBody = 0xdead_beefusize as *mut RefcountedBody;
            let src: *mut RefcountedBody = core::ptr::null_mut();
            let ret = refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert!(slot.is_null());
        }
    }

    /// Unguarded body (mutex NULL): the count is bumped and the slot
    /// repointed, with no kernel interaction.
    #[test]
    fn assign_bumps_refcount_when_mutex_is_null() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0x1111_2222,
                refcount: 3,
                mutex: core::ptr::null_mut(),
            };
            let src: *mut RefcountedBody = core::ptr::addr_of!(body).cast_mut();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            let ret = refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 4);
            assert_eq!(body.opaque0, 0x1111_2222);
        }
    }

    /// Guarded body whose mutex cell is absent: lock/unlock take the
    /// NULL-cell early-out inside `mutex_lock`/`mutex_unlock`, so the
    /// bump still happens with no ROM_KERNEL table installed.
    #[test]
    fn assign_bumps_refcount_with_empty_mutex_cell() {
        unsafe {
            let mut mutex = Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 0,
                mutex: &mut mutex,
            };
            let src: *mut RefcountedBody = core::ptr::addr_of!(body).cast_mut();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 1);
        }
    }

    /// Self-assign (dst == src): the load happens before the store, so
    /// the slot keeps its pointer and the count rises exactly once.
    #[test]
    fn self_assign_bumps_once() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 7,
                mutex: core::ptr::null_mut(),
            };
            let mut slot: *mut RefcountedBody = &mut body;
            let ret = refcounted_ptr_assign(&mut slot, &slot);
            assert_eq!(ret, &mut slot as *mut *mut RefcountedBody);
            assert_eq!(slot, &mut body as *mut RefcountedBody);
            assert_eq!(body.refcount, 8);
        }
    }

    /// The increment is a plain ARM `add` — it wraps at i32::MAX.
    #[test]
    fn refcount_increment_wraps() {
        unsafe {
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: i32::MAX,
                mutex: core::ptr::null_mut(),
            };
            let src: *mut RefcountedBody = core::ptr::addr_of!(body).cast_mut();
            let mut slot: *mut RefcountedBody = core::ptr::null_mut();
            refcounted_ptr_assign(&mut slot, &src);
            assert_eq!(body.refcount, i32::MIN);
        }
    }

    /// Direct tests of the body release use the ported mutex and heap
    /// surfaces with recording kernel/heap hooks. The crate's test
    /// configuration serializes hook-swapping tests; this atomic also keeps
    /// the fixture safe when a runner overrides that configuration.
    mod release {
        extern crate std;

        use super::super::*;
        use crate::heap::types::HeapDescriptorDescriptor;
        use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
        use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::vec::Vec;

        static OPS_LOCK: AtomicBool = AtomicBool::new(false);
        static mut EVENTS: Vec<Event> = Vec::new();

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Event {
            Wait(u32),
            Destructor(usize),
            Signal(u32),
            Delete(u32),
            MutexCellFree(usize),
            HeapFree(usize, usize),
        }

        unsafe extern "C" fn recording_wait(handle: u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Wait(handle));
        }

        unsafe extern "C" fn recording_signal(handle: u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Signal(handle));
        }

        unsafe extern "C" fn recording_delete(_kind: u32, cell: *mut u32) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Delete(cell.read()));
            cell.write(0);
        }

        unsafe extern "C" fn recording_mutex_cell_free(cell: *mut u8) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::MutexCellFree(cell as usize));
        }

        unsafe extern "C" fn recording_body_free(
            _heap: *mut HeapDescriptorDescriptor,
            ptr: *mut u8,
            tag: usize,
        ) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::HeapFree(ptr as usize, tag));
        }

        unsafe extern "C" fn recording_destructor(implementation: *mut u8) {
            (*core::ptr::addr_of_mut!(EVENTS)).push(Event::Destructor(implementation as usize));
        }

        struct Bench {
            old_kernel: RomKernelOps,
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
                let old_kernel = core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL));
                let old_heap = core::ptr::read_volatile(core::ptr::addr_of!(HEAP_OPS));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(ROM_KERNEL),
                    RomKernelOps {
                        sema_wait: recording_wait,
                        sema_signal: recording_signal,
                        sema_delete: recording_delete,
                        heap_free: recording_mutex_cell_free,
                        ..old_kernel
                    },
                );
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(HEAP_OPS),
                    HeapVeneerOps {
                        free: recording_body_free,
                        ..old_heap
                    },
                );
                Bench {
                    old_kernel,
                    old_heap,
                }
            }
        }

        impl Drop for Bench {
            fn drop(&mut self) {
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(ROM_KERNEL), self.old_kernel);
                    core::ptr::write_volatile(core::ptr::addr_of_mut!(HEAP_OPS), self.old_heap);
                }
                OPS_LOCK.store(false, Ordering::Release);
            }
        }

        fn events() -> Vec<Event> {
            unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
        }

        /// A non-final reference is decremented and unlocked; neither the
        /// virtual destructor nor either heap delete runs, but the slot is
        /// always cleared.
        #[test]
        fn shared_reference_decrements_unlocks_and_nulls_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 2,
                mutex: &mut mutex,
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release(&mut slot) };

            assert_eq!(body.refcount, 1);
            assert!(slot.is_null(), "the non-final path still clears the slot");
            assert_eq!(events(), std::vec![Event::Wait(0x42), Event::Signal(0x42)]);
        }

        /// The final reference dispatches vtable[7], unlocks before semaphore
        /// teardown, releases the mutex before its body, and preserves the
        /// wrapper's destroy-and-return-this postcondition.
        #[test]
        fn final_reference_cleans_up_in_firmware_order_and_returns_slot() {
            let _bench = bench();
            let mut semaphore = 0x42;
            let mut mutex = Mutex {
                sem_cell: &mut semaphore,
                unused: 0,
            };
            let mut vtable = [0usize; 8];
            vtable[7] = recording_destructor as usize;
            let mut implementation = [vtable.as_mut_ptr() as usize];
            let mut body = RefcountedBody {
                opaque0: implementation.as_mut_ptr() as usize,
                refcount: 1,
                mutex: &mut mutex,
            };
            let body_ptr = &mut body as *mut RefcountedBody;
            let mutex_ptr = &mut mutex as *mut Mutex;
            let cell_ptr = &mut semaphore as *mut u32;
            let implementation_ptr = implementation.as_mut_ptr() as *mut u8;
            let mut slot = body_ptr;
            let slot_ptr = &mut slot as *mut *mut RefcountedBody;

            let returned = unsafe { refcounted_ptr_release(slot_ptr) };

            assert_eq!(returned, slot_ptr, "destroy-and-return-this");
            assert!(slot.is_null(), "the final store clears the caller slot");
            assert!(mutex.sem_cell.is_null(), "mutex_delete clears its cell");
            assert_eq!(
                events(),
                std::vec![
                    Event::Wait(0x42),
                    Event::Destructor(implementation_ptr as usize),
                    Event::Signal(0x42),
                    Event::Delete(0x42),
                    Event::MutexCellFree(cell_ptr as usize),
                    Event::HeapFree(mutex_ptr as *mut u8 as usize, 2),
                    Event::HeapFree(body_ptr as *mut u8 as usize, 2),
                ],
                "lock/destructor/unlock/delete ordering follows the ARM body"
            );
        }

        /// The target's `subs` treats zero as an underflow, not a final
        /// release. It wraps and takes the shared-reference path.
        #[test]
        fn zero_refcount_wraps_without_running_cleanup() {
            let _bench = bench();
            let mut body = RefcountedBody {
                opaque0: 0,
                refcount: 0,
                mutex: core::ptr::null_mut(),
            };
            let mut slot = &mut body as *mut RefcountedBody;

            unsafe { refcounted_body_release(&mut slot) };

            assert_eq!(body.refcount, -1);
            assert!(slot.is_null());
            assert!(events().is_empty());
        }
    }
}
