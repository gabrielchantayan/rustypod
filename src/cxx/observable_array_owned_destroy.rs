//! `observable_array_owned_destroy` — original: `FUN_083e749c` @
//! **0x083e749c**.
//!
//! **36 bytes**, `0x083e749c..0x083e74c0`; the next real function begins at
//! `0x083e74c0` with `push {r4,r5,r6,lr}` (`e92d4070`), confirming the
//! extent. Binary-scanning every ARM B/BL immediate in `osos.dec` finds
//! **4 plain unconditional `bl`** callers (0x081d291c, 0x08204470, and two
//! more) and **0 predicated `bl`** callers — the "4 bl call sites" Ghidra
//! reports are these callers; the body itself contains exactly 2 `bl`s.
//!
//! ```text
//! 083e749c:  push {r4,lr}
//! 083e74a0:  mov  r4, r0            ; keep the slot for the return
//! 083e74a4:  ldr  r0, [r0]          ; array = *slot
//! 083e74a8:  cmp  r0, #0
//! 083e74ac:  beq  0x083e74b8
//! 083e74b0:  bl   0x08271d2c        ; observable_array_destruct(array)
//! 083e74b4:  bl   0x082aad24        ; operator_delete(destruct's return)
//! 083e74b8:  mov  r0, r4
//! 083e74bc:  pop  {r4,pc}
//! ```
//!
//! # Algorithm
//!
//! The teardown helper for an owning `ObservableArray*` member: load the
//! pointer from the caller's slot, and when it is non-NULL destruct the
//! array and hand the destructor's return (which is the same pointer —
//! `observable_array_destruct` returns `this`) to the tag-2
//! `operator_delete`. The slot word itself is **not** cleared — unlike the
//! sibling helper ending at 0x083e7498, which stores 0 back. Returns the
//! slot address; both callers consume it (0x081d2914 anchors sibling
//! member access at `return - 4`).
//!
//! Deliberate deviations from Ghidra's decompile: the "Subroutine does not
//! return" warning on the delete is spurious (both callees return; the raw
//! `mov r0,r4; pop {r4,pc}` epilogue is reachable), and the declared
//! `int*` is really the `ObservableArray**` slot passed in.

use super::observable_array::{observable_array_destruct, ObservableArray};
use crate::heap::veneers::operator_delete;

/// Destructs and deletes the heap [`ObservableArray`] an owning member slot
/// points to, leaving the slot word untouched, and returns the slot.
///
/// Original: `FUN_083e749c` @ `0x083e749c` (36 bytes; 4 unconditional `bl`
/// call sites, no predicated calls; binary-scanned).
///
/// `inline(never)`: on device this is a real `bl` target and both internal
/// `bl`s must survive for the callers' structural match.
///
/// # Safety
///
/// `slot` must point to one readable pointer word. When the loaded pointer
/// is non-NULL it must satisfy [`observable_array_destruct`]'s safety
/// contract and must be a live tag-2 (`operator_new`) allocation that
/// `operator_delete` may release.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_owned_destroy(
    slot: *mut *mut ObservableArray,
) -> *mut *mut ObservableArray {
    let array = slot.read();
    if !array.is_null() {
        let array = observable_array_destruct(array);
        operator_delete(array.cast());
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::observable_array_construct;
    extern crate std;
    use std::sync::Mutex;
    use std::vec::Vec;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut NOTIFY_TRACE: Vec<usize> = Vec::new();
    static mut FREE_TRACE: Vec<usize> = Vec::new();

    unsafe extern "C" fn record_notify(this: *mut ObservableArray, _reason: u32) {
        unsafe { (*core::ptr::addr_of_mut!(NOTIFY_TRACE)).push(this as usize) };
    }

    unsafe extern "C" fn record_free(ptr: *mut u8) {
        unsafe { (*core::ptr::addr_of_mut!(FREE_TRACE)).push(ptr as usize) };
    }

    struct SeamGuard {
        _heap: std::sync::MutexGuard<'static, ()>,
        _seam: std::sync::MutexGuard<'static, ()>,
        saved_notify: unsafe extern "C" fn(*mut ObservableArray, u32),
        saved_free: unsafe extern "C" fn(*mut u8),
    }

    impl SeamGuard {
        fn install() -> Self {
            let heap = crate::heap::veneers::tests::mock_heap();
            let seam = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            unsafe {
                (*core::ptr::addr_of_mut!(NOTIFY_TRACE)).clear();
                (*core::ptr::addr_of_mut!(FREE_TRACE)).clear();
                let saved_notify =
                    core::ptr::addr_of!(crate::cxx::observable_array::OBSERVABLE_ARRAY_NOTIFY)
                        .read();
                let saved_free =
                    core::ptr::addr_of!(crate::cxx::observable_array::OBSERVABLE_ARRAY_FREE)
                        .read();
                core::ptr::addr_of_mut!(crate::cxx::observable_array::OBSERVABLE_ARRAY_NOTIFY)
                    .write(record_notify);
                core::ptr::addr_of_mut!(crate::cxx::observable_array::OBSERVABLE_ARRAY_FREE)
                    .write(record_free);
                SeamGuard { _heap: heap, _seam: seam, saved_notify, saved_free }
            }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(crate::cxx::observable_array::OBSERVABLE_ARRAY_NOTIFY)
                    .write(self.saved_notify);
                core::ptr::addr_of_mut!(crate::cxx::observable_array::OBSERVABLE_ARRAY_FREE)
                    .write(self.saved_free);
            }
        }
    }

    #[test]
    fn null_slot_is_untouched_and_returned() {
        let _guard = SeamGuard::install();
        let mut slot: *mut ObservableArray = core::ptr::null_mut();

        let returned = unsafe { observable_array_owned_destroy(&mut slot) };

        assert!(core::ptr::eq(returned, &mut slot));
        assert!(slot.is_null(), "a NULL member is a no-op, word untouched");
        assert!(unsafe { (*core::ptr::addr_of!(NOTIFY_TRACE)).is_empty() });
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0, "no delete for NULL");
    }

    #[test]
    fn live_array_is_destructed_then_tag2_deleted_and_slot_is_returned() {
        let _guard = SeamGuard::install();
        let mut array = ObservableArray {
            base: crate::cxx::observable_array::FrameworkObject { vtable: 0xa5a5_a5a5 },
            len: 0xa5a5_a5a5,
            storage: 0xa5a5_a5a5,
            observers: 0xa5a5_a5a5,
        };
        let mut slot = core::ptr::addr_of_mut!(array);
        unsafe {
            observable_array_construct(slot);

            let returned = observable_array_owned_destroy(&mut slot);

            assert!(core::ptr::eq(returned, &mut slot));
            assert_eq!(
                &*core::ptr::addr_of!(NOTIFY_TRACE),
                &[core::ptr::addr_of_mut!(array) as usize],
                "the destructor ran once, on the slot's contents"
            );
            assert_eq!(
                crate::heap::veneers::tests::free_log(),
                (1, core::ptr::addr_of_mut!(array).cast::<u8>(), 2),
                "operator_delete released the same pointer under tag 2"
            );
        }
        assert_eq!(
            slot,
            core::ptr::addr_of_mut!(array),
            "the slot word is not cleared by this helper"
        );
    }

    #[test]
    fn owned_storage_is_released_before_the_object_delete() {
        let _guard = SeamGuard::install();
        let mut array = ObservableArray {
            base: crate::cxx::observable_array::FrameworkObject { vtable: 0 },
            len: 0,
            storage: 0,
            observers: 0,
        };
        let mut slot = core::ptr::addr_of_mut!(array);
        unsafe {
            observable_array_construct(slot);
            (*slot).len = 2;
            (*slot).storage = 0x0801_2340;

            observable_array_owned_destroy(&mut slot);

            assert_eq!(
                &*core::ptr::addr_of!(FREE_TRACE),
                &[0x0801_2340usize],
                "the destructor hands the element storage to free before the delete"
            );
            assert_eq!(crate::heap::veneers::tests::free_log().0, 1);
        }
    }
}
