//! Kernel object-class-four handle allocation.

use crate::kernel::once_callback::once_callback;
use crate::kernel::task_lock::kernel_create_dispatch;

#[cfg(not(target_os = "none"))]
static ONCE_CONTROL: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(crate::kernel::once_callback::ONCE_INITIAL);

// Stock callback literal 0x0807b194 is only e8bd8010 (pop {r4, pc}).
// It consumes the stock once frame, with no initialization side effects.
unsafe extern "C" fn empty_creation_callback() {}

/// `kernel_object4_allocate` — original `FUN_08086024` at `0x08086024`.
/// True extent `0x08086024..0x0808606c`: 72 bytes (64 instruction bytes,
/// two literals), followed by a new PUSH. Two plain BLs, zero predicated
/// BLs; whole-image decoding also finds two plain incoming BLs and no
/// predicated incoming BLs.
///
/// Claim once control at `0x08a09700`, ignoring its status; create class 4
/// into the caller's handle word. Return zero only for zero dispatch status
/// and a nonzero handle, otherwise `0x27`. Failure skips the handle read.
/// No null guard, clearing, or rollback is added.
///
/// Deliberate deviations: reuse the ported once and create-dispatch seams.
/// Replace the stock bare-POP callback with an empty ABI-safe callback:
/// stock skips the once epilogue and leaves r0=14 on first claim, whereas
/// Rust returns zero; that value is discarded here. The atomic claim and
/// lack of callback side effects are unchanged. Hosts use a local atomic
/// control instead of the device's fixed RAM word. The dispatcher uses the
/// existing installed kernel hook; its IRAM target is the osos mirror.
///
/// # Safety
/// `slot` must be valid for the installed dispatcher and, on dispatch success,
/// an aligned readable u32. Device once control must be live writable RAM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_object4_allocate(slot: *mut u32) -> u32 {
    #[cfg(target_os = "none")]
    let control = 0x08a09700usize as *mut u32;
    #[cfg(not(target_os = "none"))]
    let control = ONCE_CONTROL.as_ptr();
    once_callback(control, Some(empty_creation_callback));
    if kernel_create_dispatch(4, slot as usize) == 0 && slot.read() != 0 {
        0
    } else {
        0x27
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::once_callback::{ONCE_CLAIMED, ONCE_INITIAL};
    use crate::kernel::task_lock::{ROM_KERNEL, tests::OPS_LOCK};
    use core::sync::atomic::Ordering;

    static mut STATUS: usize = 0;
    static mut HANDLE: u32 = 0;

    unsafe extern "C" fn create(_class: usize, slot: usize) -> usize {
        if slot != 0 { (slot as *mut u32).write(HANDLE); }
        STATUS
    }

    #[test]
    fn status_and_handle_matrix_after_every_once_state() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            let saved = ROM_KERNEL;
            ROM_KERNEL.kernel_create_dispatch = create;
            for state in [ONCE_INITIAL, ONCE_CLAIMED, 0, u32::MAX] {
                for status in [0, 1, 0x80000000, u32::MAX as usize] {
                    for handle in [0, 1, 0x80000000, u32::MAX] {
                        ONCE_CONTROL.store(state, Ordering::Relaxed);
                        STATUS = status;
                        HANDLE = handle;
                        let mut slot = 0xfeed_beef;
                        let expected = if status == 0 && handle != 0 { 0 } else { 0x27 };
                        assert_eq!(kernel_object4_allocate(&mut slot), expected);
                        assert_eq!(slot, handle);
                        assert_eq!(ONCE_CONTROL.load(Ordering::Relaxed), ONCE_CLAIMED);
                    }
                }
            }
            ROM_KERNEL = saved;
        }
    }

    #[test]
    fn dispatch_failure_does_not_read_null_slot() {
        let _lock = OPS_LOCK.lock().unwrap();
        unsafe {
            let saved = ROM_KERNEL;
            ROM_KERNEL.kernel_create_dispatch = create;
            STATUS = 7;
            assert_eq!(kernel_object4_allocate(core::ptr::null_mut()), 0x27);
            ROM_KERNEL = saved;
        }
    }
}
