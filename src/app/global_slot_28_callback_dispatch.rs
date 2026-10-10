//! Runtime-global callback dispatch through byte offset 0x28.
//!
//! `global_slot_28_callback_dispatch` — `FUN_080bb444` at **0x080bb444**.
//! True size: 40 bytes, ending at the next function at 0x080bb46c;
//! nine A32 instructions (36 bytes) plus the 0x089ca95c literal at 0x080bb468.
//! Verified raw-image inbound calls: two plain BLs (0x08369ab4, 0x08369b84),
//! zero predicated BLs. Body: zero BLs, one predicated indirect BX tail call.
//!
//! Loads the optional object pointer at 0x089ca95c. NULL returns status 0x11;
//! otherwise invokes the callback at object+0x28 with the unchanged argument
//! and returns its result. The object's identity and callback semantics remain
//! unknown; names describe only the observed dispatch.
//!
//! Deliberate deviations: reuse the adjacent slot-eight port's native-pointer
//! host global seam. A repr(C) prefix keeps the callback at byte offset 0x28
//! on both host and target. Rust leaves tail-call selection to LLVM.

use super::global_slot_8_callback_dispatch::global_slot_8_callback_target;

pub type GlobalSlot28Callback = unsafe extern "C" fn(u32) -> u32;

#[repr(C)]
pub struct GlobalSlot28CallbackTarget {
    pub unresolved_00_to_24: [u32; 10],
    pub callback: GlobalSlot28Callback,
}

const _: [u8; 0x28] = [0; core::mem::offset_of!(GlobalSlot28CallbackTarget, callback)];

/// Dispatches an opaque argument through the runtime-global object's +0x28 slot.
///
/// # Safety
/// The global must be NULL or point to readable storage containing a valid
/// `unsafe extern "C" fn(u32) -> u32` at +0x28. The caller must satisfy that
/// callback's requirements. No callback NULL check is performed by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_slot_28_callback_dispatch(argument: u32) -> u32 {
    let target = global_slot_8_callback_target().cast::<GlobalSlot28CallbackTarget>();
    if target.is_null() {
        return 0x11;
    }
    ((*target).callback)(argument)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::global_slot_8_callback_dispatch::{GLOBAL_SLOT_8_CALLBACK_TARGET, TEST_LOCK};
    use core::sync::atomic::{AtomicU32, Ordering};

    static CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn callback(argument: u32) -> u32 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        argument.rotate_left(7) ^ 0xa5a5_5a5a
    }

    #[test]
    fn absent_then_present_then_absent_global() {
        let _guard = TEST_LOCK.lock();
        CALLS.store(0, Ordering::Relaxed);
        unsafe { GLOBAL_SLOT_8_CALLBACK_TARGET = core::ptr::null_mut(); }
        for argument in [0, 0x11, u32::MAX] {
            assert_eq!(unsafe { global_slot_28_callback_dispatch(argument) }, 0x11);
        }
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        let mut target = GlobalSlot28CallbackTarget {
            unresolved_00_to_24: [0xdead_beef; 10],
            callback,
        };
        unsafe { GLOBAL_SLOT_8_CALLBACK_TARGET = core::ptr::addr_of_mut!(target).cast(); }
        for argument in [0, 0x11, 0x8000_0000, u32::MAX] {
            assert_eq!(unsafe { global_slot_28_callback_dispatch(argument) },
                argument.rotate_left(7) ^ 0xa5a5_5a5a);
        }
        assert_eq!(CALLS.load(Ordering::Relaxed), 4);
        unsafe { GLOBAL_SLOT_8_CALLBACK_TARGET = core::ptr::null_mut(); }
        assert_eq!(unsafe { global_slot_28_callback_dispatch(0) }, 0x11);
        assert_eq!(CALLS.load(Ordering::Relaxed), 4);
        assert_eq!(target.unresolved_00_to_24, [0xdead_beef; 10]);
    }
}
