//! Runtime-global slot-eight callback dispatch.
//!
//! `global_slot_8_callback_dispatch` — original: `FUN_080bb46c` @
//! **0x080bb46c** (40 bytes, `0x080bb46c..0x080bb493`, including the
//! `0x089ca95c` literal at `0x080bb490`). The next independently decoded
//! function begins at `0x080bb494`. Raw A32 decoding finds three inbound
//! unconditional direct `bl` calls and no predicated direct `bl` calls. The
//! body has no direct `bl`; its only call is the predicated indirect `bxne`
//! through the runtime object's `+0x08` word.
//!
//! # Algorithm
//!
//! Volatile-load the optional runtime-global object pointer at `0x089ca95c`.
//! Return status `0x11` when it is NULL; otherwise tail-dispatch the supplied
//! event code through the object's `+0x08` callback and return its result.
//!
//! # Deliberate deviation
//!
//! The firmware object and callback word are 32-bit values. Host builds use a
//! native-width pointer seam and model the callback as a typed function pointer;
//! Rust leaves the tail dispatch as a normal call in source; LLVM emits the
//! equivalent tail branch.

use core::ptr::read_volatile;
#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// Runtime-global pointer loaded by the stock literal pool.
pub const GLOBAL_SLOT_8_CALLBACK_TARGET_ADDRESS: usize = 0x089c_a95c;
const NO_GLOBAL_SLOT_8_CALLBACK_STATUS: u32 = 0x11;

/// Callback ABI stored in the target object's word at `+0x08`.
pub type GlobalSlot8Callback = unsafe extern "C" fn(u32) -> u32;

/// Prefix of the runtime target used by this dispatcher.
#[repr(C)]
pub struct GlobalSlot8CallbackTarget {
    pub unresolved_00_to_04: [u32; 2],
    pub callback: GlobalSlot8Callback,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(GlobalSlot8CallbackTarget, callback)];

/// Host representation of the runtime-global callback target.
#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_SLOT_8_CALLBACK_TARGET: *mut GlobalSlot8CallbackTarget = core::ptr::null_mut();

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_slot_8_callback_target() -> *mut GlobalSlot8CallbackTarget {
    read_volatile(GLOBAL_SLOT_8_CALLBACK_TARGET_ADDRESS as *const *mut GlobalSlot8CallbackTarget)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn global_slot_8_callback_target() -> *mut GlobalSlot8CallbackTarget {
    read_volatile(addr_of!(GLOBAL_SLOT_8_CALLBACK_TARGET))
}

/// Invokes the callback at word `+0x08` of the runtime-global target.
///
/// # Safety
///
/// On target, `0x089ca95c` must be NULL or point to an object with a readable,
/// callable callback word at `+0x08`. The callback's event-code ABI is not
/// validated, matching the retailOS body.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_slot_8_callback_dispatch(event_code: u32) -> u32 {
    let target = global_slot_8_callback_target();
    if target.is_null() {
        return NO_GLOBAL_SLOT_8_CALLBACK_STATUS;
    }
    ((*target).callback)(event_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static EVENT: AtomicU32 = AtomicU32::new(0);
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn record_event(event_code: u32) -> u32 {
        EVENT.store(event_code, Ordering::Relaxed);
        event_code ^ 0x5a5a_5a5a
    }

    #[test]
    fn absent_global_returns_retail_status() {
        let _guard = TEST_LOCK.lock();
        unsafe { GLOBAL_SLOT_8_CALLBACK_TARGET = core::ptr::null_mut(); }
        assert_eq!(unsafe { global_slot_8_callback_dispatch(u32::MAX) }, NO_GLOBAL_SLOT_8_CALLBACK_STATUS);
    }

    #[test]
    fn present_global_forwards_event_and_result() {
        let _guard = TEST_LOCK.lock();
        let mut target = GlobalSlot8CallbackTarget {
            unresolved_00_to_04: [0; 2],
            callback: record_event,
        };
        EVENT.store(0, Ordering::Relaxed);
        unsafe { GLOBAL_SLOT_8_CALLBACK_TARGET = core::ptr::addr_of_mut!(target); }
        assert_eq!(unsafe { global_slot_8_callback_dispatch(0x200) }, 0x5a5a_5a5a ^ 0x200);
        assert_eq!(EVENT.load(Ordering::Relaxed), 0x200);
        unsafe { GLOBAL_SLOT_8_CALLBACK_TARGET = core::ptr::null_mut(); }
    }
}
