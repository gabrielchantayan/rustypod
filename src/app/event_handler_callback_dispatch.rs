//! `event_handler_callback_dispatch` — original: `FUN_081b0cd4` @
//! `0x081b0cd4` (36 bytes; one plain unconditional `bl`, zero predicated
//! `bl` forms, and one unconditional tail `b`).
//!
//! # Algorithm
//!
//! Obtains the event-handler source through the IRAM veneer at `0x08038060`,
//! preserving the two incoming words, then tail-dispatches callback-target
//! vtable slot `+0x14` through the veneer at `0x08038158` / `0x220077a8`.
//! The source pointer is deliberately passed as the ignored first argument of
//! that wrapper; the callback receives the original two words unchanged.
//!
//! # Deliberate deviations
//!
//! Rust composes the two already-ported wrappers rather than preserving the
#[cfg(target_os = "none")]
use crate::kernel::event_handler_source::event_handler_source;

/// Supplies the global source pointer used as the callback wrapper's ignored
/// first argument. Target builds execute the verified IRAM source getter;
/// hosts install a fixture because its retailOS shutdown-chain state is global.
pub type EventHandlerSourceGetter = unsafe extern "C" fn() -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_event_handler_source() -> *mut u8 {
    event_handler_source()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_event_handler_source() -> *mut u8 {
    core::ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
pub static mut EVENT_HANDLER_CALLBACK_DISPATCH_SOURCE: EventHandlerSourceGetter =
    missing_event_handler_source;

#[inline(always)]
unsafe fn event_handler_callback_source() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        firmware_event_handler_source()
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(EVENT_HANDLER_CALLBACK_DISPATCH_SOURCE))()
    }
}

#[cfg(not(target_arch = "arm"))]
use crate::app::callback_target_slot_14_dispatch::callback_target_slot_14_dispatch;

#[cfg(target_arch = "arm")]
extern "C" {
    fn callback_target_slot_14_dispatch(unused: *mut u8, arg2: *mut u8, arg3: *mut u8);
}

/// event_handler_callback_dispatch — original: `FUN_081b0cd4` @ `0x081b0cd4`
/// (36 bytes; one unconditional `bl`, no predicated `bl` forms, then an
/// unconditional tail branch).
///
/// Acquires the event-handler source and dispatches the callback target's
/// `+0x14` virtual slot with `value` and `kind` as its final two words.
///
/// # Safety
///
/// Executes retailOS global initialization and an unvalidated framework
/// callback ABI. `value` and `kind` must be valid for that callback.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_handler_callback_dispatch(value: u32, kind: u32) {
    let source = event_handler_callback_source();
    callback_target_slot_14_dispatch(source, value as *mut u8, kind as *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::callback_target_slot_14_dispatch::{
        CallbackTargetSlot14, CallbackTargetSlot14DispatchOps, CallbackTargetSlot14Getter,
        CallbackTargetSlot14Vtable, CALLBACK_TARGET_SLOT_14_DISPATCH_OPS,
        DEFAULT_CALLBACK_TARGET_SLOT_14_DISPATCH_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_SOURCE: *mut u8 = core::ptr::null_mut();
    static mut SEEN_VALUE: *mut u8 = core::ptr::null_mut();
    static mut SEEN_KIND: *mut u8 = core::ptr::null_mut();
    static mut TARGET: CallbackTargetSlot14 = CallbackTargetSlot14 { vtable: &VTABLE };
    static mut SOURCE: u8 = 0;

    unsafe extern "C" fn record_dispatch(
        _target: *mut CallbackTargetSlot14,
        value: *mut u8,
        kind: *mut u8,
    ) {
        SEEN_VALUE = value;
        SEEN_KIND = kind;
    }

    static VTABLE: CallbackTargetSlot14Vtable = CallbackTargetSlot14Vtable {
        unresolved_00_10: [0; 5],
        dispatch_callback: record_dispatch,
    };

    unsafe extern "C" fn record_source() -> *mut u8 {
        addr_of_mut!(SOURCE)
    }

    unsafe extern "C" fn record_target() -> *mut CallbackTargetSlot14 {
        SEEN_SOURCE = event_handler_callback_source();
        addr_of_mut!(TARGET)
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(SEEN_SOURCE).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_VALUE).write(core::ptr::null_mut());
            addr_of_mut!(SEEN_KIND).write(core::ptr::null_mut());
            addr_of_mut!(TARGET).write(CallbackTargetSlot14 { vtable: &VTABLE });
            addr_of_mut!(EVENT_HANDLER_CALLBACK_DISPATCH_SOURCE).write(record_source);
            addr_of_mut!(CALLBACK_TARGET_SLOT_14_DISPATCH_OPS).write(CallbackTargetSlot14DispatchOps {
                get_target: record_target as CallbackTargetSlot14Getter,
            });
        }
        guard
    }

    #[test]
    fn forwards_words_after_acquiring_the_event_handler_source() {
        let guard = install_recorder();
        let value = 0x1234_5678;
        let kind = 1;

        unsafe { event_handler_callback_dispatch(value, kind) };

        unsafe {
            assert_eq!(addr_of!(SEEN_SOURCE).read(), addr_of_mut!(SOURCE));
            assert_eq!(addr_of!(SEEN_VALUE).read() as usize, value as usize);
            assert_eq!(addr_of!(SEEN_KIND).read() as usize, kind as usize);
            addr_of_mut!(CALLBACK_TARGET_SLOT_14_DISPATCH_OPS)
                .write(DEFAULT_CALLBACK_TARGET_SLOT_14_DISPATCH_OPS);
            addr_of_mut!(EVENT_HANDLER_CALLBACK_DISPATCH_SOURCE).write(missing_event_handler_source);
        }
        drop(guard);
    }
}
