//! `service_handler_global_dispatch` — original: `FUN_0814e470` @
//! `0x0814e470` (64 bytes, `0x0814e470..0x0814e4b0`; the following
//! instruction at `0x0814e4b4` begins an unrelated function).
//!
//! Raw ARM loads the two pointers at `0x089ccc28` in order, selects the first
//! non-NULL handler, and tail-dispatches its selector and value through
//! `0x0814e3ac`. That helper invokes the handler's vtable `+0x14` slot; its
//! selector-8 continuation is deliberately retained in retailOS.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` found five inbound direct
//! call sites: all are unconditional plain `bl`, with no predicated `bl`
//! forms and no inbound tail branches.
//!
//! # Deliberate deviations
//!
//! Host builds use replaceable slots and a dispatch seam because host pointers
//! and function pointers are wider than the retail four-byte object layout.
//! Target builds read the two firmware words and call the verified unported
//! continuation at `0x0814e3ac`.

#[cfg(not(target_os = "none"))]
use core::ptr::{addr_of, read_volatile};

const RETAIL_SERVICE_HANDLER_GLOBALS: *const *mut u8 = 0x089c_cc28 as *const *mut u8;
const RETAIL_SERVICE_HANDLER_DISPATCH: usize = 0x0814_e3ac;

/// ABI of the unported handler selector dispatcher at `0x0814e3ac`.
pub type ServiceHandlerGlobalDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_service_handler_global_dispatch(_handler: *mut u8, _selector: u32, _value: u32) {
    panic!("install service handler global dispatch host operations before calling this dispatcher")
}

/// Host representation of the firmware's two four-byte global handler slots.
#[cfg(not(target_os = "none"))]
pub static mut SERVICE_HANDLER_GLOBAL_SLOTS: [*mut u8; 2] = [core::ptr::null_mut(); 2];

/// Volatile host replacement for the unported retail continuation.
#[cfg(not(target_os = "none"))]
pub static mut SERVICE_HANDLER_GLOBAL_DISPATCH: ServiceHandlerGlobalDispatch = missing_service_handler_global_dispatch;

#[inline(always)]
unsafe fn selected_service_handler() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let first = unsafe { core::ptr::read_volatile(RETAIL_SERVICE_HANDLER_GLOBALS) };
        if !first.is_null() {
            return first;
        }
        unsafe { core::ptr::read_volatile(RETAIL_SERVICE_HANDLER_GLOBALS.add(1)) }
    }

    #[cfg(not(target_os = "none"))]
    {
        let first = unsafe { read_volatile(addr_of!(SERVICE_HANDLER_GLOBAL_SLOTS[0])) };
        if !first.is_null() {
            return first;
        }
        unsafe { read_volatile(addr_of!(SERVICE_HANDLER_GLOBAL_SLOTS[1])) }
    }
}

/// Selects the first installed global service handler and forwards its message.
///
/// # Safety
/// On target, the selected firmware handler must have the vtable expected by
/// `0x0814e3ac`; selector and value use that handler's unvalidated ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn service_handler_global_dispatch(selector: u32, value: u32) {
    let handler = unsafe { selected_service_handler() };
    if handler.is_null() {
        return;
    }

    #[cfg(target_os = "none")]
    {
        let dispatch: ServiceHandlerGlobalDispatch = unsafe { core::mem::transmute(RETAIL_SERVICE_HANDLER_DISPATCH) };
        unsafe { dispatch(handler, selector, value) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let dispatch = unsafe { read_volatile(addr_of!(SERVICE_HANDLER_GLOBAL_DISPATCH)) };
        unsafe { dispatch(handler, selector, value) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: Option<(*mut u8, u32, u32)> = None;

    unsafe extern "C" fn record_dispatch(handler: *mut u8, selector: u32, value: u32) {
        unsafe { CALL = Some((handler, selector, value)) };
    }

    unsafe fn reset() {
        unsafe {
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_SLOTS).write([core::ptr::null_mut(); 2]);
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_DISPATCH).write(missing_service_handler_global_dispatch);
            addr_of_mut!(CALL).write(None);
        }
    }

    #[test]
    fn dispatches_to_first_installed_handler_with_both_message_words() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut first = [0u8; 4];
        let mut second = [0u8; 4];
        unsafe {
            reset();
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_SLOTS).write([first.as_mut_ptr(), second.as_mut_ptr()]);
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_DISPATCH).write(record_dispatch);
            service_handler_global_dispatch(0x80, 100);
            assert_eq!(addr_of!(CALL).read(), Some((first.as_mut_ptr(), 0x80, 100)));
            reset();
        }
    }

    #[test]
    fn falls_back_to_second_handler_or_returns_when_both_are_absent() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut second = [0u8; 4];
        unsafe {
            reset();
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_SLOTS).write([core::ptr::null_mut(), second.as_mut_ptr()]);
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_DISPATCH).write(record_dispatch);
            service_handler_global_dispatch(8, 2);
            assert_eq!(addr_of!(CALL).read(), Some((second.as_mut_ptr(), 8, 2)));
            addr_of_mut!(CALL).write(None);
            addr_of_mut!(SERVICE_HANDLER_GLOBAL_SLOTS).write([core::ptr::null_mut(); 2]);
            service_handler_global_dispatch(u32::MAX, u32::MAX);
            assert_eq!(addr_of!(CALL).read(), None);
            reset();
        }
    }
}
