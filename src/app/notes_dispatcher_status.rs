//! Notes-dispatcher preparation and status read.
//!
//! `notes_dispatcher_prepare_and_read_status` — original: `FUN_0828a700` @
//! **0x0828a700** (44 raw bytes; the distinct next function begins at
//! 0x0828a72c). Decoding every ARM `B`/`BL` word in `osos.dec` finds **9
//! direct, unconditional `bl` call sites**, with no predicated or tail-branch
//! callers.
//!
//! Algorithm: obtain the `TCNotesDispatcher` singleton, if present; inspect
//! its request byte at `+0x535`; and invoke the request-start routine at
//! 0x081178cc only while that byte is zero. Finally tail-call the 12-byte
//! status reader at 0x082724e8, which loads and zero-extends the byte at
//! 0x089cffac. The callee at 0x081178cc is not ported, so this module does not
//! assign it a stronger identity than starting the observed dispatcher request.
//!
//! Deliberate deviation: host builds use an inert request-start replacement;
//! unit tests invoke the shared body with a recorder to prove the target call
//! gate. Firmware builds call 0x081178cc directly.
use core::ptr;

use crate::app::registry::instance_of_class_4180;

const NOTES_DISPATCHER_REQUEST_OFFSET: usize = 0x4fc;
const NOTES_DISPATCHER_REQUEST_ACTIVE_OFFSET: usize = 0x39;

#[cfg(target_os = "none")]
const NOTES_DISPATCHER_STATUS: *const u8 = 0x089c_ffac as *const u8;

#[cfg(not(target_os = "none"))]
static mut HOST_NOTES_DISPATCHER_STATUS: u8 = 0;

#[inline(always)]
unsafe fn notes_dispatcher_status() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(NOTES_DISPATCHER_STATUS) as u32 }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_NOTES_DISPATCHER_STATUS)) as u32 }
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn start_notes_dispatcher_request(request: *mut u8) {
    let start: unsafe extern "C" fn(*mut u8) = unsafe { core::mem::transmute(0x0811_78ccusize) };
    unsafe { start(request) };
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn start_notes_dispatcher_request(_request: *mut u8) {}

#[inline(always)]
unsafe fn prepare_notes_dispatcher_and_read_status(
    dispatcher: *mut u8,
    start_request: unsafe fn(*mut u8),
    read_status: unsafe fn() -> u32,
) -> u32 {
    if !dispatcher.is_null() {
        let request = unsafe { dispatcher.add(NOTES_DISPATCHER_REQUEST_OFFSET) };
        if unsafe { ptr::read_volatile(request.add(NOTES_DISPATCHER_REQUEST_ACTIVE_OFFSET)) } == 0 {
            unsafe { start_request(request) };
        }
    }
    unsafe { read_status() }
}

/// notes_dispatcher_prepare_and_read_status — original: `FUN_0828a700` @
/// 0x0828a700 (44 bytes; 9 direct unconditional `bl` call sites).
///
/// Ensures the present Notes dispatcher has started its request, then returns
/// the shared status byte. A NULL singleton skips the request-byte read and
/// start call exactly as retailOS does.
///
/// # Safety
///
/// The firmware registry must be initialized. When the Notes dispatcher is
/// present, it must contain the request state through `+0x535`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn notes_dispatcher_prepare_and_read_status() -> u32 {
    let dispatcher = unsafe { instance_of_class_4180() };
    unsafe {
        prepare_notes_dispatcher_and_read_status(
            dispatcher,
            start_notes_dispatcher_request,
            notes_dispatcher_status,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::{Mutex, MutexGuard};
    

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut REQUESTS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut REQUEST_COUNT: usize = 0;
    static mut TEST_STATUS: u32 = 0;

    unsafe fn record_request(request: *mut u8) {
        unsafe {
            REQUESTS[REQUEST_COUNT] = request;
            REQUEST_COUNT += 1;
            TEST_STATUS = 0x67;
        }
    }

    unsafe fn read_test_status() -> u32 {
        unsafe { TEST_STATUS }
    }

    fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn reset_requests(status: u32) {
        unsafe {
            REQUESTS = [ptr::null_mut(); 2];
            REQUEST_COUNT = 0;
            TEST_STATUS = status;
        }
    }

    #[test]
    fn null_dispatcher_skips_request_start_and_preserves_status_byte() {
        let _guard = lock();
        reset_requests(0xff);

        let status = unsafe {
            prepare_notes_dispatcher_and_read_status(
                ptr::null_mut(),
                record_request,
                read_test_status,
            )
        };

        assert_eq!(status, 0xff);
        assert_eq!(unsafe { REQUEST_COUNT }, 0);
    }

    #[test]
    fn active_request_skips_start_without_touching_status() {
        let _guard = lock();
        reset_requests(0x9d);
        let mut dispatcher = [0u8; NOTES_DISPATCHER_REQUEST_OFFSET + NOTES_DISPATCHER_REQUEST_ACTIVE_OFFSET + 1];
        dispatcher[NOTES_DISPATCHER_REQUEST_OFFSET + NOTES_DISPATCHER_REQUEST_ACTIVE_OFFSET] = 1;

        let status = unsafe {
            prepare_notes_dispatcher_and_read_status(
                dispatcher.as_mut_ptr(),
                record_request,
                read_test_status,
            )
        };

        assert_eq!(status, 0x9d);
        assert_eq!(unsafe { REQUEST_COUNT }, 0);
        assert_eq!(dispatcher[NOTES_DISPATCHER_REQUEST_OFFSET + NOTES_DISPATCHER_REQUEST_ACTIVE_OFFSET], 1);
    }

    #[test]
    fn inactive_request_starts_at_the_retail_request_offset() {
        let _guard = lock();
        reset_requests(0);
        let mut dispatcher = [0u8; NOTES_DISPATCHER_REQUEST_OFFSET + NOTES_DISPATCHER_REQUEST_ACTIVE_OFFSET + 1];

        let status = unsafe {
            prepare_notes_dispatcher_and_read_status(
                dispatcher.as_mut_ptr(),
                record_request,
                read_test_status,
            )
        };

        assert_eq!(status, 0x67);
        assert_eq!(unsafe { REQUEST_COUNT }, 1);
        assert_eq!(unsafe { REQUESTS[0] }, unsafe { dispatcher.as_mut_ptr().add(NOTES_DISPATCHER_REQUEST_OFFSET) });
    }
}
