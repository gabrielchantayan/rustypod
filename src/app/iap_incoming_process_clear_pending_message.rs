//! Clears an iAP incoming-process request's pending message.
//!
//! `iap_incoming_process_clear_pending_message` — retailOS `FUN_081055f0` @
//! `0x081055f0` (**64 bytes**, `0x081055f0..0x0810562f`; the next real
//! function starts at `0x08105630`). Raw ARM has one unconditional direct
//! `bl` (to `0x081d71b0`) and one predicated virtual `blxne` through vtable
//! slot `+0x04`. Full-image decoding finds three inbound plain `bl` call sites
//! (0x0810565c, 0x081056dc, and 0x082a9770), with no predicated inbound forms.
//!
//! If a pending message is present, notify the incoming-process thread with
//! the request's handler index, release the message through vtable slot `+4`,
//! and clear the pending slot. Deliberate deviation: `0x081d71b0` is not yet
//! ported, so host tests use a volatile completion seam while target builds
//! call its fixed retailOS address. Host pointer-width widens the final two
//! fields; on ARM they remain the observed words at `+0x20` and `+0x24`.

#[cfg(test)]
extern crate std;

use core::ptr;

/// The recovered target layout of the request fields read by this function.
#[repr(C)]
pub struct IapIncomingProcessRequest {
    _reserved_0_4: [u32; 2],
    pub handler_index: u32,
    _reserved_c_1c: [u32; 5],
    pub thread: *mut u8,
    pub pending_message: *mut PendingMessage,
}

/// Object with the vtable entry used to release a pending message.
#[repr(C)]
pub struct PendingMessage {
    pub vtable: *const PendingMessageVtable,
}

/// Recovered prefix of a pending message vtable.
#[repr(C)]
pub struct PendingMessageVtable {
    _slot_0: usize,
    pub release: unsafe extern "C" fn(*mut PendingMessage),
}

type CompletePendingMessage = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn complete_pending_message(thread: *mut u8, handler_index: u32) {
    let complete: CompletePendingMessage = core::mem::transmute(0x081d_71b0usize);
    complete(thread, handler_index);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_complete_pending_message(_thread: *mut u8, _handler_index: u32) {
    panic!("install iAP pending-message completion host operations before calling this port")
}

/// Host replacement for the unported completion callee at `0x081d71b0`.
#[cfg(not(target_os = "none"))]
pub static mut IAP_PENDING_MESSAGE_COMPLETE: CompletePendingMessage = missing_complete_pending_message;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn complete_pending_message(thread: *mut u8, handler_index: u32) {
    let complete = ptr::read_volatile(ptr::addr_of!(IAP_PENDING_MESSAGE_COMPLETE));
    complete(thread, handler_index);
}

/// Completes and releases a request's pending iAP message, if any.
///
/// # Safety
///
/// `request` must point to a valid request. A non-NULL pending message must
/// have a readable vtable and callable release entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn iap_incoming_process_clear_pending_message(
    request: *mut IapIncomingProcessRequest,
) {
    let pending_message = (*request).pending_message;
    if pending_message.is_null() {
        return;
    }

    complete_pending_message((*request).thread, (*request).handler_index);
    ((*(*pending_message).vtable).release)(pending_message);
    (*request).pending_message = ptr::null_mut();
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut COMPLETED_THREAD: *mut u8 = ptr::null_mut();
    static mut COMPLETED_INDEX: u32 = 0;
    static mut RELEASED_MESSAGE: *mut PendingMessage = ptr::null_mut();

    unsafe extern "C" fn record_completion(thread: *mut u8, handler_index: u32) {
        COMPLETED_THREAD = thread;
        COMPLETED_INDEX = handler_index;
    }

    unsafe extern "C" fn record_release(message: *mut PendingMessage) {
        RELEASED_MESSAGE = message;
    }

    #[test]
    fn completes_releases_and_clears_a_pending_message() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            let saved = IAP_PENDING_MESSAGE_COMPLETE;
            IAP_PENDING_MESSAGE_COMPLETE = record_completion;
            COMPLETED_THREAD = ptr::null_mut();
            COMPLETED_INDEX = 0;
            RELEASED_MESSAGE = ptr::null_mut();

            let vtable = PendingMessageVtable { _slot_0: 0, release: record_release };
            let mut message = PendingMessage { vtable: &vtable };
            let thread = 0x1234usize as *mut u8;
            let mut request = IapIncomingProcessRequest {
                _reserved_0_4: [0; 2],
                handler_index: 2,
                _reserved_c_1c: [0; 5],
                thread,
                pending_message: &mut message,
            };

            iap_incoming_process_clear_pending_message(&mut request);

            assert_eq!(COMPLETED_THREAD, thread);
            assert_eq!(COMPLETED_INDEX, 2);
            assert!(core::ptr::eq(RELEASED_MESSAGE, &mut message));
            assert!(request.pending_message.is_null());
            IAP_PENDING_MESSAGE_COMPLETE = saved;
        }
    }

    #[test]
    fn leaves_an_empty_pending_slot_untouched() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            let mut request = IapIncomingProcessRequest {
                _reserved_0_4: [0; 2],
                handler_index: 1,
                _reserved_c_1c: [0; 5],
                thread: ptr::null_mut(),
                pending_message: ptr::null_mut(),
            };

            iap_incoming_process_clear_pending_message(&mut request);

            assert!(request.pending_message.is_null());
        }
    }
}
