//! `indexed_payload_lookup` — original: `FUN_0809e3d0` @ `0x0809e3d0`
//! (24 bytes).
//!
//! Raw ARM decoding establishes the exact extent `0x0809e3d0..0x0809e3e8`:
//!
//! ```text
//! 0809e3d0  push {r3, lr}
//! 0809e3d4  str  r3, [sp]
//! 0809e3d8  mov  r3, r2
//! 0809e3dc  mov  r2, #0
//! 0809e3e0  bl   0x080d6d94
//! 0809e3e4  pop  {ip, pc}
//! ```
//!
//! The first instruction of the next separately entered function is the
//! `push {r4-r8, lr}` at `0x0809e3e8`; there is no literal pool. Decoding
//! every ARM B/BL word in `osos.dec` finds 20 unconditional plain `bl` call
//! sites and one unconditional tail `b` site (`0x08055afc`), with no
//! predicated calls or data-word references. Callers therefore do not gate
//! this wrapper on flags or NULL checks.
//!
//! # Algorithm
//!
//! Move the third ABI argument to the fourth argument register, put the
//! original fourth argument in the fifth stack slot, force the third argument
//! of `0x080d6d94` to zero, then return that callee's status word unchanged.
//! The callee's concrete identity is not established: its recovered contract
//! is an indexed-payload lookup `(index, entry, mode, payload_out,
//! encoded_length_out) -> status`, and this wrapper selects `mode = 0`.
//!
//! # Deliberate deviations
//!
//! The unported `0x080d6d94` is reached directly at its retail address on the
//! device. Host tests replace only that edge with
//! [`INDEXED_PAYLOAD_LOOKUP_BACKEND`]; the wrapper's register/stack argument
//! shuffle is represented by the equivalent five-argument call.

/// ABI of the still-unported indexed-payload backend at `0x080d6d94`.
pub type IndexedPayloadLookupBackend = unsafe extern "C" fn(
    index: *mut u8,
    entry: u32,
    mode: u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32;

#[cfg(target_os = "none")]
unsafe fn retail_indexed_payload_lookup_backend(
    index: *mut u8,
    entry: u32,
    mode: u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    let backend: IndexedPayloadLookupBackend = core::mem::transmute(0x080d_6d94usize);
    backend(index, entry, mode, payload_out, encoded_length_out)
}

/// Host fallback for an unconfigured retail-only dependency.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_indexed_payload_lookup_backend(
    _index: *mut u8,
    _entry: u32,
    _mode: u32,
    _payload_out: *mut *mut u8,
    _encoded_length_out: *mut u32,
) -> u32 {
    panic!("indexed_payload_lookup requires backend 0x080d6d94")
}

/// Host replacement for the still-unported indexed-payload backend.
#[cfg(not(target_os = "none"))]
pub static mut INDEXED_PAYLOAD_LOOKUP_BACKEND: IndexedPayloadLookupBackend =
    missing_indexed_payload_lookup_backend;

/// indexed_payload_lookup — original: `FUN_0809e3d0` @ `0x0809e3d0` (24 bytes).
///
/// Looks up `entry` through `index` with the backend's mode forced to zero.
/// `payload_out`, `encoded_length_out`, and the backend status are forwarded
/// unchanged.
///
/// # Safety
///
/// The backend owns all pointer validity requirements. This function has no
/// NULL guards; its output pointers may be NULL only if the backend accepts
/// NULL output pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_payload_lookup(
    index: *mut u8,
    entry: u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        retail_indexed_payload_lookup_backend(index, entry, 0, payload_out, encoded_length_out)
    }

    #[cfg(not(target_os = "none"))]
    {
        let backend = core::ptr::read_volatile(core::ptr::addr_of!(INDEXED_PAYLOAD_LOOKUP_BACKEND));
        backend(index, entry, 0, payload_out, encoded_length_out)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    static BACKEND_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_INDEX: usize = 0;
    static mut SEEN_ENTRY: u32 = 0;
    static mut SEEN_MODE: u32 = 1;
    static mut SEEN_PAYLOAD_OUT: usize = 0;
    static mut SEEN_LENGTH_OUT: usize = 0;
    static mut BACKEND_STATUS: u32 = 0;
    static mut BACKEND_PAYLOAD: *mut u8 = ptr::null_mut();
    static mut BACKEND_LENGTH: u32 = 0;

    unsafe extern "C" fn recording_backend(
        index: *mut u8,
        entry: u32,
        mode: u32,
        payload_out: *mut *mut u8,
        encoded_length_out: *mut u32,
    ) -> u32 {
        SEEN_INDEX = index as usize;
        SEEN_ENTRY = entry;
        SEEN_MODE = mode;
        SEEN_PAYLOAD_OUT = payload_out as usize;
        SEEN_LENGTH_OUT = encoded_length_out as usize;
        if !payload_out.is_null() {
            payload_out.write(BACKEND_PAYLOAD);
        }
        if !encoded_length_out.is_null() {
            encoded_length_out.write(BACKEND_LENGTH);
        }
        BACKEND_STATUS
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                INDEXED_PAYLOAD_LOOKUP_BACKEND = missing_indexed_payload_lookup_backend;
                SEEN_INDEX = 0;
                SEEN_ENTRY = 0;
                SEEN_MODE = 1;
                SEEN_PAYLOAD_OUT = 0;
                SEEN_LENGTH_OUT = 0;
                BACKEND_STATUS = 0;
                BACKEND_PAYLOAD = ptr::null_mut();
                BACKEND_LENGTH = 0;
            }
        }
    }

    fn arrange(status: u32, payload: *mut u8, length: u32) -> (MutexGuard<'static, ()>, Reset) {
        let guard = BACKEND_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            INDEXED_PAYLOAD_LOOKUP_BACKEND = recording_backend;
            BACKEND_STATUS = status;
            BACKEND_PAYLOAD = payload;
            BACKEND_LENGTH = length;
        }
        (guard, Reset)
    }

    #[test]
    fn forces_mode_zero_and_forwards_outputs_and_status() {
        let index = 0x1234_5000usize as *mut u8;
        let expected_payload = 0x7654_3000usize as *mut u8;
        let (guard, _reset) = arrange(0xffff_ffce, expected_payload, 0x8000_0001);
        let mut payload = ptr::null_mut();
        let mut encoded_length = 0;

        let status = unsafe {
            indexed_payload_lookup(index, u32::MAX, &mut payload, &mut encoded_length)
        };

        assert_eq!(status, 0xffff_ffce);
        assert_eq!(payload, expected_payload);
        assert_eq!(encoded_length, 0x8000_0001);
        unsafe {
            assert_eq!(SEEN_INDEX, index as usize);
            assert_eq!(SEEN_ENTRY, u32::MAX);
            assert_eq!(SEEN_MODE, 0);
            assert_eq!(SEEN_PAYLOAD_OUT, (&mut payload as *mut *mut u8) as usize);
            assert_eq!(SEEN_LENGTH_OUT, (&mut encoded_length as *mut u32) as usize);
        }
        drop(guard);
    }

    #[test]
    fn forwards_null_optional_outputs() {
        let index = 0xffff_f000usize as *mut u8;
        let (guard, _reset) = arrange(0, ptr::null_mut(), 0);

        let status = unsafe { indexed_payload_lookup(index, 0, ptr::null_mut(), ptr::null_mut()) };

        assert_eq!(status, 0);
        unsafe {
            assert_eq!(SEEN_INDEX, index as usize);
            assert_eq!(SEEN_ENTRY, 0);
            assert_eq!(SEEN_MODE, 0);
            assert_eq!(SEEN_PAYLOAD_OUT, 0);
            assert_eq!(SEEN_LENGTH_OUT, 0);
        }
        drop(guard);
    }
}
