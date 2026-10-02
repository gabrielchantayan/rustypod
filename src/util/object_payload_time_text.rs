//! Time text from the final word of an object's resolved payload.
//!
//! `object_payload_time_text` — retailOS `FUN_0829b654` at **0x0829b654**.
//! True extent: **48 bytes**, ending with `ldr pc, [sp], #4` at 0x0829b680;
//! the next function begins at 0x0829b684. Raw ARM decoding verifies three
//! outgoing unconditional BLs, zero predicated BLs, and two inbound
//! unconditional BL call sites (0x0812714c and 0x08127e34).
//!
//! Resolve the object's four-word payload, copy it to another stack record,
//! and pass the last word by address to the time-text formatter at 0x081404b4.
//! That formatter converts seconds to calendar/time fields through 0x080964cc,
//! formats through the service vtable, and returns the shared buffer 0x08ad2ce8.
//! The wrapper preserves its returned r0, unlike Ghidra's void signature.
//!
//! Deliberate deviations: reuse the existing Rust resolver and paired copy;
//! retain the unported time formatter as a target-address dispatch seam.
//! Host tests supply a boundary-classifying formatter, not a firmware service.

use crate::copy_four_words::copy_four_words_paired;
use crate::object_word_payload_resolve::object_word_payload_resolve;

pub type PayloadTimeFormatter = unsafe extern "C" fn(*const u32) -> *const u8;

unsafe extern "C" fn firmware_time_formatter(seconds: *const u32) -> *const u8 {
    #[cfg(target_os = "none")]
    {
        let formatter: PayloadTimeFormatter = unsafe { core::mem::transmute(0x081404b4usize) };
        unsafe { formatter(seconds) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = seconds;
        panic!("retailOS time formatter requires a host implementation")
    }
}

pub static mut OBJECT_PAYLOAD_TIME_FORMATTER: PayloadTimeFormatter = firmware_time_formatter;

unsafe fn format_resolved_payload(object: *mut u32, formatter: PayloadTimeFormatter) -> *const u8 {
    let mut resolved = [0u32; 4];
    let mut copied = [0u32; 4];
    unsafe {
        object_word_payload_resolve(resolved.as_mut_ptr(), object);
        copy_four_words_paired(copied.as_mut_ptr(), resolved.as_ptr());
        formatter(copied.as_ptr().add(3))
    }
}

/// # Safety
/// `object` must satisfy `object_word_payload_resolve`'s contract. The active
/// formatter must accept one aligned seconds word and return a live text pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_payload_time_text(object: *mut u32) -> *const u8 {
    let formatter = unsafe { core::ptr::addr_of!(OBJECT_PAYLOAD_TIME_FORMATTER).read_volatile() };
    unsafe { format_resolved_payload(object, formatter) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    unsafe extern "C" fn classify_seconds(seconds: *const u32) -> *const u8 {
        match unsafe { seconds.read() } {
            0 => b"epoch\0".as_ptr(),
            1..=59 => b"first minute\0".as_ptr(),
            60..=3599 => b"first hour\0".as_ptr(),
            3600..=86399 => b"first day\0".as_ptr(),
            _ => b"later\0".as_ptr(),
        }
    }

    #[test]
    fn time_boundaries_use_final_payload_word_without_mutating_object() {
        let _lock = crate::object_word_payload_resolve::tests::PROCESSOR_TEST_LOCK.lock();
        for (seconds, expected) in [
            (0, "epoch"), (1, "first minute"), (59, "first minute"),
            (60, "first hour"), (3599, "first hour"), (3600, "first day"),
            (86399, "first day"), (86400, "later"), (u32::MAX, "later"),
        ] {
            // A null processor field at +0x2c selects the real resolver's
            // unchanged-payload path. All fields accessed by it exist here.
            let mut object = [0u32; 14];
            object[7..11].copy_from_slice(&[seconds ^ u32::MAX, 60, 3600, seconds]);
            let before = object;
            let text = unsafe { format_resolved_payload(object.as_mut_ptr(), classify_seconds) };
            let text = unsafe { std::ffi::CStr::from_ptr(text.cast()) };
            assert_eq!(text.to_str().unwrap(), expected);
            assert_eq!(object, before);
        }
    }
}
