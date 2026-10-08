//! Bounded error accumulation, FUN_08117d50 @ 0x08117d50.
//!
//! True extent: 172 bytes to the next function at 0x08117dfc: 112 code
//! bytes, two literal words, and 52 bytes of padded message data. Raw ARM
//! scan verifies two incoming plain BLs, five outgoing plain BLs, and zero
//! predicated BLs; the final B calls string_object_insert_cstr as a tail call.
//! If state byte +2 is set, return without reading the input. Otherwise sum
//! both NULL-safe payload lengths INCLUDING their NULs with u32 wrapping.
//! Below 4096, append the PowerCntlr label and input; at/above 4096, first
//! latch suppression, then append the label and the fixed suppression message.
//! Deliberate deviations: host builds inject the state pointer and reuse the
//! existing ERROR_TEXT stand-in; the message uses identical static bytes.
//! All callees use their canonical Rust ports; native pointer fields widen on
//! hosts through StringObject, retaining the exact four-byte target layout.

use crate::cxx::string_object::{StringObject, string_object_c_str, string_object_insert_cstr};
use crate::libc::strlen_safe_plus1::strlen_safe_plus1;
use super::error_text_append_power_controller::error_text_append_power_controller;

#[cfg(not(target_os = "none"))]
pub static mut ERROR_ACCUMULATION_STATE: *mut u8 = core::ptr::null_mut();

const SUPPRESSION_MESSAGE: &[u8] = b"Too many errors, further errors discarded. (13)\n\0";

/// # Safety
/// The fixed globals (or host replacements) must be valid. Unless already
/// suppressed, input must point to a valid StringObject and its NUL-terminated
/// payload. The destination must satisfy the insertion allocator's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn error_text_append_bounded(input: *const StringObject) {
    #[cfg(target_os = "none")]
    let state = 0x089cffb0 as *mut u8;
    #[cfg(not(target_os = "none"))]
    let state = core::ptr::read_volatile(core::ptr::addr_of!(ERROR_ACCUMULATION_STATE));
    if state.add(2).read() != 0 { return; }
    #[cfg(target_os = "none")]
    let text = 0x089d0020 as *mut StringObject;
    #[cfg(not(target_os = "none"))]
    let text = core::ptr::read_volatile(core::ptr::addr_of!(super::error_text_append_power_controller::ERROR_TEXT));
    let total = (strlen_safe_plus1((*text).payload) as u32)
        .wrapping_add(strlen_safe_plus1((*input).payload) as u32);
    let source = if total >= 4096 {
        state.add(2).write(1);
        error_text_append_power_controller();
        SUPPRESSION_MESSAGE.as_ptr()
    } else {
        error_text_append_power_controller();
        string_object_c_str(input)
    };
    string_object_insert_cstr(text, i32::MAX, source);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};
    use super::super::error_text_append_power_controller::ERROR_TEXT;

    struct Restore(*mut u8, *mut StringObject, StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ERROR_ACCUMULATION_STATE = self.0;
            ERROR_TEXT = self.1;
            STRING_OBJECT_ASSIGN_CSTR_OPS = self.2;
        } }
    }
    unsafe extern "C" fn allocate(text: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert!(size <= 8192);
        assert_eq!(flags, 1);
        (*text).payload
    }
    unsafe extern "C" fn refuse(_: *mut StringObject, _: usize, _: u32) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn forbidden_clear(_: *mut StringObject) {
        panic!("append must not clear");
    }

    #[test]
    fn inclusive_threshold_null_payload_and_persistent_suppression() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(ERROR_ACCUMULATION_STATE, ERROR_TEXT, STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: forbidden_clear,
            };
            let mut state = [0x55, 0xaa, 0, 0x33];
            ERROR_ACCUMULATION_STATE = state.as_mut_ptr();
            let mut storage = [0xa5; 8192];
            storage[0] = 0;
            let mut text = StringObject { vtable: core::ptr::null(), payload: storage.as_mut_ptr() };
            ERROR_TEXT = &mut text;
            let mut input = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
            error_text_append_bounded(&input);
            assert_eq!(storage[0], 0);
            assert_eq!(state, [0x55, 0xaa, 0, 0x33]);
            let mut source = [b'x'; 4095];
            source[4093] = 0;
            input.payload = source.as_mut_ptr();
            error_text_append_bounded(&input); // 1 + 4094 = 4095, accepted.
            assert_eq!(&storage[..4094], &source[..4094]);
            assert_eq!(state[2], 0);
            storage[0] = 0;
            source[4093] = b'x';
            source[4094] = 0;
            error_text_append_bounded(&input); // 1 + 4095 = 4096, suppressed.
            assert_eq!(&storage[..SUPPRESSION_MESSAGE.len()], SUPPRESSION_MESSAGE);
            assert_eq!(state, [0x55, 0xaa, 1, 0x33]);
            let before = storage;
            error_text_append_bounded(core::ptr::null());
            assert_eq!(storage, before);

            state[2] = 0;
            storage[..4].copy_from_slice(b"old\0");
            input.payload = b"\xe2\x82\xac\0".as_ptr() as *mut u8;
            error_text_append_bounded(&input);
            assert_eq!(&storage[..17], b"oldPowerCntlr\xe2\x82\xac\0");
            state[2] = 0;
            source[4094] = 0;
            input.payload = source.as_mut_ptr();
            STRING_OBJECT_ASSIGN_CSTR_OPS.allocate_payload = refuse;
            let before = storage;
            error_text_append_bounded(&input);
            assert_eq!(storage, before);
            assert_eq!(state[2], 1, "failed allocation must not undo suppression");
        }
    }
}
