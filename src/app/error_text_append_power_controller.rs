//! Conditional error-text label append, FUN_081197dc @ 0x081197dc.
//!
//! True extent: 48 bytes (40 code + 8 literal-pool bytes), ending at the
//! next real function @ 0x0811980c. Raw binary scan: two incoming plain
//! BLs (@ 0x08117d94, 0x08117da0), zero predicated BLs. The body has one
//! plain BL to string_object_is_empty and one conditional tail B to
//! string_object_insert_cstr. If the error-text StringObject @ 0x089d0020
//! is nonempty, append the NUL-terminated literal @ 0x083f64d4 with
//! INT_MAX as the insertion index. Empty/NULL payloads remain unchanged.
//!
//! Deliberate deviations: host builds substitute the exact literal bytes
//! and an injectable global object pointer; targets retain both firmware
//! addresses. Both callees are canonical Rust ports, including the existing
//! allocation boundary. Ghidra incorrectly inlines the insertion body.

use crate::cxx::string_object::{StringObject, string_object_is_empty, string_object_insert_cstr};

/// Host replacement for the firmware's fixed global StringObject.
/// Must point to a valid object before calling the public entry.
#[cfg(not(target_os = "none"))]
pub static mut ERROR_TEXT: *mut StringObject = core::ptr::null_mut();

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn error_text_append_power_controller() {
    #[cfg(target_os = "none")]
    let text = 0x089d0020 as *mut StringObject;
    #[cfg(not(target_os = "none"))]
    let text = core::ptr::read_volatile(core::ptr::addr_of!(ERROR_TEXT));
    if !string_object_is_empty(text) {
        #[cfg(target_os = "none")]
        let label = 0x083f64d4 as *const u8;
        #[cfg(not(target_os = "none"))]
        let label = b"PowerCntlr\0".as_ptr();
        string_object_insert_cstr(text, i32::MAX, label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};

    struct Restore(*mut StringObject, StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ERROR_TEXT = self.0;
            STRING_OBJECT_ASSIGN_CSTR_OPS = self.1;
        } }
    }
    unsafe extern "C" fn allocate(text: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert!(size <= 64);
        assert_eq!(flags, 1);
        (*text).payload
    }
    unsafe extern "C" fn refuse(_: *mut StringObject, _: usize, _: u32) -> *mut u8 {
        core::ptr::null_mut()
    }
    unsafe extern "C" fn forbidden_clear(_: *mut StringObject) {
        panic!("append must not clear the object");
    }

    #[test]
    fn empty_payloads_utf8_repeated_append_and_failed_allocation() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(ERROR_TEXT, STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: forbidden_clear,
            };
            let mut storage = [0xa5u8; 64];
            let mut text = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
            ERROR_TEXT = &mut text;
            error_text_append_power_controller();
            assert!(text.payload.is_null());
            storage[0] = 0;
            text.payload = storage.as_mut_ptr();
            error_text_append_power_controller();
            assert_eq!(storage[0], 0);
            assert!(storage[1..].iter().all(|&byte| byte == 0xa5));

            storage[..4].copy_from_slice(b"\xe2\x82\xac\0");
            error_text_append_power_controller();
            assert_eq!(&storage[..14], b"\xe2\x82\xacPowerCntlr\0");
            error_text_append_power_controller();
            assert_eq!(&storage[..24], b"\xe2\x82\xacPowerCntlrPowerCntlr\0");
            assert!(storage[24..].iter().all(|&byte| byte == 0xa5));
            let before = storage;
            STRING_OBJECT_ASSIGN_CSTR_OPS.allocate_payload = refuse;
            error_text_append_power_controller();
            assert_eq!(storage, before);
            assert_eq!(text.payload, storage.as_mut_ptr());
            assert!(text.vtable.is_null());
        }
    }
}
