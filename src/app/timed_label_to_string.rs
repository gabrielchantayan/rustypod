//! Optional timed-label conversion: `FUN_0815cb84` @ 0x0815cb84.
//!
//! True extent [0x0815cb84,0x0815cba0): 24 instruction bytes and the
//! four-byte 0x083eb28c literal, before the next PUSH. Whole-image aligned
//! decoding finds two inbound plain BLs (0x0815d36c,0x0815e004), zero
//! predicated inbound BLs, and zero outbound BLs. Two conditional tail Bs
//! select string_object_assign_cstr @ 0x0827639c for NULL, otherwise the
//! formatter @ 0x081d1068. The latter dispatches sport-timer provider slot
//! +0x88 with (output,17,label+0x24). The first argument is ignored.
//!
//! Raw bytes at 0x083eb28c are `72 00` ("r"), not an empty string. Preserve
//! the firmware pointer on target and its verified contents on hosts.
//! Deliberate deviations: Rust expresses tail branches as final calls and
//! exposes a void result (both observed callers discard r0). Keep unported
//! formatting and target virtual string allocation in firmware; hosts use
//! the existing string assignment port and an injectable formatter boundary.

use crate::cxx::string_object::StringObject;

type FormatLabel = unsafe extern "C" fn(*const u8, *mut StringObject);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_format_label(label: *const u8, output: *mut StringObject) {
    core::mem::transmute::<usize, FormatLabel>(0x081d_1068)(label, output);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_format_label(_: *const u8, _: *mut StringObject) {
    panic!("timed-label formatting requires firmware or a host seam");
}

#[cfg(target_os = "none")]
pub static mut TIMED_LABEL_FORMAT: FormatLabel = firmware_format_label;
#[cfg(not(target_os = "none"))]
pub static mut TIMED_LABEL_FORMAT: FormatLabel = unavailable_format_label;

/// # Safety
/// `output` is a live polymorphic string object. A non-NULL `label` must be
/// valid for the firmware formatter; the configured formatter must be callable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_label_to_string(
    _owner: *mut u8, label: *const u8, output: *mut StringObject,
) {
    if label.is_null() {
        #[cfg(target_os = "none")]
        {
            let assign = core::mem::transmute::<usize,
                unsafe extern "C" fn(*mut StringObject, *const u8)>(0x0827_639c);
            assign(output, 0x083e_b28c as *const u8);
        }
        #[cfg(not(target_os = "none"))]
        crate::cxx::string_object::string_object_assign_cstr(output, b"r\0".as_ptr());
    } else {
        core::ptr::read_volatile(core::ptr::addr_of!(TIMED_LABEL_FORMAT))(label, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};

    unsafe extern "C" fn allocate(output: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert_eq!((size, flags), (2, 0));
        (*output).payload
    }
    unsafe extern "C" fn forbidden_clear(_: *mut StringObject) {
        panic!("NULL label is not an empty-string assignment");
    }
    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; } }
    }

    #[test]
    fn null_label_replaces_payload_and_failed_allocation_does_not_clear() {
        // Share the existing assignment seam lock; changing its type would
        // require migrating unrelated tests.
        let _lock = match crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("assignment test lock poisoned: {error}"),
        };
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: forbidden_clear,
            };
            let mut bytes = [0xa5; 4];
            let mut output = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
            timed_label_to_string(core::ptr::null_mut(), core::ptr::null(), &mut output);
            assert_eq!(bytes, [b'r', 0, 0xa5, 0xa5]);
            output.payload = core::ptr::null_mut();
            timed_label_to_string(core::ptr::dangling_mut(), core::ptr::null(), &mut output);
            assert!(output.payload.is_null());
            assert_eq!(bytes, [b'r', 0, 0xa5, 0xa5]);
        }
    }
}
