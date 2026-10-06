//! Optional timed-label time conversion: `FUN_0815cb60` @ 0x0815cb60.
//!
//! True extent [0x0815cb60,0x0815cb84): 32 instruction bytes plus the
//! four-byte 0x083eb28c literal, ending at the next independently callable
//! wrapper. Whole-image aligned word decoding finds two inbound plain BLs
//! (0x0815d34c,0x0815dfd8), no predicated inbound BLs, and no outgoing BLs.
//! NULL assigns the C string at 0x083eb28c via 0x0827639c. Its raw bytes
//! are `72 00` ("r"), not an empty string. Otherwise tail-call 0x081d102c
//! with (label,output,mode); that helper invokes sport-timer provider slot
//! +0x88 with (output, mode == 0 ? 13 : 14, label+0x24). Owner is ignored.
//!
//! Deliberate deviations: express tail branches as final Rust calls and
//! return void, since both raw callers discard r0. Preserve the firmware
//! C-string pointer and virtual allocation/formatter on target. Hosts reuse
//! the existing assignment port with the verified literal contents and an
//! injectable formatter, following timed_label_to_string's seam convention.

use crate::cxx::string_object::StringObject;

type FormatTime = unsafe extern "C" fn(*const u8, *mut StringObject, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_format_time(label: *const u8, output: *mut StringObject, mode: u32) {
    core::mem::transmute::<usize, FormatTime>(0x081d_102c)(label, output, mode);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_format_time(_: *const u8, _: *mut StringObject, _: u32) {
    panic!("timed-label time formatting requires firmware or a host seam");
}

#[cfg(target_os = "none")]
pub static mut TIMED_LABEL_TIME_FORMAT: FormatTime = firmware_format_time;
#[cfg(not(target_os = "none"))]
pub static mut TIMED_LABEL_TIME_FORMAT: FormatTime = unavailable_format_time;

/// # Safety
/// `output` is a live polymorphic string object. A non-NULL `label` must
/// satisfy the firmware formatter's contract. The configured formatter must
/// be callable; replacing the formatter requires exclusive access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_label_time_to_string(
    _owner: *mut u8, label: *const u8, output: *mut StringObject, mode: u32,
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
        core::ptr::read_volatile(core::ptr::addr_of!(TIMED_LABEL_TIME_FORMAT))(label, output, mode);
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
        panic!("NULL label must assign the nonempty fallback, not clear");
    }
    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { STRING_OBJECT_ASSIGN_CSTR_OPS = self.0; } }
    }

    #[test]
    fn absent_label_replaces_only_fallback_bytes_regardless_of_mode() {
        let _lock = match crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("assignment test lock poisoned: {error}"),
        };
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: forbidden_clear,
            };
            for mode in [0, 1, 2, u32::MAX] {
                let mut bytes = [b'o', b'l', b'd', 0, 0xa5];
                let mut output = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
                timed_label_time_to_string(core::ptr::dangling_mut(), core::ptr::null(), &mut output, mode);
                assert_eq!(bytes, [b'r', 0, b'd', 0, 0xa5]);
                assert_eq!(output.payload, bytes.as_mut_ptr());
                assert!(output.vtable.is_null());
            }
        }
    }

    #[test]
    fn failed_fallback_allocation_preserves_previous_payload() {
        unsafe extern "C" fn fail(_: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
            assert_eq!((size, flags), (2, 0));
            core::ptr::null_mut()
        }
        let _lock = match crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock() {
            Ok(guard) => guard,
            Err(error) => panic!("assignment test lock poisoned: {error}"),
        };
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: fail, clear_payload: forbidden_clear,
            };
            let mut bytes = *b"old\0";
            let mut output = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
            timed_label_time_to_string(core::ptr::null_mut(), core::ptr::null(), &mut output, 1);
            assert_eq!(bytes, *b"old\0");
            assert_eq!(output.payload, bytes.as_mut_ptr());
            assert!(output.vtable.is_null());
        }
    }
}
