//! Selector-one path initialization @ 0x080741d0.

use crate::cxx::string_object::{StringObject, string_object_assign_cstr_returning_this};

/// Original: `FUN_080741d0` @ 0x080741d0, 32 bytes through the next
/// function at 0x080741f0: 28 code bytes and the literal at 0x080741ec.
/// Raw-word scan verifies two incoming plain BLs (0x08074218, 0x082752e4),
/// zero predicated BLs, and zero outgoing BLs. One conditional tail branch
/// reaches string_object_assign_cstr_returning_this @ 0x08279300.
///
/// For selector 1, write mode byte 4 and assign the single-byte path marker
/// 0x01 followed by NUL (raw source at 0x083ecb3c), returning the path object.
/// Otherwise return the selector unchanged without accessing either output.
/// Assignment failure still leaves mode set and returns the path object.
///
/// Deliberate deviations: use static marker bytes instead of the firmware
/// literal address, and call the existing Rust assignment seam. `usize`
/// represents the mixed integer/pointer r0 result without truncating host
/// pointers; it remains a single 32-bit word on the target.
///
/// # Safety
/// For selector 1, mode must be writable and path must satisfy the string
/// assignment callee's contract. Other selectors permit NULL outputs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_selector_initialize(
    selector: u32,
    mode: *mut u8,
    path: *mut StringObject,
) -> usize {
    if selector != 1 {
        return selector as usize;
    }
    mode.write(4);
    string_object_assign_cstr_returning_this(path, b"\x01\0".as_ptr()) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{StringObjectAssignCstrOps, STRING_OBJECT_ASSIGN_CSTR_OPS};
    use core::ptr;

    struct Restore(StringObjectAssignCstrOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write(self.0);
        } }
    }

    unsafe extern "C" fn allocate(path: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert_eq!(size, 2);
        assert_eq!(flags, 0);
        (*path).payload
    }
    unsafe extern "C" fn refuse(_: *mut StringObject, _: usize, _: u32) -> *mut u8 {
        ptr::null_mut()
    }
    unsafe extern "C" fn forbidden_clear(_: *mut StringObject) {
        panic!("nonempty marker must not clear the path");
    }

    #[test]
    fn other_selectors_preserve_outputs_and_accept_null() { unsafe {
        let mut mode = 0xa5;
        let mut storage = *b"old\0";
        let mut path = StringObject { vtable: ptr::null(), payload: storage.as_mut_ptr() };
        for selector in [0, 2, 4, 0x80000000, u32::MAX] {
            assert_eq!(path_selector_initialize(selector, &mut mode, &mut path), selector as usize);
            assert_eq!(mode, 0xa5);
            assert_eq!(storage, *b"old\0");
            assert_eq!(path_selector_initialize(selector, ptr::null_mut(), ptr::null_mut()), selector as usize);
        }
    } }

    #[test]
    fn selector_one_sets_mode_and_marker_even_when_allocation_fails() {
        let _lock = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read());
            let mut bytes = [0x55, 0x66, 0x77, 0x88];
            let mut path = StringObject { vtable: ptr::null(), payload: bytes.as_mut_ptr() };
            let mut mode = [0xa5, 0x5a];
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate, clear_payload: forbidden_clear,
            };
            assert_eq!(path_selector_initialize(1, mode.as_mut_ptr(), &mut path), &mut path as *mut _ as usize);
            assert_eq!(mode, [4, 0x5a]);
            assert_eq!(bytes, [1, 0, 0x77, 0x88]);
            bytes = [0x11, 0x22, 0x33, 0x44];
            mode[0] = 0xff;
            STRING_OBJECT_ASSIGN_CSTR_OPS.allocate_payload = refuse;
            assert_eq!(path_selector_initialize(1, mode.as_mut_ptr(), &mut path), &mut path as *mut _ as usize);
            assert_eq!(mode, [4, 0x5a]);
            assert_eq!(bytes, [0x11, 0x22, 0x33, 0x44]);
        }
    }
}
