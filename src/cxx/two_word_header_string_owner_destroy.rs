//! Plain destructor for an unidentified two-word-header StringObject owner.
//!
//! Original: `FUN_081b022c` @ load address `0x081b022c`, 20 bytes,
//! extent [0x081b022c, 0x081b0240). The next real function starts with
//! `push {r4,lr}` at 0x081b0240. Raw ARM decoding finds two inbound plain
//! BL sites (0x0839cadc, 0x0839cb2c), one outbound plain BL to
//! string_object_destroy @ 0x08277484, and no predicated BLs in either set.
//!
//! Destroy the embedded StringObject at target offset +8, then subtract
//! eight from the callee's returned pointer to return the enclosing owner.
//! Neither header word is touched; there is no NULL guard or owner delete.
//! The caller paths subsequently delete the enclosing allocation separately.
//!
//! Deliberate host deviation: repr(C) keeps the two opaque u32 header words
//! eight bytes wide while StringObject's pointer fields widen on hosts.
//! The owner class and header meanings remain unidentified; no new seam.

use crate::cxx::string_object::{string_object_destroy, StringObject};

#[repr(C)]
pub struct TwoWordHeaderStringOwner {
    pub header: [u32; 2],
    pub string: StringObject,
}

/// Destroy the embedded string and return its enclosing owner.
/// Safety: `this` must point to a live, writable owner with a valid payload.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_word_header_string_owner_destroy(
    this: *mut TwoWordHeaderStringOwner,
) -> *mut TwoWordHeaderStringOwner {
    let string = string_object_destroy(core::ptr::addr_of_mut!((*this).string));
    (string as *mut u8).sub(8) as *mut TwoWordHeaderStringOwner
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{STRING_OBJECT_VTABLE, tests::STRING_OBJECT_OPS_TEST_LOCK};

    #[test]
    fn empty_and_owned_payloads_preserve_header_and_release_only_once() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _lock = STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut payload_storage = *b"owned\0";
        let payload = payload_storage.as_mut_ptr();
        let mut owner = TwoWordHeaderStringOwner {
            header: [0x80000000, u32::MAX],
            string: StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() },
        };
        unsafe {
            assert_eq!(two_word_header_string_owner_destroy(&mut owner), &mut owner as *mut _);
        }
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
        assert_eq!(owner.header, [0x80000000, u32::MAX]);
        assert_eq!(owner.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        owner.string.payload = payload;
        unsafe {
            assert_eq!(two_word_header_string_owner_destroy(&mut owner), &mut owner as *mut _);
        }
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, payload, 0x34));
        assert!(owner.string.payload.is_null());
        assert_eq!(owner.header, [0x80000000, u32::MAX]);
        assert_eq!(owner.string.vtable, &STRING_OBJECT_VTABLE as *const _);
        unsafe { two_word_header_string_owner_destroy(&mut owner); }
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, payload, 0x34));
    }
}
