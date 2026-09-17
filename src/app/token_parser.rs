//! `string_object_find_and_erase_cstr` — original: `FUN_08178034` @
//! `0x08178034` (88 bytes, `0x08178034..0x0817808c`; the next separately
//! linked function starts at `0x0817808c`).
//!
//! Calls the unresolved string-object token lookup at `0x082a4f88` with start
//! index zero. It writes that index to the optional out-pointer before testing
//! it; `-1` returns zero. Any other result measures the token with retailOS's
//! unguarded [`crate::libc::strlen::strlen`] and erases that many
//! *codepoints* from the string object, then returns one. Consequently a
//! multibyte token's byte length removes more codepoints than its own character
//! count; this is retained from the ARM register flow.
//!
//! **6 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `osos.dec`: 0x08178468,
//! 0x0817848c, 0x08178514, 0x0817858c, 0x08178604, and 0x08178620.
//!
//! Deliberate deferral: the lookup is now identified as
//! `string_object_find_casefolded`, but its bounded case-fold comparator
//! depends on an unrecovered retail table. Target builds therefore retain the
//! typed known-address call and host tests install a volatile seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

use crate::cxx::string_object::{string_object_erase, StringObject};
use crate::libc::strlen::strlen;

const RETAIL_STRING_OBJECT_TOKEN_LOOKUP: usize = 0x082a_4f88;

/// ABI of the unresolved lookup helper at `0x082a4f88`.
pub type StringObjectTokenLookup = unsafe extern "C" fn(
    *const StringObject,
    *const u8,
    i32,
) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_string_object_token_lookup(
    string: *const StringObject,
    token: *const u8,
    start_index: i32,
) -> i32 {
    let lookup: StringObjectTokenLookup = core::mem::transmute(RETAIL_STRING_OBJECT_TOKEN_LOOKUP);
    lookup(string, token, start_index)
}

/// Host seam for the unresolved lookup helper.
#[cfg(not(target_os = "none"))]
pub static mut STRING_OBJECT_FIND_AND_ERASE_CSTR_OPS: StringObjectFindAndEraseCstrOps =
    StringObjectFindAndEraseCstrOps { lookup: missing_string_object_token_lookup };

/// Operations not yet available as Rust ports.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct StringObjectFindAndEraseCstrOps {
    pub lookup: StringObjectTokenLookup,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_string_object_token_lookup(
    _string: *const StringObject,
    _token: *const u8,
    _start_index: i32,
) -> i32 {
    panic!("install string-object token lookup host operations before calling this wrapper")
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_string_object_token_lookup(
    string: *const StringObject,
    token: *const u8,
    start_index: i32,
) -> i32 {
    let lookup = core::ptr::read_volatile(addr_of!(STRING_OBJECT_FIND_AND_ERASE_CSTR_OPS.lookup));
    lookup(string, token, start_index)
}

/// Finds `token` at or after character zero, reports its index, and removes a
/// number of UTF-8 codepoints equal to the token's C-string byte length.
///
/// # Safety
///
/// `string` and `token` must satisfy the unresolved lookup helper's contract.
/// On a nonnegative result, `token` must be readable through its NUL and
/// `string` must meet [`string_object_erase`]'s raw-pointer preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.string_object_find_and_erase_cstr")]
#[inline(never)]
pub unsafe extern "C" fn string_object_find_and_erase_cstr(
    _context: *mut u8,
    string: *mut StringObject,
    token: *const u8,
    out_index: *mut i32,
) -> u32 {
    #[cfg(target_os = "none")]
    let index = retail_string_object_token_lookup(string, token, 0);
    #[cfg(not(target_os = "none"))]
    let index = host_string_object_token_lookup(string, token, 0);

    if !out_index.is_null() {
        out_index.write(index);
    }
    if index == -1 {
        return 0;
    }

    string_object_erase(string, index, strlen(token) as i32);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOOKUP_RESULT: i32 = -1;
    static mut LOOKUP_CALLS: usize = 0;
    static mut SEEN_STRING: *const StringObject = core::ptr::null();
    static mut SEEN_TOKEN: *const u8 = core::ptr::null();
    static mut SEEN_START_INDEX: i32 = -1;

    unsafe extern "C" fn recording_lookup(
        string: *const StringObject,
        token: *const u8,
        start_index: i32,
    ) -> i32 {
        LOOKUP_CALLS += 1;
        SEEN_STRING = string;
        SEEN_TOKEN = token;
        SEEN_START_INDEX = start_index;
        LOOKUP_RESULT
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
        original: StringObjectFindAndEraseCstrOps,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(STRING_OBJECT_FIND_AND_ERASE_CSTR_OPS).write_volatile(self.original) };
        }
    }

    fn install_lookup(result: i32) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let original = addr_of!(STRING_OBJECT_FIND_AND_ERASE_CSTR_OPS).read_volatile();
            addr_of_mut!(STRING_OBJECT_FIND_AND_ERASE_CSTR_OPS).write_volatile(
                StringObjectFindAndEraseCstrOps { lookup: recording_lookup },
            );
            LOOKUP_RESULT = result;
            LOOKUP_CALLS = 0;
            SEEN_STRING = core::ptr::null();
            SEEN_TOKEN = core::ptr::null();
            SEEN_START_INDEX = -1;
            OpsGuard { _lock: lock, original }
        }
    }

    #[test]
    fn finds_reports_and_removes_the_token_byte_length_in_codepoints() {
        let mut bytes = [0u8; 32];
        bytes[..6].copy_from_slice(b"a\xc3\xa9Xq\0");
        let mut string = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
        let token = b"\xc3\xa9\0";
        let _ops = install_lookup(1);
        let mut index = i32::MIN;

        let found = unsafe {
            string_object_find_and_erase_cstr(
                core::ptr::null_mut(),
                addr_of_mut!(string),
                token.as_ptr(),
                addr_of_mut!(index),
            )
        };

        assert_eq!(found, 1);
        assert_eq!(index, 1);
        assert_eq!(&bytes[..3], b"aq\0");
        unsafe {
            assert_eq!(LOOKUP_CALLS, 1);
            assert_eq!(SEEN_STRING, addr_of!(string));
            assert_eq!(SEEN_TOKEN, token.as_ptr());
            assert_eq!(SEEN_START_INDEX, 0);
        }
    }

    #[test]
    fn reports_minus_one_without_erasing_when_the_lookup_misses() {
        let mut bytes = [0u8; 32];
        bytes[..6].copy_from_slice(b"stay!\0");
        let before = bytes;
        let mut string = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
        let token = b"none\0";
        let _ops = install_lookup(-1);
        let mut index = i32::MIN;

        let found = unsafe {
            string_object_find_and_erase_cstr(
                core::ptr::null_mut(),
                addr_of_mut!(string),
                token.as_ptr(),
                addr_of_mut!(index),
            )
        };

        assert_eq!(found, 0);
        assert_eq!(index, -1);
        assert_eq!(bytes, before);
        unsafe { assert_eq!(LOOKUP_CALLS, 1) };
    }

    #[test]
    fn accepts_a_null_index_output_pointer() {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(b"abc\0");
        let mut string = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
        let token = b"b\0";
        let _ops = install_lookup(1);

        let found = unsafe {
            string_object_find_and_erase_cstr(
                core::ptr::null_mut(),
                addr_of_mut!(string),
                token.as_ptr(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(found, 1);
        assert_eq!(&bytes[..3], b"ac\0");
    }
}
