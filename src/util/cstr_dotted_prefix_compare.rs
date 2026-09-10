//! C string dotted-prefix comparison — `FUN_082dacdc` @ 0x082dacdc (72 bytes;
//! 10 `bl` call sites, binary-scanned).
//!
//! First measures `prefix` with the unguarded retailOS `strlen` at
//! 0x08392478, then calls the ADS `strncmp` at 0x0803105c over precisely that
//! many bytes. A nonzero comparison result passes through unchanged. On an
//! equal prefix, only a NUL or `'.'` byte immediately after the prefix is a
//! match; any other byte returns 1. Thus `"issuer"` and `"issuer.name"`
//! match `"issuer"`, while `"issuers"` does not.
//!
//! The raw ARM extent is exactly 0x082dacdc..0x082dad24: the following
//! `push {r4,r5,lr}` starts the separately linked next function. All ten
//! direct call sites are unconditional `bl`; none is predicated. Volatile
//! function-pointer loads deliberately preserve the two original call
//! boundaries against LLVM inlining, with no behavioral deviation.

use crate::libc::strlen::strlen;
use crate::libc::strncmp::strncmp;

/// Compares `candidate` with a complete or dotted `prefix`.
///
/// Returns zero if `candidate` starts with all bytes of `prefix` and the next
/// candidate byte is NUL or `'.'`; otherwise returns the original `strncmp`
/// difference, or one for a non-boundary continuation.
///
/// # Safety
///
/// `candidate` and `prefix` must each point to readable NUL-terminated C
/// strings. As in the retailOS function, neither pointer has a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_dotted_prefix_compare(candidate: *const u8, prefix: *const u8) -> i32 {
    let measure: unsafe extern "C" fn(*const u8) -> usize =
        core::ptr::read_volatile(&(strlen as unsafe extern "C" fn(*const u8) -> usize));
    let prefix_len = measure(prefix);
    let compare: unsafe extern "C" fn(*const u8, *const u8, usize) -> i32 =
        core::ptr::read_volatile(&(strncmp as unsafe extern "C" fn(*const u8, *const u8, usize) -> i32));
    let result = compare(candidate, prefix, prefix_len);
    if result != 0 {
        return result;
    }

    let following = candidate.add(prefix_len).read();
    if following == 0 || following == b'.' { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(candidate: &[u8], prefix: &[u8]) -> i32 {
        let prefix_len = prefix.iter().position(|&byte| byte == 0).expect("prefix must terminate");
        for index in 0..prefix_len {
            if candidate[index] == 0 || candidate[index] != prefix[index] {
                return candidate[index] as i32 - prefix[index] as i32;
            }
        }
        if candidate[prefix_len] == 0 || candidate[prefix_len] == b'.' { 0 } else { 1 }
    }

    #[test]
    fn accepts_complete_and_dotted_prefixes() {
        let prefix = b"issuer\0";
        for candidate in [b"issuer\0".as_slice(), b"issuer.name\0", b"issuer.authority.value\0"] {
            assert_eq!(unsafe { cstr_dotted_prefix_compare(candidate.as_ptr(), prefix.as_ptr()) }, 0);
        }
    }

    #[test]
    fn rejects_non_boundary_continuations() {
        let prefix = b"email\0";
        for candidate in [b"emails\0".as_slice(), b"email/name\0", b"email_2\0"] {
            assert_eq!(unsafe { cstr_dotted_prefix_compare(candidate.as_ptr(), prefix.as_ptr()) }, 1);
        }
    }

    #[test]
    fn forwards_strncmp_difference_for_nonmatching_prefixes() {
        let prefix = b"issuer\0";
        for candidate in [b"hssuer\0".as_slice(), b"is\0", b"issx\0", b"\xffssuer\0"] {
            assert_eq!(
                unsafe { cstr_dotted_prefix_compare(candidate.as_ptr(), prefix.as_ptr()) },
                reference(candidate, prefix),
            );
        }
    }

    #[test]
    fn empty_prefix_still_requires_a_boundary() {
        let prefix = b"\0";
        assert_eq!(unsafe { cstr_dotted_prefix_compare(b"\0".as_ptr(), prefix.as_ptr()) }, 0);
        assert_eq!(unsafe { cstr_dotted_prefix_compare(b".child\0".as_ptr(), prefix.as_ptr()) }, 0);
        assert_eq!(unsafe { cstr_dotted_prefix_compare(b"child\0".as_ptr(), prefix.as_ptr()) }, 1);
    }

    #[test]
    fn prefix_terminator_ends_the_compare() {
        let prefix = b"issuer\0ignored\0";
        let candidate = b"issuer.subject\0";
        assert_eq!(unsafe { cstr_dotted_prefix_compare(candidate.as_ptr(), prefix.as_ptr()) }, 0);
    }
}
