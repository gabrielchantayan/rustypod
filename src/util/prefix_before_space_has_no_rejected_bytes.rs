//! `prefix_before_space_has_no_rejected_bytes` — original: `FUN_08396dc4` @
//! `0x08396dc4` (**88 bytes**, `0x08396dc4..0x08396e1b`; the next real
//! function begins at `0x08396e1c` with `push {r1, r2, r3, r4, r5, r6, r7,
//! lr}`). Raw A32 decoding finds three plain unconditional inbound `bl` call
//! sites (`0x082e313c`, `0x082e35c8`, and `0x082e63b4`) and no predicated
//! forms. Its body makes one plain `bl` to the byte-list predicate at
//! `0x082b14e8`.
//!
//! Scans at most `len` bytes. A rejected byte before the first space rejects;
//! a space at index zero rejects, while a later space accepts immediately and
//! leaves the suffix unchecked. Exhausting a nonnegative length accepts.
//!
//! ## Deliberate deviations
//!
//! Calls the ported Rust byte-list predicate rather than branching to retailOS
//! at `0x082b14e8`.

use super::short_filename_byte_is_rejected::short_filename_byte_is_rejected;

/// Returns one when the bounded prefix passes the retail byte-list predicate.
///
/// # Safety
///
/// `bytes` must be readable for `len` bytes when `len` is positive.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn prefix_before_space_has_no_rejected_bytes(bytes: *const u8, len: i32) -> u32 {
    let mut index = 0i32;
    while index < len {
        let byte = u32::from(bytes.add(index as usize).read_volatile());
        if byte == u32::from(b' ') {
            return u32::from(index != 0);
        }
        if short_filename_byte_is_rejected(byte) != 0 {
            return 0;
        }
        index = index.wrapping_add(1);
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn accepts_empty_and_nonpositive_bounds_without_reading() {
        let bytes = [0xff];
        unsafe {
            assert_eq!(prefix_before_space_has_no_rejected_bytes(bytes.as_ptr(), 0), 1);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(bytes.as_ptr(), -1), 1);
        }
    }

    #[test]
    fn rejects_a_leading_space_but_accepts_later_space_without_scanning_suffix() {
        unsafe {
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b" x".as_ptr(), 2), 0);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"OK x".as_ptr(), 4), 1);
        }
    }

    #[test]
    fn checks_each_byte_before_space_and_honors_the_bound() {
        unsafe {
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"Ax".as_ptr(), 2), 0);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"Ax".as_ptr(), 1), 1);
            assert_eq!(prefix_before_space_has_no_rejected_bytes(b"ABC".as_ptr(), 3), 1);
        }
    }
}
