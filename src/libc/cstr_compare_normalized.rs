//! Normalized C-string comparison — `thunk_FUN_08057924` @ 0x080578fc.
//!
//! Original: a 4-byte entry veneer (`b 0x08057924`); raw ARM decoding finds
//! four direct `bl` callers, all unconditional and no predicated `bl` forms.
//! The branch enters the shared byte-compare loop at 0x08057924. It walks both
//! NUL-terminated byte strings and returns the normalized unsigned ordering:
//! `-1`, `0`, or `1`.
//!
//! Deliberate deviation: Rust incorporates the unnamed branch target's compare
//! loop instead of emitting a tail branch, preserving the veneer entry's
//! externally observable result while avoiding an invented callee seam.

/// Compares two NUL-terminated byte strings and returns `-1`, `0`, or `1`.
///
/// Original entry veneer: `thunk_FUN_08057924` @ 0x080578fc (4 bytes; four
/// unpredicated direct `bl` call sites, verified from raw ARM words).
///
/// # Safety
///
/// `left` and `right` must each point to readable NUL-terminated byte strings.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cstr_compare_normalized(left: *const u8, right: *const u8) -> i32 {
    let mut left = left;
    let mut right = right;
    loop {
        let left_byte = unsafe { core::ptr::read_volatile(left) };
        let right_byte = unsafe { core::ptr::read_volatile(right) };
        if left_byte != right_byte {
            return if left_byte < right_byte { -1 } else { 1 };
        }
        if left_byte == 0 {
            return 0;
        }
        left = unsafe { left.add(1) };
        right = unsafe { right.add(1) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::cstr_compare_normalized;

    #[test]
    fn equal_and_empty_strings_compare_equal() {
        unsafe {
            assert_eq!(cstr_compare_normalized(b"\0".as_ptr(), b"\0".as_ptr()), 0);
            assert_eq!(cstr_compare_normalized(b"same\0".as_ptr(), b"same\0".as_ptr()), 0);
        }
    }

    #[test]
    fn nul_terminator_orders_a_strict_prefix() {
        unsafe {
            assert_eq!(cstr_compare_normalized(b"ab\0".as_ptr(), b"abc\0".as_ptr()), -1);
            assert_eq!(cstr_compare_normalized(b"abc\0".as_ptr(), b"ab\0".as_ptr()), 1);
        }
    }

    #[test]
    fn compares_the_first_mismatch_as_unsigned_bytes_at_unaligned_addresses() {
        let left = [0, b'a', 0xff, 0];
        let right = [0, b'a', b'z', 0];
        unsafe {
            assert_eq!(cstr_compare_normalized(left.as_ptr().add(1), right.as_ptr().add(1)), 1);
            assert_eq!(cstr_compare_normalized(right.as_ptr().add(1), left.as_ptr().add(1)), -1);
        }
    }
}
