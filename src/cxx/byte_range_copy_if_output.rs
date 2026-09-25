//! byte_range_copy_if_output — `thunk_FUN_083e8abc` @ 0x083e8aa4 (4-byte
//! thunk; branch target body is 0x083e8aa8..0x083e8acb, 36 bytes).
//!
//! Raw `osos.dec` establishes that the assigned entry is `b 0x083e8abc`, into
//! a byte-copy loop whose first instruction is at 0x083e8aa8. The next real
//! function begins with `push {r4,lr}` at 0x083e8acc. The loop copies
//! `[first, last)` one byte at a time when the current output cursor is
//! non-NULL, advances both cursors after every iteration, and returns the
//! advanced output cursor. Whole-image A32 decoding finds two inbound plain
//! `bl` sites and zero predicated inbound `bl` sites; the body has no calls.
//!
//! # Deliberate deviations
//!
//! The stock branch thunk and its shared-entry loop become one Rust function:
//! a hook at 0x083e8aa4 reaches the same loop. `wrapping_add` preserves ARM's
//! modulo-32-bit cursor progression, including progression from a NULL output.
//!
//! # Safety
//!
//! `first..last` must be a valid forward byte range. Whenever the current
//! output cursor is non-NULL, it must be writable for one byte. As in retailOS,
//! a NULL initial output only suppresses the first store; a multi-byte range
//! advances it to address one before its second iteration.

/// Copies a byte range while conditionally storing through the current cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.byte_range_copy_if_output")]
#[inline(never)]
pub unsafe extern "C" fn byte_range_copy_if_output(
    mut first: *const u8,
    last: *const u8,
    mut output: *mut u8,
) -> *mut u8 {
    while first != last {
        if !output.is_null() {
            output.write(first.read());
        }
        first = first.wrapping_add(1);
        output = output.wrapping_add(1);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::byte_range_copy_if_output;

    #[test]
    fn copies_range_and_returns_advanced_output() {
        let source = [0x12, 0x34, 0x56];
        let mut destination = [0; 5];
        let returned = unsafe {
            byte_range_copy_if_output(source.as_ptr(), source.as_ptr().wrapping_add(3), destination.as_mut_ptr().wrapping_add(1))
        };

        assert_eq!(destination, [0, 0x12, 0x34, 0x56, 0]);
        assert_eq!(returned, destination.as_mut_ptr().wrapping_add(4));
    }

    #[test]
    fn empty_range_preserves_output_cursor() {
        let source = [0x12];
        let mut destination = [0; 1];
        let output = destination.as_mut_ptr();
        let returned = unsafe { byte_range_copy_if_output(source.as_ptr(), source.as_ptr(), output) };

        assert_eq!(returned, output);
        assert_eq!(destination, [0]);
    }

    #[test]
    fn null_output_skips_the_single_source_read_and_advances() {
        let returned = unsafe {
            byte_range_copy_if_output(core::ptr::null(), 1usize as *const u8, core::ptr::null_mut())
        };

        assert_eq!(returned, 1usize as *mut u8);
    }
}
