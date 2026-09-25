//! counted_u16_copy — original: `FUN_08045fb0` @ 0x08045fb0 (60 bytes).
//!
//! Raw ARM extent: 0x08045fb0..0x08045fec; the next function begins with
//! `stmdb sp!,{r4,r5,r6,r7,r8,lr}` at 0x08045fec. It contains no direct `bl`
//! instructions. Its three inbound `bl` call sites are 0x080433f0 (plain)
//! and 0x0805d8b0 / 0x0805d908 (both `blne`).
//! The source is a counted string. A nonzero `wide` selects a u16 count and
//! copies `(count + 1) * 2` bytes; zero selects a u8 count and copies
//! `count + 1` bytes. Spans of one byte or less are represented by a zero u16
//! at `destination`; longer spans tail-branch to `bcopy`.
//!
//! Deliberate deviation: the stock tail branch enters `bcopy` at 0x08042cbc;
//! this port calls its existing Rust implementation directly.

use crate::libc::bcopy::bcopy;

/// Copy a byte- or UTF-16-counted string, including its count field.
///
/// # Safety
///
/// `destination` must be writable for the selected counted span whenever it
/// is non-NULL. A non-NULL `source` must point to that span. These match the
/// stock faulting behavior for invalid non-NULL pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_u16_copy(
    source: *const u8,
    destination: *mut u8,
    wide: i32,
) {
    if source.is_null() {
        destination.cast::<u16>().write(0);
        return;
    }

    let count = if wide == 0 {
        source.read() as usize
    } else {
        source.cast::<u16>().read() as usize
    };
    let bytes = if wide == 0 { count + 1 } else { (count + 1) * 2 };

    if bytes > 1 {
        bcopy(source, destination, bytes);
    } else {
        destination.cast::<u16>().write(0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn copies_wide_count_and_code_units() {
        let source = [2_u16, 0x0041, 0xd800];
        let mut destination = [0_u16; 3];

        unsafe { counted_u16_copy(source.as_ptr().cast(), destination.as_mut_ptr().cast(), 1) };

        assert_eq!(destination, source);
    }

    #[test]
    fn copies_byte_counted_payload_when_not_wide() {
        let source = [3_u8, b'a', b'b', b'c'];
        let mut destination = [0xee_u8; 4];

        unsafe { counted_u16_copy(source.as_ptr(), destination.as_mut_ptr(), 0) };

        assert_eq!(destination, source);
    }

    #[test]
    fn empty_byte_counted_source_writes_a_zero_halfword() {
        let source = [0_u8, 0xaa];
        let mut destination = [0xee_u8; 2];

        unsafe { counted_u16_copy(source.as_ptr(), destination.as_mut_ptr(), 0) };

        assert_eq!(destination, [0, 0]);
    }

    #[test]
    fn null_source_clears_destination_before_any_copy() {
        let mut destination = [0xbeef_u16; 2];

        unsafe { counted_u16_copy(core::ptr::null(), destination.as_mut_ptr().cast(), 1) };

        assert_eq!(destination, [0, 0xbeef]);
    }

    #[test]
    fn wide_copy_preserves_overlap_semantics() {
        let mut buffer = [2_u16, 0x0041, 0x0042, 0xbeef, 0xbeef, 0xbeef];

        unsafe {
            counted_u16_copy(
                buffer.as_ptr().cast(),
                buffer.as_mut_ptr().add(2).cast(),
                1,
            )
        };

        assert_eq!(buffer, [2, 0x0041, 2, 0x0041, 0x0042, 0xbeef]);
    }
}
