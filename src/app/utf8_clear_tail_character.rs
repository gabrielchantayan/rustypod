//! `utf8_clear_tail_character` — original: `FUN_08139b90` @ 0x08139b90
//! (88 bytes, 0x08139b90..0x08139be4; the next function begins at
//! 0x08139be8).
//!
//! Clears bytes backward from `bytes[(length - 1) & 0xffff]` through the first
//! ASCII byte or UTF-8 lead byte (`0xc0..=0xf7`). Thus it removes a trailing
//! UTF-8 character, or clears all trailing continuation (`0x80..=0xbf`) and
//! out-of-range (`0xf8..=0xff`) bytes when no lead byte is found. The original
//! calls `heap_panic` when `bytes` is NULL or `length` is zero.
//!
//! A whole-image ARM B/BL-immediate decode finds 11 direct inbound `bl` sites,
//! all unconditional: 0x081aceb8, 0x081ad3b4, 0x081ade14, 0x081ae528,
//! 0x081ae948, 0x081aec28, 0x081aee30, 0x081af088, 0x081e2ac8, 0x081fd914,
//! and 0x081fe174. There are no predicated calls or tail branches. Every
//! caller discards the incidental `r0` index left by the ARM routine.
//!
//! Source: raw words in `work/firmware/osos.dec` decoded at 0x08139b90;
//! Ghidra's `decomp/c/012/08139b90_FUN_08139b90.c` incorrectly skips index
//! zero. Deviation: none.

use crate::heap::veneers::heap_panic;

/// Clears the final UTF-8 character or malformed high-byte tail in `bytes`.
///
/// # Safety
///
/// `bytes` must be non-NULL and readable/writable through the selected
/// low-16-bit index. `length` must be nonzero; either violated precondition
/// enters the retail fatal path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn utf8_clear_tail_character(
    _context: *mut u8,
    bytes: *mut u8,
    length: u32,
) {
    if bytes.is_null() || length == 0 {
        heap_panic();
    }

    let mut index = length.wrapping_sub(1) as u16 as usize;
    loop {
        let byte = bytes.add(index).read();
        bytes.add(index).write(0);

        if byte <= 0x7f || (0xc0..=0xf7).contains(&byte) || index == 0 {
            return;
        }
        index -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_one_complete_trailing_four_byte_character() {
        let mut bytes = [b'A', 0xc2, 0xa2, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80, 0xa5];

        unsafe { utf8_clear_tail_character(core::ptr::null_mut(), bytes.as_mut_ptr(), 10) };

        assert_eq!(&bytes[..6], &[b'A', 0xc2, 0xa2, 0xe2, 0x82, 0xac]);
        assert_eq!(&bytes[6..10], &[0; 4], "the lead and all continuations clear");
        assert_eq!(bytes[10], 0xa5, "the byte outside length is untouched");
    }

    #[test]
    fn clears_malformed_tail_through_its_last_valid_lead() {
        let mut bytes = [b'A', 0xc2, 0xa2, 0x80, 0xbf, 0xa5];

        unsafe { utf8_clear_tail_character(core::ptr::null_mut(), bytes.as_mut_ptr(), 5) };

        assert_eq!(&bytes[..5], &[b'A', 0, 0, 0, 0]);
        assert_eq!(bytes[5], 0xa5, "the routine never writes beyond length");
    }

    #[test]
    fn clears_every_byte_when_tail_has_no_ascii_or_lead_byte() {
        let mut bytes = [b'A', 0xf8, 0x80, 0xbf];

        unsafe { utf8_clear_tail_character(core::ptr::null_mut(), bytes.as_mut_ptr(), 4) };

        assert_eq!(bytes, [0; 4], "index zero is cleared before the ARM return");
    }

    #[test]
    fn uses_only_the_low_sixteen_bits_after_subtraction() {
        let mut bytes = [b'A', 0xa5];

        unsafe { utf8_clear_tail_character(core::ptr::null_mut(), bytes.as_mut_ptr(), 0x1_0001) };

        assert_eq!(bytes, [0, 0xa5]);
    }
}
