//! `u16_cstr_buffer_assign` — original: `FUN_080aa474` @ **0x080aa474**.
//!
//! True extent is 36 bytes, `0x080aa474..0x080aa498`; the next distinct
//! function starts at `0x080aa498`. Raw ARM-word decoding finds three direct
//! inbound calls, all unconditional `bl` (at 0x081a30c8, 0x081a3d10, and
//! 0x081a4354), with no predicated calls. Its sole outbound call is `strncpy`
//! at 0x080310d4.
//!
//! # Algorithm
//!
//! Stores the supplied little-endian `u16` tag at offsets 0..1, copies up to
//! 255 bytes from the supplied C string into offsets 2..256 with `strncpy`
//! semantics, then forces a NUL at offset 257. It returns zero in r0. The
//! `strncpy` port is marked `#[inline(never)]` to retain the verified call
//! boundary; otherwise there are no deliberate deviations.

use crate::libc::strncpy::strncpy;

/// Stores a tag and a bounded C string in the retailOS 258-byte opaque buffer.
///
/// # Safety
///
/// `buffer` must be non-NULL, two-byte aligned, and writable for 258 bytes.
/// `source` must be a valid C string readable for the 255-byte `strncpy` window.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u16_cstr_buffer_assign(tag: u16, source: *const u8, buffer: *mut u8) -> i32 {
    (buffer as *mut u16).write(tag);
    strncpy(buffer.add(2), source, 0xff);
    buffer.add(0x101).write(0);
    0
}

#[cfg(test)]
mod tests {
    use super::u16_cstr_buffer_assign;

    #[test]
    fn stores_little_endian_tag_pads_short_source_and_forces_final_nul() {
        let mut buffer = [0xa5; 258];
        let source = b"pod\0";

        let result = unsafe { u16_cstr_buffer_assign(0x1234, source.as_ptr(), buffer.as_mut_ptr()) };

        assert_eq!(result, 0);
        assert_eq!(&buffer[..2], &[0x34, 0x12]);
        assert_eq!(&buffer[2..6], b"pod\0");
        assert!(buffer[6..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn truncates_a_255_byte_source_but_terminates_the_extra_byte() {
        let source = [0x5c; 255];
        let mut buffer = [0xa5; 258];

        unsafe { u16_cstr_buffer_assign(0xbeef, source.as_ptr(), buffer.as_mut_ptr()) };

        assert_eq!(&buffer[..2], &[0xef, 0xbe]);
        assert_eq!(&buffer[2..0x101], &source);
        assert_eq!(buffer[0x101], 0);
    }
}
