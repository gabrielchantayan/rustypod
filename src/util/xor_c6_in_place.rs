//! In-place fixed-key byte obfuscation helper.

/// `xor_c6_in_place` — original: `FUN_0833dd48` @ 0x0833dd48 (48 bytes;
/// 33 verified direct `bl` call sites, all unconditional).
///
/// Starting at `bytes`, XORs each byte in the signed half-open range `0..len`
/// with `0xc6`, loading and storing each element before advancing to the next.
/// Non-positive lengths execute no loads or stores. The retail code has no NULL
/// guard: a non-null, writable `len`-byte range is required when `len > 0`.
///
/// Deliberate deviations: none.
///
/// # Safety
/// When `len > 0`, `bytes` must be valid and writable for `len` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn xor_c6_in_place(bytes: *mut u8, len: i32) {
    for offset in 0..len {
        let byte = bytes.add(offset as usize);
        byte.write(byte.read() ^ 0xc6);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::xor_c6_in_place;

    fn reference_xor_c6_in_place(bytes: &mut [u8], len: i32) {
        for offset in 0..len {
            bytes[offset as usize] ^= 0xc6;
        }
    }

    #[test]
    fn xors_only_the_requested_range_with_c6() {
        let initial = [0x00, 0x39, 0xc6, 0xff, 0x80, 0x55, 0xaa, 0x7e];
        let mut actual = [0xa5; 12];
        let mut expected = actual;
        actual[2..10].copy_from_slice(&initial);
        expected[2..10].copy_from_slice(&initial);

        reference_xor_c6_in_place(&mut expected[2..10], 5);
        unsafe { xor_c6_in_place(actual[2..10].as_mut_ptr(), 5) };

        assert_eq!(actual, expected);
        assert_eq!(&actual[..2], &[0xa5; 2], "leading guard changed");
        assert_eq!(&actual[7..], &[0x55, 0xaa, 0x7e, 0xa5, 0xa5], "bytes after len changed");
    }

    #[test]
    fn non_positive_lengths_leave_the_buffer_untouched() {
        for len in [-7, -1, 0] {
            let mut actual = [0x11, 0x22, 0x33, 0x44];
            unsafe { xor_c6_in_place(actual.as_mut_ptr(), len) };
            assert_eq!(actual, [0x11, 0x22, 0x33, 0x44], "len {len}");
        }
    }
}
