//! `fat_short_name_render` — original: `FUN_082e2fe0` at load address
//! `0x082e2fe0`.
//!
//! Raw `osos.dec` decoding establishes the true 160-byte extent
//! `0x082e2fe0..0x082e307f`; `push {r4, r5, r6, lr}` at `0x082e3080` starts
//! the next independently linked function. Complete-image ARM decoding finds
//! two inbound plain `bl` sites (`0x082e1234`, `0x082e49b8`) and no predicated
//! inbound `bl` sites. The function itself is a leaf.
//!
//! Copies at most eight non-space, non-NUL stem bytes and, only if a stem was
//! copied, appends a dot plus at most three non-space, non-NUL extension bytes.
//! It removes a trailing dot and NUL-terminates the result. No deliberate
//! deviations.

/// Renders the two fixed-width fields of a FAT 8.3 name into `output`.
///
/// Original: `FUN_082e2fe0` at `0x082e2fe0`, 160 bytes; two binary-verified
/// inbound plain-`bl` call sites and zero predicated inbound `bl` forms.
///
/// # Safety
/// `output` must hold at least 13 bytes. `stem` and `extension` must each
/// reference readable 8-byte and 3-byte fields respectively.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fat_short_name_render")]
#[inline(never)]
pub unsafe extern "C" fn fat_short_name_render(
    output: *mut u8,
    stem: *const u8,
    extension: *const u8,
) -> *mut u8 {
    let mut cursor = output;
    let mut index = 0usize;
    while index != 8 {
        let byte = unsafe { stem.add(index).read() };
        if byte == 0 || byte == b' ' { break; }
        unsafe { cursor.write(byte) };
        cursor = unsafe { cursor.add(1) };
        index += 1;
    }
    if cursor != output {
        unsafe { cursor.write(b'.') };
        cursor = unsafe { cursor.add(1) };
        index = 0;
        while index != 3 {
            let byte = unsafe { extension.add(index).read() };
            if byte == 0 || byte == b' ' { break; }
            unsafe { cursor.write(byte) };
            cursor = unsafe { cursor.add(1) };
            index += 1;
        }
    }
    if cursor != output && unsafe { cursor.sub(1).read() } == b'.' {
        cursor = unsafe { cursor.sub(1) };
    }
    unsafe { cursor.write(0) };
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_full_width_stem_and_extension() {
        let stem = *b"ABCDEFGH";
        let extension = *b"TXT";
        let mut output = [0xa5; 13];
        unsafe { fat_short_name_render(output.as_mut_ptr(), stem.as_ptr(), extension.as_ptr()) };
        assert_eq!(&output, b"ABCDEFGH.TXT\0");
    }

    #[test]
    fn stops_at_space_and_removes_dot_for_empty_extension() {
        let stem = *b"FILE    ";
        let extension = *b"   ";
        let mut output = [0xa5; 13];
        unsafe { fat_short_name_render(output.as_mut_ptr(), stem.as_ptr(), extension.as_ptr()) };
        assert_eq!(&output[..5], b"FILE\0");
        assert_eq!(output[5], 0xa5);
    }

    #[test]
    fn ignores_extension_without_a_stem() {
        let stem = [0, b'X', b'X', b'X', b'X', b'X', b'X', b'X'];
        let extension = *b"TXT";
        let mut output = [0xa5; 13];
        unsafe { fat_short_name_render(output.as_mut_ptr(), stem.as_ptr(), extension.as_ptr()) };
        assert_eq!(output[0], 0);
        assert_eq!(output[1], 0xa5);
    }

    #[test]
    fn stops_at_nul_in_each_field() {
        let stem = [b'A', b'B', 0, b'X', b'X', b'X', b'X', b'X'];
        let extension = [b'Z', 0, b'X'];
        let mut output = [0xa5; 13];
        unsafe { fat_short_name_render(output.as_mut_ptr(), stem.as_ptr(), extension.as_ptr()) };
        assert_eq!(&output[..5], b"AB.Z\0");
        assert_eq!(output[5], 0xa5);
    }
}
