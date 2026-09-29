//! `fat_short_name_split` — original: `FUN_082e0e8c` @ `0x082e0e8c` (204
//! bytes, `0x082e0e8c..0x082e0f57`; **2 direct plain `bl` calls and 0
//! predicated forms**, verified by decoding the raw ARM words in `osos.dec`).
//!
//! Initializes an 8-byte base and 3-byte extension with ASCII spaces, each
//! followed by a NUL terminator. A leading `.` accepts only `.` or `..`;
//! otherwise it splits the input at its first dot and copies at most eight base
//! and three extension bytes. Deliberate deviation: the two direct calls to
//! `zero_bytes` at `0x082e2ef0` are represented by `write_bytes`, preserving
//! their exact fill ranges without creating an unverified Rust seam.

use core::ptr;

/// Splits `input` into fixed-width FAT 8.3 base and extension buffers.
///
/// All pointers must be valid: `base` requires nine writable bytes,
/// `extension` four, and `input` a readable NUL-terminated byte string.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fat_short_name_split(
    mut base: *mut u8,
    mut extension: *mut u8,
    mut input: *const u8,
) -> u32 {
    ptr::write_bytes(base, b' ', 8);
    base.add(8).write(0);
    ptr::write_bytes(extension, b' ', 3);
    extension.add(3).write(0);

    if input.read() == b'.' {
        base.write(b'.');
        match input.add(1).read() {
            b'.' => base.add(1).write(b'.'),
            0 => {}
            _ => return 0,
        }
        return 1;
    }

    let mut copied = 0;
    while input.read() != 0 {
        let byte = input.read();
        if byte == b'.' {
            input = input.add(1);
            break;
        }
        if copied < 8 {
            base.write(byte);
            base = base.add(1);
        }
        copied += 1;
        input = input.add(1);
    }

    copied = 0;
    while input.read() != 0 {
        if copied < 3 {
            extension.write(input.read());
            extension = extension.add(1);
        }
        copied += 1;
        input = input.add(1);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::fat_short_name_split;

    unsafe fn split(input: &[u8]) -> (u32, [u8; 9], [u8; 4]) {
        let mut base = [0xff; 9];
        let mut extension = [0xff; 4];
        let result = fat_short_name_split(base.as_mut_ptr(), extension.as_mut_ptr(), input.as_ptr());
        (result, base, extension)
    }

    #[test]
    fn splits_and_truncates_each_83_component() {
        unsafe {
            let (result, base, extension) = split(b"123456789.abcdef\0");
            assert_eq!(result, 1);
            assert_eq!(base, *b"12345678\0");
            assert_eq!(extension, *b"abc\0");
        }
    }

    #[test]
    fn pads_a_name_without_extension() {
        unsafe {
            let (result, base, extension) = split(b"file\0");
            assert_eq!(result, 1);
            assert_eq!(base, *b"file    \0");
            assert_eq!(extension, *b"   \0");
        }
    }

    #[test]
    fn accepts_only_current_and_parent_leading_dot_names() {
        unsafe {
            let (result, base, extension) = split(b"..\0");
            assert_eq!(result, 1);
            assert_eq!(base, *b"..      \0");
            assert_eq!(extension, *b"   \0");

            let (result, base, extension) = split(b".hidden\0");
            assert_eq!(result, 0);
            assert_eq!(base, *b".       \0");
            assert_eq!(extension, *b"   \0");
        }
    }

    #[test]
    fn preserves_later_dots_in_the_extension() {
        unsafe {
            let (result, base, extension) = split(b"a.b.c\0");
            assert_eq!(result, 1);
            assert_eq!(base, *b"a       \0");
            assert_eq!(extension, *b"b.c\0");
        }
    }
}
