//! configured_path_suffix_digit — `FUN_0809a7e4` @ 0x0809a7e4.
//!
//! True body: 88 bytes, 0x0809a7e4..0x0809a83c; the following four-byte
//! literal ends at the separate branch veneer at 0x0809a840 (next prologue
//! at 0x0809a844). Two incoming plain BLs, zero predicated BLs; one outgoing
//! plain BL to strncmp at 0x0803105c, zero outgoing predicated BLs.
//! Compare path against the live record's +8 prefix for (+0x14 length - 2)
//! bytes. Return one for equality, zero otherwise. On equality with a non-NULL
//! output, read path[length - 2], subtract ASCII '0', and store digits 0..6,
//! mapping every other byte to zero. The length is reloaded after comparison.
//! Deliberate deviations: native-pointer host configuration seam and a volatile
//! indirect call to the existing comparator to prevent LLVM inlining. No slash
//! stripping, full-string validation, or length checks are added.

use core::ptr;

#[cfg(target_os = "none")]
const CONFIGURED_PATH_RECORD: *const u32 = 0x089c_a3a4 as *const u32;

#[cfg(not(target_os = "none"))]
static mut HOST_PREFIX: *const u8 = ptr::null();
#[cfg(not(target_os = "none"))]
static mut HOST_LENGTH: u32 = 0;

#[inline(always)]
unsafe fn configured_length() -> u32 {
    #[cfg(target_os = "none")]
    { ptr::read_volatile(CONFIGURED_PATH_RECORD.add(5)) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_LENGTH)) }
}

#[inline(always)]
unsafe fn configured_prefix() -> *const u8 {
    #[cfg(target_os = "none")]
    { ptr::read_volatile(CONFIGURED_PATH_RECORD.add(2)) as *const u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_PREFIX)) }
}

/// Match the configured prefix, optionally returning its following digit.
///
/// # Safety
/// The live configuration must supply a readable prefix and a valid length.
/// `path` must be readable for strncmp and, on a match with non-NULL `digit`,
/// at the reloaded length minus two. Non-NULL `digit` must be aligned/writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn configured_path_suffix_digit(path: *const u8, digit: *mut u32) -> i32 {
    let length = configured_length().wrapping_sub(2);
    let prefix = configured_prefix();
    let compare = ptr::read_volatile(
        &(crate::libc::strncmp::strncmp as unsafe extern "C" fn(*const u8, *const u8, usize) -> i32),
    );
    let comparison = compare(path, prefix, length as usize);
    let result = if (comparison as u32) > 1 { 0 } else { 1i32.wrapping_sub(comparison) };
    if result != 0 && !digit.is_null() {
        let offset = configured_length().wrapping_sub(2);
        let value = (ptr::read_volatile(path.wrapping_add(offset as usize)) as u32).wrapping_sub(b'0' as u32);
        ptr::write(digit, if value < 7 { value } else { 0 });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn configure(prefix: &[u8], length: u32) {
        HOST_PREFIX = prefix.as_ptr();
        HOST_LENGTH = length;
    }

    // Independent byte-level reference: stop at the first mismatch or NUL.
    fn reference(path: &[u8], prefix: &[u8], length: usize) -> (i32, Option<u32>) {
        for index in 0..length - 2 {
            if path[index] != prefix[index] { return (0, None); }
            if path[index] == 0 { break; }
        }
        let byte = path[length - 2];
        (1, Some(if (b'0'..=b'6').contains(&byte) { (byte - b'0') as u32 } else { 0 }))
    }

    #[test]
    fn all_suffix_bytes_and_comparison_boundaries_match_reference() {
        let _guard = LOCK.lock();
        let prefix = *b"music/\0\0\0\0\0\0";
        unsafe {
            configure(&prefix, 8);
            for byte in 0..=255u8 {
                for mismatch in 0..=6 {
                    let mut path = *b"music/0tail\0\0";
                    path[6] = byte;
                    if mismatch < 6 { path[mismatch] ^= 0x40; }
                    let expected = reference(&path, &prefix, 8);
                    let mut output = 0xdead_beef;
                    assert_eq!(configured_path_suffix_digit(path.as_ptr(), &mut output), expected.0);
                    assert_eq!(output, expected.1.unwrap_or(0xdead_beef));
                    assert_eq!(configured_path_suffix_digit(path.as_ptr(), ptr::null_mut()), expected.0);
                }
            }
        }
    }

    #[test]
    fn empty_prefix_and_embedded_nul_keep_original_read_offset() {
        let _guard = LOCK.lock();
        unsafe {
            configure(b"\0\0\0\0\0\0\0\0", 2);
            let mut output = 99;
            assert_eq!(configured_path_suffix_digit(b"6\0\0\0".as_ptr(), &mut output), 1);
            assert_eq!(output, 6);
            assert_eq!(configured_path_suffix_digit(ptr::null(), ptr::null_mut()), 1);

            let prefix = b"a\0xxxx\0\0\0\0\0\0";
            let path = b"a\0yyyy4tail\0\0";
            configure(prefix, 8);
            let expected = reference(path, prefix, 8);
            assert_eq!(configured_path_suffix_digit(path.as_ptr(), &mut output), expected.0);
            assert_eq!(output, expected.1.unwrap());
        }
    }
}
