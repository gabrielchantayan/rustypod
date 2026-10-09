//! Space-padded string copy — retailOS `FUN_080efcb4` @ 0x080efcb4.
//!
//! Raw extent [0x080efcb4, 0x080efcf4): 64 bytes, ending before the next
//! PUSH prologue. Two outgoing plain BLs, zero predicated BLs; two incoming
//! plain BLs, zero predicated BLs (0x0818cc6c and 0x0818d16c).
//! Fill the field with ASCII spaces, measure the complete NUL-terminated
//! source, then copy the signed minimum of its length and the field width.
//! No terminator is written. The final branch to 0x08037db0 resolves through
//! 0x22000020, the IRAM mirror of __rt_memcpy at 0x08000020.
//!
//! Deviations: call the existing Rust memset with its classic argument order
//! rather than ADS (dst, len, value), and ignore the memcpy return register
//! (the firmware callers consume no return). Host lengths are narrowed to
//! 32 bits before the signed comparison, matching the target register width.

/// # Safety
/// `width` must be nonnegative; `dst` must be writable for that many bytes.
/// `src` must remain a readable NUL-terminated string after the fill, with
/// padding for the existing __rt_memcpy word-read path. The copied source
/// and destination ranges must not overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn space_padded_string_copy(dst: *mut u8, src: *const u8, width: i32) {
    crate::libc::memzero::memset(dst, 0x20, width as u32 as usize);
    let length = crate::libc::strlen::strlen(src) as u32 as i32;
    let copied = if length >= width { width } else { length };
    crate::libc::rt_memcpy::__rt_memcpy(dst, src, copied as u32 as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_padding_and_alignment_match_reference() {
        for dst_alignment in 0..4 {
            for src_alignment in 0..4 {
                for width in 0..=64 {
                    for length in 0..=64 {
                        // Word-aligned backing storage plus padding for funnel reads.
                        let mut source = [0u32; 20];
                        let mut destination = [0xa5a5a5a5u32; 20];
                        let source_bytes = unsafe {
                            core::slice::from_raw_parts_mut(source.as_mut_ptr().cast::<u8>(), 80)
                        };
                        for i in 0..length {
                            source_bytes[src_alignment + i] = 0x41 + (i % 26) as u8;
                        }
                        source_bytes[src_alignment + length] = 0;
                        let source_before = source;
                        unsafe {
                            space_padded_string_copy(
                                destination.as_mut_ptr().cast::<u8>().add(dst_alignment),
                                source.as_ptr().cast::<u8>().add(src_alignment),
                                width as i32,
                            );
                        }
                        let actual = unsafe {
                            core::slice::from_raw_parts(destination.as_ptr().cast::<u8>(), 80)
                        };
                        let mut expected = [0xa5; 80];
                        expected[dst_alignment..dst_alignment + width].fill(b' ');
                        for i in 0..core::cmp::min(length, width) {
                            expected[dst_alignment + i] = 0x41 + (i % 26) as u8;
                        }
                        assert_eq!(actual, &expected, "dst={dst_alignment} src={src_alignment} width={width} length={length}");
                        assert_eq!(source, source_before);
                    }
                }
            }
        }
    }

    #[test]
    fn embedded_nul_leaves_spaces_not_a_terminator() {
        let source = [u32::from_le_bytes(*b"A\0BC"), 0];
        let mut destination = [0xa5u8; 8];
        unsafe {
            space_padded_string_copy(destination.as_mut_ptr().add(1), source.as_ptr().cast(), 5);
        }
        assert_eq!(destination, [0xa5, b'A', b' ', b' ', b' ', b' ', 0xa5, 0xa5]);
    }
}
