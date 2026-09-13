//! strlcpy — original: `FUN_080422c0` @ 0x080422c0 (76 bytes, 7 inbound
//! `bl` call sites: six unconditional and one `blgt`, binary-scanned).
//!
//! Copies at most `capacity - 1` bytes from `src` to `dst`, NUL-terminating
//! when capacity is nonzero. It then calls the ported unguarded strlen
//! @ 0x08392478 on the remaining source and adds the copied byte count, so
//! the return is always the complete source length. `capacity == 0` neither
//! reads nor writes `dst`. No NULL guards, overlap handling, or other
//! deviations: these match the retail byte loop exactly.

use super::strlen::strlen;

/// Bounded C-string copy returning the complete source length.
///
/// Load address: 0x080422c0. The destination has room for `capacity` bytes
/// when `capacity != 0`; `src` is NUL-terminated.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlcpy(mut dst: *mut u8, mut src: *const u8, mut capacity: usize) -> usize {
    let mut copied = 0usize;

    while capacity > 1 && *src != 0 {
        *dst = *src;
        dst = dst.add(1);
        src = src.add(1);
        copied = copied.wrapping_add(1);
        capacity -= 1;
    }

    if capacity != 0 {
        *dst = 0;
    }

    copied.wrapping_add(strlen(src))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::null_mut;
    use std::vec;

    fn source_byte(index: usize) -> u8 {
        ((index * 37 + 17) % 255 + 1) as u8
    }

    fn reference_strlcpy(dst: &mut [u8], src: &[u8], capacity: usize) -> usize {
        let source_len = src.iter().position(|&byte| byte == 0).expect("NUL-terminated source");
        if capacity != 0 {
            let copied = source_len.min(capacity - 1);
            dst[..copied].copy_from_slice(&src[..copied]);
            dst[copied] = 0;
        }
        source_len
    }

    /// Every source length and capacity through 64 at all byte alignments.
    /// This covers empty input, single-byte capacity, exact fit, truncation,
    /// high-bit source bytes, and preservation outside the destination range.
    #[test]
    fn matches_reference_across_lengths_capacities_and_alignments() {
        const MAX: usize = 64;
        const PAD: usize = 4;

        for src_align in 0..4usize {
            for dst_align in 0..4usize {
                for source_len in 0..=MAX {
                    let mut source = vec![0xa5u8; src_align + source_len + 1 + PAD];
                    for index in 0..source_len {
                        source[src_align + index] = source_byte(index);
                    }
                    source[src_align + source_len] = 0;

                    for capacity in 0..=MAX {
                        let mut actual = vec![0x5au8; dst_align + MAX + PAD];
                        let mut expected = actual.clone();
                        let expected_len = reference_strlcpy(
                            &mut expected[dst_align..dst_align + capacity],
                            &source[src_align..],
                            capacity,
                        );
                        let actual_len = unsafe {
                            strlcpy(
                                actual.as_mut_ptr().add(dst_align),
                                source.as_ptr().add(src_align),
                                capacity,
                            )
                        };

                        assert_eq!(actual_len, expected_len, "src={source_len} cap={capacity}");
                        assert_eq!(actual, expected, "src={source_len} cap={capacity}");
                    }
                }
            }
        }
    }

    /// The original takes the zero-capacity path directly to strlen and never
    /// dereferences the destination pointer.
    #[test]
    fn zero_capacity_accepts_a_null_destination() {
        assert_eq!(unsafe { strlcpy(null_mut(), b"retail\0".as_ptr(), 0) }, 6);
    }
}
