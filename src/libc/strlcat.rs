//! strlcat — original: `FUN_0804228c` @ 0x0804228c (52 bytes, one plain
//! `bl`, no predicated `bl`; binary-decoded).
//!
//! Scans `dst` for at most `capacity` bytes, then delegates the unconsumed
//! space to retailOS `strlcpy` @ 0x080422c0. The returned length is the
//! initial bounded destination length plus the complete source length. A
//! destination without a NUL in `capacity` bytes is not modified. Deliberate
//! deviations: none.

use super::strlcpy::strlcpy;

/// Bounded C-string concatenation returning the attempted total length.
///
/// Load address: 0x0804228c. `dst` has room for `capacity` bytes when
/// `capacity != 0`; `src` is NUL-terminated. The initial `capacity` bytes of
/// `dst` are readable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn strlcat(mut dst: *mut u8, src: *const u8, mut capacity: usize) -> usize {
    let mut dst_len = 0usize;

    while capacity != 0 && *dst != 0 {
        dst_len = dst_len.wrapping_add(1);
        capacity -= 1;
        dst = dst.add(1);
    }

    dst_len.wrapping_add(strlcpy(dst, src, capacity))
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

    fn reference_strlcat(dst: &mut [u8], src: &[u8], capacity: usize) -> usize {
        let src_len = src.iter().position(|&byte| byte == 0).expect("NUL-terminated source");
        let dst_len = dst[..capacity].iter().position(|&byte| byte == 0).unwrap_or(capacity);

        if dst_len < capacity {
            let copied = src_len.min(capacity - dst_len - 1);
            dst[dst_len..dst_len + copied].copy_from_slice(&src[..copied]);
            dst[dst_len + copied] = 0;
        }

        dst_len + src_len
    }

    /// Every source length, initial destination length, and capacity through
    /// 64 at all byte alignments, including full non-NUL destination ranges.
    #[test]
    fn matches_reference_across_lengths_capacities_and_alignments() {
        const MAX: usize = 64;
        const PAD: usize = 4;

        for src_align in 0..4usize {
            for dst_align in 0..4usize {
                for src_len in 0..=MAX {
                    let mut src = vec![0xa5u8; src_align + src_len + 1 + PAD];
                    for index in 0..src_len {
                        src[src_align + index] = source_byte(index);
                    }
                    src[src_align + src_len] = 0;

                    for initial_len in 0..=MAX {
                        for capacity in 0..=MAX {
                            let mut actual = vec![0x5au8; dst_align + MAX + 1 + PAD];
                            for index in 0..initial_len {
                                actual[dst_align + index] = source_byte(index + MAX);
                            }
                            actual[dst_align + initial_len] = 0;
                            let mut expected = actual.clone();
                            let expected_len = reference_strlcat(
                                &mut expected[dst_align..dst_align + capacity],
                                &src[src_align..],
                                capacity,
                            );
                            let actual_len = unsafe {
                                strlcat(
                                    actual.as_mut_ptr().add(dst_align),
                                    src.as_ptr().add(src_align),
                                    capacity,
                                )
                            };

                            assert_eq!(actual_len, expected_len, "src={src_len} dst={initial_len} cap={capacity}");
                            assert_eq!(actual, expected, "src={src_len} dst={initial_len} cap={capacity}");
                        }
                    }
                }
            }
        }
    }

    /// With no destination capacity, the firmware follows strlcpy's direct
    /// strlen path and never dereferences the destination pointer.
    #[test]
    fn zero_capacity_accepts_a_null_destination() {
        assert_eq!(unsafe { strlcat(null_mut(), b"retail\0".as_ptr(), 0) }, 6);
    }
}
