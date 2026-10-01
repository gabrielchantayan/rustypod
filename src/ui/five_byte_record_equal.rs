//! Five-byte record equality — `FUN_0829ff94` @ `0x0829ff94`.
//! True extent: 76 bytes, ending at `bx lr` at `0x0829ffdc`; the next
//! function starts at `0x0829ffe0` (argument-shuffling tail branch).
//! Raw ARM-word scan: two unconditional incoming BLs at `0x0829fc7c` and
//! `0x0829fe24`, zero predicated incoming BLs, zero outgoing BLs.
//!
//! Compares bytes 0..4 in order, stopping at the first mismatch. Returns
//! integer 1 for equality, otherwise 0. Both callers pass embedded records
//! at object offset 0x7c; their domain-specific identity is not established.
//! Deliberate deviations: none. Volatile byte reads preserve the original
//! conditional access boundary rather than allowing widened/speculative reads.

/// # Safety
/// Both pointers must be readable through the first mismatching byte, or
/// through all five bytes when equal. No alignment requirement or NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn five_byte_record_equal(left: *const u8, right: *const u8) -> u32 {
    for index in 0..5 {
        let left_byte = core::ptr::read_volatile(left.add(index));
        let right_byte = core::ptr::read_volatile(right.add(index));
        if left_byte != right_byte {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::five_byte_record_equal;

    extern crate std;
    #[test]
    fn compares_every_byte_without_nul_termination_at_all_alignments() {
        for left_offset in 0..4 {
            for right_offset in 0..4 {
                for record in [[0; 5], [0xff; 5], [0, 0x80, 0xff, 1, 0]] {
                    let mut left = [0xa5; 9];
                    let mut right = [0x5a; 9];
                    left[left_offset..left_offset + 5].copy_from_slice(&record);
                    right[right_offset..right_offset + 5].copy_from_slice(&record);
                    let lhs = unsafe { left.as_ptr().add(left_offset) };
                    let rhs = unsafe { right.as_ptr().add(right_offset) };
                    assert_eq!(unsafe { five_byte_record_equal(lhs, rhs) }, 1);
                    assert_eq!(unsafe { five_byte_record_equal(lhs, lhs) }, 1);
                    for index in 0..5 {
                        for difference in [1, 0x80, 0xff] {
                            right[right_offset + index] ^= difference;
                            assert_eq!(unsafe { five_byte_record_equal(lhs, rhs) }, 0);
                            assert_eq!(unsafe { five_byte_record_equal(rhs, lhs) }, 0);
                            right[right_offset + index] ^= difference;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn accepts_overlap_and_ignores_bytes_after_the_record() {
        let equal = [0x80; 6];
        assert_eq!(unsafe {
            five_byte_record_equal(equal.as_ptr(), equal.as_ptr().add(1))
        }, 1);
        let different = [0x80, 0x80, 0x80, 0x80, 0x80, 0xff];
        assert_eq!(unsafe {
            five_byte_record_equal(different.as_ptr(), different.as_ptr().add(1))
        }, 0);
        assert_eq!(unsafe { five_byte_record_equal(equal.as_ptr(), different.as_ptr()) }, 1);
    }

    #[test]
    fn stops_at_the_first_mismatch_with_only_a_readable_prefix() {
        for length in 1..=5 {
            let left = std::vec![0x80; length];
            let mut right = left.clone();
            right[length - 1] = 0xff;
            assert_eq!(unsafe { five_byte_record_equal(left.as_ptr(), right.as_ptr()) }, 0);
        }
    }
}
