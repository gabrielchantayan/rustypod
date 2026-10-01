//! Optional three-byte field equality — `FUN_0829f8fc` @ `0x0829f8fc`.
//! True size: 68 bytes through `bx lr` at 0x0829f93c; the next real
//! function starts at 0x0829f940 with `stmdb sp!,{r4,lr}`.
//! Raw aligned ARM words verify two plain incoming BLs (0x0829fca4,
//! 0x0829fe4c), zero predicated incoming BLs, and zero outgoing BLs.
//!
//! Compare the unsigned presence bytes exactly. Unequal bytes return 0;
//! equal zero bytes return 1 without reading payload. Otherwise compare
//! signed bytes at +1, then at +2 only when +1 matches. Both callers pass
//! record +0x8c; the field's domain identity is unproven.
//! Deliberate deviation: volatile byte reads preserve conditional access
//! rather than permitting wider or speculative payload loads. No seams.

/// # Safety
/// Both pointers must be readable at +0. Equal nonzero presence bytes
/// require readable +1 bytes; matching +1 bytes additionally require +2.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tri_byte_field_equal(left: *const u8, right: *const u8) -> u32 {
    let left_present = left.read_volatile();
    let right_present = right.read_volatile();
    if left_present != right_present {
        return 0;
    }
    if left_present == 0 {
        return 1;
    }
    if (left.add(1).read_volatile() as i8) != (right.add(1).read_volatile() as i8) {
        return 0;
    }
    u32::from((left.add(2).read_volatile() as i8) == (right.add(2).read_volatile() as i8))
}

#[cfg(test)]
mod tests {
    use super::tri_byte_field_equal;

    #[test]
    fn presence_gate_does_not_require_payload() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right && left != 0 { continue; }
                assert_eq!(unsafe { tri_byte_field_equal(&left, &right) }, u32::from(left == right));
            }
        }
    }

    #[test]
    fn first_payload_mismatch_does_not_require_second_payload() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right { continue; }
                let left = [0xff, left];
                let right = [0xff, right];
                assert_eq!(unsafe { tri_byte_field_equal(left.as_ptr(), right.as_ptr()) }, 0);
            }
        }
    }

    #[test]
    fn compares_each_signed_payload_byte_for_nonzero_presence() {
        for present in [1, 0x80, 0xff] {
            for offset in [1, 2] {
                for left_byte in 0..=255u8 {
                    for right_byte in 0..=255u8 {
                        let mut left = [present, 0x80, 0xff];
                        let mut right = left;
                        left[offset] = left_byte;
                        right[offset] = right_byte;
                        let expected = u32::from(i32::from(left_byte as i8) == i32::from(right_byte as i8));
                        assert_eq!(unsafe { tri_byte_field_equal(left.as_ptr(), right.as_ptr()) }, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn ignores_absent_payload_and_storage_after_three_bytes() {
        let left = [0, 0x80, 0xff, 1];
        let right = [0, 0xff, 0x80, 2];
        assert_eq!(unsafe { tri_byte_field_equal(left.as_ptr(), right.as_ptr()) }, 1);
        let left = [0xff, 0x80, 0xff, 1];
        let right = [0xff, 0x80, 0xff, 2];
        assert_eq!(unsafe { tri_byte_field_equal(left.as_ptr(), right.as_ptr()) }, 1);
        assert_eq!(unsafe { tri_byte_field_equal(left.as_ptr(), left.as_ptr()) }, 1);
    }
}
