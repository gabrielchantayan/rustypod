//! Optional signed-byte record equality — `FUN_0829f9f8` @ `0x0829f9f8`.
//! True extent: 48 bytes through `bx lr` at 0x0829fa24; the next real
//! function starts at 0x0829fa28 with independent presence-byte loads.
//! Raw aligned ARM words verify two plain incoming BLs (0x0829fccc,
//! 0x0829fe60), zero predicated incoming BLs, and zero outgoing BLs.
//!
//! Compare presence bytes exactly; unequal bytes return 0 and equal zero
//! bytes return 1 without reading payload. Otherwise compare signed bytes
//! at +1. Both callers pass object +0x91; domain identity is unproven.
//! Deliberate deviations: volatile reads preserve conditional access;
//! LLVM may fold this body with optional_byte_record_equal, whose unsigned
//! payload equality is equivalent. No callee seams or NULL guard.

/// # Safety
/// Both pointers must be readable for the first byte. If presence bytes
/// are equal and nonzero, both must also be readable at +1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_signed_byte_record_equal(left: *const u8, right: *const u8) -> u32 {
    let left_present = left.read_volatile();
    let right_present = right.read_volatile();
    if left_present != right_present {
        return 0;
    }
    if left_present == 0 {
        return 1;
    }
    u32::from((left.add(1).read_volatile() as i8) == (right.add(1).read_volatile() as i8))
}

#[cfg(test)]
mod tests {
    use super::optional_signed_byte_record_equal;

    #[test]
    fn presence_gate_does_not_require_payload() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right && left != 0 { continue; }
                assert_eq!(unsafe { optional_signed_byte_record_equal(&left, &right) },
                    u32::from(left == right));
            }
        }
    }

    #[test]
    fn all_signed_payload_pairs() {
        for present in [1, 0x80, 0xff] {
            for left_byte in 0..=255u8 {
                for right_byte in 0..=255u8 {
                    let left = [present, left_byte];
                    let right = [present, right_byte];
                    let expected = u32::from(i32::from(left_byte as i8) == i32::from(right_byte as i8));
                    assert_eq!(unsafe { optional_signed_byte_record_equal(left.as_ptr(), right.as_ptr()) }, expected);
                }
            }
        }
    }

    #[test]
    fn ignores_absent_payload_and_trailing_storage() {
        let left = [0, 0x80, 1];
        let right = [0, 0xff, 2];
        assert_eq!(unsafe { optional_signed_byte_record_equal(left.as_ptr(), right.as_ptr()) }, 1);
        let left = [0xff, 0x80, 1];
        let right = [0xff, 0x80, 2];
        assert_eq!(unsafe { optional_signed_byte_record_equal(left.as_ptr(), right.as_ptr()) }, 1);
        assert_eq!(unsafe { optional_signed_byte_record_equal(left.as_ptr(), left.as_ptr()) }, 1);
    }
}
