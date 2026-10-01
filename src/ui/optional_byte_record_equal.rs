//! Optional byte record equality — `FUN_0829fd20` @ `0x0829fd20`.
//! True extent: 48 bytes, ending at `bx lr` at 0x0829fd4c; the next real
//! function starts at 0x0829fd50 with its own pair of presence-byte loads.
//! Raw aligned ARM-word decoding verifies two plain incoming BLs
//! (0x0829fc38, 0x0829feec), zero predicated incoming BLs, and zero outgoing
//! plain or predicated BLs.
//!
//! Compare presence bytes exactly. Mismatches return 0; equal zero bytes
//! return 1 without accessing payload. Equal nonzero bytes compare the byte
//! at +1. Both callers pass object +0x8f; domain identity is unproven.
//! Deliberate deviations: unsigned payload loads instead of signed loads;
//! equality is unchanged. Volatile reads preserve conditional access.

/// # Safety
/// Both pointers must be readable for the first byte. If the presence bytes
/// are equal and nonzero, both must also be readable at +1. No NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_byte_record_equal(left: *const u8, right: *const u8) -> u32 {
    let left_present = left.read_volatile();
    let right_present = right.read_volatile();
    if left_present != right_present {
        return 0;
    }
    if left_present == 0 {
        return 1;
    }
    u32::from(left.add(1).read_volatile() == right.add(1).read_volatile())
}

#[cfg(test)]
mod tests {
    use super::optional_byte_record_equal;

    #[test]
    fn exact_presence_gate_needs_no_payload() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right && left != 0 { continue; }
                assert_eq!(unsafe { optional_byte_record_equal(&left, &right) },
                    u32::from(left == right));
            }
        }
    }

    #[test]
    fn payload_equality_matches_signed_arm_byte_comparison() {
        for present in [1, 0x80, 0xff] {
            for left_byte in 0..=255u8 {
                for right_byte in 0..=255u8 {
                    let left = [present, left_byte];
                    let right = [present, right_byte];
                    let expected = u32::from((left_byte as i8 as i32) == (right_byte as i8 as i32));
                    assert_eq!(unsafe { optional_byte_record_equal(left.as_ptr(), right.as_ptr()) }, expected);
                }
            }
        }
    }

    #[test]
    fn absent_payload_and_trailing_bytes_are_ignored() {
        let left = [0, 0x80, 1];
        let right = [0, 0xff, 2];
        assert_eq!(unsafe { optional_byte_record_equal(left.as_ptr(), right.as_ptr()) }, 1);
        let left = [0xff, 0x80, 1];
        let right = [0xff, 0x80, 2];
        assert_eq!(unsafe { optional_byte_record_equal(left.as_ptr(), right.as_ptr()) }, 1);
        assert_eq!(unsafe { optional_byte_record_equal(left.as_ptr(), left.as_ptr()) }, 1);
    }
}
