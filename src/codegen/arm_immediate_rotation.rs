//! cg_arm_immediate_rotation — `FUN_082be96c` @ 0x082be96c (72 bytes; 6 `bl` call sites, all unconditional).
//!
//! Determines whether a 32-bit literal, or its complement, occupies one
//! eight-bit field after an even right rotation.  For the first matching
//! rotation `r` in `0, 2, ..., 30`, it returns `r` when the literal itself is
//! encodable and `-(r + 2)` when only its complement is encodable.  It returns
//! one when neither representation is available.  This is the Vincent ARM
//! code generator's immediate-operand encoder; callers use a negative result
//! to select an MVN-form instruction.  Raw ARM ends at 0x082be9b4, immediately
//! before the next function at 0x082be9b4, and contains no calls.  A complete
//! decode of every ARM B/BL-immediate word in osos.dec finds six inbound plain,
//! unconditional `bl` calls (0x082b482c, 0x082cb668, 0x082cb8d8, 0x082cbd4c,
//! 0x082cc944, 0x082d72fc), zero predicated calls, and no tail branches.  No
//! deliberate behavioural deviations.

/// Returns the first ARM immediate rotation for `literal`, its complemented
/// encoding marker, or the non-encodable sentinel one.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn cg_arm_immediate_rotation(literal: u32) -> i32 {
    let mut rotation = 0_u32;
    while rotation < 32 {
        let mask = 0xff_u32.rotate_right(rotation);
        if literal & !mask == 0 {
            return rotation as i32;
        }
        if literal | mask == u32::MAX {
            return -((rotation + 2) as i32);
        }
        rotation += 2;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_arm_immediate_rotation(literal: u32) -> i32 {
        for rotation in (0..32).step_by(2) {
            let mask = 0xff_u32.rotate_right(rotation);
            if literal & !mask == 0 {
                return rotation as i32;
            }
            if literal | mask == u32::MAX {
                return -((rotation + 2) as i32);
            }
        }
        1
    }

    #[test]
    fn returns_rotation_complement_marker_or_sentinel() {
        assert_eq!(cg_arm_immediate_rotation(0), 0);
        assert_eq!(cg_arm_immediate_rotation(0xff), 0);
        assert_eq!(cg_arm_immediate_rotation(0x8000_0001), 2);
        assert_eq!(cg_arm_immediate_rotation(0x0100_0000), 8);
        assert_eq!(cg_arm_immediate_rotation(!0xff), -2);
        assert_eq!(cg_arm_immediate_rotation(!0xff00_0000), -10);
        assert_eq!(cg_arm_immediate_rotation(u32::MAX), -2);
        assert_eq!(cg_arm_immediate_rotation(0x1234_5678), 1);
    }

    #[test]
    fn handles_every_byte_and_complement_at_every_arm_rotation() {
        for rotation in (0..32).step_by(2) {
            for byte in 0_u32..=u8::MAX.into() {
                let encoded = byte.rotate_right(rotation);
                let complemented = !encoded;
                assert_eq!(
                    cg_arm_immediate_rotation(encoded),
                    reference_arm_immediate_rotation(encoded)
                );
                assert_eq!(
                    cg_arm_immediate_rotation(complemented),
                    reference_arm_immediate_rotation(complemented)
                );
            }
        }
    }

    #[test]
    fn preserves_the_sentinel_for_unencodable_bit_patterns() {
        for literal in [0x0000_0101, 0x00ff_00ff, 0x1234_5678, 0x5555_5555, 0xaaaa_aaaa] {
            assert_eq!(cg_arm_immediate_rotation(literal), 1);
        }
    }
}
