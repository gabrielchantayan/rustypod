//! mode_position_validate — original: `FUN_0809c758` @ 0x0809c758 (68 bytes;
//! three direct inbound `bl` call sites).
//!
//! Raw osos.dec A32 words establish the complete body from 0x0809c758 through
//! 0x0809c798; `stmdb sp!, {r4,lr}` at 0x0809c79c begins the next function.
//! It makes one plain outgoing `bl` at 0x0809c768 and no predicated calls;
//! whole-image decoding finds three inbound plain `bl` instructions
//! (0x080a3dd4, 0x082e7cec, and 0x082e857c), with none predicated. Mode 2
//! accepts positions in the inclusive signed interval -62..=63. Modes 1 and
//! 3 return 0x31; every other mode returns 0x1a. The original obtains the
//! interval from its sole callee, but that callee has no established semantic
//! name and is only called here, so its verified fixed result is inlined;
//! this is a deliberate seam-free deviation.

/// Validates a signed position accepted by a retailOS mode.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.mode_position_validate"]
pub unsafe extern "C" fn mode_position_validate(mode: u32, position: *const i32) -> u32 {
    match mode {
        2 => {
            let position = unsafe { *position };
            if (-62..=63).contains(&position) {
                0
            } else {
                0x1a
            }
        }
        1 | 3 => 0x31,
        _ => 0x1a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_two_accepts_inclusive_signed_interval() {
        for position in [-62, -1, 0, 63] {
            assert_eq!(unsafe { mode_position_validate(2, &position) }, 0);
        }
    }

    #[test]
    fn mode_two_rejects_values_outside_interval() {
        for position in [i32::MIN, -63, 64, i32::MAX] {
            assert_eq!(unsafe { mode_position_validate(2, &position) }, 0x1a);
        }
    }

    #[test]
    fn unsupported_modes_return_their_distinct_statuses() {
        let position = 0;
        assert_eq!(unsafe { mode_position_validate(1, &position) }, 0x31);
        assert_eq!(unsafe { mode_position_validate(3, &position) }, 0x31);
        for mode in [0, 4, u32::MAX] {
            assert_eq!(unsafe { mode_position_validate(mode, &position) }, 0x1a);
        }
    }
}
