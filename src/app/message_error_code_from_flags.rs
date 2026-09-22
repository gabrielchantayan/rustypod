//! Selects the message-construction error code from two state flags.
//!
//! - `message_error_code_from_flags` — original: `FUN_0820429c` @
//!   0x0820429c (28 bytes; 3 direct plain `bl` call sites, 0 predicated BL
//!   call sites, and no outgoing calls; verified from `osos.dec`).

/// Error selected when the first flag is clear.
const ERR_FIRST_FLAG_CLEAR: u32 = 0x3b;
/// Error selected when only the first flag is set.
const ERR_SECOND_FLAG_CLEAR: u32 = 0x2c;
/// Error selected when both flags are set.
const ERR_BOTH_FLAGS_SET: u32 = 0x20;

/// message_error_code_from_flags — original: `FUN_0820429c` @ 0x0820429c
/// (28 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x0820429c..0x082042b8`; the following `push {r4, r5, lr}` at
/// `0x082042b8` begins the next real function:
///
/// ```text
/// 0820429c  cmp r0, #0
/// 082042a0  moveq r0, #0x3b
/// 082042a4  bx lr
/// 082042a8  cmp r1, #0
/// 082042ac  moveq r0, #0x2c
/// 082042b0  movne r0, #0x20
/// 082042b4  bx lr
/// ```
///
/// Algorithm: a clear `first_flag` selects `0x3b` without reading the
/// second flag. Otherwise, a clear `second_flag` selects `0x2c`; both set
/// selects `0x20`. The three verified direct callers forward the result as
/// the fourth argument to the message constructor at `0x08204434`.
///
/// Call sites: three unconditional plain `bl` instructions (0x081dcd88,
/// 0x081dce48, and 0x0820fe40), zero predicated BL instructions.
/// Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.message_error_code_from_flags")]
pub extern "C" fn message_error_code_from_flags(first_flag: u32, second_flag: u32) -> u32 {
    if first_flag == 0 {
        ERR_FIRST_FLAG_CLEAR
    } else if second_flag == 0 {
        ERR_SECOND_FLAG_CLEAR
    } else {
        ERR_BOTH_FLAGS_SET
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_codes_for_all_flag_combinations() {
        for (first_flag, second_flag, expected) in [
            (0, 0, ERR_FIRST_FLAG_CLEAR),
            (0, 1, ERR_FIRST_FLAG_CLEAR),
            (1, 0, ERR_SECOND_FLAG_CLEAR),
            (1, 1, ERR_BOTH_FLAGS_SET),
        ] {
            assert_eq!(message_error_code_from_flags(first_flag, second_flag), expected);
        }
    }

    #[test]
    fn treats_every_nonzero_value_as_set() {
        assert_eq!(message_error_code_from_flags(u32::MAX, 0), ERR_SECOND_FLAG_CLEAR);
        assert_eq!(message_error_code_from_flags(2, 0x8000_0000), ERR_BOTH_FLAGS_SET);
    }
}
