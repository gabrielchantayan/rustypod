//! object_word_at_f0_or_zero — original: `FUN_082980ac` @ `0x082980ac`
//! (true size: 16 bytes; next real function starts at `0x082980bc`).
//!
//! Raw ARM words: e59000f0 e3700001 03a00000 e12fff1e:
//! `ldr r0,[r0,#0xf0]; cmn r0,#1; moveq r0,#0; bx lr`.
//! Whole-image aligned A32 decoding verifies two plain unconditional inbound
//! BLs (0x08111fb8, 0x0822f20c), zero predicated inbound BLs, and no outgoing
//! calls. The first caller returns the value through its dispatch path; the
//! second selects empty/nonempty podcast highlight text. Object identity and
//! field units remain unknown; Ghidra's overlapping caller adds no third BL.
//!
//! Read the signed word at +0xf0 and normalize only -1 to zero, preserving
//! every other bit pattern. No deliberate behavioral deviations: retain the
//! unchecked aligned read, with no NULL, bounds, or value validation.

const WORD_OFFSET: usize = 0xf0;

/// Reads the signed word at +0xf0, mapping only -1 to zero.
///
/// # Safety
/// `object` must be non-NULL, four-byte aligned, and readable through the
/// signed 32-bit field at +0xf0.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_at_f0_or_zero(object: *const u8) -> i32 {
    let word = unsafe { (object.add(WORD_OFFSET) as *const i32).read() };
    if word == -1 { 0 } else { word }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_negative_one_and_preserves_the_object() {
        for (word, expected) in [
            (-1, 0), (0, 0), (1, 1), (-2, -2),
            (i32::MIN, i32::MIN), (i32::MAX, i32::MAX),
            (0x1234_5678, 0x1234_5678),
        ] {
            let mut object = [0xa5a5_a5a5u32; WORD_OFFSET / 4 + 2];
            object[0xe8 / 4] = 0x1122_3344;
            object[WORD_OFFSET / 4 - 1] = 0x5566_7788;
            object[WORD_OFFSET / 4] = word as u32;
            object[WORD_OFFSET / 4 + 1] = 0x7788_99aa;
            let before = object;

            assert_eq!(unsafe { object_word_at_f0_or_zero(object.as_ptr().cast()) }, expected);
            assert_eq!(object, before, "accessor must not modify the object");
        }
    }
}
