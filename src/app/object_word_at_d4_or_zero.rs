//! object_word_at_d4_or_zero — original: `FUN_082980dc` @ `0x082980dc`
//! (16 bytes).
//!
//! Raw ARM is `ldr r0,[r0,#0xd4]; cmn r0,#1; moveq r0,#0; bx lr` at
//! `0x082980dc..0x082980e8`; the separately linked sibling
//! `FUN_082980ec` starts immediately afterward. Complete aligned ARM
//! `B`/`BL`-immediate decoding of `osos.dec` finds exactly seven direct
//! inbound calls, all unconditional plain `bl` at `0x08111f50`,
//! `0x08111f6c`, `0x08112ba4`, `0x08114658`, `0x08115718`, `0x082982f4`,
//! and `0x0829830c`; there are no predicated calls or aligned raw-word
//! references.
//!
//! Loads the signed word at +0xd4 of an otherwise opaque object. The `-1`
//! sentinel is normalized to zero; every other 32-bit value, including
//! negative values other than `-1`, passes through unchanged. Direct callers
//! compare the result with requested indices, so it is count-like, but neither
//! the concrete object type nor the field's unit is recovered. No deliberate
//! deviations: as in retailOS, the unchecked aligned field read has no NULL,
//! bounds, ownership, or sentinel validation beyond `-1`.

/// Byte offset of the opaque object's signed sentinel word.
const WORD_OFFSET: usize = 0xd4;

/// Reads the signed word at +0xd4, mapping only its `-1` sentinel to zero.
///
/// # Safety
///
/// `object` must be non-NULL, four-byte aligned, and readable through its
/// signed 32-bit field at +0xd4. This is the exact precondition of the ARM
/// `ldr`; no additional validation is performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_at_d4_or_zero(object: *const u8) -> i32 {
    let word = unsafe { (object.add(WORD_OFFSET) as *const i32).read() };
    if word == -1 { 0 } else { word }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_WORDS: usize = (WORD_OFFSET / core::mem::size_of::<u32>()) + 1;
    const FIELD_WORD_INDEX: usize = WORD_OFFSET / core::mem::size_of::<u32>();
    const SENTINEL: u32 = 0xa5a5_a5a5;

    fn with_word(word: i32) -> [u32; OBJECT_WORDS] {
        let mut object = [SENTINEL; OBJECT_WORDS];
        object[FIELD_WORD_INDEX] = word as u32;
        object
    }

    #[test]
    fn maps_only_the_negative_one_sentinel_to_zero() {
        let object = with_word(-1);

        assert_eq!(unsafe { object_word_at_d4_or_zero(object.as_ptr().cast()) }, 0);
    }

    #[test]
    fn preserves_zero_positive_and_other_negative_bit_patterns() {
        for word in [0, 1, i32::MAX, i32::MIN, -2] {
            let object = with_word(word);

            assert_eq!(unsafe { object_word_at_d4_or_zero(object.as_ptr().cast()) }, word);
        }
    }

    #[test]
    fn reads_only_the_sentinel_word() {
        let object = with_word(0x1234_5678);
        let before = object;

        assert_eq!(unsafe { object_word_at_d4_or_zero(object.as_ptr().cast()) }, 0x1234_5678);
        assert_eq!(object, before, "accessor must not write the object");
    }
}
