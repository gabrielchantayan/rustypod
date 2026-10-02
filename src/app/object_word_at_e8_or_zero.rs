//! object_word_at_e8_or_zero — original: `FUN_082980cc` @ `0x082980cc`
//! (true size: 16 bytes).
//!
//! Raw ARM: `ldr r0,[r0,#0xe8]; cmn r0,#1; moveq r0,#0; bx lr`.
//! The next independently called function starts at `0x082980dc`.
//! Complete aligned raw ARM BL decoding verifies two plain inbound calls
//! (`0x08111f18`, `0x0822f5fc`), zero predicated inbound calls, and zero
//! outgoing calls. Callers consume the result as a value or test it for zero;
//! neither the concrete object type nor the field's unit is recovered.
//!
//! Read the signed word at +0xe8 and normalize only -1 to zero, preserving
//! every other bit pattern. No deliberate deviations: retain the unchecked
//! aligned field read without NULL, bounds, or additional value validation.

const WORD_OFFSET: usize = 0xe8;

/// Reads the signed word at +0xe8, mapping only -1 to zero.
///
/// # Safety
/// `object` must be non-NULL, four-byte aligned, and readable through the
/// signed 32-bit field at +0xe8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_at_e8_or_zero(object: *const u8) -> i32 {
    let word = unsafe { (object.add(WORD_OFFSET) as *const i32).read() };
    if word == -1 { 0 } else { word }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_only_negative_one_and_preserves_the_object() {
        // Distinct adjacent fields catch selection of another sibling's offset.
        for word in [-1, 0, 1, i32::MAX, i32::MIN, -2, 0x1234_5678] {
            let mut object = [0xa5a5_a5a5u32; WORD_OFFSET / 4 + 2];
            object[WORD_OFFSET / 4 - 1] = 0x1122_3344;
            object[WORD_OFFSET / 4] = word as u32;
            object[WORD_OFFSET / 4 + 1] = 0x5566_7788;
            let before = object;
            let expected = if word == -1 { 0 } else { word };

            assert_eq!(unsafe { object_word_at_e8_or_zero(object.as_ptr().cast()) }, expected);
            assert_eq!(object, before, "accessor must not modify the object");
        }
    }
}
