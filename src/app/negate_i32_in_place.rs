//! `negate_i32_in_place` — original: `FUN_082e9b40` @ 0x082e9b40 (20
//! bytes; 21 `bl` call sites, all unconditional; no plain `b` entries).
//!
//! The raw ARM words are `ldr r1,[r0]; rsb r1,r1,#0; str r1,[r0]; mov
//! r0,#0; bx lr`. It negates the signed 32-bit word at `value` with
//! two's-complement wrapping arithmetic, then returns the zero status word.
//! The next separately entered function starts at 0x082e9b54, confirming
//! Ghidra's 20-byte extent. The 21-site count comes from decoding every
//! ARM B/BL word in osos.dec; every entry is an unconditional `bl`.
//!
//! Deliberate deviations: none. There is no NULL or alignment guard,
//! matching the original's direct aligned word load and store.

/// Negates the signed word at `value` in place and returns the zero status word.
///
/// # Safety
///
/// `value` must be non-NULL, aligned for `i32`, and point to writable memory.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn negate_i32_in_place(value: *mut i32) -> u32 {
    let original = core::ptr::read(value);
    core::ptr::write(value, original.wrapping_neg());
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negates_representative_signed_words_and_returns_zero() {
        for (input, expected) in [
            (0, 0),
            (1, -1),
            (-1, 1),
            (0x1234_5678, -0x1234_5678),
            (i32::MAX, -i32::MAX),
            (i32::MIN, i32::MIN),
        ] {
            let mut value = input;
            assert_eq!(unsafe { negate_i32_in_place(&mut value) }, 0, "input {input}");
            assert_eq!(value, expected, "input {input}");
        }
    }

    #[test]
    fn repeated_calls_restore_the_original_word() {
        let mut value = 0x5a5a_a5a5u32 as i32;
        unsafe {
            assert_eq!(negate_i32_in_place(&mut value), 0);
            assert_eq!(negate_i32_in_place(&mut value), 0);
        }
        assert_eq!(value, 0x5a5a_a5a5u32 as i32);
    }
}
