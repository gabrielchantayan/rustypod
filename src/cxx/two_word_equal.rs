//! `two_word_equal` — original: `FUN_0829bea4` @ **0x0829bea4**.
//! **36 bytes**, `0x0829bea4..0x0829bec8`; the next function begins with
//! `ldrb r2,[r0,#0xec]` at `0x0829bec8`, after this leaf's `bx lr`.
//!
//! Raw ARM branch decoding verifies two inbound plain BL sites (0x0827506c,
//! 0x08275560), zero predicated BL sites, zero tail branches, and zero outbound
//! calls. Compare the first 32-bit words, then only if equal compare the second
//! words at +4. Return exactly 0 or 1. Callers compare two-word font handles
//! against a zero pair; the leaf neither masks tag bits nor follows pointers.
//! No deliberate deviations; word indices preserve the target layout on hosts.

/// Returns 1 iff both consecutive words match, otherwise 0.
///
/// Both pointers must be aligned and readable for their first `u32`; when
/// those words match, both second words must also be readable. No NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn two_word_equal(left: *const u32, right: *const u32) -> u32 {
    if left.read() != right.read() {
        return 0;
    }
    (left.add(1).read() == right.add(1).read()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_exact_words_including_tags_and_high_bits() {
        let cases = [
            ([0, 0], [0, 0], 1),
            ([0, 0], [0, 1], 0),
            ([0x1000, 7], [0x1001, 7], 0),
            ([0x8000_0000, u32::MAX], [0x8000_0000, u32::MAX], 1),
            ([u32::MAX, 0], [u32::MAX, 0x8000_0000], 0),
            ([1, 0], [0, 1], 0),
        ];
        for (left, right, expected) in cases {
            assert_eq!(unsafe { two_word_equal(left.as_ptr(), right.as_ptr()) }, expected);
            assert_eq!(unsafe { two_word_equal(right.as_ptr(), left.as_ptr()) }, expected);
            assert_eq!(unsafe { two_word_equal(left.as_ptr(), left.as_ptr()) }, 1);
        }
    }

    #[test]
    fn unequal_first_words_need_no_second_word() {
        let left = 0x1122_3344u32;
        let right = 0x5566_7788u32;
        assert_eq!(unsafe { two_word_equal(&left, &right) }, 0);
    }
}
