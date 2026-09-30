//! Inequality predicate for opaque pairs of retailOS words.

/// `word_pair_not_equal` — original `FUN_082a4e28` @ `0x082a4e28`.
/// True size: 36 bytes, ending at `bx lr` at `0x082a4e48`; the next
/// function begins with `push {r4-r8, lr}` at `0x082a4e4c`.
/// Full-image aligned ARM decoding verifies two inbound plain BL calls
/// (`0x0812b19c`, `0x0812b228`), zero predicated BL calls, and zero outgoing
/// BL calls. Callers compare stored two-word state against a replacement.
///
/// Compare the first words, then compare the second words only if the first
/// words match. Return exactly 0 or 1 without dereferencing word values or
/// modifying either input. Deliberate deviations: none; word indexing keeps
/// the original four-byte field stride on both host and target.
///
/// # Safety
/// Both pointers must be aligned and readable for one u32. If their first
/// words match, both must also be readable for a second u32. No NULL checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_pair_not_equal(left: *const u32, right: *const u32) -> bool {
    left.read() != right.read() || left.add(1).read() != right.add(1).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_both_words_by_value() {
        let values = [0, 1, 0x8000_0000, u32::MAX];
        for a in values {
            for b in values {
                for c in values {
                    for d in values {
                        let left = [a, b];
                        let right = [c, d];
                        assert_eq!(unsafe { word_pair_not_equal(left.as_ptr(), right.as_ptr()) },
                                   left != right);
                        assert_eq!(left, [a, b]);
                        assert_eq!(right, [c, d]);
                    }
                }
            }
        }
    }

    #[test]
    fn different_first_words_need_no_second_word() {
        let left = 0u32;
        let right = u32::MAX;
        assert!(unsafe { word_pair_not_equal(&left, &right) });
        assert!(unsafe { word_pair_not_equal(&right, &left) });
    }

    #[test]
    fn same_pair_is_equal_even_with_nonzero_words() {
        let pair = [u32::MAX, 0x8000_0000];
        assert!(!unsafe { word_pair_not_equal(pair.as_ptr(), pair.as_ptr()) });
    }
}
