//! Unsigned comparison of equal-length little-endian bignum limb arrays.
//!
//! Port: `FUN_082b8028` @ `0x082b8028` (96 bytes,
//! `0x082b8028..0x082b8087`; **3 inbound plain `bl` call sites, zero
//! predicated**; no outbound calls). Raw `osos.dec` words establish the
//! extent: `e0803102 e081c102 e51cc004 e5133004` begin the preloaded
//! highest limb comparison, and `e92d47f0` at `0x082b8088` starts the next
//! independently entered function.
//!
//! Algorithm: compare the highest (`words - 1`) unsigned 32-bit limbs first;
//! if equal, scan the remaining limbs downward, returning `1` or `-1` at the
//! first difference and `0` when all limbs match. The precondition is
//! `words >= 1`: the original loads `a[words - 1]` and `b[words - 1]` before
//! any loop guard.
//!
//! Deliberate deviations: none. The signed decrement and address arithmetic
//! use wrapping operations, matching ARM's 32-bit arithmetic for invalid
//! counts without introducing host debug-overflow panics.

/// Compare `words` little-endian unsigned limbs, most-significant limb first.
///
/// # Safety
///
/// `a` and `b` must each point to at least `words` readable, aligned `u32`
/// limbs, and `words` must be positive.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bn_cmp_words(a: *const u32, b: *const u32, words: i32) -> i32 {
    let mut index = words.wrapping_sub(1);
    let mut a_word = a.wrapping_add(index as usize).read();
    let mut b_word = b.wrapping_add(index as usize).read();

    if a_word != b_word {
        return if a_word > b_word { 1 } else { -1 };
    }

    index = index.wrapping_sub(1);
    while index >= 0 {
        a_word = a.wrapping_add(index as usize).read();
        b_word = b.wrapping_add(index as usize).read();
        if a_word != b_word {
            return if a_word > b_word { 1 } else { -1 };
        }
        index = index.wrapping_sub(1);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    fn reference_cmp_words(a: &[u32], b: &[u32]) -> i32 {
        for index in (0..a.len()).rev() {
            if a[index] != b[index] {
                return if a[index] > b[index] { 1 } else { -1 };
            }
        }
        0
    }

    #[test]
    fn highest_differing_limb_decides() {
        let a = [0xffff_ffff, 0, 1];
        let b = [0, 0, 2];
        assert_eq!(unsafe { bn_cmp_words(a.as_ptr(), b.as_ptr(), 3) }, -1);
        assert_eq!(unsafe { bn_cmp_words(b.as_ptr(), a.as_ptr(), 3) }, 1);
    }

    #[test]
    fn scans_to_the_lowest_limb_and_compares_unsigned() {
        let a = [0x8000_0000, 7, 7];
        let b = [0x7fff_ffff, 7, 7];
        assert_eq!(unsafe { bn_cmp_words(a.as_ptr(), b.as_ptr(), 3) }, 1);
        assert_eq!(unsafe { bn_cmp_words(b.as_ptr(), a.as_ptr(), 3) }, -1);
    }

    #[test]
    fn equal_arrays_compare_equal() {
        let limbs = [0xdead_beef, 0x1234_5678, 1];
        assert_eq!(unsafe { bn_cmp_words(limbs.as_ptr(), limbs.as_ptr(), 3) }, 0);
    }

    #[test]
    fn matches_reference_for_positive_lengths() {
        let mut state = 0x1234_5678u32;
        let mut random = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };

        for words in 1..=8 {
            for _ in 0..100 {
                let a: Vec<u32> = (0..words).map(|_| random()).collect();
                let b: Vec<u32> = (0..words).map(|_| random()).collect();
                assert_eq!(
                    unsafe { bn_cmp_words(a.as_ptr(), b.as_ptr(), words as i32) },
                    reference_cmp_words(&a, &b),
                    "a={a:?} b={b:?}"
                );
            }
        }
    }
}
