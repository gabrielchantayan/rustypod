//! Removes high zero limbs from the retailOS encoded multi-limb integer.
//!
//! `bigint_trim_high_zero_limbs` — original `FUN_082f777c` at `0x082f777c`
//! (120 bytes: 30 ARM words, including three multiplier literals; 3 verified
//! direct plain `bl` call sites and 0 predicated forms).
//!
//! The header's signed limb count is decoded with `0x0a7e377f`. Starting at
//! the most-significant limb, the routine removes zero words, then re-encodes
//! the remaining count with `0xed99887f`, preserving its original sign. The
//! zero test intentionally retains the original nonzero multiplier
//! `0x76b4197f`; it is equivalent to a word-zero test modulo 2^32. There are
//! no deliberate behavioral deviations.

use core::ptr;

const ENCODED_COUNT_MULTIPLIER: u32 = 0x0a7e_377f;
const LIMB_NONZERO_MULTIPLIER: u32 = 0x76b4_197f;
const COUNT_ENCODING_MULTIPLIER: u32 = 0xed99_887f;

/// Removes zero-valued most-significant limbs and returns zero.
///
/// `value` is the retailOS two-word layout: an encoded signed limb count,
/// followed by a 32-bit target pointer to its little-endian limb array.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bigint_trim_high_zero_limbs")]
#[inline(never)]
pub unsafe extern "C" fn bigint_trim_high_zero_limbs(value: *mut u32) -> u32 {
    let decoded_count = ptr::read(value).wrapping_mul(ENCODED_COUNT_MULTIPLIER) as i32;
    let mut limb_count = decoded_count.wrapping_abs() as u32;
    let limbs = ptr::read(value.add(1)) as usize as *const u32;

    while limb_count != 0 {
        let limb = ptr::read(limbs.add((limb_count - 1) as usize));
        if limb.wrapping_mul(LIMB_NONZERO_MULTIPLIER) != 0 {
            break;
        }
        limb_count -= 1;
    }

    let encoded_count = limb_count.wrapping_mul(COUNT_ENCODING_MULTIPLIER);
    ptr::write(
        value,
        if decoded_count < 0 {
            encoded_count.wrapping_neg()
        } else {
            encoded_count
        },
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_BYTES: usize = 0x1000;
    const LIMBS_OFFSET: usize = 0x100;

    unsafe fn normalize(object: *mut u32, limbs: *mut u32, encoded_count: u32, words: &[u32]) -> u32 {
        ptr::write(object, encoded_count);
        ptr::write(object.add(1), limbs as usize as u32);
        for (index, &word) in words.iter().enumerate() {
            ptr::write(limbs.add(index), word);
        }
        bigint_trim_high_zero_limbs(object)
    }

    #[test]
    fn removes_only_high_zero_limbs_and_preserves_count_sign() {
        let Some(slab) = try_map_u32_slab(hints::BIGINT_TRIM_HIGH_ZERO_LIMBS, FIXTURE_BYTES) else {
            assert!(note_missing_u32_fixture("fp::bigint_trim_high_zero_limbs"));
            return;
        };
        let object = slab.cast::<u32>();
        let limbs = unsafe { slab.add(LIMBS_OFFSET).cast::<u32>() };

        for &(encoded_count, words, expected_count) in &[
            (0, &[][..], 0),
            (COUNT_ENCODING_MULTIPLIER, &[0, 0, 0][..], 0),
            (3u32.wrapping_mul(COUNT_ENCODING_MULTIPLIER), &[7, 0, 0][..], 1),
            (3u32.wrapping_mul(COUNT_ENCODING_MULTIPLIER), &[7, 8, 0][..], 2),
            ((-3i32 as u32).wrapping_mul(COUNT_ENCODING_MULTIPLIER), &[7, 0, 0][..], -1),
            ((-3i32 as u32).wrapping_mul(COUNT_ENCODING_MULTIPLIER), &[0, 8, 0][..], -2),
        ] {
            assert_eq!(unsafe { normalize(object, limbs, encoded_count, words) }, 0);
            let expected = (expected_count as u32).wrapping_mul(COUNT_ENCODING_MULTIPLIER);
            assert_eq!(unsafe { ptr::read(object) }, expected);
        }
    }
}
