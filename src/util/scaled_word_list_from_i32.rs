//! `scaled_word_list_from_i32` — original `FUN_08346ecc` at `0x08346ecc`.
//!
//! True extent: 116 bytes (`0x08346ecc..0x08346f40`): 29 ARM instruction
//! words followed by the two literal multipliers `0xff5fdd7f` and
//! `0xda8ebbff`; the next real function starts at `0x08346f48`. Four verified
//! inbound direct calls are plain `bl`; none is predicated. The leaf has no
//! outgoing calls.
//!
//! The routine writes the signed count at `words[0]`, scaled by
//! `0xda8ebbff`, then writes one or two magnitude words at `words[1..]`, each
//! multiplied by `0xff5fdd7f` modulo 2^32. `i32::MIN` is deliberately handled
//! as ARM's wrapping negate: its sign-extended magnitude produces two words.
//! Deliberate deviations: none.

const WORD_MULTIPLIER: u32 = 0xff5f_dd7f;
const COUNT_MULTIPLIER: u32 = 0xda8e_bbff;

/// Initializes the retailOS scaled word-list representation of `value`.
///
/// # Safety
///
/// `words` must point to at least three writable, aligned `u32` words. The
/// third word is written only when `value` is `i32::MIN`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.scaled_word_list_from_i32")]
#[inline(never)]
pub unsafe extern "C" fn scaled_word_list_from_i32(words: *mut u32, value: i32) {
    let mut magnitude = if value < 0 { (value as u32).wrapping_neg() } else { value as u32 };
    let mut extension = ((magnitude as i32) >> 31) as u32;
    let mut count = 0u32;

    while extension != 0 || magnitude != 0 {
        words.add(count as usize + 1).write(magnitude.wrapping_mul(WORD_MULTIPLIER));
        count = count.wrapping_add(1);
        magnitude = extension;
        extension = 0;
    }

    if value < 0 {
        count = count.wrapping_neg();
    }
    words.write(count.wrapping_mul(COUNT_MULTIPLIER));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    fn output() -> Option<*mut u32> {
        let slab = try_map_u32_slab(hints::SCALED_WORD_LIST_FROM_I32, 0x100)?;
        Some(slab.cast())
    }


    #[test]
    fn initializes_zero_and_signed_single_word_values() {
        let Some(words) = output() else {
            assert!(note_missing_u32_fixture("util/scaled_word_list_from_i32"));
            return;
        };

        for (value, expected) in [
            (0, [0, 0xfeed_face, 0xfeed_face]),
            (1, [0xda8e_bbff, 0xff5f_dd7f, 0xfeed_face]),
            (-1, [0x2571_4401, 0xff5f_dd7f, 0xfeed_face]),
        ] {
            unsafe {
                words.write(0xfeed_face);
                words.add(1).write(0xfeed_face);
                words.add(2).write(0xfeed_face);
                scaled_word_list_from_i32(words, value);
                assert_eq!([words.read(), words.add(1).read(), words.add(2).read()], expected);
            }
        }
    }

    #[test]
    fn preserves_arm_wrapping_negate_for_i32_min() {
        let Some(words) = output() else {
            assert!(note_missing_u32_fixture("util/scaled_word_list_from_i32"));
            return;
        };
        let expected = [0x4ae2_8802, 0x8000_0000, 0x00a0_2281];

        unsafe {
            scaled_word_list_from_i32(words, i32::MIN);
            assert_eq!([words.read(), words.add(1).read(), words.add(2).read()], expected);
        }
    }
}
