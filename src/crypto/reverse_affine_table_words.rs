//! Backward in-place affine transform used by the proprietary table decoder.
//!
//! FUN_0800cbe8 @ 0x0800cbe8: true extent 320 bytes to the independently
//! entered 0x0800cd28; 200 executable bytes followed by 120 literal/data bytes.
//! Raw aligned A32 scan: two plain inbound BLs (0x0802cb2c, 0x0802d910),
//! zero predicated inbound BLs, zero outgoing plain or predicated BLs.
//! Callers pass the end pointer from FUN_0802b5d4 and count 256. Walk backward,
//! applying (word * 0x149660ff - 0x1220abc2) * 0x808107a3 + 0xbcb72aa2
//! modulo 2^32, preserving the raw MBA signed stopping predicate. Constants
//! are verified from literal words at 0x0800cd0c..0x0800cd24.
//! Deliberate deviations: fold the affine stages to one multiply/add; delay
//! pointer subtraction until the bound passes, avoiding unused invalid pointer
//! formation on no-access paths. No callee seams or trailing data reproduced.

const INDEX_BIAS: u32 = 0x6cd60ec1;
const BOUND_MASK: u32 = 0x40407e00;

/// # Safety
/// `end` must delimit enough aligned readable/writable u32 words for the raw
/// stopping predicate (count words for ordinary nonnegative counts).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.reverse_affine_table_words"]
pub unsafe extern "C" fn reverse_affine_table_words(mut end: *mut u32, count: u32) -> u32 {
    let adjusted_count = count.wrapping_sub(INDEX_BIAS);
    let biased_one = INDEX_BIAS.wrapping_add(1);
    let negative_limit = adjusted_count.wrapping_neg().wrapping_sub(biased_one);
    // RSB r1,r10,r10,ASR #31: the positive bias has a zero sign word.
    let mut encoded_index = INDEX_BIAS.wrapping_neg();
    loop {
        let inverse_index = encoded_index.wrapping_neg();
        let remaining_index = inverse_index.wrapping_sub(biased_one);
        let upper_index = inverse_index.wrapping_add(adjusted_count).wrapping_sub(1);
        let combined = upper_index | remaining_index;
        let masked_complement = (combined & BOUND_MASK).wrapping_add(!combined & !BOUND_MASK);
        let correction = adjusted_count.wrapping_sub(upper_index | negative_limit)
            .wrapping_sub(2).wrapping_add(inverse_index);
        let bound = 0x9329f13eu32.wrapping_sub(remaining_index | negative_limit)
            .wrapping_add(masked_complement ^ correction ^ BOUND_MASK)
            .wrapping_add(inverse_index);
        if (bound as i32) < 0 {
            return 0;
        }
        end = end.sub(1);
        let word = end.read();
        end.write(word.wrapping_mul(0x98e5bb5d).wrapping_add(0xc075801c));
        encoded_index = encoded_index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::reverse_affine_table_words;

    #[test]
    fn transforms_counted_words_preserving_both_neighbors() {
        for count in 0..=256usize {
            let mut words = [0u32; 258];
            for (index, word) in words.iter_mut().enumerate() {
                *word = (index as u32).wrapping_mul(0x9e3779b9);
            }
            words[1] = u32::MAX;
            words[2] = 0x80000000;
            words[3] = 0;
            let mut expected = words;
            for word in &mut expected[1..count + 1] {
                *word = word.wrapping_mul(0x149660ff).wrapping_sub(0x1220abc2)
                    .wrapping_mul(0x808107a3).wrapping_add(0xbcb72aa2);
            }
            assert_eq!(unsafe {
                reverse_affine_table_words(words.as_mut_ptr().add(count + 1), count as u32)
            }, 0);
            assert_eq!(words, expected, "count={count}");
        }
    }

    #[test]
    fn zero_and_negative_counts_do_not_access_memory() {
        for count in [0, 0x80000000, 0x80000001, u32::MAX] {
            assert_eq!(unsafe { reverse_affine_table_words(core::ptr::null_mut(), count) }, 0);
        }
    }
}
