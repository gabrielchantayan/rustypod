//! Reverse in-place affine word transform from the proprietary table decoder.
//!
//! Original: FUN_0800d124 @ 0x0800d124, 200 bytes, ending at the independently
//! entered function 0x0800d1ec. Raw aligned A32 scanning finds two plain inbound
//! BLs (0x0802cd44, 0x0802dbd8), zero predicated inbound BLs and no outgoing BLs.
//! The callers pass the end pointer produced by FUN_0802b5d4 and count 256.
//! Walk backward, applying (word * 0x1a33640b - 0x725560f6) * 0xb57d1ebf
//! - 0x0c916c82 modulo 2^32. Retain the raw MBA-obfuscated signed stopping
//! predicate rather than assuming a simplified signed count comparison.
//! Literal words at 0x0800dd1c..0x0800dd38 supply all seven constants.
//! Deliberate deviations: fold the two affine stages into one equivalent
//! multiply/subtract; form each preceding pointer only after the bound passes
//! (the original forms end - 4 even when it never accesses memory).

const INDEX_BIAS: u32 = 0x445f52c1;
const BOUND_MASK: u32 = 0x99ea4e00;

/// # Safety
/// `end` must delimit enough aligned readable/writable u32 words for the raw
/// stopping predicate (count words for ordinary nonnegative counts).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[link_section = ".text.reverse_affine_words"]
pub unsafe extern "C" fn reverse_affine_words(mut end: *mut u32, count: u32) -> u32 {
    let adjusted_count = count.wrapping_sub(INDEX_BIAS);
    let biased_one = INDEX_BIAS.wrapping_add(1);
    let negative_limit = adjusted_count.wrapping_neg().wrapping_sub(biased_one);
    let mut encoded_index = INDEX_BIAS ^ 0xfffffffe;
    loop {
        let inverse_index = encoded_index.wrapping_neg();
        let remaining_index = inverse_index.wrapping_sub(biased_one);
        let upper_index = inverse_index.wrapping_add(adjusted_count).wrapping_sub(1);
        let combined = upper_index | remaining_index;
        let masked_complement = (combined & BOUND_MASK).wrapping_add(!combined & !BOUND_MASK);
        let correction = adjusted_count.wrapping_sub(upper_index | negative_limit)
            .wrapping_sub(2).wrapping_add(inverse_index);
        let bound = 0xbba0ad3eu32.wrapping_sub(remaining_index | negative_limit)
            .wrapping_add(masked_complement ^ correction ^ BOUND_MASK)
            .wrapping_add(inverse_index);
        if (bound as i32) < 0 {
            return 0;
        }
        end = end.sub(1);
        let word = end.read();
        end.write(word.wrapping_mul(0x326fee35).wrapping_sub(0xa1bf980c));
        encoded_index = encoded_index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::reverse_affine_words;

    #[test]
    fn transforms_requested_words_without_touching_neighbors() {
        for count in 0..=256usize {
            let mut words = [0u32; 262];
            for (i, word) in words.iter_mut().enumerate() {
                *word = (i as u32).wrapping_mul(0x9e3779b9);
            }
            words[1] = u32::MAX;
            words[2] = 0x80000000;
            let mut expected = words;
            for word in &mut expected[1..count + 1] {
                *word = word.wrapping_mul(0x1a33640b).wrapping_sub(0x725560f6)
                    .wrapping_mul(0xb57d1ebf).wrapping_sub(0x0c916c82);
            }
            let result = unsafe { reverse_affine_words(words.as_mut_ptr().add(count + 1), count as u32) };
            assert_eq!(result, 0);
            assert_eq!(words, expected, "count={count}");
        }
    }

    #[test]
    fn zero_and_negative_counts_exit_without_access() {
        for count in [0, 0x80000000, 0x80000001, u32::MAX] {
            assert_eq!(unsafe { reverse_affine_words(core::ptr::null_mut(), count) }, 0);
        }
    }
}
