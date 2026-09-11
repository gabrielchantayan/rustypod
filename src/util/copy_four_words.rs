//! A fixed-width four-word copy helper.

/// copy_four_words — original: `FUN_08248698` @ **0x08248698** (**36 bytes
/// exactly**, `0x08248698..0x082486bc`; `0x082486bc` opens the distinct
/// source-to-destination sibling).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **14 direct inbound
/// `bl` call sites**, all unconditional; there are no predicated BL forms or
/// direct tail branches. The nine-instruction body copies four aligned words
/// from `source` (r0) to `destination` (r1), each load immediately followed
/// by its corresponding store. The final load reuses r0, so its value is both
/// stored in `destination[3]` and returned in r0. With overlap, each later
/// load observes earlier stores exactly as the instruction order dictates.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words(source: *const u32, destination: *mut u32) -> u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination.add(2).write(source.add(2).read());
    let final_word = source.add(3).read();
    destination.add(3).write(final_word);
    final_word
}

/// copy_four_words_paired — original: `FUN_08158c94` @ **0x08158c94**
/// (**28 bytes exactly**, `0x08158c94..0x08158cac`; the separately linked
/// next function begins at `0x08158cb0`).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **9 direct inbound
/// `bl` call sites**, all unconditional; there are no predicated BL forms or
/// direct tail branches. The six-instruction body first loads words 0 and 1
/// together, stores them together, then loads word 3 before word 2 and stores
/// word 2 before word 3. It leaves r0 untouched, so it returns `destination`.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap; load/store order is
/// observable in that case and is retained exactly.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_four_words_paired")]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_paired(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    let word0 = source.read();
    let word1 = source.add(1).read();
    destination.write(word0);
    destination.add(1).write(word1);
    let word3 = source.add(3).read();
    let word2 = source.add(2).read();
    destination.add(2).write(word2);
    destination.add(3).write(word3);
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{copy_four_words, copy_four_words_paired};

    /// Independent model of the four ordered `ldr`/`str` pairs. The returned
    /// value comes from the fourth load, after the first three stores.
    fn reference_four_word_copy(words: &mut [u32], source: usize, destination: usize) -> u32 {
        words[destination] = words[source];
        words[destination + 1] = words[source + 1];
        words[destination + 2] = words[source + 2];
        let final_word = words[source + 3];
        words[destination + 3] = final_word;
        final_word
    }

    /// Independent model of `FUN_08158c94`'s paired load/store schedule.
    fn reference_paired_four_word_copy(words: &mut [u32], source: usize, destination: usize) {
        let word0 = words[source];
        let word1 = words[source + 1];
        words[destination] = word0;
        words[destination + 1] = word1;
        let word3 = words[source + 3];
        let word2 = words[source + 2];
        words[destination + 2] = word2;
        words[destination + 3] = word3;
    }

    #[test]
    fn copies_distinct_four_word_ranges_and_returns_final_word() {
        let source = [0x1020_3040, 0x5060_7080, 0x90a0_b0c0, 0xd0e0_f001];
        let mut destination = [0; 4];

        let returned = unsafe { copy_four_words(source.as_ptr(), destination.as_mut_ptr()) };

        assert_eq!(destination, source);
        assert_eq!(returned, source[3]);
    }

    #[test]
    fn matches_ordered_instruction_model_for_all_four_word_overlaps() {
        // destination offsets -3 through +3 cover every overlap shape. In
        // particular, offsets +1..+3 prove later loads observe earlier stores.
        for destination in 0..=6 {
            let source = 3;
            let initial = [
                0x0000_0000,
                0x1111_1111,
                0x2222_2222,
                0x3333_3333,
                0x4444_4444,
                0x5555_5555,
                0x6666_6666,
                0x7777_7777,
                0x8888_8888,
                0x9999_9999,
            ];
            let mut expected = initial;
            let mut actual = initial;

            let expected_return = reference_four_word_copy(&mut expected, source, destination);
            let actual_return = unsafe {
                copy_four_words(actual.as_ptr().add(source), actual.as_mut_ptr().add(destination))
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(actual_return, expected_return, "destination={destination}");
        }
    }

    #[test]
    fn paired_copy_matches_instruction_order_for_all_four_word_overlaps() {
        // destination offsets -3 through +3 cover every overlap shape.
        // Positive offsets prove the second pair observes the first stores.
        for destination in 0..=6 {
            let source = 3;
            let initial = [
                0x0000_0000,
                0x1111_1111,
                0x2222_2222,
                0x3333_3333,
                0x4444_4444,
                0x5555_5555,
                0x6666_6666,
                0x7777_7777,
                0x8888_8888,
                0x9999_9999,
            ];
            let mut expected = initial;
            let mut actual = initial;

            reference_paired_four_word_copy(&mut expected, source, destination);
            let returned = unsafe {
                copy_four_words_paired(
                    actual.as_mut_ptr().add(destination),
                    actual.as_ptr().add(source),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(
                returned,
                actual.as_mut_ptr().wrapping_add(destination),
                "destination={destination}"
            );
        }
    }
}
