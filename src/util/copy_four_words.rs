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
/// `copy_four_words_property_output` — retailOS `FUN_0823b4a4` at
/// **0x0823b4a4** (36 bytes, `0x0823b4a4..0x0823b4c8`).
///
/// Raw A32 words decode to four alternating aligned LDR/STR pairs and BX LR;
/// the next function begins with PUSH {r4,r5,lr}. Whole-image branch decoding
/// verifies two plain inbound BLs (0x0824d2e4 and 0x08255560), zero predicated
/// BLs, and zero outbound calls. Copy four property words from r0 to r1 in
/// ascending order, returning the final word loaded into r0. Later reads
/// observe earlier stores when the ranges overlap.
///
/// Deliberate deviations: none. A dedicated text section retains this hook
/// symbol separately from byte-identical copy helpers.
///
/// # Safety
/// `source` must allow four aligned u32 reads and `destination` four aligned
/// u32 writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_four_words_property_output")]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_property_output(
    source: *const u32,
    destination: *mut u32,
) -> u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination.add(2).write(source.add(2).read());
    let final_word = source.add(3).read();
    destination.add(3).write(final_word);
    final_word
}

/// copy_four_words_forward — original: `FUN_083da42c` @ **0x083da42c**
/// (**36 bytes exactly**, `0x083da42c..0x083da450`; `0x083da450` opens the
/// next separately linked function).
///
/// Raw ARM decoding verifies four direct inbound `bl` call sites, all
/// unconditional; there are no predicated `bl` forms. The nine-instruction
/// body copies four aligned words from `source` (r1) to `destination` (r0),
/// with each load immediately followed by its store. This ordered schedule is
/// observable when the ranges overlap; r0 remains the destination return
/// value.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_forward(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination.add(2).write(source.add(2).read());
    destination.add(3).write(source.add(3).read());
    destination
}
/// `copy_four_words_forward_property` — retailOS `FUN_08256d74` at
/// **0x08256d74** (36 bytes exactly, `0x08256d74..0x08256d98`; the next
/// separately linked function begins with `push {r0-r11,lr}` at 0x08256d98).
///
/// Raw ARM decoding verifies four direct inbound plain `bl` calls
/// (0x0824d2a4, 0x0824f180, 0x08250340, and 0x08255758), with no predicated
/// `bl` calls. The body copies four aligned words from `source` (r0) to
/// `destination` (r1), each load immediately followed by its store. The
/// final load reuses r0, so it is stored at `destination[3]` and returned.
/// That schedule is observable for overlapping ranges.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_four_words_forward_property")]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_forward_property(
    source: *const u32,
    destination: *mut u32,
) -> u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination.add(2).write(source.add(2).read());
    let final_word = source.add(3).read();
    destination.add(3).write(final_word);
    final_word
}

/// copy_four_words_forward_alt — retailOS `FUN_083da248` at `0x083da248`
/// (36 bytes; four unconditional plain-`bl` call sites, binary-verified).
///
/// Raw ARM establishes the true extent as `0x083da248..0x083da26c`: four
/// aligned load/store pairs followed by `bx lr`; the next independent function
/// begins with `push {r4,r5,lr}` at `0x083da26c`. The body is byte-identical
/// to [`copy_four_words_forward`] at 0x083da42c, but needs its own symbol for
/// a hook at this separately linked entry. It copies four words from `source`
/// to `destination` in ascending offset order and returns `destination`.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_four_words_forward_alt")]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_forward_alt(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination.add(2).write(source.add(2).read());
    destination.add(3).write(source.add(3).read());
    destination
}
/// copy_four_words_forward_alias_a2e0 — original: `FUN_083da2e0` @
/// **0x083da2e0** (36 bytes exactly, `0x083da2e0..0x083da300`; the next real
/// function begins at `0x083da304`).
///
/// Raw ARM verifies two direct inbound plain `bl` calls (0x083df1a8 and
/// 0x083dff4c), no predicated `bl` forms, and no outgoing calls. The
/// nine-instruction body copies four aligned words from `source` (r1) to
/// `destination` (r0), each load immediately followed by its store; r0 is
/// retained as the return value. This schedule is observable when ranges
/// overlap.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_four_words_forward_alias_a2e0")]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_forward_alias_a2e0(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination.add(2).write(source.add(2).read());
    destination.add(3).write(source.add(3).read());
    destination
}



/// copy_four_words_staggered — original: `FUN_08248704` @ **0x08248704**
/// (**36 bytes exactly**, `0x08248704..0x08248728`; `0x08248728` opens the
/// next separately linked function).
///
/// Decoding every ARM B/BL word in `osos.dec` verifies **8 direct inbound
/// `bl` call sites**, all unconditional; seven unconditional direct `b` tail
/// branches also target it, and there are no predicated forms. The
/// nine-instruction body copies four aligned words from `source` (r1) to
/// `destination` (r0), loading and storing words in 0, 2, 1, 3 order. It
/// leaves r0 intact and returns `destination`. With overlap, each later load
/// observes earlier stores exactly as the instruction order dictates.
///
/// Deliberate deviations: none.
///
/// # Safety
/// `source` must be valid for four aligned `u32` reads and `destination` for
/// four aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_four_words_staggered")]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_staggered(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    destination.write(source.read());
    destination.add(2).write(source.add(2).read());
    destination.add(1).write(source.add(1).read());
    destination.add(3).write(source.add(3).read());
    destination
}

/// copy_four_words_staggered_property — retailOS `thunk_FUN_08248704`
/// at **0x08256c50**, **4 bytes**, `0x08256c50..0x08256c54`.
///
/// The sole raw word is `0xeaffc6ab`: an unconditional tail branch to
/// [`copy_four_words_staggered`] at 0x08248704. The next real function at
/// 0x08256c54 adjusts r0 by 16 before branching to the same helper.
/// Full-image ARM decoding finds two inbound plain BL calls (0x0824d47c,
/// 0x0824d4b0), zero predicated BL calls, and no outgoing BL calls.
/// Copy four aligned words in load/store order 0, 2, 1, 3 and return the
/// unchanged destination pointer, including for overlapping ranges.
///
/// Deliberate deviations: LLVM adds a balanced frame-pointer prologue and
/// epilogue before the tail branch; argument and return semantics are unchanged.
///
/// # Safety
/// `source` must allow four aligned u32 reads and `destination` four aligned
/// u32 writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_staggered_property(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    copy_four_words_staggered(destination, source)
}

/// copy_four_words_staggered_member_10 — retailOS `FUN_0824c39c` at
/// **0x0824c39c**, **8 bytes**, `0x0824c39c..0x0824c3a4`.
///
/// Raw words `0xe2800010, 0xeafff0d7` add 16 bytes to r0 and tail-branch
/// to [`copy_four_words_staggered`] at 0x08248704. The next real function
/// starts at 0x0824c3a4 with `str r1,[r0,#0x64]; bx lr`.
/// Full-image ARM decoding finds two inbound plain BL calls (0x08254614,
/// 0x08256300), zero predicated BL calls, and zero outgoing BL calls.
/// Copy four aligned words into object words 4..8 in load/store order
/// 0, 2, 1, 3, observing earlier stores on overlap; return object + 16.
///
/// Deliberate deviations: LLVM adds balanced frame-pointer setup/teardown
/// before the tail branch; algorithm and ABI are unchanged. Ghidra's void
/// return is corrected to preserve the adjusted destination returned in r0.
///
/// # Safety
/// `object` must allow pointer arithmetic through word 8 and aligned writes
/// to words 4..8; `source` must allow four aligned u32 reads. Ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_staggered_member_10(
    object: *mut u32,
    source: *const u32,
) -> *mut u32 {
    copy_four_words_staggered(object.add(4), source)
}

/// copy_four_words_staggered_member_20 — retailOS `FUN_0824c484` at
/// **0x0824c484**, **8 bytes**, `0x0824c484..0x0824c48c`.
///
/// Raw words `0xe2800020, 0xeafff09d` add 32 bytes to r0 and tail-branch
/// to [`copy_four_words_staggered`] at 0x08248704. The next real function
/// starts at 0x0824c48c with `str r1,[r0,#0x5c]; bx lr`.
/// Full-image ARM decoding finds two inbound plain BL calls (0x08254630,
/// 0x08256350), zero predicated BL calls, and zero outgoing BL calls.
/// Copy four aligned words into object words 8..12 in load/store order
/// 0, 2, 1, 3, observing earlier stores on overlap; return object + 32.
///
/// Deliberate deviations: LLVM adds balanced frame-pointer setup/teardown
/// before the tail branch; algorithm and ABI are unchanged. Ghidra's void
/// return is corrected to preserve the adjusted destination returned in r0.
///
/// # Safety
/// `object` must allow pointer arithmetic through word 12 and aligned writes
/// to words 8..12; `source` must allow four aligned u32 reads. Ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_four_words_staggered_member_20(
    object: *mut u32,
    source: *const u32,
) -> *mut u32 {
    copy_four_words_staggered(object.add(8), source)
}

#[cfg(test)]
mod staggered_member_10_tests {
    use super::copy_four_words_staggered_member_10;

    #[test]
    fn member_copy_preserves_overlap_order_return_and_surroundings() {
        for object in 0..=8 {
            for source in 0..=12 {
                let mut actual = core::array::from_fn::<_, 16, _>(
                    |i| [0, u32::MAX, 0x8000_0000, 0x1234_5678][i % 4] ^ i as u32,
                );
                let mut expected = actual;
                let destination = object + 4;
                for word in [0, 2, 1, 3] {
                    expected[destination + word] = expected[source + word];
                }
                let base = actual.as_mut_ptr();
                let returned = unsafe {
                    copy_four_words_staggered_member_10(
                        base.add(object), base.add(source),
                    )
                };
                assert_eq!(returned, unsafe { base.add(destination) });
                assert_eq!(actual, expected, "object={object}, src={source}");
            }
        }
    }
}

#[cfg(test)]
mod staggered_member_20_tests {
    use super::copy_four_words_staggered_member_20;

    #[test]
    fn member_copy_preserves_overlap_order_return_and_surroundings() {
        for object in 0..=4 {
            for source in 0..=12 {
                let mut actual = core::array::from_fn::<_, 16, _>(
                    |i| 0x8765_0000 + i as u32,
                );
                let mut expected = actual;
                let destination = object + 8;
                for word in [0, 2, 1, 3] {
                    expected[destination + word] = expected[source + word];
                }
                let base = actual.as_mut_ptr();
                let returned = unsafe {
                    copy_four_words_staggered_member_20(
                        base.add(object), base.add(source),
                    )
                };
                assert_eq!(returned, unsafe { base.add(destination) });
                assert_eq!(actual, expected, "object={object}, src={source}");
            }
        }
    }
}

#[cfg(test)]
mod staggered_property_tests {
    use super::copy_four_words_staggered_property;

    #[test]
    fn preserves_order_for_every_overlap_and_disjoint_range() {
        for source in 0..=8 {
            for destination in 0..=8 {
                let mut actual = core::array::from_fn::<_, 12, _>(
                    |i| 0x1234_0000 + i as u32,
                );
                let mut expected = actual;
                for word in [0, 2, 1, 3] {
                    expected[destination + word] = expected[source + word];
                }
                let base = actual.as_mut_ptr();
                let dst = unsafe { base.add(destination) };
                let returned = unsafe {
                    copy_four_words_staggered_property(dst, base.add(source))
                };
                assert_eq!(returned, dst);
                assert_eq!(actual, expected, "src={source}, dst={destination}");
            }
        }
    }
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

    use super::{
        copy_four_words, copy_four_words_forward, copy_four_words_forward_alias_a2e0,
        copy_four_words_forward_alt, copy_four_words_forward_property, copy_four_words_paired,
        copy_four_words_staggered,
    };
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

    /// Independent model of `FUN_08248704`'s ordered load/store schedule.
    fn reference_staggered_four_word_copy(
        words: &mut [u32],
        source: usize,
        destination: usize,
    ) {
        words[destination] = words[source];
        words[destination + 2] = words[source + 2];
        words[destination + 1] = words[source + 1];
        words[destination + 3] = words[source + 3];
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
    fn forward_property_matches_ordered_instruction_model_for_all_four_word_overlaps() {
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
                copy_four_words_forward_property(
                    actual.as_ptr().add(source),
                    actual.as_mut_ptr().add(destination),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(actual_return, expected_return, "destination={destination}");
        }
    }

    #[test]
    fn forward_alt_matches_ordered_instruction_model_for_all_four_word_overlaps() {
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

            reference_four_word_copy(&mut expected, source, destination);
            let expected_return = unsafe { actual.as_mut_ptr().add(destination) };
            let actual_return = unsafe {
                copy_four_words_forward_alt(expected_return, actual.as_ptr().add(source))
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(actual_return, expected_return);
        }
    }
    #[test]
    fn forward_alias_a2e0_returns_destination_and_matches_all_overlap_shapes() {
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

            reference_four_word_copy(&mut expected, source, destination);
            let returned = unsafe {
                copy_four_words_forward_alias_a2e0(
                    actual.as_mut_ptr().add(destination),
                    actual.as_ptr().add(source),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(returned, actual.as_mut_ptr().wrapping_add(destination));
        }
    }


    #[test]
    fn forward_copy_returns_destination_and_matches_all_word_overlap_shapes() {
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

            reference_four_word_copy(&mut expected, source, destination);
            let returned = unsafe {
                copy_four_words_forward(
                    actual.as_mut_ptr().add(destination),
                    actual.as_ptr().add(source),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(returned, actual.as_mut_ptr().wrapping_add(destination));
        }
    }

    #[test]
    fn staggered_copy_returns_destination_after_copying_distinct_range() {
        let source = [0x1020_3040, 0x5060_7080, 0x90a0_b0c0, 0xd0e0_f001];
        let mut destination = [0; 4];

        let returned = unsafe {
            copy_four_words_staggered(destination.as_mut_ptr(), source.as_ptr())
        };

        assert_eq!(destination, source);
        assert_eq!(returned, destination.as_mut_ptr());
    }

    #[test]
    fn staggered_copy_matches_instruction_order_for_all_four_word_overlaps() {
        // Destination offsets -3 through +3 cover every overlap shape. In
        // particular, offsets +1..+3 prove the 2, 1, 3 loads observe prior
        // stores, unlike the source-order sibling.
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

            reference_staggered_four_word_copy(&mut expected, source, destination);
            let returned = unsafe {
                copy_four_words_staggered(
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
    #[test]
    fn property_output_preserves_order_return_and_guards() {
        let initial = [
            0, 0xffff_ffff, 0x8000_0000, 0x1234_5678, 0x90ab_cdef,
            0x5555_aaaa, 0xdead_beef, 7, 8, 9, 10, 11,
        ];
        for source in 0..=8 {
            for destination in 0..=8 {
                let mut expected = initial;
                let mut actual = initial;
                reference_four_word_copy(&mut expected, source, destination);
                let returned = unsafe {
                    super::copy_four_words_property_output(
                        actual.as_ptr().add(source),
                        actual.as_mut_ptr().add(destination),
                    )
                };
                assert_eq!(actual, expected, "source={source}, destination={destination}");
                assert_eq!(returned, expected[destination + 3]);
            }
        }
    }
}
