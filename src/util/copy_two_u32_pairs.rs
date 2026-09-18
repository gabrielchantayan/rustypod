//! An ordered copy from two fixed-width word pairs.

use super::u32_pair_copy::copy_u32_pair;

/// copy_two_u32_pairs — retailOS `FUN_08158c6c` @ 0x08158c6c (40 bytes,
/// 0x08158c6c..0x08158c94; the next separately linked function begins at
/// 0x08158c94).
///
/// Raw ARM words establish `push {r4,lr}; ldr/str` of the first source pair,
/// followed by `mov r1,r2; add r0,#8; bl 0x081b4e10; sub r0,#8; pop {r4,pc}`.
/// Decoding every ARM B/BL word in `osos.dec` finds four incoming unconditional
/// plain `bl` calls and no predicated BL forms. It copies an aligned two-word
/// first source to words 0–1 of `destination`, then delegates the ordered
/// two-word second-source copy to words 2–3, returning `destination`.
///
/// Deliberate deviations: volatile first-pair accesses preserve the original
/// load/store order against LLVM; the existing `copy_u32_pair` port implements
/// the original direct callee rather than duplicating its body.
///
/// # Safety
/// `first_source` and `second_source` must each be valid for two aligned `u32`
/// reads, and `destination` must be valid for four aligned `u32` writes. All
/// ranges may overlap; instruction order is observable.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_two_u32_pairs")]
#[inline(never)]
pub unsafe extern "C" fn copy_two_u32_pairs(
    destination: *mut u32,
    first_source: *const u32,
    second_source: *const u32,
) -> *mut u32 {
    destination.write_volatile(first_source.read_volatile());
    destination.add(1).write_volatile(first_source.add(1).read_volatile());
    copy_u32_pair(destination.add(2), second_source).sub(2)
}

#[cfg(test)]
mod tests {
    use super::copy_two_u32_pairs;

    fn reference_copy_two_u32_pairs(
        words: &mut [u32],
        destination: usize,
        first_source: usize,
        second_source: usize,
    ) {
        words[destination] = words[first_source];
        words[destination + 1] = words[first_source + 1];
        words[destination + 2] = words[second_source];
        words[destination + 3] = words[second_source + 1];
    }

    #[test]
    fn copies_distinct_pairs_and_returns_destination() {
        let first = [0x0123_4567, 0x89ab_cdef];
        let second = [0xfeed_face, 0xdead_beef];
        let mut destination = [0; 4];

        let returned = unsafe {
            copy_two_u32_pairs(destination.as_mut_ptr(), first.as_ptr(), second.as_ptr())
        };

        assert_eq!(destination, [first[0], first[1], second[0], second[1]]);
        assert_eq!(returned, destination.as_mut_ptr());
    }

    #[test]
    fn preserves_instruction_order_for_all_pair_overlaps() {
        for destination in 0..=4 {
            for first_source in 0..=6 {
                for second_source in 0..=6 {
                    let initial = [
                        0x1111_1111,
                        0x2222_2222,
                        0x3333_3333,
                        0x4444_4444,
                        0x5555_5555,
                        0x6666_6666,
                        0x7777_7777,
                        0x8888_8888,
                    ];
                    let mut expected = initial;
                    let mut actual = initial;
                    reference_copy_two_u32_pairs(
                        &mut expected,
                        destination,
                        first_source,
                        second_source,
                    );

                    let returned = unsafe {
                        copy_two_u32_pairs(
                            actual.as_mut_ptr().add(destination),
                            actual.as_ptr().add(first_source),
                            actual.as_ptr().add(second_source),
                        )
                    };

                    assert_eq!(
                        actual, expected,
                        "destination={destination}, first_source={first_source}, second_source={second_source}"
                    );
                    assert_eq!(returned, unsafe { actual.as_mut_ptr().add(destination) });
                }
            }
        }
    }
}
