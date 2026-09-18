//! A fixed-width two-word copy helper.

/// copy_u32_pair — retailOS `FUN_081b4e10` @ 0x081b4e10,
/// `FUN_081bb6a4` @ 0x081bb6a4, and `FUN_083dc0cc` @ 0x083dc0cc (20 bytes
/// each).
///
/// Raw words establish the `FUN_081b4e10` extent as
/// `0x081b4e10..0x081b4e24`: `ldr r2,[r1]; str r2,[r0]; ldr r1,[r1,#4];
/// str r1,[r0,#4]; bx lr`; the next separately linked function begins at
/// 0x081b4e24. Decoding every ARM B/BL word in `osos.dec` verifies four
/// unconditional direct `bl` call sites (0x08158c88, 0x08158ccc,
/// 0x08158ce0, and 0x0815fbf8), with no predicated forms. The same
/// five-instruction leaf loads word 0 from `source` and stores it to
/// `destination`, then loads and stores word 1. It leaves `r0` unchanged,
/// returning `destination`. The second source load occurs after the first
/// destination store, so overlapping ranges have ordered forward-copy
/// semantics.
///
/// Deliberate deviations: volatile accesses preserve the retail load/store
/// order against LLVM transformations; they otherwise use the same aligned
/// word accesses as the ARM body.
///
/// # Safety
/// `source` must be valid for two aligned `u32` reads and `destination` for
/// two aligned `u32` writes. The ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_u32_pair")]
#[inline(never)]
pub unsafe extern "C" fn copy_u32_pair(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    destination.write_volatile(source.read_volatile());
    destination.add(1).write_volatile(source.add(1).read_volatile());
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_u32_pair;

    /// Independent instruction-order model: later source reads observe prior
    /// destination stores when the two ranges overlap.
    fn reference_ordered_pair_copy(words: &mut [u32], destination: usize, source: usize) {
        words[destination] = words[source];
        words[destination + 1] = words[source + 1];
    }

    #[test]
    fn copies_full_width_words_and_returns_destination() {
        let source = [0x0123_4567, 0x89ab_cdef];
        let mut surrounding = [0xfeed_face, 0, 0, 0xdead_beef];
        let destination = unsafe { surrounding.as_mut_ptr().add(1) };

        let returned = unsafe { copy_u32_pair(destination, source.as_ptr()) };

        assert_eq!(returned, destination);
        assert_eq!(surrounding, [0xfeed_face, source[0], source[1], 0xdead_beef]);
    }

    #[test]
    fn matches_two_instruction_pairs_for_all_overlaps() {
        for source in 0..=2 {
            for destination in 0..=2 {
                let initial = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
                let mut expected = initial;
                let mut actual = initial;

                reference_ordered_pair_copy(&mut expected, destination, source);
                let returned = unsafe {
                    copy_u32_pair(
                        actual.as_mut_ptr().add(destination),
                        actual.as_ptr().add(source),
                    )
                };

                assert_eq!(actual, expected, "source={source}, destination={destination}");
                assert_eq!(returned, unsafe { actual.as_mut_ptr().add(destination) });
            }
        }
    }
}
