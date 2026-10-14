//! Ordered copy of two aligned firmware words.

/// `word_pair_copy_forward` — retailOS `FUN_083d3070` at **0x083d3070**.
/// True extent: **20 bytes**, `0x083d3070..0x083d3084`; the next function
/// begins with PUSH {r4,r5,r6,r7,lr}. Whole-image raw ARM decoding verifies
/// one plain inbound BL at 0x082691c8, zero predicated inbound BLs, and zero
/// outbound BLs. Copy source[0] to destination[0], then source[1] to
/// destination[1], using alternating aligned loads and stores. Later reads
/// observe earlier writes if the ranges overlap. r0 remains destination.
/// Caller 0x082690a4 copies the first two words of an insertion result into
/// an eight-byte stack object. No callee seam is needed.
///
/// Deliberate deviations: none; expose the preserved r0 as the return value.
///
/// # Safety
/// Source must permit two aligned u32 reads and destination two aligned u32
/// writes. The ranges may overlap; neither pointer may be null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_pair_copy_forward(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    destination.write(source.read());
    destination.add(1).write(source.add(1).read());
    destination
}

#[cfg(test)]
mod tests {
    use super::word_pair_copy_forward;

    #[test]
    fn disjoint_copy_preserves_neighbors_and_all_bits() {
        for pair in [[0, u32::MAX], [0x80000000, 0x12345678], [u32::MAX, 0]] {
            let source = [0x11111111, pair[0], pair[1], 0x22222222];
            let mut destination = [0x33333333, 0, 0, 0x44444444];
            let dst = unsafe { destination.as_mut_ptr().add(1) };
            assert_eq!(unsafe { word_pair_copy_forward(dst, source.as_ptr().add(1)) }, dst);
            assert_eq!(destination, [0x33333333, pair[0], pair[1], 0x44444444]);
            assert_eq!(source, [0x11111111, pair[0], pair[1], 0x22222222]);
        }
    }

    #[test]
    fn overlapping_copy_matches_sequential_word_reference() {
        for source_index in 0..4 {
            for destination_index in 0..4 {
                let mut actual = [0x12345678, 0xabcdef01, 0, u32::MAX, 0x80000000];
                let mut expected = actual;
                expected[destination_index] = expected[source_index];
                expected[destination_index + 1] = expected[source_index + 1];
                let base = actual.as_mut_ptr();
                let dst = unsafe { base.add(destination_index) };
                assert_eq!(unsafe { word_pair_copy_forward(dst, base.add(source_index)) }, dst);
                assert_eq!(actual, expected, "source={source_index}, destination={destination_index}");
            }
        }
    }
}
