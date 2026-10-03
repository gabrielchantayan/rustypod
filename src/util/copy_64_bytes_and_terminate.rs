//! Fixed-size, word-aligned copy with an appended byte terminator.

/// copy_64_bytes_and_terminate — retailOS `FUN_08257288` @ 0x08257288.
/// True extent: 36 bytes, through 0x082572ac (next function's push).
/// Whole-image A32 decoding verifies two plain inbound BLs at 0x0824f29c
/// and 0x0824f310, zero predicated inbound BLs, and zero outbound BLs.
/// Copies exactly sixteen aligned words in ascending order, then writes
/// zero to destination byte 64. Embedded zero bytes do not stop the copy.
/// Leaves r0 unchanged, returning destination; both raw callers consume it.
/// Ghidra's void return and caller addresses do not match the raw evidence.
///
/// Deliberate deviations: volatile word accesses preserve sequential overlap
/// behavior and prevent LLVM from substituting a memcpy builtin. No behavioral
/// deviations; this is not memmove and must not snapshot overlapping input.
///
/// # Safety
/// Source must permit sixteen aligned u32 reads. Destination must permit
/// sixteen aligned u32 writes plus a byte write at offset 64. Ranges may
/// overlap; neither pointer may be null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_64_bytes_and_terminate(
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    for index in 0..16 {
        destination.add(index).write_volatile(source.add(index).read_volatile());
    }
    destination.cast::<u8>().add(64).write_volatile(0);
    destination
}

#[cfg(test)]
mod tests {
    use super::copy_64_bytes_and_terminate;

    #[test]
    fn copies_past_embedded_nuls_and_only_clears_one_trailing_byte() {
        let source = [0x8000_00ff, 0, 0xffff_ffff, 0x1234_5678,
            4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xabcd_ef00];
        let mut storage = [0xfeed_face; 19];
        let destination = unsafe { storage.as_mut_ptr().add(1) };
        let returned = unsafe { copy_64_bytes_and_terminate(destination, source.as_ptr()) };
        assert_eq!(returned, destination);
        assert_eq!(&storage[1..17], &source);
        assert_eq!(storage[0], 0xfeed_face);
        let mut expected_tail = 0xfeed_faceu32.to_ne_bytes();
        expected_tail[0] = 0;
        assert_eq!(storage[17].to_ne_bytes(), expected_tail);
        assert_eq!(storage[18], 0xfeed_face);
    }

    #[test]
    fn matches_ordered_word_copy_for_aliasing_and_both_overlap_directions() {
        for source in 0..=16 {
            for destination in 0..=16 {
                let mut actual = [0u32; 34];
                for (index, word) in actual.iter_mut().enumerate() {
                    *word = 0x8102_03ffu32.wrapping_mul(index as u32 + 1);
                }
                let mut expected = actual;
                for index in 0..16 {
                    expected[destination + index] = expected[source + index];
                }
                let mut tail = expected[destination + 16].to_ne_bytes();
                tail[0] = 0;
                expected[destination + 16] = u32::from_ne_bytes(tail);
                let returned = unsafe {
                    copy_64_bytes_and_terminate(
                        actual.as_mut_ptr().add(destination), actual.as_ptr().add(source),
                    )
                };
                assert_eq!(actual, expected, "source={source}, destination={destination}");
                assert_eq!(returned, unsafe { actual.as_mut_ptr().add(destination) });
            }
        }
    }
}
