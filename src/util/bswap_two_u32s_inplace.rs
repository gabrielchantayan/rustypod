//! Reverses the bytes of each word in a two-word record in place.

/// `bswap_two_u32s_inplace` — original: `FUN_0807fefc` @ **0x0807fefc**
/// (68 bytes exactly, `0x0807fefc..0x0807ff40`; the next function starts
/// with its own register-save prologue at `0x0807ff40`).
///
/// Raw ARM words contain two aligned load, shift/mask/OR, and store
/// sequences followed by `bx lr`. Each word's bytes are reversed without
/// exchanging the words. There are zero outgoing plain or predicated BLs;
/// incoming calls are zero plain BLs and two `blne`s, at `0x080be374` and
/// `0x080e4ecc`. Both callers conditionally convert a two-word stack record
/// according to the byte at receiver +0x400e3. The unchanged r0 is returned;
/// Ghidra's void prototype omits it. Deliberate deviations: none.
///
/// # Safety
///
/// `record` must be non-NULL, four-byte aligned, and writable for two u32s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bswap_two_u32s_inplace")]
#[inline(never)]
pub unsafe extern "C" fn bswap_two_u32s_inplace(record: *mut u32) -> *mut u32 {
    record.write_volatile(record.read_volatile().swap_bytes());
    record.add(1).write_volatile(record.add(1).read_volatile().swap_bytes());
    record
}

#[cfg(test)]
mod tests {
    use super::bswap_two_u32s_inplace;

    #[test]
    fn reverses_independent_words_without_touching_neighbors() {
        let mut words = [0x1357_9bdf, 0x0123_4567, 0x80fe_7fa5, 0x2468_ace0];
        let record = unsafe { words.as_mut_ptr().add(1) };
        assert_eq!(unsafe { bswap_two_u32s_inplace(record) }, record);
        assert_eq!(words, [0x1357_9bdf, 0x6745_2301, 0xa57f_fe80, 0x2468_ace0]);
    }

    #[test]
    fn byte_lane_boundaries_match_bytewise_reference() {
        for first in [0, u32::MAX, 1, 0xff, 0xff00, 0xff0000, 0xff000000, 0x80000000] {
            for second in [0, u32::MAX, 0x0102_0304, 0x807f_fe01] {
                let mut words = [first, second];
                let expected = words.map(|word: u32| {
                    let mut bytes = word.to_ne_bytes();
                    bytes.reverse();
                    u32::from_ne_bytes(bytes)
                });
                unsafe { bswap_two_u32s_inplace(words.as_mut_ptr()) };
                assert_eq!(words, expected);
            }
        }
    }
}
