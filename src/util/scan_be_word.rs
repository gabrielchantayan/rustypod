//! Exact overlapping big-endian word search.

/// retailOS `0x0808ea4c`, 16 bytes, ending at the independent function at
/// `0x0808ea5c`. Raw aligned A32 decoding verifies two incoming plain BLs,
/// zero incoming predicated BLs, one outgoing plain BL, and no predicated BLs.
/// Search overlapping big-endian words by supplying `word` as both inclusive
/// bounds to `scan_be_word_range` (verified callee `0x080b4df4`). Return zero
/// on a match, one on exhaustion, and write the rejected-window count to
/// `skipped`. The signed wrapping length gate excludes the final four-byte
/// window. Deliberate deviations: Rust delegates directly instead of manually
/// spilling r3 as the fifth ABI argument; no behavioral deviations.
///
/// # Safety
/// `skipped` must be writable and aligned. `data` must support four-byte reads
/// at each examined position, including wrapping signed lengths. Output may
/// alias input; the callee resets it before examining the first window.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scan_be_word(
    data: *const u8,
    remaining: i32,
    skipped: *mut u32,
    word: u32,
) -> u32 {
    super::scan_be_word_range::scan_be_word_range(data, remaining, skipped, word, word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_unsigned_match_and_excluded_final_window() {
        let storage = [0xff, 0x80, 0, 0, 1, 0x80, 0, 0, 2, 0];
        let data = &storage[1..];
        for (len, word, expected) in [
            (9, 0x80000001, (0, 0)),
            (9, 0x80000002, (0, 4)),
            (8, 0x80000002, (1, 4)),
            (9, 0x80000000, (1, 5)),
            (9, 0x80000003, (1, 5)),
        ] {
            let mut skipped = 99;
            let result = unsafe { scan_be_word(data.as_ptr(), len, &mut skipped, word) };
            assert_eq!((result, skipped), expected);
        }
    }

    #[test]
    fn signed_length_gate_and_wrap() {
        for len in [i32::MIN + 4, -1, 0, 1, 2, 3, 4] {
            let mut skipped = 99;
            let result = unsafe { scan_be_word(core::ptr::null(), len, &mut skipped, 0) };
            assert_eq!((result, skipped), (1, 0));
        }
        let data = [0xff; 4];
        for len in i32::MIN..=i32::MIN + 3 {
            let mut skipped = 99;
            let result = unsafe { scan_be_word(data.as_ptr(), len, &mut skipped, u32::MAX) };
            assert_eq!((result, skipped), (0, 0));
        }
    }

    #[test]
    fn aliased_output_is_reset_before_search() {
        let mut data = [u32::MAX, u32::MAX];
        let output = data.as_mut_ptr();
        let result = unsafe { scan_be_word(output.cast(), 5, output, 0) };
        assert_eq!(result, 0);
        assert_eq!(data, [0, u32::MAX]);
    }
}
