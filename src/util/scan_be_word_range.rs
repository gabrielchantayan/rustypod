//! Overlapping big-endian word range search.

/// Scan for the first big-endian u32 in the inclusive `[lower, upper]` range.
///
/// retailOS: `0x080b4df4`, 108 bytes, ending at the independent prologue at
/// `0x080b4e60`. Raw A32: zero outgoing BLs; two incoming plain BLs
/// (`0x0808ea54`, `0x081b0568`), zero incoming predicated BLs.
/// Initialize `skipped` to zero; while signed wrapping `remaining - 4 > 0`,
/// assemble four bytes, return 0 on a match, otherwise advance one byte and
/// increment `skipped`. Exhaustion returns 1. The final four-byte window is
/// intentionally not examined. Callers use this for video start-code searches;
/// `0x0808ea4c` supplies identical lower and upper bounds.
/// Deliberate deviations: none in behavior; Rust expresses the byte assembly
/// with `from_be_bytes` rather than the original shift/OR sequence.
/// Verification: host edge tests and ARM release build passed; a standalone
/// executable matched a reference across 22,692 searches. `match.py` reports
/// 27 stock versus 34 Rust instructions: same bytewise scan, unsigned inclusive
/// bounds, count writes, and strict length gate, with a larger frame and
/// byte-swap assembly. No callee seams or intentional symbol folding.
///
/// # Safety
/// `skipped` must be writable and aligned. `data` must permit four-byte reads
/// at every examined position, including for lengths whose wrapping subtraction
/// becomes positive. Byte reads preserve unaligned input and output aliasing.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scan_be_word_range(
    mut data: *const u8,
    mut remaining: i32,
    skipped: *mut u32,
    lower: u32,
    upper: u32,
) -> u32 {
    skipped.write(0);
    while remaining.wrapping_sub(4) > 0 {
        let word = u32::from_be_bytes([
            data.read(), data.add(1).read(), data.add(2).read(), data.add(3).read(),
        ]);
        if lower <= word && word <= upper {
            return 0;
        }
        data = data.add(1);
        skipped.write(skipped.read().wrapping_add(1));
        remaining = remaining.wrapping_sub(1);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(data: &[u8], lower: u32, upper: u32) -> (u32, u32) {
        for offset in 0..data.len().saturating_sub(4) {
            let word = data[offset..offset + 4].iter()
                .fold(0u32, |word, &byte| (word << 8) | u32::from(byte));
            if word >= lower && word <= upper {
                return (0, offset as u32);
            }
        }
        (1, data.len().saturating_sub(4) as u32)
    }

    #[test]
    fn short_and_signed_lengths_reset_output_without_reading() {
        for len in [i32::MIN + 4, -100, -1, 0, 1, 2, 3, 4] {
            let mut skipped = 99;
            let result = unsafe {
                scan_be_word_range(core::ptr::null(), len, &mut skipped, 0, u32::MAX)
            };
            assert_eq!((result, skipped), (1, 0), "length {len}");
        }
    }

    #[test]
    fn inclusive_unsigned_bounds_and_reversed_range() {
        let data = [0x80, 0, 0, 1, 0];
        for (lower, upper, expected) in [
            (0x80000001, 0x80000001, 0),
            (0x80000001, u32::MAX, 0),
            (0, 0x80000001, 0),
            (0, 0x80000000, 1),
            (0x80000002, u32::MAX, 1),
            (u32::MAX, 0, 1),
        ] {
            let mut skipped = 99;
            let result = unsafe {
                scan_be_word_range(data.as_ptr(), 5, &mut skipped, lower, upper)
            };
            assert_eq!((result, skipped), (expected, expected));
        }
    }

    #[test]
    fn overlapping_unaligned_windows_and_excluded_tail() {
        let storage = [0xff, 0xff, 0, 0, 1, 0xb0, 0xff, 0xff];
        let data = &storage[1..];
        for len in 0..=data.len() {
            for (lower, upper) in [(0x1b0, 0x1b0), (0x120, 0x1ff),
                (0, u32::MAX), (u32::MAX, 0), (0xff000001, 0xff000001)] {
                let mut skipped = 99;
                let result = unsafe {
                    scan_be_word_range(data.as_ptr(), len as i32, &mut skipped, lower, upper)
                };
                assert_eq!((result, skipped), reference(&data[..len], lower, upper));
            }
        }
        let mut skipped = 99;
        assert_eq!(unsafe {
            scan_be_word_range(data.as_ptr(), 5, &mut skipped, 0x1b0, 0x1b0)
        }, 1);
        assert_eq!(skipped, 1); // Match at offset 1 is the excluded final window.
        assert_eq!(unsafe {
            scan_be_word_range(data.as_ptr(), 6, &mut skipped, 0x1b0, 0x1b0)
        }, 0);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn output_alias_is_written_before_input_is_read() {
        let mut words = [u32::MAX, u32::MAX];
        let output = words.as_mut_ptr();
        let result = unsafe { scan_be_word_range(output.cast(), 5, output, 0, 0) };
        assert_eq!(result, 0);
        assert_eq!(words, [0, u32::MAX]);
    }
}
