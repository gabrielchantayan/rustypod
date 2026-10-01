//! Optional mixed-field record equality — `FUN_0829fa28` @ `0x0829fa28`.
//! True size: 132 bytes, ending at `bx lr` at 0x0829faa8, before the
//! independent function's push at 0x0829faac. Raw ARM-word decoding finds
//! two plain incoming BLs (0x0829fce0, 0x0829ff14), zero predicated incoming
//! BLs, and zero plain or predicated outgoing BLs.
//!
//! Compare presence bytes exactly; equal zero bytes ignore all payload.
//! Otherwise compare byte +1, words +4/+12/+8, then bytes +16/+17/+18,
//! stopping at the first mismatch. Padding +2/+3 and +19 is ignored.
//! Both real callers pass object +0x94; domain identity is unproven.
//! Deliberate deviations: unsigned byte loads replace signed payload loads
//! without changing equality. Volatile reads preserve conditional access.

/// # Safety
/// Both pointers must be readable through the first compared mismatch (or
/// through byte +18 when present and equal). Word fields must be four-byte
/// aligned when reached. Absent records need only one readable byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_mixed_record_equal(left: *const u8, right: *const u8) -> u32 {
    let left_present = left.read_volatile();
    let right_present = right.read_volatile();
    if left_present != right_present {
        return 0;
    }
    if left_present == 0 {
        return 1;
    }
    if left.add(1).read_volatile() != right.add(1).read_volatile() {
        return 0;
    }
    for index in [1, 3, 2] {
        let left_word = left.cast::<u32>().add(index).read_volatile();
        let right_word = right.cast::<u32>().add(index).read_volatile();
        if left_word != right_word {
            return 0;
        }
    }
    for offset in 16..=18 {
        if left.add(offset).read_volatile() != right.add(offset).read_volatile() {
            return 0;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::optional_mixed_record_equal;

    fn compare(left: &[u32], right: &[u32]) -> u32 {
        unsafe { optional_mixed_record_equal(left.as_ptr().cast(), right.as_ptr().cast()) }
    }

    fn reference(left: &[u8], right: &[u8]) -> u32 {
        if left[0] != right[0] { return 0; }
        if left[0] == 0 { return 1; }
        u32::from([1, 4, 5, 6, 7, 12, 13, 14, 15, 8, 9, 10, 11, 16, 17, 18]
            .iter().all(|&offset| left[offset] == right[offset]))
    }

    #[test]
    fn exact_presence_gates_payload_access() {
        for left in 0..=255u8 {
            for right in 0..=255u8 {
                if left == right && left != 0 { continue; }
                assert_eq!(unsafe { optional_mixed_record_equal(&left, &right) },
                    u32::from(left == right));
            }
        }
        assert_eq!(compare(&[0xffff_ff00, 1, 2, 3, 4], &[0, 9, 8, 7, 6]), 1);
    }

    #[test]
    fn every_payload_bit_and_ignored_padding_matches_reference() {
        for present in [1u32, 0x80, 0xff] {
            let left = [0xa5a5_8000 | present, 0, 0x8000_0000, 0xffff_ffff, 0x5aff_0180, 7];
            for offset in 1..24 {
                for bit in 0..8 {
                    let mut right = left;
                    unsafe { right.as_mut_ptr().cast::<u8>().add(offset).write(
                        left.as_ptr().cast::<u8>().add(offset).read() ^ (1 << bit)); }
                    let left_bytes = unsafe { core::slice::from_raw_parts(left.as_ptr().cast(), 24) };
                    let right_bytes = unsafe { core::slice::from_raw_parts(right.as_ptr().cast(), 24) };
                    let expected = reference(left_bytes, right_bytes);
                    assert_eq!(compare(&left, &right), expected, "offset {offset}, bit {bit}");
                    assert_eq!(compare(&right, &left), expected);
                }
            }
            assert_eq!(compare(&left, &left), 1);
        }
    }

    #[test]
    fn mismatch_stops_before_unavailable_suffix() {
        assert_eq!(unsafe { optional_mixed_record_equal([1u8, 0x80].as_ptr(),
            [1u8, 0xff].as_ptr()) }, 0);
        assert_eq!(compare(&[1, 0], &[1, 1]), 0);
        // +12 precedes +8: no trailing byte fields are readable here.
        assert_eq!(compare(&[1, 2, 3, 4], &[1, 2, 3, 5]), 0);
        assert_eq!(compare(&[1, 2, 3, 4], &[1, 2, 5, 4]), 0);
        for offset in 16..=18 {
            let left = [1u32, 2, 3, 4, 0];
            let mut right = left;
            unsafe { right.as_mut_ptr().cast::<u8>().add(offset).write(0xff); }
            assert_eq!(compare(&left, &right), 0);
        }
    }
}
