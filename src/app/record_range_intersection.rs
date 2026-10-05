//! `record_range_intersection` — `FUN_081e3ecc` @ **0x081e3ecc**, 100 bytes.
//! Raw A32 extent ends at the independent push at 0x081e3f30. Whole-image
//! word decoding verifies two incoming plain BLs (0x081e3514, 0x081e5598),
//! zero predicated incoming BLs, and zero outgoing calls.
//!
//! Seed outputs from the first record's signed start/end at +0x1268/+0x126c,
//! then scan the signed count at +0x1080 with a 0x50-byte record stride.
//! Return the maximum start and minimum end, even for disjoint ranges; always
//! return status zero. Nonpositive counts still seed from the first record.
//! Callers use the result as a half-open interval for position checks.
//! Deliberate deviations: none. Volatile aligned word accesses retain the
//! original alias-sensitive ordering, including count reloads each iteration.

/// # Safety
/// `owner` must be aligned and readable through the count and first range,
/// and through every record selected by the signed count. Outputs must be
/// aligned writable words. They may alias each other or writable owner words;
/// any count mutations must leave the accessed records valid. No NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_range_intersection(
    owner: *const i32, start: *mut i32, end: *mut i32,
) -> u32 {
    unsafe {
        start.write_volatile(owner.add(0x1268 / 4).read_volatile());
        end.write_volatile(owner.add(0x126c / 4).read_volatile());
        let mut index = 0i32;
        while owner.add(0x1080 / 4).read_volatile() > index {
            let record = owner.add(0x1268 / 4 + index as usize * (0x50 / 4));
            let record_start = record.read_volatile();
            let current_start = start.read_volatile();
            index += 1;
            if record_start > current_start {
                start.write_volatile(record_start);
            }
            let record_end = record.add(1).read_volatile();
            if record_end < end.read_volatile() {
                end.write_volatile(record_end);
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const START: usize = 0x1268 / 4;
    const END: usize = START + 1;
    const COUNT: usize = 0x1080 / 4;
    const STRIDE: usize = 0x50 / 4;

    #[test]
    fn signed_intersections_include_empty_counts_and_disjoint_ranges() {
        let cases: &[&[(i32, i32)]] = &[
            &[(4, 20)], &[(4, 20), (9, 15), (6, 18)],
            &[(-20, -2), (-10, -5)], &[(10, 11), (30, 40)],
            &[(i32::MIN, i32::MAX), (-1, 0), (i32::MAX, i32::MIN)],
            &[(7, 7), (7, 7)],
        ];
        for ranges in cases {
            for count in [-3, 0, 1, ranges.len() as i32] {
                let mut owner = [0x55555555i32; START + 3 * STRIDE + 2];
                owner[COUNT] = count;
                for (index, &(start, end)) in ranges.iter().enumerate() {
                    owner[START + index * STRIDE] = start;
                    owner[END + index * STRIDE] = end;
                }
                let before = owner;
                let mut expected = ranges[0];
                for &(start, end) in ranges.iter().take(count.max(0) as usize) {
                    expected.0 = expected.0.max(start);
                    expected.1 = expected.1.min(end);
                }
                let (mut start, mut end) = (123, 456);
                assert_eq!(unsafe { record_range_intersection(owner.as_ptr(), &mut start, &mut end) }, 0);
                assert_eq!((start, end), expected);
                assert_eq!(owner, before);
            }
        }
    }

    #[test]
    fn shared_output_retains_sequential_updates() {
        let mut owner = [0i32; START + STRIDE + 2];
        owner[COUNT] = 2;
        owner[START] = 5;
        owner[END] = 10;
        owner[START + STRIDE] = 20;
        owner[END + STRIDE] = 15;
        let mut output = -1;
        let output_ptr = &mut output as *mut i32;
        unsafe { record_range_intersection(owner.as_ptr(), output_ptr, output_ptr) };
        assert_eq!(output, 15);
    }

    #[test]
    fn output_aliases_record_and_count_with_reloads() {
        let mut owner = [0i32; START + STRIDE + 2];
        owner[COUNT] = 2;
        owner[START] = 0;
        owner[END] = 10;
        owner[START + STRIDE] = 5;
        owner[END + STRIDE] = 6;
        let ptr = owner.as_mut_ptr();
        let mut end = -1;
        unsafe { record_range_intersection(ptr, ptr.add(COUNT), &mut end) };
        assert_eq!(owner[COUNT], 0);
        assert_eq!(end, 10);

        owner[COUNT] = 2;
        owner[START] = 8;
        owner[END] = 3;
        unsafe { record_range_intersection(ptr, ptr.add(END), &mut end) };
        assert_eq!(owner[END], 8);
        assert_eq!(end, 6);
    }
}
