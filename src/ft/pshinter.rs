use crate::ft::memory::{ft_mem_realloc, FtMemory};

/// Appends a blank 16-byte stem record — original `FUN_080b089c` @
/// 0x080b089c (160 bytes; 1 plain `bl`, 0 predicated `bl`; 3 direct `bl`
/// caller sites).
///
/// The three-word target-width array header holds `count`, `capacity`, and a
/// record pointer. When full, capacity rounds `count + 1` up to eight records
/// and [`ft_mem_realloc`] grows the 16-byte record array. On success the new
/// record's first and fourth words are cleared, the count advances, and its
/// address is returned through `out_record`. Allocation failure leaves the
/// header unchanged and returns the allocator error with a null output.
///
/// Deliberate deviation: target pointers remain `u32` words rather than host
/// pointers so the firmware layout is preserved; the caller must supply a
/// target-addressable record buffer on host tests.
///
/// # Safety
/// `records` and `out_record` must be valid target-width objects. If growth is
/// required, `memory` must satisfy [`ft_mem_realloc`]'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_dimension_append_stem_record(
    records: *mut u32,
    memory: *mut FtMemory,
    out_record: *mut u32,
) -> i32 {
    let count = *records;
    let next_count = count.wrapping_add(1);
    let capacity = *records.add(1);
    let mut error = 0;

    if capacity < next_count {
        let next_capacity = next_count.wrapping_add(7) & !7;
        let block = *records.add(2) as usize as *mut u8;
        let grown = ft_mem_realloc(
            memory,
            16,
            capacity as i32,
            next_capacity as i32,
            block,
            &mut error,
        );
        *records.add(2) = grown as usize as u32;
        if error == 0 {
            *records.add(1) = next_capacity;
        }
    }

    let record = if error == 0 {
        let record = ((*records.add(2) as usize as *mut u8).add(next_count as usize * 16 - 16)).cast::<u32>();
        *record = 0;
        *record.add(3) = 0;
        *records = next_count;
        record as usize as u32
    } else {
        0
    };
    *out_record = record;
    error
}

/// Scales a dimension's stem widths — original `FUN_080d4898` @
/// 0x080d4898 (144 bytes, next function at 0x080d4928; 2 plain BL sites,
/// 0 predicated BL sites, both to `ft_mulfix` @ 0x0804d2cc).
///
/// Selects a 51-word (0xcc-byte) dimension, reads its count at word 1 and
/// 16.16 scale at word 50, and scales the width triples starting at word 2.
/// The first scaled width is the reference: subsequent widths whose signed,
/// wrapping absolute difference is less than 128 reuse it. Each scaled width
/// also gets a grid-rounded value `(width + 32) & !63`. Zero count writes
/// nothing. No deliberate behavioral deviations; word indexing preserves
/// the target layout on hosts, including ARM's wrapping signed arithmetic.
///
/// # Safety
/// `dimensions` must point to aligned, writable 51-word dimension records;
/// `dimension` must select a valid record, whose count is at most 16.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn psh_dimension_scale_widths(dimensions: *mut i32, dimension: u32) {
    let selected = dimensions.add(dimension.wrapping_mul(51) as usize);
    let mut remaining = *selected.add(1) as u32;
    let scale = *selected.add(50);
    if remaining == 0 {
        return;
    }
    let first = selected.add(2);
    let reference = crate::ft::calc::ft_mulfix(*first, scale);
    *first.add(1) = reference;
    *first.add(2) = reference.wrapping_add(32) & !63;
    remaining = remaining.wrapping_sub(1);
    let mut width = first.add(3);
    while remaining != 0 {
        let mut scaled = crate::ft::calc::ft_mulfix(*width, scale);
        let difference = scaled.wrapping_sub(reference);
        let magnitude = if difference < 0 { difference.wrapping_neg() } else { difference };
        if magnitude < 128 {
            scaled = reference;
        }
        *width.add(1) = scaled;
        *width.add(2) = scaled.wrapping_add(32) & !63;
        width = width.add(3);
        remaining = remaining.wrapping_sub(1);
    }
}

#[cfg(test)]
mod scale_width_tests {
    use super::psh_dimension_scale_widths;

    #[test]
    fn empty_dimension_preserves_every_word() {
        let mut dimensions = [0x12345678; 102];
        dimensions[52] = 0;
        let original = dimensions;
        unsafe { psh_dimension_scale_widths(dimensions.as_mut_ptr(), 1); }
        assert_eq!(dimensions, original);
    }

    #[test]
    fn selected_dimension_snaps_strictly_to_first_and_preserves_inputs() {
        let mut dimensions = [0x12345678; 102];
        let widths = [1000, 1127, 1128, 873, 872, 1254, 1380];
        dimensions[52] = widths.len() as i32;
        dimensions[101] = 0x10000;
        for (i, width) in widths.iter().enumerate() {
            dimensions[53 + i * 3] = *width;
        }
        let mut expected = dimensions;
        for (i, scaled) in [1000i32, 1000, 1128, 1000, 872, 1254, 1380].iter().enumerate() {
            expected[54 + i * 3] = *scaled;
            expected[55 + i * 3] = scaled.wrapping_add(32) & !63;
        }
        unsafe { psh_dimension_scale_widths(dimensions.as_mut_ptr(), 1); }
        assert_eq!(dimensions, expected);
    }

    #[test]
    fn negative_half_scale_and_grid_ties() {
        let mut dimension = [0; 51];
        dimension[1] = 4;
        dimension[50] = -0x8000;
        for (i, input) in [64, 320, 576, -64].iter().enumerate() {
            dimension[2 + i * 3] = *input;
        }
        unsafe { psh_dimension_scale_widths(dimension.as_mut_ptr(), 0); }
        assert_eq!([dimension[3], dimension[6], dimension[9], dimension[12]], [-32, -160, -288, -32]);
        assert_eq!([dimension[4], dimension[7], dimension[10], dimension[13]], [0, -128, -256, 0]);
    }

    #[test]
    fn signed_absolute_minimum_and_rounding_wrap_like_arm() {
        let mut dimension = [0; 51];
        dimension[1] = 3;
        dimension[50] = 0x10000;
        dimension[2] = i32::MAX;
        dimension[5] = -1; // difference is MIN; wrapping abs stays negative.
        dimension[8] = i32::MIN; // difference wraps to 1.
        unsafe { psh_dimension_scale_widths(dimension.as_mut_ptr(), 0); }
        for i in 0..3 {
            assert_eq!(dimension[3 + 3 * i], i32::MAX);
            assert_eq!(dimension[4 + 3 * i], i32::MIN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn appends_at_count_and_clears_only_outer_stem_words() {
        let Some(slab) = try_map_u32_slab(hints::PSH_DIMENSION_APPEND_STEM_RECORD, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let header = slab.cast::<u32>();
            let records = slab.add(0x100).cast::<u32>();
            *header = 1;
            *header.add(1) = 2;
            *header.add(2) = records as usize as u32;
            let mut output = u32::MAX;

            assert_eq!(psh_dimension_append_stem_record(header, core::ptr::null_mut(), &mut output), 0);
            assert_eq!(*header, 2);
            assert_eq!(*header.add(1), 2);
            assert_eq!(output, records.add(4) as usize as u32);
            assert_eq!(*records.add(4), 0);
            assert_eq!(*records.add(7), 0);
            assert_eq!(*records.add(5), 0xa5a5_a5a5);
            assert_eq!(*records.add(6), 0xa5a5_a5a5);
        }
    }

    #[test]
    fn uses_the_last_existing_capacity_slot_without_allocator() {
        let Some(slab) = try_map_u32_slab(hints::PSH_DIMENSION_APPEND_STEM_RECORD_CAPACITY, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0xff, 0x1000);
            let header = slab.cast::<u32>();
            let records = slab.add(0x100).cast::<u32>();
            *header = 7;
            *header.add(1) = 8;
            *header.add(2) = records as usize as u32;
            let mut output = 0;

            assert_eq!(psh_dimension_append_stem_record(header, core::ptr::null_mut(), &mut output), 0);
            assert_eq!(*header, 8);
            assert_eq!(*header.add(1), 8);
            assert_eq!(output, records.add(28) as usize as u32);
            assert_eq!(*records.add(28), 0);
            assert_eq!(*records.add(31), 0);
        }
    }
}
