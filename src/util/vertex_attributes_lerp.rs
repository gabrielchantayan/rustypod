//! Interpolation of homogeneous vertex coordinates and trailing attributes.

use crate::util::fixed::fixed28_lerp;

/// `vertex_attributes_lerp` — original `FUN_08242cb0` @ `0x08242cb0`.
/// True extent: 176 bytes, `0x08242cb0..0x08242d60`; the next function
/// begins with its own push at `0x08242d60`. Raw A32 decoding finds two
/// unconditional inbound BLs (0x082498cc, 0x0824ff0c), five unconditional
/// outbound BLs to `fixed28_lerp`, and no predicated BLs in either count.
///
/// Interpolates the four homogeneous-coordinate words at +0x10..+0x1c,
/// then `attribute_count` words beginning at +0x6c, using signed Q4.28
/// interpolation with wrapping arithmetic and half-up rounding. All other
/// words are preserved. Reads and writes occur one component at a time,
/// including when the output aliases either source.
///
/// Deliberate deviation: word pointers expose only the observed layout,
/// rather than inventing the surrounding vertex type. No arithmetic or
/// memory-effect deviations; the existing Rust scalar port is reused.
///
/// # Safety
/// All pointers must be aligned and valid for the four words at indices
/// 4..8 and `attribute_count` words starting at index 27. Output locations
/// must be writable. Overlap is permitted; no concurrent access is allowed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vertex_attributes_lerp(
    output: *mut i32,
    start: *const i32,
    end: *const i32,
    factor_q4_28: i32,
    attribute_count: u32,
) {
    for index in 4..8 {
        let value = fixed28_lerp(start.add(index).read(), end.add(index).read(), factor_q4_28);
        output.add(index).write(value);
    }
    for attribute in 0..attribute_count {
        let index = 27 + attribute as usize;
        let value = fixed28_lerp(start.add(index).read(), end.add(index).read(), factor_q4_28);
        output.add(index).write(value);
    }
}

#[cfg(test)]
mod tests {
    use super::vertex_attributes_lerp;

    fn reference(start: i32, end: i32, factor: i32) -> i32 {
        let delta = (end as u32).wrapping_sub(start as u32) as i32;
        let product = (delta as i64 * factor as i64) as u64;
        let biased = product.wrapping_add(0x0800_0000);
        (start as u32).wrapping_add((biased >> 28) as u32) as i32
    }

    #[test]
    fn counts_factors_rounding_and_untouched_fields() {
        let mut start = [0i32; 36];
        let mut end = [0i32; 36];
        let values = [i32::MIN, i32::MAX, -1, 0, 1, -12345, 98765];
        for i in 0..36 {
            start[i] = values[i % values.len()];
            end[i] = values[(i + 3) % values.len()];
        }
        for count in [0, 1, 8] {
            for factor in [i32::MIN, -0x1000_0000, 0, 0x0800_0000, 0x1000_0000, i32::MAX] {
                let mut output = [0x1357_2468; 36];
                unsafe { vertex_attributes_lerp(output.as_mut_ptr(), start.as_ptr(), end.as_ptr(), factor, count); }
                for i in 0..36 {
                    let expected = if (4..8).contains(&i) || (27..27 + count as usize).contains(&i) {
                        reference(start[i], end[i], factor)
                    } else { 0x1357_2468 };
                    assert_eq!(output[i], expected, "index={i} count={count} factor={factor}");
                }
            }
        }
    }

    #[test]
    fn aliasing_sources_preserves_sequential_register_effects() {
        for (output_offset, start_offset, end_offset) in [(0, 0, 40), (40, 0, 40), (1, 0, 40), (41, 0, 40)] {
            let mut actual = [0i32; 80];
            for i in 0..80 { actual[i] = (i as i32 * 17).wrapping_sub(500); }
            let mut expected = actual;
            for i in (4..8).chain(27..31) {
                expected[output_offset + i] = reference(expected[start_offset + i], expected[end_offset + i], 0x0800_0000);
            }
            let base = actual.as_mut_ptr();
            unsafe { vertex_attributes_lerp(base.add(output_offset), base.add(start_offset), base.add(end_offset), 0x0800_0000, 4); }
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn zero_attributes_never_accesses_trailing_storage() {
        let start = [0, 0, 0, 0, 0, 1, 1, -1];
        let end = [0, 0, 0, 0, 1, 0, 2, -2];
        let mut output = [99; 8];
        unsafe { vertex_attributes_lerp(output.as_mut_ptr(), start.as_ptr(), end.as_ptr(), 0x0800_0000, 0); }
        assert_eq!(output, [99, 99, 99, 99, 1, 1, 2, -1]);
    }
}
