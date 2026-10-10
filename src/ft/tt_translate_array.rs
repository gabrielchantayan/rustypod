//! TrueType point-array translation.

use super::types::FtVector;

/// Original `FUN_080931e0` at load address `0x080931e0`, 84 bytes
/// (`0x080931e0..0x08093234`; next function initializes an execution zone).
/// Raw ARM verifies zero outgoing plain/predicated BLs; the two incoming
/// calls at 0x080813fc and 0x080e24d8 are BLNE, with zero plain incoming BLs.
/// Add the X delta to every point first, then the Y delta to every point,
/// skipping each complete pass when its delta is zero. Count is unsigned;
/// coordinate arithmetic wraps modulo 2^32. Deliberate deviations: none.
///
/// # Safety
/// For a nonzero count and any nonzero delta, `points` must reference that
/// many aligned, writable FtVector records. With zero count or both deltas
/// zero, the pointer is not accessed and may be null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tt_translate_array(
    count: u32, points: *mut FtVector, x_delta: i32, y_delta: i32,
) {
    if x_delta != 0 {
        for index in 0..count {
            let x = core::ptr::addr_of_mut!((*points.add(index as usize)).x);
            x.write(x.read().wrapping_add(x_delta));
        }
    }
    if y_delta != 0 {
        for index in 0..count {
            let y = core::ptr::addr_of_mut!((*points.add(index as usize)).y);
            y.write(y.read().wrapping_add(y_delta));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_zero_delta_paths_do_not_access_points() {
        unsafe {
            tt_translate_array(0, core::ptr::null_mut(), i32::MIN, i32::MAX);
            tt_translate_array(u32::MAX, core::ptr::null_mut(), 0, 0);
        }
    }

    #[test]
    fn translates_selected_prefix_with_wrapping_and_independent_axes() {
        let values = [0, 1, -1, i32::MIN, i32::MAX, 0x12345678, -0x12345678];
        for count in 0..=values.len() {
            for dx in values {
                for dy in values {
                    let mut points = core::array::from_fn::<_, 9, _>(|i| FtVector {
                        x: values[i % values.len()], y: values[(i + 3) % values.len()],
                    });
                    let before = points;
                    unsafe { tt_translate_array(count as u32, points.as_mut_ptr().add(1), dx, dy); }
                    for i in 0..points.len() {
                        let selected = i > 0 && i <= count;
                        // Wide signed reference followed by target-word truncation.
                        let x = (before[i].x as i64 + if selected { dx as i64 } else { 0 }) as i32;
                        let y = (before[i].y as i64 + if selected { dy as i64 } else { 0 }) as i32;
                        assert_eq!(points[i], FtVector { x, y });
                    }
                }
            }
        }
    }
}
