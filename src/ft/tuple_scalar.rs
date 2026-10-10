use super::calc::ft_muldiv;

/// Prefix of the FreeType variation blend; pointer is at +4 on ARM.
#[repr(C)]
pub struct FtVariationBlend {
    pub axis_count: u32,
    pub normalized_coordinates: *const i32,
}

/// FreeType variation tuple scalar — FUN_080a88c4 @ 0x080a88c4.
/// True extent: 212 bytes, ending at the next prologue at 0x080a8998.
/// Raw-word verification: two plain BLs to ft_muldiv, zero predicated BLs.
/// Starts at Q16.16 unity and multiplies contributions from nonzero peak
/// axes. Zero coordinates or opposite signs reject the tuple. Without an
/// intermediate region, use the coordinate magnitude (no peak division).
/// With flag 0x4000, require start < coordinate < end, then interpolate
/// on the appropriate side of the peak using rounded FT_MulDiv twice.
/// Deviations: native-width host pointers in the repr(C) prefix; none in
/// arithmetic. Wrapping negation/subtraction preserve ARM overflow. The
/// raw r2 denominator, omitted by Ghidra, is end-peak or peak-start.
///
/// # Safety
/// `blend` must point to a valid prefix. Peaks and coordinates must contain
/// axis_count aligned i32 values; starts/ends must too when flag 0x4000 is
/// set and a nonzero peak passes the sign check. Unused arrays may be null.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_variation_tuple_scalar(
    blend: *const FtVariationBlend,
    flags: u32,
    peaks: *const i32,
    starts: *const i32,
    ends: *const i32,
) -> i32 {
    let mut scalar = 0x10000;
    let mut axis = 0u32;
    while axis < (*blend).axis_count {
        let peak = *peaks.add(axis as usize);
        if peak != 0 {
            let coordinate = *(*blend).normalized_coordinates.add(axis as usize);
            if coordinate == 0 || (coordinate < 0) != (peak < 0) {
                return 0;
            }
            let contribution = if flags & 0x4000 == 0 {
                coordinate.wrapping_abs()
            } else {
                let start = *starts.add(axis as usize);
                if coordinate <= start {
                    return 0;
                }
                let end = *ends.add(axis as usize);
                if coordinate >= end {
                    return 0;
                }
                let (distance, span) = if coordinate < peak {
                    (coordinate.wrapping_sub(start), peak.wrapping_sub(start))
                } else {
                    (end.wrapping_sub(coordinate), end.wrapping_sub(peak))
                };
                ft_muldiv(distance, 0x10000, span)
            };
            scalar = ft_muldiv(scalar, contribution, 0x10000);
        }
        axis = axis.wrapping_add(1);
    }
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(coordinates: &[i32], peaks: &[i32], region: Option<(&[i32], &[i32])>) -> i32 {
        assert_eq!(coordinates.len(), peaks.len());
        let blend = FtVariationBlend {
            axis_count: coordinates.len() as u32,
            normalized_coordinates: coordinates.as_ptr(),
        };
        let (flags, starts, ends) = match region {
            Some((starts, ends)) => {
                assert_eq!(starts.len(), peaks.len());
                assert_eq!(ends.len(), peaks.len());
                (0x4000, starts.as_ptr(), ends.as_ptr())
            }
            None => (0, core::ptr::null(), core::ptr::null()),
        };
        unsafe { ft_variation_tuple_scalar(&blend, flags, peaks.as_ptr(), starts, ends) }
    }

    #[test]
    fn inactive_axes_and_empty_blend_are_unity() {
        let blend = FtVariationBlend { axis_count: 0, normalized_coordinates: core::ptr::null() };
        assert_eq!(unsafe { ft_variation_tuple_scalar(&blend, 0x4000,
            core::ptr::null(), core::ptr::null(), core::ptr::null()) }, 0x10000);
        assert_eq!(evaluate(&[0, i32::MIN], &[0, 0], None), 0x10000);
    }

    #[test]
    fn sign_rejection_and_coordinate_magnitude() {
        for (coordinate, peak) in [(0, 1), (-1, 1), (1, -1)] {
            assert_eq!(evaluate(&[coordinate], &[peak], None), 0);
        }
        assert_eq!(evaluate(&[0x8000, -0x4000], &[1, -1], None), 0x2000);
        assert_eq!(evaluate(&[0x18000], &[0x4000], None), 0x18000);
        assert_eq!(evaluate(&[i32::MIN], &[-1], None), i32::MIN);
    }

    #[test]
    fn intermediate_open_bounds_peak_and_both_slopes() {
        for (coordinate, expected) in [(0x2000, 0), (0x5000, 0x8000),
            (0x8000, 0x10000), (0xc000, 0x8000), (0x10000, 0), (0x11000, 0)] {
            assert_eq!(evaluate(&[coordinate], &[0x8000],
                Some((&[0x2000], &[0x10000]))), expected);
        }
        assert_eq!(evaluate(&[-0xc000], &[-0x8000],
            Some((&[-0x10000], &[-0x2000]))), 0x8000);
        assert_eq!(evaluate(&[1], &[2], Some((&[0], &[3]))), 0x8000);
        assert_eq!(evaluate(&[2], &[3], Some((&[0], &[5]))), 43691);
        assert_eq!(evaluate(&[1, 1], &[2, 2], Some((&[0, 0], &[3, 3]))), 0x4000);
    }

    #[test]
    fn zero_peaks_skip_invalid_region_and_sign_checks_precede_region() {
        let blend = FtVariationBlend { axis_count: 1, normalized_coordinates: core::ptr::null() };
        assert_eq!(unsafe { ft_variation_tuple_scalar(&blend, 0x4000,
            [0].as_ptr(), core::ptr::null(), core::ptr::null()) }, 0x10000);
        let coordinate = -1;
        let blend = FtVariationBlend { axis_count: 1, normalized_coordinates: &coordinate };
        assert_eq!(unsafe { ft_variation_tuple_scalar(&blend, 0x4000,
            [1].as_ptr(), core::ptr::null(), core::ptr::null()) }, 0);
        assert_eq!(evaluate(&[5], &[5], Some((&[5], &[10]))), 0);
        assert_eq!(evaluate(&[5], &[5], Some((&[0], &[5]))), 0);
    }
}
