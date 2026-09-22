//! FreeType TrueType interpolation delta helper.

use crate::runtime::rt_div::__rt_sdiv;

/// Four target-width words supplied by the TrueType interpreter. Only the
/// two reference coordinates participate in this helper.
#[repr(C)]
pub struct InterpolationReference {
    pub first: i32,
    pub reference_start: i32,
    pub third: i32,
    pub reference_end: i32,
}

/// `tt_interpolate_delta` — original: `FUN_0820f018` @ `0x0820f018`
/// (132 bytes, not Ghidra's truncated 108-byte extent; true extent is
/// `0x0820f018..0x0820f09c`). One unconditional internal `bl` to
/// `__rt_sdiv` @ `0x08031568`; no predicated `bl` instructions. The function
/// has three inbound unconditional `bl` call sites and no predicated inbound
/// calls.
///
/// Computes the signed-16-bit interpolation delta
/// `((reference_end - reference_start) * (current - origin_start)) / (origin_end - origin_start)`.
/// The multiplication wraps at 32 bits and division truncates toward zero.
/// If the origin span is zero, it instead returns the signed-16-bit reference
/// span when `origin_end` is nonzero, or zero when both origins are zero.
///
/// Deliberate deviation: named `InterpolationReference` exposes the target's
/// four 32-bit words rather than the unrecovered surrounding interpreter type;
/// its `repr(C)` layout preserves the target +4 and +12 field offsets on hosts.
///
/// # Safety
/// `reference` must point to a readable four-word target-layout record. The
/// original ignores `interpreter` and performs no validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tt_interpolate_delta(
    _interpreter: *mut u8,
    origin_start: i32,
    origin_end: i32,
    current: i32,
    reference: *const InterpolationReference,
) -> i32 {
    let reference = &*reference;
    let reference_span = reference.reference_end.wrapping_sub(reference.reference_start);

    if origin_end == origin_start {
        if origin_end == 0 {
            0
        } else {
            ((reference_span as u32 & 0xffff) as i16) as i32
        }
    } else {
        let numerator = reference_span.wrapping_mul(current.wrapping_sub(origin_start));
        let delta = __rt_sdiv(numerator, origin_end.wrapping_sub(origin_start));
        ((delta as u32 & 0xffff) as i16) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::{tt_interpolate_delta, InterpolationReference};

    fn interpolate(
        origin_start: i32,
        origin_end: i32,
        current: i32,
        reference: &InterpolationReference,
    ) -> i32 {
        unsafe {
            tt_interpolate_delta(
                core::ptr::null_mut(),
                origin_start,
                origin_end,
                current,
                reference,
            )
        }
    }

    #[test]
    fn interpolates_with_truncation_toward_zero() {
        let reference = InterpolationReference { first: 0, reference_start: 100, third: 0, reference_end: 160 };
        assert_eq!(interpolate(20, 50, 35, &reference), 30);
        assert_eq!(interpolate(20, 50, 13, &reference), -14);
    }

    #[test]
    fn zero_origin_span_uses_the_signed_reference_span() {
        let positive = InterpolationReference { first: 0, reference_start: -2, third: 0, reference_end: 0x1_0001 };
        let negative = InterpolationReference { first: 0, reference_start: 2, third: 0, reference_end: -1 };
        assert_eq!(interpolate(7, 7, 99, &positive), 3);
        assert_eq!(interpolate(7, 7, 99, &negative), -3);
        assert_eq!(interpolate(0, 0, 99, &negative), 0);
    }

    #[test]
    fn multiplication_wraps_before_division_and_result_is_signed_16_bit() {
        let reference = InterpolationReference { first: 0, reference_start: 0, third: 0, reference_end: 0x1_0001 };
        assert_eq!(interpolate(0, 2, i32::MAX, &reference), 32767);
    }
}
