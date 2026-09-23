//! Seven-unit window bounds — `FUN_081f7154` @ 0x081f7154 (64 bytes; 3
//! inbound plain `bl` call sites, 0 inbound predicated `bl` call sites; 1
//! outbound plain `bl`, 0 outbound predicated `bl` calls).
//!
//! Algorithm: divide the first observed value by seven, retaining the
//! remainder; subtract `(remainder - span)` from that value. If a second
//! observed value is below this provisional lower bound, back it up one
//! seven-unit block. Store the lower bound and lower bound plus seven.
//! Deliberate deviations: `__rt_udivmod` exposes the retail r1 remainder via
//! an out-pointer; volatile loads retain the original's two distinct loads.

use crate::runtime::rt_div::__rt_udivmod;

/// Stores the seven-unit-aligned bounds for `span` relative to `value`.
///
/// `value` and `bounds` must point to readable and two writable `u32` words,
/// respectively. Arithmetic wraps modulo 2^32 like the ARM `sub` and `add`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn seven_unit_window_bounds(value: *const u32, span: u32, bounds: *mut u32) {
    let initial_value = value.read_volatile();
    let mut remainder = 0;
    __rt_udivmod(initial_value, 7, &mut remainder);

    let mut lower_bound = initial_value.wrapping_sub(remainder.wrapping_sub(span));
    if value.read_volatile() < lower_bound {
        lower_bound = lower_bound.wrapping_sub(7);
    }

    bounds.write(lower_bound);
    bounds.add(1).write(lower_bound.wrapping_add(7));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(value: u32, span: u32) -> (u32, u32) {
        let remainder = value % 7;
        let lower_bound = value.wrapping_sub(remainder.wrapping_sub(span));
        let lower_bound = if value < lower_bound { lower_bound.wrapping_sub(7) } else { lower_bound };
        (lower_bound, lower_bound.wrapping_add(7))
    }

    #[test]
    fn stores_bounds_for_every_remainder_and_small_span() {
        for value in 0..=64 {
            for span in 0..=16 {
                let mut bounds = [0u32; 2];
                unsafe { seven_unit_window_bounds(&value, span, bounds.as_mut_ptr()) };
                assert_eq!((bounds[0], bounds[1]), reference(value, span), "value {value}, span {span}");
            }
        }
    }

    #[test]
    fn preserves_wrapping_and_underflow_cases() {
        for &(value, span) in &[
            (0, 0),
            (0, 1),
            (6, 0),
            (u32::MAX, 0),
            (u32::MAX, 7),
            (0x8000_0000, u32::MAX),
        ] {
            let mut bounds = [0u32; 2];
            unsafe { seven_unit_window_bounds(&value, span, bounds.as_mut_ptr()) };
            assert_eq!((bounds[0], bounds[1]), reference(value, span), "value {value:#x}, span {span:#x}");
        }
    }
}
