//! Power-of-two round-up — `FUN_08260558` @ 0x08260558 (20 bytes;
//! 76 `bl` call sites).
//!
//! A pure leaf used all over retailOS to round sizes, offsets and pointers
//! up to an alignment boundary. The original is five instructions of
//! wrapping unsigned arithmetic:
//!
//! ```text
//! add  r0, r0, r1
//! sub  r0, r0, #1
//! sub  r1, r1, #1
//! bic  r0, r0, r1
//! bx   lr
//! ```
//!
//! i.e. `result = (value + align - 1) & ~(align - 1)` with all arithmetic
//! mod 2^32. For power-of-two `align` this is the usual "round up to a
//! multiple of `align`"; `value` already aligned is returned unchanged and
//! `align == 1` is the identity. The port is behavior-only and preserves
//! the original's wrapping semantics for degenerate inputs as well:
//! `align == 0` always yields 0, and overflow of `value + align - 1`
//! wraps rather than panicking.

/// align_up — original: `FUN_08260558` @ 0x08260558 (20 bytes).
///
/// Returns `value` rounded up to the next multiple of `align`
/// (`(value + align - 1) & !(align - 1)`, wrapping). Only meaningful for
/// power-of-two `align`; the exact original arithmetic is kept so
/// non-power-of-two and overflowing inputs behave bit-for-bit like the
/// firmware.
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn align_up(value: u32, align: u32) -> u32 {
    value
        .wrapping_add(align)
        .wrapping_sub(1)
        & !align.wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference model computed with arbitrary precision, asserting only
    /// for power-of-two alignments where the closed form is exact.
    fn reference(value: u32, align: u32) -> u32 {
        assert!(align.is_power_of_two());
        let v = value as u64;
        let a = align as u64;
        ((v + a - 1) & !(a - 1)) as u32
    }

    #[test]
    fn rounds_up_to_power_of_two_boundaries() {
        for &align in &[1u32, 2, 4, 8] {
            for value in 0..=64u32 {
                assert_eq!(align_up(value, align), reference(value, align),
                    "value {value}, align {align}");
            }
        }
    }

    #[test]
    fn already_aligned_values_are_returned_unchanged() {
        for &align in &[1u32, 2, 4, 8] {
            for k in 0..=16u32 {
                let value = k * align;
                assert_eq!(align_up(value, align), value,
                    "value {value}, align {align}");
            }
        }
    }

    #[test]
    fn zero_value_is_aligned_to_everything() {
        for &align in &[1u32, 2, 4, 8, 0x1000] {
            assert_eq!(align_up(0, align), 0);
        }
    }

    #[test]
    fn one_past_a_boundary_rounds_to_the_next() {
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(9, 8), 16);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn overflow_wraps_like_the_original_arithmetic() {
        // (0xffffffff + 4 - 1) mod 2^32 = 2, & ~3 = 0 — the firmware
        // wraps instead of saturating, and so do we.
        assert_eq!(align_up(0xffff_ffff, 4), 0);
        assert_eq!(align_up(0xffff_fffe, 8), 0);
        // (0xffffff00 + 0x100 - 1) mod 2^32 = 0xffffffff, & ~0xff wraps
        // back to the original value — no rounding up happens at all.
        assert_eq!(align_up(0xffff_ff00, 0x100), 0xffff_ff00);
    }

    #[test]
    fn align_zero_matches_the_original_degenerate_case() {
        // ~(0 - 1) == 0, so the bic clears every bit.
        assert_eq!(align_up(0, 0), 0);
        assert_eq!(align_up(123, 0), 0);
        assert_eq!(align_up(0xffff_ffff, 0), 0);
    }
}
