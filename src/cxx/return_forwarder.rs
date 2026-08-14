//! `return_second_argument` — original: `FUN_080275f0` @ 0x080275f0
//! (8 bytes).
//!
//! Source: `ipod-decomp/decomp/c/001/080275f0_FUN_080275f0.c`.
//!
//! ARM's two-instruction leaf copies the second 32-bit argument from `r1` to
//! the return register `r0`, then returns. It neither inspects the first
//! argument nor accesses memory, so both arguments and the result retain raw
//! `u32` bit patterns.

/// Returns the second ARM ABI argument unchanged.
///
/// The first argument is forwarded only in the ABI sense: the original
/// `mov r0, r1; bx lr` ignores it completely.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn return_second_argument(_first_argument: u32, second_argument: u32) -> u32 {
    second_argument
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_second_argument_regardless_of_the_first() {
        assert_eq!(return_second_argument(0, 0x1234_5678), 0x1234_5678);
        assert_eq!(return_second_argument(u32::MAX, 0x89ab_cdef), 0x89ab_cdef);
    }

    #[test]
    fn preserves_second_argument_bit_patterns() {
        assert_eq!(return_second_argument(0xfeed_face, 0), 0);
        assert_eq!(return_second_argument(0x0123_4567, u32::MAX), u32::MAX);
    }
}
