//! Constant-zero return — `FUN_080275f8` @ 0x080275f8 (8 bytes).
//!
//! Reference: `decomp/c/001/080275f8_FUN_080275f8.c`. The two-instruction ARM
//! leaf executes `mov r0, #0; bx lr`: it neither reads ABI argument registers
//! nor memory, and always returns an unsigned zero word. A recovered caller
//! presents live arguments, but the callee intentionally discards them all.

/// return_zero — original: `FUN_080275f8` @ 0x080275f8 (8 bytes).
///
/// Returns a zero-valued 32-bit ABI result without reading arguments or memory.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn return_zero() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_returns_the_zero_word() {
        assert_eq!(return_zero(), 0);
    }

    #[test]
    fn returned_zero_has_no_set_bits() {
        assert_eq!(return_zero().count_ones(), 0);
    }
}
