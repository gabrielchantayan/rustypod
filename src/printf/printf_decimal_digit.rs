//! `printf_decimal_digit` — original: `FUN_082ccd14` @ `0x082ccd14`.
//!
//! True extent: 116 bytes: 108 bytes of code at `0x082ccd14..0x082ccd7f`
//! plus the double-precision `10.0` literal at `0x082ccd80..0x082ccd87`;
//! the next real function starts at `0x082ccd88`. Raw ARM words contain four
//! unconditional `bl` instructions (`__d2i`, `__i2d`, `__dsub`, and
//! `__dmul`) and no predicated `bl`.
//!
//! Emits one ASCII decimal digit from `*decimal_state`: truncate it toward
//! zero, add `'0'`, then retain and scale its fractional part by ten for the
//! next call. `*digit_count` advances on every call; once its signed pre-
//! increment value reaches 16, the function returns `'0'` without reading or
//! changing the state. Deliberate deviation: volatile function-pointer loads
//! preserve the four target helper-call boundaries rather than permitting LLVM
//! to inline their soft-float bodies.

const MAX_DIGITS: i32 = 16;
const ASCII_ZERO: i32 = b'0' as i32;
const TEN: u64 = 10.0f64.to_bits();

/// Emit the next decimal digit while advancing a software-double state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn printf_decimal_digit(decimal_state: *mut u64, digit_count: *mut i32) -> i32 {
    let count = digit_count.read_volatile();
    digit_count.write_volatile(count.wrapping_add(1));
    if count >= MAX_DIGITS {
        return ASCII_ZERO;
    }

    let d2i: unsafe extern "C" fn(u64) -> i32 =
        core::ptr::read_volatile(&(crate::fp::fp_dconv::__d2i as unsafe extern "C" fn(u64) -> i32));
    let i2d: unsafe extern "C" fn(i32) -> u64 =
        core::ptr::read_volatile(&(crate::fp::fp_dconv::__i2d as unsafe extern "C" fn(i32) -> u64));
    let dsub: unsafe extern "C" fn(u64, u64) -> u64 =
        core::ptr::read_volatile(&(crate::fp::fp_dadd::__dsub as unsafe extern "C" fn(u64, u64) -> u64));
    let dmul: unsafe extern "C" fn(u64, u64) -> u64 =
        core::ptr::read_volatile(&(crate::fp::fp_dmul::__dmul as unsafe extern "C" fn(u64, u64) -> u64));
    let state = decimal_state.read_volatile();
    let integer = d2i(state);
    let fractional = dsub(state, i2d(integer));
    decimal_state.write_volatile(dmul(fractional, TEN));
    integer.wrapping_add(ASCII_ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_digits_and_advances_fractional_state() {
        let mut state = 12.34f64.to_bits();
        let mut count = 0;

        assert_eq!(unsafe { printf_decimal_digit(&mut state, &mut count) }, b'<' as i32);
        assert_eq!(count, 1);
        assert_eq!(f64::from_bits(state), 3.3999999999999986);
        assert_eq!(unsafe { printf_decimal_digit(&mut state, &mut count) }, b'3' as i32);
        assert_eq!(count, 2);
    }

    #[test]
    fn sixteenth_digit_is_processed_but_later_digits_are_zero_without_state_access() {
        let mut state = 7.25f64.to_bits();
        let mut count = 15;
        assert_eq!(unsafe { printf_decimal_digit(&mut state, &mut count) }, b'7' as i32);
        assert_eq!(count, 16);
        assert_eq!(f64::from_bits(state), 2.5);

        let unchanged = state;
        assert_eq!(unsafe { printf_decimal_digit(&mut state, &mut count) }, b'0' as i32);
        assert_eq!(count, 17);
        assert_eq!(state, unchanged);
    }

    #[test]
    fn signed_count_and_increment_wrap_match_arm_arithmetic() {
        let mut state = 0.125f64.to_bits();
        let mut count = -1;
        assert_eq!(unsafe { printf_decimal_digit(&mut state, &mut count) }, b'0' as i32);
        assert_eq!(count, 0);
        assert_eq!(f64::from_bits(state), 1.25);

        count = i32::MAX;
        let unchanged = state;
        assert_eq!(unsafe { printf_decimal_digit(&mut state, &mut count) }, b'0' as i32);
        assert_eq!(count, i32::MIN);
        assert_eq!(state, unchanged);
    }
}
