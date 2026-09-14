//! `format_signed_radix_integer` — original: `FUN_080e9514` @ 0x080e9514
//! (232 bytes).
//!
//! Formats a signed 32-bit value in a caller-selected radix. The retailOS
//! body wraps a negative value to its unsigned magnitude, repeatedly calls
//! the unsigned divide-with-remainder helper, and writes remainders into a
//! reverse stack buffer through the literal loaded from 0x080e95fc (whose
//! target address is 0x083ecb4c). It caps a requested precision at 31,
//! prepends precision zeroes and a `-`/optional `+`, records the resulting
//! byte length, then invokes the direct padding helper around reverse-byte
//! emission.
//!
//! Deliberate deviation: the external retailOS unsigned divide/mod helper
//! (`FUN_08036f14`) remains a callback seam. Field padding is now handled by
//! [`crate::printf::format_field_padding::format_field_padding`], and bounded
//! character output (`FUN_08280f7c`) by
//! [`crate::printf::format_bounded_byte::format_bounded_byte`].
//! On the firmware target digit bytes are read from the original literal;
//! host tests use an ordinary printable radix alphabet because that firmware
//! address is not mapped into the host process. The scratch buffer has 33
//! bytes rather than the original's 32-byte nominal local, avoiding its
//! one-byte edge overrun for a base-2 `u32` while preserving emitted bytes.

use core::{ffi::c_void, mem::MaybeUninit};
use crate::printf::format_bounded_byte::format_bounded_byte;
use crate::printf::format_field_padding::format_field_padding;

/// Callback seam for retailOS `FUN_08036f14`: `(quotient, remainder)` for
/// unsigned `dividend / radix`. The original receives the quotient in r0 and
/// the remainder in r1.
pub type RadixDivideFn = unsafe extern "C" fn(dividend: u32, radix: u32) -> RadixDivision;

/// ABI-safe representation of the two register results of [`RadixDivideFn`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RadixDivision {
    pub quotient: u32,
    pub remainder: u32,
}



/// Format-state ABI consumed by `FUN_080e9514` and its output callbacks.
///
/// The first 0x30 bytes have their retailOS ARM layout. Pointer fields are
/// naturally wider in host tests; field access remains semantic there, while
/// the documented offsets apply to the 32-bit firmware target.
#[repr(C)]
pub struct RadixFormatSpec {
    /// Underlying writer used by the bounded-output callback (state +0x00).
    pub write_byte: unsafe extern "C" fn(byte: u8, context: *mut c_void),
    /// Underlying writer context (state +0x04 on ARM).
    pub write_context: *mut c_void,
    /// Logical number of bytes attempted (state +0x08).
    pub emitted: u32,
    /// Maximum physically written bytes (state +0x0c).
    pub limit: u32,
    /// Padding-helper control word (state +0x10).
    pub padding_enabled: u32,
    /// Nonzero selects trailing rather than leading field padding (state +0x14).
    pub left_justify: u32,
    /// Nonzero makes `precision` active (state +0x18).
    pub precision_specified: u32,
    /// Nonzero prefixes a nonnegative value with `+` (state +0x1c).
    pub show_plus: u32,
    /// Length of the constructed sign-and-digit text (state +0x20).
    pub text_len: u32,
    /// Minimum field width used by `format_field_padding` (state +0x24).
    pub width: i32,
    /// Minimum digit count when [`Self::precision_specified`] is nonzero
    /// (state +0x28).
    pub precision: i32,
    pub fill: u8,
    pub reserved_2d: [u8; 3],
}

unsafe extern "C" fn divide_not_ported(_dividend: u32, _radix: u32) -> RadixDivision {
    RadixDivision { quotient: 0, remainder: 0 }
}



/// Active divide helper. The eventual port of `FUN_08036f14` replaces this
/// slot; tests install a precise host divider.
pub static mut RADIX_DIVIDE: RadixDivideFn = divide_not_ported;

#[inline(always)]
unsafe fn radix_divide() -> RadixDivideFn {
    core::ptr::read_volatile(core::ptr::addr_of!(RADIX_DIVIDE))
}



#[cfg(target_os = "none")]
const FIRMWARE_RADIX_DIGITS: *const u8 = 0x083e_cb4c as *const u8;
#[cfg(not(target_os = "none"))]
const HOST_RADIX_DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

#[inline(always)]
unsafe fn digit_for(remainder: u32) -> u8 {
    #[cfg(target_os = "none")]
    {
        FIRMWARE_RADIX_DIGITS.add(remainder as usize).read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        // The formatter's callers supply a radix whose remainders index the
        // firmware literal. Keep host use defined for conventional 2..=36.
        *HOST_RADIX_DIGITS.get_unchecked(remainder as usize)
    }
}

/// `format_signed_radix_integer` — port of `FUN_080e9514` @ 0x080e9514.
///
/// `radix` is forwarded to the installed unsigned divide/mod seam. The
/// function itself returns no value; it writes `text_len` and invokes the
/// padding/output callbacks in the same leading-content-trailing order as
/// the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn format_signed_radix_integer(
    value: i32,
    radix: u32,
    spec: *mut RadixFormatSpec,
) {
    let spec_ref = &mut *spec;
    let negative = value < 0;
    // ARM `rsblt`: `i32::MIN` becomes 0x8000_0000 rather than trapping.
    let mut quotient = if negative { (value as u32).wrapping_neg() } else { value as u32 };
    let mut remaining_precision = spec_ref.precision;
    if remaining_precision >= 32 {
        remaining_precision = 31;
    }

    // The original emits at least one digit, including for zero. Keep the
    // expanded scratch uninitialized: each byte is written before the final
    // reverse walk reads it, and ARM has no bounds check on this local.
    let mut reverse = MaybeUninit::<[u8; 33]>::uninit();
    let reverse = reverse.as_mut_ptr().cast::<u8>();
    let mut end = 0usize;
    loop {
        let result = (radix_divide())(quotient, radix);
        quotient = result.quotient;
        reverse.add(end).write(digit_for(result.remainder));
        end += 1;
        remaining_precision = remaining_precision.wrapping_sub(1);
        if quotient == 0 {
            break;
        }
    }

    if spec_ref.precision_specified != 0 {
        while remaining_precision > 0 {
            reverse.add(end).write_volatile(b'0');
            end += 1;
            remaining_precision = remaining_precision.wrapping_sub(1);
        }
    }
    if negative {
        reverse.add(end).write(b'-');
        end += 1;
    } else if spec_ref.show_plus != 0 {
        reverse.add(end).write(b'+');
        end += 1;
    }

    spec_ref.text_len = end as u32;
    let leading_phase = if spec_ref.left_justify > 1 {
        0
    } else {
        1u32.wrapping_sub(spec_ref.left_justify)
    };
    format_field_padding(leading_phase, spec);
    while end != 0 {
        end -= 1;
        format_bounded_byte(spec, reverse.add(end).read());
    }
    format_field_padding(spec_ref.left_justify, spec);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static CALLBACK_LOCK: Mutex<()> = Mutex::new(());

    struct Sink {
        bytes: Vec<u8>,
    }

    unsafe extern "C" fn collect_byte(byte: u8, context: *mut c_void) {
        (*(context as *mut Sink)).bytes.push(byte);
    }

    /// Exact host counterpart of `FUN_08036f14` for the valid format radices.
    unsafe extern "C" fn host_divide(dividend: u32, radix: u32) -> RadixDivision {
        RadixDivision { quotient: dividend / radix, remainder: dividend % radix }
    }



    struct Hooks {
        divide: RadixDivideFn,
    }

    impl Hooks {
        unsafe fn install() -> Self {
            let hooks = Self {
                divide: core::ptr::read_volatile(core::ptr::addr_of!(RADIX_DIVIDE)),
            };
            core::ptr::write_volatile(core::ptr::addr_of_mut!(RADIX_DIVIDE), host_divide);
            hooks
        }
    }

    impl Drop for Hooks {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(RADIX_DIVIDE), self.divide);
            }
        }
    }

    fn state(sink: &mut Sink, width: i32, precision_specified: bool, precision: i32) -> RadixFormatSpec {
        RadixFormatSpec {
            write_byte: collect_byte,
            write_context: sink as *mut Sink as *mut c_void,
            emitted: 0,
            limit: u32::MAX,
            padding_enabled: 1,
            left_justify: 0,
            precision_specified: precision_specified as u32,
            show_plus: 0,
            text_len: 0,
            width,
            precision,
            fill: b' ',
            reserved_2d: [0; 3],
        }
    }

    fn lock() -> MutexGuard<'static, ()> {
        CALLBACK_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn wraps_i32_min_and_emits_negative_decimal() {
        let _lock = lock();
        let _hooks = unsafe { Hooks::install() };
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, 0, false, 0);
        unsafe { format_signed_radix_integer(i32::MIN, 10, &mut spec) };
        assert_eq!(sink.bytes, b"-2147483648");
        assert_eq!(spec.text_len, 11);
        assert_eq!(spec.emitted, 11);
    }

    #[test]
    fn plus_flag_marks_nonnegative_and_zero_precision_keeps_zero_digit() {
        let _lock = lock();
        let _hooks = unsafe { Hooks::install() };
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, 0, true, 0);
        spec.show_plus = 1;
        unsafe { format_signed_radix_integer(0, 10, &mut spec) };
        // This is retailOS behavior: the unconditional digit loop precedes
        // precision zero handling, unlike ISO C's empty `%#.0d`-style case.
        assert_eq!(sink.bytes, b"+0");
        assert_eq!(spec.text_len, 2);
    }

    #[test]
    fn width_padding_precedes_reverse_sign_and_digits() {
        let _lock = lock();
        let _hooks = unsafe { Hooks::install() };
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, 6, false, 0);
        unsafe { format_signed_radix_integer(-42, 10, &mut spec) };
        assert_eq!(sink.bytes, b"   -42");
        assert_eq!(spec.emitted, 6);
    }

    #[test]
    fn left_justify_moves_padding_after_output() {
        let _lock = lock();
        let _hooks = unsafe { Hooks::install() };
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, 6, false, 0);
        spec.left_justify = 1;
        spec.show_plus = 1;
        unsafe { format_signed_radix_integer(42, 10, &mut spec) };
        assert_eq!(sink.bytes, b"+42   ");
        assert_eq!(spec.emitted, 6);
    }

    #[test]
    fn precision_is_capped_at_31_and_radix_is_not_fixed_to_decimal() {
        let _lock = lock();
        let _hooks = unsafe { Hooks::install() };
        let mut sink = Sink { bytes: Vec::new() };
        let mut spec = state(&mut sink, 0, true, 40);
        unsafe { format_signed_radix_integer(0x2a, 16, &mut spec) };
        assert_eq!(sink.bytes.len(), 31);
        assert!(sink.bytes.iter().take(29).all(|byte| *byte == b'0'));
        assert_eq!(&sink.bytes[29..], b"2a");
        assert_eq!(spec.text_len, 31);
    }
}
