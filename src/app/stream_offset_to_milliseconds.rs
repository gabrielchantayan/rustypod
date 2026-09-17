//! Quantized stream-offset timestamp conversion.
//!
//! `stream_offset_to_milliseconds` — original: `FUN_082958dc` @ 0x082958dc
//! (76 bytes). Raw ARM extent is exactly 0x082958dc..0x08295928; the next
//! separately linked function starts at 0x08295930 after its two-word
//! double-precision literal. It has four unconditional plain `bl` calls and
//! no predicated `bl` calls, followed by a plain-B tail call to `__d2u`.
//!
//! The retail body reads the opaque stream context's `units_per_second` at
//! +0x418 and `offset_quantum` at +0x430, first truncates
//! `offset / offset_quantum`, then evaluates that integer quantity times
//! 1000.0 divided by `units_per_second`, and truncates/saturates to `u32`.
//! The floating-point sequence, rather than an algebraically equivalent
//! integer formula, preserves the retail rounding and exceptional behavior.
//!
//! Deliberate deviation: Rust calls the canonical soft-float ports directly;
//! the original's final `b __d2u` is an ordinary return from this function.

use core::ptr::read_volatile;

type U32ToDouble = unsafe extern "C" fn(u32) -> u64;
type DoubleBinaryOp = unsafe extern "C" fn(u64, u64) -> u64;
type DoubleToU32 = unsafe extern "C" fn(u64) -> u32;

const UNITS_PER_SECOND_OFFSET: usize = 0x418;
const OFFSET_QUANTUM_OFFSET: usize = 0x430;
const MILLISECONDS_AS_DOUBLE: u64 = 1000.0f64.to_bits();

/// Converts a quantized opaque-stream offset to a saturated millisecond time.
///
/// `stream` must point to an object with initialized aligned `u32` fields at
/// +0x418 and +0x430. As in retailOS, a zero `offset_quantum` reaches the
/// unsigned division helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_offset_to_milliseconds(stream: *const u8, offset: u32) -> u32 {
    let units_per_second = (stream.add(UNITS_PER_SECOND_OFFSET) as *const u32).read();
    let offset_quantum = (stream.add(OFFSET_QUANTUM_OFFSET) as *const u32).read();
    let u2d: U32ToDouble = read_volatile(&(crate::fp::fp_dconv::__u2d as U32ToDouble));
    let dmul: DoubleBinaryOp = read_volatile(&(crate::fp::fp_dmul::__dmul as DoubleBinaryOp));
    let ddiv: DoubleBinaryOp = read_volatile(&(crate::fp::fp_ddiv::__ddiv as DoubleBinaryOp));
    let d2u: DoubleToU32 = read_volatile(&(crate::fp::fp_dconv::__d2u as DoubleToU32));
    let quantized_offset = crate::runtime::rt_div::__rt_udiv(offset, offset_quantum);
    let milliseconds = dmul(u2d(quantized_offset), MILLISECONDS_AS_DOUBLE);
    d2u(ddiv(milliseconds, u2d(units_per_second)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM_WORDS: usize = OFFSET_QUANTUM_OFFSET / 4 + 1;

    fn stream(units_per_second: u32, offset_quantum: u32) -> [u32; STREAM_WORDS] {
        let mut stream = [0; STREAM_WORDS];
        stream[UNITS_PER_SECOND_OFFSET / 4] = units_per_second;
        stream[OFFSET_QUANTUM_OFFSET / 4] = offset_quantum;
        stream
    }

    #[test]
    fn truncates_the_offset_before_scaling() {
        let stream = stream(44_100, 4);
        assert_eq!(unsafe { stream_offset_to_milliseconds(stream.as_ptr().cast(), 179) }, 0);
        assert_eq!(unsafe { stream_offset_to_milliseconds(stream.as_ptr().cast(), 180) }, 1);
    }

    #[test]
    fn scales_a_multi_second_quantized_offset() {
        let stream = stream(48_000, 2);
        assert_eq!(unsafe { stream_offset_to_milliseconds(stream.as_ptr().cast(), 288_000) }, 3_000);
    }

    #[test]
    fn preserves_the_u32_saturation_path() {
        let stream = stream(1, 1);
        assert_eq!(unsafe { stream_offset_to_milliseconds(stream.as_ptr().cast(), u32::MAX) }, u32::MAX);
    }
}
