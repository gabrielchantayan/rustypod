//! Buffered-stream offset timestamp conversion.
//!
//! `stream_buffer_offset_to_milliseconds` — original: `FUN_080f67c4` @
//! 0x080f67c4 (76 bytes). Raw ARM extent is exactly 0x080f67c4..0x080f6810:
//! the following two words are its 1000.0 double literal and the next real
//! function starts at 0x080f6818. It has five unconditional plain `bl` calls,
//! no predicated `bl` calls, then a plain-`b` tail call to `__d2u`.
//!
//! The retail body reads the opaque buffered stream's `units_per_second` at
//! +0x418 and `offset_quantum` at +0x434, truncates `offset / offset_quantum`,
//! multiplies that integer by 1000.0, divides by `units_per_second`, and
//! truncates/saturates the result to `u32`. Keeping the soft-float sequence
//! preserves retail rounding and exceptional behavior.
//!
//! Deliberate deviation: Rust calls canonical soft-float ports directly and
//! returns normally instead of tail-branching to `__d2u`.

use core::ptr::read_volatile;

type U32ToDouble = unsafe extern "C" fn(u32) -> u64;
type DoubleBinaryOp = unsafe extern "C" fn(u64, u64) -> u64;
type DoubleToU32 = unsafe extern "C" fn(u64) -> u32;

const UNITS_PER_SECOND_OFFSET: usize = 0x418;
const OFFSET_QUANTUM_OFFSET: usize = 0x434;
const MILLISECONDS_AS_DOUBLE: u64 = 1000.0f64.to_bits();

/// Converts a buffered-stream offset to a saturated millisecond timestamp.
///
/// `stream` must point to an object with initialized aligned `u32` fields at
/// +0x418 and +0x434. As in retailOS, a zero `offset_quantum` reaches the
/// unsigned division helper.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_offset_to_milliseconds(stream: *const u8, offset: u32) -> u32 {
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
    fn truncates_before_scaling() {
        let stream = stream(44_100, 4);
        assert_eq!(unsafe { stream_buffer_offset_to_milliseconds(stream.as_ptr().cast(), 179) }, 0);
        assert_eq!(unsafe { stream_buffer_offset_to_milliseconds(stream.as_ptr().cast(), 180) }, 1);
    }

    #[test]
    fn preserves_fractional_millisecond_truncation() {
        let stream = stream(48_000, 2);
        assert_eq!(unsafe { stream_buffer_offset_to_milliseconds(stream.as_ptr().cast(), 95) }, 0);
        assert_eq!(unsafe { stream_buffer_offset_to_milliseconds(stream.as_ptr().cast(), 96) }, 1);
    }

    #[test]
    fn scales_multi_second_offsets() {
        let stream = stream(48_000, 2);
        assert_eq!(unsafe { stream_buffer_offset_to_milliseconds(stream.as_ptr().cast(), 288_000) }, 3_000);
    }

    #[test]
    fn saturates_large_results() {
        let stream = stream(1, 1);
        assert_eq!(unsafe { stream_buffer_offset_to_milliseconds(stream.as_ptr().cast(), u32::MAX) }, u32::MAX);
    }
}
