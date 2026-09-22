//! `range_value_to_u8` — retailOS `FUN_082004f0` at **0x082004f0**.
//!
//! Raw ARM establishes the exact **92-byte** extent (`0x082004f0..0x0820054b`):
//! `push {r4,lr}` opens the body, `pop {r4,pc}` at `0x08200548` returns, and
//! the next real function starts at `0x0820054c`. Full-image raw decoding finds
//! three inbound plain `bl` calls (`0x081ff820`, `0x081ffbe8`, `0x08200b00`)
//! and no predicated inbound calls. The body has one plain `bl` to `__rt_udiv`
//! and one predicated `blhi` to `heap_panic`.
//!
//! Algorithm: a range whose maximum is 255 encodes values relative to its
//! offset, rejecting values more than 255 above that offset. Other nonzero
//! maxima clamp the input and scale it to the inclusive 0..255 byte range;
//! a zero maximum returns zero.
//!
//! ## Deliberate deviations
//!
//! None. The port calls the already ported divide and fatal-path entries
//! directly; their out-of-line boundaries preserve the two retail call sites.

use crate::heap::veneers::heap_panic;
use crate::runtime::rt_div::__rt_udiv;

const RANGE_MAX_OFFSET: usize = 0x2d4;
const RANGE_OFFSET_OFFSET: usize = 0x2d8;

/// Encodes `value` as the range's retailOS byte representation.
///
/// `range` must point to an aligned retail range object with u32 fields at
/// `+0x2d4` (maximum) and `+0x2d8` (offset).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_value_to_u8(range: *const u8, value: u32) -> u32 {
    let maximum = unsafe { range.add(RANGE_MAX_OFFSET).cast::<u32>().read() };
    if maximum == u8::MAX as u32 {
        let offset = unsafe { range.add(RANGE_OFFSET_OFFSET).cast::<u32>().read() };
        if value <= offset {
            return 0;
        }
        let relative = value.wrapping_sub(offset);
        if relative > u8::MAX as u32 {
            unsafe { heap_panic() };
        }
        return relative;
    }

    let clamped_value = if maximum < value { maximum } else { value };
    if maximum == 0 {
        return 0;
    }
    unsafe { __rt_udiv(clamped_value.wrapping_mul(u8::MAX as u32), maximum) & u8::MAX as u32 }
}

#[cfg(test)]
mod tests {
    use super::range_value_to_u8;

    #[repr(C)]
    struct RangeFixture {
        padding: [u32; 0xb5],
        maximum: u32,
        offset: u32,
    }

    impl RangeFixture {
        const fn new(maximum: u32, offset: u32) -> Self {
            Self { padding: [0; 0xb5], maximum, offset }
        }
    }

    #[test]
    fn byte_range_subtracts_offset_and_floors_at_zero() {
        let range = RangeFixture::new(255, 100);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 0) }, 0);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 100) }, 0);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 101) }, 1);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 355) }, 255);
    }

    #[test]
    fn non_byte_range_scales_with_flooring_and_clamps() {
        let range = RangeFixture::new(100, 0xdead_beef);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 0) }, 0);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 1) }, 2);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 50) }, 127);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 100) }, 255);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), 101) }, 255);
    }

    #[test]
    fn zero_maximum_returns_zero_without_dividing() {
        let range = RangeFixture::new(0, 0);
        assert_eq!(unsafe { range_value_to_u8((&raw const range).cast(), u32::MAX) }, 0);
    }
}
