//! `identity_noop_with_options` — original: `FUN_08210f64` @ `0x08210f64`.
//!
//! True extent: 4 bytes, `0x08210f64..0x08210f68`. The raw word is
//! `e12fff1e` (`bx lr`); the next real function starts with `e92d4070`
//! (`push {r4,r5,r6,lr}`). Whole-image aligned A32 decoding verifies two
//! inbound plain BLs (0x0817c93c and 0x081df054), zero predicated inbound
//! BLs, and zero outgoing calls. No aligned data words reference the entry.
//!
//! Algorithm: return the incoming r0 word unchanged, ignoring r1 and r2.
//! Both callers pass the result of 0x081ba040 with options (0,0) or (3,8),
//! then discard r0. The empty body establishes no destructor or higher-level
//! subsystem identity, and neither dereferences nor modifies its arguments.
//!
//! Deliberate deviations: LLVM emits a frame-pointer push/pop instead of the
//! stock `bx lr`; the return word and ignored arguments remain unchanged.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn identity_noop_with_options(value: u32, _option: u32, _flags: u32) -> u32 {
    value
}

#[cfg(test)]
mod tests {
    use super::identity_noop_with_options;

    #[test]
    fn preserves_word_bits_independently_of_ignored_options() {
        for value in [0, 1, 0x0821_0f64, 0x8000_0000, u32::MAX] {
            for (option, flags) in [(0, 0), (3, 8), (u32::MAX, 0), (0, u32::MAX), (u32::MAX, u32::MAX)] {
                assert_eq!(identity_noop_with_options(value, option, flags), value);
            }
        }
    }
}
