//! Empty u32 handler — `FUN_08155684` @ 0x08155684 (4 bytes).
//!
//! Raw `osos.dec` is a single `bx lr`, so the handler reads no memory, has no
//! side effects, and returns its incoming `r0` unchanged. The next independent
//! function starts at 0x08155688 with `push {r4, lr}`. Four plain direct `bl`
//! instructions target this address; no predicated direct `bl` instructions do.
//!
//! Deliberate deviation: the original preserves every register by executing
//! only `bx lr`; this ABI function guarantees only the observable `r0` result.

/// Returns the incoming ABI word without side effects.
///
/// Original: `FUN_08155684` @ 0x08155684 (4 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn no_op_u32(value: u32) -> u32 {
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_zero_word() {
        assert_eq!(no_op_u32(0), 0);
    }

    #[test]
    fn preserves_all_set_word() {
        assert_eq!(no_op_u32(u32::MAX), u32::MAX);
    }

    #[test]
    fn preserves_mixed_bit_word() {
        assert_eq!(no_op_u32(0x8123_4567), 0x8123_4567);
    }
}
