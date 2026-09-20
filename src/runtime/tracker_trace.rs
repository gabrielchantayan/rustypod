//! Inert tracker trace — `FUN_083d3a8c` @ 0x083d3a8c (4 bytes).
//!
//! Raw `osos.dec` contains only `bx lr`, so this trace hook reads no memory,
//! performs no formatting or logging, and returns its incoming `r0` unchanged.
//! The preceding function ends with a tail branch at 0x083d3a88; the next
//! independently linked function starts at 0x083d3a90 with
//! `push {r4, r5, r6, lr}`. Whole-image ARM decoding finds three inbound plain
//! direct `bl` instructions (0x08106334, 0x083d3b98, and 0x083d3cbc) and no
//! predicated direct `bl` instructions.
//!
//! Deliberate deviation: callers supply tracker-format arguments in `r1` and
//! later argument registers, but `bx lr` neither observes them nor establishes
//! a variadic ABI. This typed ABI exposes only the observable preserved `r0`.
//! ARM LLVM intentionally folds this identical four-byte behavior into the
//! existing `no_op_u32` body; `tracker_trace` remains an exported archive
//! symbol, but `match.py` cannot locate a distinct objdump label.

/// Returns the incoming tracker word without trace side effects.
///
/// Original: `FUN_083d3a8c` @ 0x083d3a8c (4 bytes).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn tracker_trace(value: u32) -> u32 {
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_zero_word() {
        assert_eq!(tracker_trace(0), 0);
    }

    #[test]
    fn preserves_all_set_word() {
        assert_eq!(tracker_trace(u32::MAX), u32::MAX);
    }

    #[test]
    fn preserves_mixed_word() {
        assert_eq!(tracker_trace(0x8123_4567), 0x8123_4567);
    }
}
