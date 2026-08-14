//! `reset_u32_slot` — original: `FUN_08027c7c` @ 0x08027c7c (12 bytes).
//!
//! Source: `ipod-decomp/decomp/c/001/08027c7c_FUN_08027c7c.c`.
//!
//! Leaf reset helper: writes zero to the single 32-bit slot addressed by its
//! first ARM argument (`r0`) and returns. The recovered caller invokes it as
//! part of a batch of independent state-slot resets; it neither reads the
//! slot nor accesses adjacent memory.

/// reset_u32_slot — original: `FUN_08027c7c` @ 0x08027c7c (12 bytes).
///
/// Clears exactly one 32-bit state slot. The slot must be a valid, aligned,
/// writable target, as required by the original `str r1, [r0]` instruction.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn reset_u32_slot(slot: *mut u32) {
    slot.write(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct GuardedSlot {
        before: u32,
        slot: u32,
        after: u32,
    }

    #[test]
    fn clears_the_target_word_without_touching_adjacent_words() {
        let mut state = GuardedSlot {
            before: 0x1122_3344,
            slot: 0xa5a5_5a5a,
            after: 0x5566_7788,
        };

        unsafe { reset_u32_slot(&mut state.slot) };

        assert_eq!(state.slot, 0);
        assert_eq!(state.before, 0x1122_3344);
        assert_eq!(state.after, 0x5566_7788);
    }
}
