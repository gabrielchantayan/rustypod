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

/// reset_u32_slot_alias_08027c88 — original: `FUN_08027c88` @ 0x08027c88
/// (12 bytes).
///
/// Source: `ipod-decomp/decomp/c/001/08027c88_FUN_08027c88.c`.
///
/// Byte-identical retailOS alias of [`reset_u32_slot`]: clears exactly one
/// aligned, writable 32-bit state slot through the first ARM argument (`r0`).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    unsafe(link_section = ".text.reset_u32_slot_alias_08027c88")
)]
#[inline(never)]
pub unsafe extern "C" fn reset_u32_slot_alias_08027c88(slot: *mut u32) {
    slot.write(0);
}
/// reset_u32_slot_alias_08027c94 — original: `FUN_08027c94` @ 0x08027c94
/// (12 bytes).
///
/// Source: `ipod-decomp/decomp/c/001/08027c94_FUN_08027c94.c`.
///
/// Byte-identical retailOS alias of [`reset_u32_slot`]: clears exactly one
/// aligned, writable 32-bit state slot through the first ARM argument (`r0`).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    unsafe(link_section = ".text.reset_u32_slot_alias_08027c94")
)]
#[inline(never)]
pub unsafe extern "C" fn reset_u32_slot_alias_08027c94(slot: *mut u32) {
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

    #[test]
    fn alias_clears_only_its_target_word() {
        let mut state = GuardedSlot {
            before: 0xdead_beef,
            slot: 0xfeed_face,
            after: 0xc001_d00d,
        };

        unsafe { reset_u32_slot_alias_08027c88(&mut state.slot) };

        assert_eq!(state.slot, 0);
        assert_eq!(state.before, 0xdead_beef);
        assert_eq!(state.after, 0xc001_d00d);
    }

    #[test]
    fn alias_08027c94_clears_only_its_target_word() {
        let mut state = GuardedSlot {
            before: 0x1020_3040,
            slot: 0x5060_7080,
            after: 0x90a0_b0c0,
        };

        unsafe { reset_u32_slot_alias_08027c94(&mut state.slot) };

        assert_eq!(state.slot, 0);
        assert_eq!(state.before, 0x1020_3040);
        assert_eq!(state.after, 0x90a0_b0c0);
    }
}
