//! latch_first_error — `FUN_0824f388` @ 0x0824f388 (24 bytes; 22 call
//! sites in osos, binary-verified B/BL scan: 20 plain `bl` + 2 `blcs`).
//!
//! Original:
//!
//! ```text
//! cmp  r1, #0          ; code == 0?
//! bxeq lr              ; a zero code is never recorded
//! ldr  r2, [r0]        ; current = *slot
//! cmp  r2, #0
//! streq r1, [r0]       ; first error wins: store only when still 0
//! bx   lr
//! ```
//!
//! Sticky first-error latch: `if (code != 0 && *slot == 0) *slot = code;`.
//! Error code zero doubles as "no error", so it can never be recorded and
//! an already-latched slot is never overwritten — the earliest nonzero
//! error survives until the caller clears the slot itself.
//!
//! Callers: all 22 sites sit inside the video-engine cluster
//! (0x0824d224..0x082551e0; see `util/video_engine.rs`). The two
//! predicated `blcs` sites (@ 0x0824fb40, 0x0825314c) gate the call on
//! their own unsigned range check (`code - 0x84c0 >= 2`) and pass the
//! unknown-property error code 0x500 — the callee itself has no flag or
//! NULL-slot guard, only the zero-code and first-wins guards decoded
//! above. Most other sites pass 0x500 for an unknown property id or an
//! out-of-range property value.
//!
//! No deviations: a two-argument leaf with no callees, no globals, and no
//! literal pool. Ghidra's decompile (`void FUN_0824f388(int *, int)`)
//! matches the raw bytes exactly.

/// latch_first_error — original: `FUN_0824f388` @ 0x0824f388 (24 bytes).
///
/// Records `code` into `*slot` only when `code` is nonzero and `*slot` is
/// still zero; a zero code or an already-latched slot leaves `*slot`
/// untouched, so the first nonzero error sticks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn latch_first_error(slot: *mut u32, code: u32) {
    if code == 0 {
        return;
    }
    if slot.read() == 0 {
        slot.write(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Literal model of the recovered C:
    /// `if (code != 0 && *slot == 0) *slot = code;`.
    fn reference_latch_first_error(slot: &mut u32, code: u32) {
        if code != 0 && *slot == 0 {
            *slot = code;
        }
    }

    #[test]
    fn zero_code_never_latches_into_an_empty_slot() {
        let mut slot = 0u32;
        unsafe { latch_first_error(&mut slot, 0) };
        assert_eq!(slot, 0);
    }

    #[test]
    fn nonzero_code_latches_into_an_empty_slot() {
        let mut slot = 0u32;
        unsafe { latch_first_error(&mut slot, 0x500) };
        assert_eq!(slot, 0x500);
    }

    #[test]
    fn first_error_wins_over_a_second_one() {
        let mut slot = 0u32;
        unsafe {
            latch_first_error(&mut slot, 0x500);
            latch_first_error(&mut slot, 0x501);
        }
        assert_eq!(slot, 0x500);
    }

    #[test]
    fn zero_code_does_not_clear_an_existing_error() {
        let mut slot = 0x500u32;
        unsafe { latch_first_error(&mut slot, 0) };
        assert_eq!(slot, 0x500);
    }

    #[test]
    fn boundary_codes_latch_verbatim() {
        for code in [1u32, 0x8000_0000, 0xffff_ffff] {
            let mut slot = 0u32;
            unsafe { latch_first_error(&mut slot, code) };
            assert_eq!(slot, code);
        }
    }

    #[test]
    fn matches_reference_across_slot_and_code_combinations() {
        for slot_seed in [0u32, 1, 0x500, 0xffff_ffff] {
            for code in [0u32, 1, 0x500, 0xffff_ffff] {
                let mut slot = slot_seed;
                let mut model = slot_seed;
                unsafe { latch_first_error(&mut slot, code) };
                reference_latch_first_error(&mut model, code);
                assert_eq!(slot, model, "slot={slot_seed:#x} code={code:#x}");
            }
        }
    }
}
