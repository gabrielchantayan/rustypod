//! `draw_state_counted_text_width` — retailOS `FUN_08263168` at
//! `0x08263168`, 44 bytes (`0x08263168..0x08263194`). Raw ARM scan verifies
//! two plain inbound BL sites (0x08263378, 0x08263a24), zero predicated
//! inbound BL sites, and one plain outgoing BL to 0x0807b1f4.
//!
//! Measures a signed count of permissively decoded UTF-8 codepoints using
//! the renderer at +0x1c, embedded metric context at +0x20, and flag byte at
//! +0x28. Preserves the callee's r0 result, unlike Ghidra's void signature.
//! The next function is the color setter at 0x08263194. Calls the Rust counted
//! accumulator; omits the unused sixth stack argument. Target-width word
//! indexing keeps host offsets unchanged.

/// # Safety
/// `state` must be word-aligned and readable through +0x28; its embedded
/// context and `text` must satisfy the counted accumulator's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn draw_state_counted_text_width(state: *mut u32, text: *const u8, count: i32) -> i32 {
    crate::util::counted_text_width_accumulator::counted_text_width_accumulator(
        state.add(7).read(), text, count, state.add(8).cast(), state.add(10).cast::<u8>().read() as u32)
}
