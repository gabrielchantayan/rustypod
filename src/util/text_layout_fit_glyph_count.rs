//! `text_layout_fit_glyph_count` — original: `FUN_082634e0` @
//! `0x082634e0` (72 bytes).
//!
//! # Algorithm
//!
//! The wrapper loads the layout's target-width font word at `+0x1c`, passes
//! its embedded metric context at `+0x20` and flag byte at `+0x28` to
//! `glyph_fit_engine`, and returns its count narrowed to sixteen bits. The
//! original has one plain `bl` and no predicated calls.

use super::glyph_fit_engine::glyph_fit_engine;

/// Counts at most `glyph_count` glyphs from `text` that fit within
/// `max_advance`, using the font, metric context, and flags embedded in
/// `layout`. The supplied engine records the accumulated advance when
/// `measured_advance` is non-NULL. The retail result is explicitly narrowed
/// to `u16` before return.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn text_layout_fit_glyph_count(
    layout: *mut u8,
    text: *const u8,
    glyph_count: u32,
    max_advance: u32,
    measured_advance: *mut u32,
) -> u32 {
    let font = (layout.add(0x1c) as *const u32).read();
    let metric_context = layout.add(0x20);
    let layout_flags = layout.add(0x28).read() as u32;
    glyph_fit_engine(
        font,
        text,
        glyph_count,
        metric_context,
        layout_flags,
        max_advance,
        measured_advance,
        0,
    ) & 0xffff
}
