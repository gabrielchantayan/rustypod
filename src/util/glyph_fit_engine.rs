//! `glyph_fit_engine` — original: `FUN_080a7aa0` @ `0x080a7aa0`.
//!
//! Raw osos.dec establishes a 144-byte body at `0x080a7aa0..0x080a7b30`; the
//! separately entered next function begins at `0x080a7b30`. The body contains
//! three plain `bl` calls and no predicated calls. Whole-image A32 decoding
//! finds four plain inbound `bl` calls at `0x0808f574`, `0x0808f5ec`,
//! `0x08263244`, and `0x08263514`, with no predicated inbound calls.
//!
//! # Algorithm
//!
//! Resolves the metric table for `metric_context`. If one exists, decodes at
//! most `glyph_count` permissive UTF-8 codepoints, obtains each signed glyph
//! advance, and stops before that advance would make the signed accumulated
//! width exceed `max_advance`. It returns the number accepted and, only after
//! a metric table was resolved, stores the accumulated width when requested.
//!
//! Deliberate deviation: the two unported callees remain raw-address ARM
//! veneers. Host builds expose those calls as seams; their identities are
//! limited to the observed resolver and glyph-advance ABIs.

use super::utf8_next_codepoint_permissive::utf8_next_codepoint_permissive;

#[cfg(not(target_arch = "arm"))]
pub type MetricTableResolver = unsafe extern "C" fn(*mut u8, *mut *mut u8);
#[cfg(not(target_arch = "arm"))]
pub type GlyphAdvance = unsafe extern "C" fn(u32, *mut u8, *mut u8, u32) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn no_metric_table(_metric_context: *mut u8, table: *mut *mut u8) {
    *table = core::ptr::null_mut();
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn zero_glyph_advance(
    _codepoint: u32,
    _metric_context: *mut u8,
    _metric_table: *mut u8,
    _flags: u32,
) -> i32 {
    0
}

#[cfg(not(target_arch = "arm"))]
pub static mut METRIC_TABLE_RESOLVER: MetricTableResolver = no_metric_table;
#[cfg(not(target_arch = "arm"))]
pub static mut GLYPH_ADVANCE: GlyphAdvance = zero_glyph_advance;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_metric_table_resolve(metric_context: *mut u8, table: *mut *mut u8);
    fn retail_glyph_advance(codepoint: u32, metric_context: *mut u8, metric_table: *mut u8, flags: u32) -> i32;
}

/// Fits decoded glyphs within a signed advance budget.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.glyph_fit_engine_080a7aa0")]
#[inline(never)]
pub unsafe extern "C" fn glyph_fit_engine(
    _font: u32,
    text: *const u8,
    glyph_count: u32,
    metric_context: *mut u8,
    layout_flags: u32,
    max_advance: u32,
    measured_advance: *mut u32,
    _reserved: u32,
) -> u32 {
    let mut metric_table = core::ptr::null_mut();

    #[cfg(target_arch = "arm")]
    retail_metric_table_resolve(metric_context, &mut metric_table);
    #[cfg(not(target_arch = "arm"))]
    METRIC_TABLE_RESOLVER(metric_context, &mut metric_table);

    if metric_table.is_null() {
        return 0;
    }

    let mut cursor = text;
    let mut remaining = glyph_count as i32;
    let mut accepted = 0u32;
    let mut accumulated = 0i32;
    while remaining > 0 {
        let codepoint = utf8_next_codepoint_permissive(&mut cursor);
        #[cfg(target_arch = "arm")]
        let advance = retail_glyph_advance(codepoint, metric_context, metric_table, layout_flags);
        #[cfg(not(target_arch = "arm"))]
        let advance = GLYPH_ADVANCE(codepoint, metric_context, metric_table, layout_flags);
        let next_advance = accumulated.wrapping_add(advance);
        if next_advance > max_advance as i32 {
            break;
        }
        accumulated = next_advance;
        accepted = accepted.wrapping_add(1);
        remaining -= 1;
    }

    if !measured_advance.is_null() {
        *measured_advance = accumulated as u32;
    }
    accepted
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
retail_metric_table_resolve:
    ldr     pc, [pc, #-4]
    .word   0x0809e224
retail_glyph_advance:
    ldr     pc, [pc, #-4]
    .word   0x08080f18
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ADVANCES: [i32; 4] = [0; 4];
    static mut ADVANCE_INDEX: usize = 0;
    static mut RESOLVE_TABLE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn resolve_metric_table(_context: *mut u8, table: *mut *mut u8) {
        *table = RESOLVE_TABLE;
    }

    unsafe extern "C" fn next_glyph_advance(_codepoint: u32, _context: *mut u8, _table: *mut u8, _flags: u32) -> i32 {
        let advance = ADVANCES[ADVANCE_INDEX];
        ADVANCE_INDEX += 1;
        advance
    }

    fn arrange(advances: [i32; 4], table: *mut u8) -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            ADVANCES = advances;
            ADVANCE_INDEX = 0;
            RESOLVE_TABLE = table;
            METRIC_TABLE_RESOLVER = resolve_metric_table;
            GLYPH_ADVANCE = next_glyph_advance;
        }
        guard
    }

    #[test]
    fn stops_before_the_first_over_budget_glyph_and_reports_prior_width() {
        let mut metric_table = 0u8;
        let _guard = arrange([3, 4, 8, 0], &mut metric_table);
        let mut measured = 99;
        let accepted = unsafe { glyph_fit_engine(0, b"abc".as_ptr(), 3, core::ptr::null_mut(), 8, 10, &mut measured, 0) };
        assert_eq!(accepted, 2);
        assert_eq!(measured, 7);
        unsafe { assert_eq!(ADVANCE_INDEX, 3); }
    }

    #[test]
    fn null_metric_table_returns_without_writing_the_measurement() {
        let _guard = arrange([1, 0, 0, 0], core::ptr::null_mut());
        let mut measured = 99;
        let accepted = unsafe { glyph_fit_engine(0, b"a".as_ptr(), 1, core::ptr::null_mut(), 0, 10, &mut measured, 0) };
        assert_eq!(accepted, 0);
        assert_eq!(measured, 99);
    }

    #[test]
    fn empty_input_with_a_table_reports_zero() {
        let mut metric_table = 0u8;
        let _guard = arrange([0; 4], &mut metric_table);
        let mut measured = 99;
        let accepted = unsafe { glyph_fit_engine(0, b"".as_ptr(), 0, core::ptr::null_mut(), 0, 0, &mut measured, 0) };
        assert_eq!(accepted, 0);
        assert_eq!(measured, 0);
    }
}
