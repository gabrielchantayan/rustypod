//! `text_layout_fit_glyph_count` — original: `FUN_082634e0` @
//! `0x082634e0` (72 bytes).
//!
//! # Algorithm
//!
//! The wrapper loads the layout's target-width font word at `+0x1c`, passes
//! its embedded metric context at `+0x20` and flag byte at `+0x28` to the
//! retail glyph-fitting engine at `0x080a7aa0`, and returns its count narrowed
//! to sixteen bits. The original has one plain `bl` and no predicated calls.
//!
//! Deliberate deviation: the unported engine is reached through a
//! relocation-safe ARM veneer; host builds expose a callback seam.

/// ABI of the unported glyph-fitting engine at `0x080a7aa0`.
pub type GlyphFitEngine = unsafe extern "C" fn(
    u32,
    *const u8,
    u32,
    *mut u8,
    u32,
    u32,
    *mut u32,
    u32,
) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_glyph_fit_engine(
    _font: u32,
    _text: *const u8,
    _glyph_count: u32,
    _metric_context: *mut u8,
    _layout_flags: u32,
    _max_advance: u32,
    _measured_advance: *mut u32,
    _reserved: u32,
) -> u32 {
    0
}

/// Host-only seam for the unported glyph-fitting engine.
#[cfg(not(target_arch = "arm"))]
pub static mut GLYPH_FIT_ENGINE: GlyphFitEngine = missing_glyph_fit_engine;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_glyph_fit_engine(
        font: u32,
        text: *const u8,
        glyph_count: u32,
        metric_context: *mut u8,
        layout_flags: u32,
        max_advance: u32,
        measured_advance: *mut u32,
        reserved: u32,
    ) -> u32;
}

/// text_layout_fit_glyph_count — original: `FUN_082634e0` @ `0x082634e0`
/// (72 bytes; one plain `bl`, no predicated calls).
///
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

    #[cfg(target_arch = "arm")]
    let fitted_count = retail_glyph_fit_engine(
        font,
        text,
        glyph_count,
        metric_context,
        layout_flags,
        max_advance,
        measured_advance,
        0,
    );

    #[cfg(not(target_arch = "arm"))]
    let fitted_count = GLYPH_FIT_ENGINE(
        font,
        text,
        glyph_count,
        metric_context,
        layout_flags,
        max_advance,
        measured_advance,
        0,
    );

    fitted_count & 0xffff
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
retail_glyph_fit_engine:
    ldr     pc, [pc, #-4]
    .word   0x080a7aa0
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static ENGINE_CALLED: AtomicBool = AtomicBool::new(false);
    static mut RECEIVED: (u32, usize, u32, usize, u32, u32, usize, u32) = (0, 0, 0, 0, 0, 0, 0, 0);

    unsafe extern "C" fn recording_glyph_fit_engine(
        font: u32,
        text: *const u8,
        glyph_count: u32,
        metric_context: *mut u8,
        layout_flags: u32,
        max_advance: u32,
        measured_advance: *mut u32,
        reserved: u32,
    ) -> u32 {
        RECEIVED = (font, text as usize, glyph_count, metric_context as usize, layout_flags, max_advance, measured_advance as usize, reserved);
        ENGINE_CALLED.store(true, Ordering::SeqCst);
        0x12345
    }

    fn arrange() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        ENGINE_CALLED.store(false, Ordering::SeqCst);
        unsafe { GLYPH_FIT_ENGINE = recording_glyph_fit_engine; }
        guard
    }

    #[test]
    fn forwards_layout_fields_and_narrows_the_retail_result() {
        let _guard = arrange();
        let mut layout = [0u8; 0x2c];
        let font = 0x9abc_def0u32;
        layout[0x1c..0x20].copy_from_slice(&font.to_ne_bytes());
        layout[0x28] = 0x8d;
        let text = b"glyphs";
        let mut measured_advance = 0u32;

        let count = unsafe {
            text_layout_fit_glyph_count(
                layout.as_mut_ptr(),
                text.as_ptr(),
                6,
                0x1020_3040,
                &mut measured_advance,
            )
        };

        assert_eq!(count, 0x2345);
        assert!(ENGINE_CALLED.load(Ordering::SeqCst));
        unsafe {
            assert_eq!(RECEIVED, (font, text.as_ptr() as usize, 6, layout.as_mut_ptr().add(0x20) as usize, 0x8d, 0x1020_3040, &mut measured_advance as *mut u32 as usize, 0));
        }
    }

    #[test]
    fn passes_null_measured_advance_unchanged() {
        let _guard = arrange();
        let mut layout = [0u8; 0x2c];
        let text = [0u8];

        unsafe { text_layout_fit_glyph_count(layout.as_mut_ptr(), text.as_ptr(), 0, 0, core::ptr::null_mut()); }

        unsafe { assert_eq!(RECEIVED.6, 0); }
    }
}
