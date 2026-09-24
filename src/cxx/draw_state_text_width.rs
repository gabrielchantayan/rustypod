//! `draw_state_text_width` — original: `FUN_08263384` @ **0x08263384**
//! (20 bytes, 0x08263384..0x08263398; 10 verified direct `bl` call sites,
//! all unconditional).
//!
//! # Algorithm
//!
//! This five-instruction draw-state adapter selects the text renderer word at
//! draw-state word 7 (`+0x1c`), the embedded two-word layout state at words
//! 8–9 (`+0x20`), and the low byte of word 10 (`+0x28`). It preserves the
//! caller's text pointer in `r1`, then tail-branches to `text_width_accumulate`.
//!
//! The raw next entry begins at 0x08263398, so the reported 20-byte extent has
//! no literal pool or swallowed sibling. A complete osos.dec ARM B/BL scan
//! found exactly 10 direct BL sites, with no predicated form and no plain B
//! references. No deliberate behavioral deviations: it calls the Rust port of
//! the shared accumulator directly.

use crate::text_width_accumulate::text_width_accumulate;

/// Prefix of the 0x44-byte draw-state record used by the width adapter.
///
/// These are 32-bit firmware words even on a 64-bit host: representing the
/// renderer identity as a host pointer would shift all later fields by four
/// bytes. `layout_state` is the embedded pair passed verbatim to the shared
/// text-width accumulator; its internal layout remains unidentified.
#[repr(C)]
pub struct DrawStateTextMeasureFields {
    opaque_prefix: [u32; 7],
    renderer: u32,
    layout_state: [u32; 2],
    layout_flags: u32,
}


/// Measure a NUL-terminated UTF-8 string using the renderer in `draw_state`.
///
/// The adapter itself has no NULL, alignment, or text termination guard: it
/// unconditionally reads words 7–10 of the draw-state record and tail-calls
/// the accumulator. `draw_state` must therefore point to a word-aligned,
/// initialized draw-state record and `text` must satisfy the accumulator's
/// NUL-terminated-string contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.draw_state_text_width_08263384")]
#[inline(never)]
pub unsafe extern "C" fn draw_state_text_width(
    draw_state: *mut DrawStateTextMeasureFields,
    text: *const u8,
) -> u32 {
    let renderer = core::ptr::addr_of!((*draw_state).renderer).read() as usize as *mut u8;
    let layout_state = core::ptr::addr_of_mut!((*draw_state).layout_state).cast::<u8>();
    let flags = core::ptr::addr_of!((*draw_state).layout_flags).cast::<u8>().read() as u32;
    text_width_accumulate(renderer, text, layout_state, flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut FLAGS: u32 = 0;

    unsafe extern "C" fn resolve_metric_table(_context: *mut u8, table: *mut *mut u8) {
        *table = 1 as *mut u8;
    }

    unsafe extern "C" fn record_dispatch_result_seam(_codepoint: u32, _context: *mut u8, _table: *mut u8, flags: u32) -> i32 {
        FLAGS = flags;
        37
    }

    #[test]
    fn forwards_renderer_text_embedded_layout_state_and_low_flag_byte() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let text = b"A\0";
        let mut draw_state = DrawStateTextMeasureFields {
            opaque_prefix: [0; 7],
            renderer: 0x08a7_7c3c,
            layout_state: [0x1122_3344, 0x5566_7788],
            layout_flags: 0xdead_be8e,
        };

        unsafe {
            crate::text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER = resolve_metric_table;
            crate::text_width_accumulate::TEXT_WIDTH_RECORD_DISPATCH_RESULT = record_dispatch_result_seam;
            FLAGS = 0;
            assert_eq!(draw_state_text_width(&mut draw_state, text.as_ptr()), 37);
            assert_eq!(FLAGS, 8);
        }
    }
}
