//! `text_width_accumulate` — original: `FUN_080878d8` @ `0x080878d8`
//! (88 bytes, `0x080878d8..0x08087930`; the next separately entered function
//! begins at `0x08087944`).
//!
//! Raw ARM contains three plain `bl` calls (to `0x0809e224`, `0x08080f18`, and
//! `0x0807a0c8`) and no predicated `bl` calls. It resolves a glyph metric table,
//! then decodes a NUL-terminated string as permissive UTF-8 and adds each glyph
//! advance. Only layout flag bit 3 reaches the advance routine.
//!
//! Deliberate deviation: the unresolved metric-table resolver remains a fixed
//! retailOS veneer on ARM; host builds expose it and the ported dispatch-result
//! callee as typed seams.

use crate::app::record_dispatch_result::record_dispatch_result;
use super::utf8_next_codepoint_permissive::utf8_next_codepoint_permissive;

#[cfg(not(target_arch = "arm"))]
pub type MetricTableResolver = unsafe extern "C" fn(*mut u8, *mut *mut u8);
#[cfg(not(target_arch = "arm"))]
pub type RecordDispatchResult = unsafe extern "C" fn(u32, *mut u8, *mut u8, u32) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn no_metric_table(_metric_context: *mut u8, table: *mut *mut u8) {
    *table = core::ptr::null_mut();
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn zero_record_dispatch_result(
    _codepoint: u32,
    _metric_context: *mut u8,
    _metric_table: *mut u8,
    _flags: u32,
) -> i32 {
    0
}

#[cfg(not(target_arch = "arm"))]
pub static mut TEXT_WIDTH_METRIC_TABLE_RESOLVER: MetricTableResolver = no_metric_table;
#[cfg(not(target_arch = "arm"))]
pub static mut TEXT_WIDTH_RECORD_DISPATCH_RESULT: RecordDispatchResult = zero_record_dispatch_result;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_text_width_metric_table_resolve(metric_context: *mut u8, table: *mut *mut u8);
}

/// Sums the advances of every permissively decoded codepoint before the NUL.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.text_width_accumulate_080878d8")]
#[inline(never)]
pub unsafe extern "C" fn text_width_accumulate(
    _renderer: *mut u8,
    text: *const u8,
    metric_context: *mut u8,
    layout_flags: u32,
) -> u32 {
    let mut metric_table = core::ptr::null_mut();
    #[cfg(target_arch = "arm")]
    retail_text_width_metric_table_resolve(metric_context, &mut metric_table);
    #[cfg(not(target_arch = "arm"))]
    TEXT_WIDTH_METRIC_TABLE_RESOLVER(metric_context, &mut metric_table);

    let mut cursor = text;
    let mut width = 0u32;
    loop {
        let codepoint = utf8_next_codepoint_permissive(&mut cursor);
        if codepoint == 0 {
            return width;
        }
        #[cfg(target_arch = "arm")]
        let advance = record_dispatch_result(codepoint, metric_context as usize as u32, metric_table as usize as u32, layout_flags & 8);
        #[cfg(not(target_arch = "arm"))]
        let advance = TEXT_WIDTH_RECORD_DISPATCH_RESULT(codepoint, metric_context, metric_table, layout_flags & 8);
        width = width.wrapping_add(advance as u32);
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
retail_text_width_metric_table_resolve:
    ldr     pc, [pc, #-4]
    .word   0x0809e224
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut METRIC_TABLE: *mut u8 = core::ptr::null_mut();
    static mut ADVANCES: [i32; 3] = [0; 3];
    static mut ADVANCE_INDEX: usize = 0;
    static mut LAST_FLAGS: u32 = 0;

    unsafe extern "C" fn resolve_metric_table(_context: *mut u8, table: *mut *mut u8) {
        *table = METRIC_TABLE;
    }

    unsafe extern "C" fn record_dispatch_result_seam(_codepoint: u32, _context: *mut u8, _table: *mut u8, flags: u32) -> i32 {
        LAST_FLAGS = flags;
        let advance = ADVANCES[ADVANCE_INDEX];
        ADVANCE_INDEX += 1;
        advance
    }

    fn arrange(table: *mut u8, advances: [i32; 3]) {
        unsafe {
            METRIC_TABLE = table;
            ADVANCES = advances;
            ADVANCE_INDEX = 0;
            LAST_FLAGS = 0;
            TEXT_WIDTH_METRIC_TABLE_RESOLVER = resolve_metric_table;
            TEXT_WIDTH_RECORD_DISPATCH_RESULT = record_dispatch_result_seam;
        }
    }

    #[test]
    fn accumulates_multibyte_text_and_masks_layout_flags() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let mut metric_table = 0u8;
        arrange(&mut metric_table, [3, -5, 0]);
        let width = unsafe { text_width_accumulate(core::ptr::null_mut(), b"A\xc2\xa2\0".as_ptr(), core::ptr::null_mut(), 0xffff_fff8) };
        assert_eq!(width, u32::MAX - 1);
        unsafe {
            assert_eq!(ADVANCE_INDEX, 2);
            assert_eq!(LAST_FLAGS, 8);
        }
    }

    #[test]
    fn empty_text_does_not_call_the_glyph_advance() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let mut metric_table = 0u8;
        arrange(&mut metric_table, [99; 3]);
        assert_eq!(unsafe { text_width_accumulate(core::ptr::null_mut(), b"\0".as_ptr(), core::ptr::null_mut(), 0) }, 0);
        unsafe { assert_eq!(ADVANCE_INDEX, 0); }
    }
}
