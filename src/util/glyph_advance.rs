//! `glyph_advance` — original: `FUN_0807b1c0` @ `0x0807b1c0`.
//! True extent: 52 bytes, ending at the next function entry `0x0807b1f4`.
//! Raw ARM has two plain BLs (0x0809e224, 0x08080f18), no predicated BLs.
//! Resolves the context's metric table and returns one codepoint's signed
//! advance using only layout flag bit 3. The renderer argument is unused.
//! Deliberate deviations: reuses the existing resolver veneer/host seam and
//! ported dispatch-result callee. Initializes the output slot to null instead
//! of incoming flags; the resolver overwrites the slot on every return path.

use crate::app::record_dispatch_result::record_dispatch_result;

/// # Safety
/// `metric_context` must satisfy the retailOS metric resolver and dispatch
/// contracts. The renderer is never dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn glyph_advance(
    _renderer: *mut u8,
    codepoint: u32,
    metric_context: *mut u8,
    layout_flags: u32,
) -> i32 {
    let mut metric_table = core::ptr::null_mut();
    #[cfg(target_arch = "arm")]
    super::text_width_accumulate::retail_text_width_metric_table_resolve(metric_context, &mut metric_table);
    #[cfg(not(target_arch = "arm"))]
    super::text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER(metric_context, &mut metric_table);
    record_dispatch_result(codepoint, metric_context as usize as u32, metric_table as usize as u32, layout_flags & 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::record_dispatch_result::{RECORD_DISPATCH, TEST_LOCK};
    use crate::util::text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER;

    unsafe extern "C" fn no_table(_context: *mut u8, table: *mut *mut u8) {
        *table = core::ptr::null_mut();
    }

    unsafe extern "C" fn dispatch(
        record: *mut u8, codepoint: u32, _context: u32, _table: *mut u32, flags: u32,
    ) -> u32 {
        // Model a missing glyph and a signed advance selected by layout mode.
        record.add(12).cast::<i16>().write(if flags == 8 { i16::MIN } else { i16::MAX });
        u32::from(codepoint != 0)
    }

    #[test]
    fn signed_extremes_missing_glyph_and_unrelated_layout_bits() {
        let _system = crate::ft::system::TEST_OPS_LOCK.lock();
        let _dispatch = TEST_LOCK.lock();
        unsafe {
            let old_resolver = TEXT_WIDTH_METRIC_TABLE_RESOLVER;
            let old_dispatch = RECORD_DISPATCH;
            TEXT_WIDTH_METRIC_TABLE_RESOLVER = no_table;
            RECORD_DISPATCH = dispatch;
            let context = core::ptr::null_mut();
            for (codepoint, flags, expected) in [
                (0x10ffff, 0, i16::MAX as i32),
                (0x10ffff, 0xffff_fff7, i16::MAX as i32),
                (0x10ffff, 8, i16::MIN as i32),
                (0x10ffff, u32::MAX, i16::MIN as i32),
                (0, 8, 0),
                (0, 0, 0),
            ] {
                assert_eq!(glyph_advance(core::ptr::null_mut(), codepoint, context, flags), expected);
            }
            TEXT_WIDTH_METRIC_TABLE_RESOLVER = old_resolver;
            RECORD_DISPATCH = old_dispatch;
        }
    }
}
