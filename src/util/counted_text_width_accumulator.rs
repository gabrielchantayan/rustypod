//! `counted_text_width_accumulator` — retailOS `FUN_0807b1f4` at
//! `0x0807b1f4`, 96 bytes (`0x0807b1f4..0x0807b254`, next real entry).
//! Raw aligned ARM decoding finds two plain inbound BLs and zero predicated
//! inbound BLs; three plain outbound BLs and zero predicated outbound BLs.
//!
//! Resolves metrics even for nonpositive counts, then decodes exactly the
//! positive signed count of permissive UTF-8 codepoints (including NUL and
//! invalid leads), summing signed advances modulo 2^32. Only flag bit 3 is used.
//! Deliberate deviations: decoder and result dispatcher use existing Rust ports;
//! the unresolved resolver uses the existing firmware veneer and host seams.
//! Renderer is unused; callers' extra sixth argument is not read by retailOS.

use super::utf8_next_codepoint_permissive::utf8_next_codepoint_permissive;
use super::text_width_accumulate;

/// # Safety
/// `context` must satisfy the metric resolver and dispatcher contracts. For a
/// positive count, `text` must contain that many permissively decoded sequences,
/// including the decoder's required padding for malformed high-bit leads.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_text_width_accumulator(
    _renderer: u32, text: *const u8, count: i32, context: *mut u8, flags: u32,
) -> i32 {
    let mut table = core::ptr::null_mut();
    #[cfg(target_arch = "arm")]
    text_width_accumulate::retail_text_width_metric_table_resolve(context, &mut table);
    #[cfg(not(target_arch = "arm"))]
    text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER(context, &mut table);
    let mut cursor = text;
    let mut width = 0i32;
    let mut remaining = count;
    while remaining > 0 {
        let codepoint = utf8_next_codepoint_permissive(&mut cursor);
        #[cfg(target_arch = "arm")]
        let advance = crate::app::record_dispatch_result::record_dispatch_result(
            codepoint, context as usize as u32, table as usize as u32, flags & 8);
        #[cfg(not(target_arch = "arm"))]
        let advance = text_width_accumulate::TEXT_WIDTH_RECORD_DISPATCH_RESULT(codepoint, context, table, flags & 8);
        width = width.wrapping_add(advance);
        remaining -= 1;
    }
    width
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn resolve(context: *mut u8, table: *mut *mut u8) {
        // A resolver side effect is observable even for nonpositive counts.
        let context = context.cast::<i32>();
        *context += 1;
        *table = context.add(1).cast();
    }

    unsafe extern "C" fn advance(codepoint: u32, _: *mut u8, table: *mut u8, flags: u32) -> i32 {
        let index = match codepoint { 0 => 0, 0x41 => 1, 0xa2 => 2, 0x20ac => 3, _ => 4 };
        let value = table.cast::<i32>().add(index).read();
        if flags == 8 { value.wrapping_neg() } else { value }
    }

    #[test]
    fn counted_prefix_includes_nul_and_invalid_sequences_and_wraps() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        unsafe {
            let resolver = text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER;
            let dispatch = text_width_accumulate::TEXT_WIDTH_RECORD_DISPATCH_RESULT;
            text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER = resolve;
            text_width_accumulate::TEXT_WIDTH_RECORD_DISPATCH_RESULT = advance;
            let mut context = [0, 11, i32::MAX, -7, 23, 99];
            let text = b"A\xc2\xa2\xe2\x82\xac\0\xf0\x80\x80Z";
            let expected = [0i32, i32::MAX, i32::MAX - 7, (i32::MAX - 7).wrapping_add(23),
                (i32::MAX - 7).wrapping_add(34), (i32::MAX - 7).wrapping_add(45)];
            for count in 0..=5 {
                for flags in [0, 0xffff_fff7, 8, u32::MAX] {
                    let value = expected[count];
                    assert_eq!(counted_text_width_accumulator(0, text.as_ptr(), count as i32, context.as_mut_ptr().cast(), flags),
                        if flags & 8 != 0 { value.wrapping_neg() } else { value });
                }
            }
            for count in [0, -1, i32::MIN] {
                let before = context[0];
                assert_eq!(counted_text_width_accumulator(0, core::ptr::null(), count, context.as_mut_ptr().cast(), 8), 0);
                assert_eq!(context[0], before + 1);
            }
            // Exercise the real migrated caller, including its flag-byte load.
            let mut state = [0u32; 17];
            state[9] = 11;
            state[10] = 0xffff_ff00;
            assert_eq!(crate::cxx::draw_state_counted_text_width::draw_state_counted_text_width(state.as_mut_ptr(), b"\0".as_ptr(), 1), 11);
            text_width_accumulate::TEXT_WIDTH_METRIC_TABLE_RESOLVER = resolver;
            text_width_accumulate::TEXT_WIDTH_RECORD_DISPATCH_RESULT = dispatch;
        }
    }
}
