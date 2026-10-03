//! `draw_state_counted_text_width` — retailOS `FUN_08263168` at
//! `0x08263168`, 44 bytes (`0x08263168..0x08263194`). Raw ARM scan verifies
//! two plain inbound BL sites (0x08263378, 0x08263a24), zero predicated
//! inbound BL sites, and one plain outgoing BL to 0x0807b1f4.
//!
//! Measures a signed count of permissively decoded UTF-8 codepoints using
//! the renderer at +0x1c, embedded metric context at +0x20, and flag byte at
//! +0x28. Passes a zero sixth stack argument and preserves the callee's r0
//! result, unlike Ghidra's void signature. The next function is the color
//! setter at 0x08263194. No target behavioral deviations: the unported
//! counted accumulator remains a fixed firmware call; hosts must install a
//! typed seam. Target-width word indexing keeps host offsets unchanged.

pub type CountedTextWidth = unsafe extern "C" fn(u32, *const u8, i32, *mut u8, u32, u32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_counted_text_width(renderer: u32, text: *const u8, count: i32, context: *mut u8, flags: u32, reserved: u32) -> i32 {
    let measure: CountedTextWidth = core::mem::transmute(0x0807_b1f4usize);
    measure(renderer, text, count, context, flags, reserved)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_counted_text_width(_: u32, _: *const u8, _: i32, _: *mut u8, _: u32, _: u32) -> i32 {
    panic!("counted text width requires firmware callee 0x0807b1f4")
}

#[cfg(not(target_os = "none"))]
pub static mut DRAW_STATE_COUNTED_TEXT_WIDTH: CountedTextWidth = missing_counted_text_width;

/// # Safety
/// `state` must be word-aligned and readable through +0x28; its embedded
/// context and `text` must satisfy the installed counted accumulator's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn draw_state_counted_text_width(state: *mut u32, text: *const u8, count: i32) -> i32 {
    #[cfg(target_os = "none")]
    let measure = firmware_counted_text_width;
    #[cfg(not(target_os = "none"))]
    let measure = core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_COUNTED_TEXT_WIDTH));
    measure(state.add(7).read(), text, count, state.add(8).cast(), state.add(10).cast::<u8>().read() as u32, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::utf8_next_codepoint_permissive::utf8_next_codepoint_permissive;

    // Behavioral fixture for the unported accumulator: metric context words
    // are signed ASCII/non-ASCII advances; flag bit 3 selects negative widths.
    unsafe extern "C" fn measure(_: u32, text: *const u8, count: i32, context: *mut u8, flags: u32, reserved: u32) -> i32 {
        assert_eq!(reserved, 0);
        let mut cursor = text;
        let mut width = 0i32;
        for _ in 0..count {
            let codepoint = utf8_next_codepoint_permissive(&mut cursor);
            let advance = context.cast::<i32>().add((codepoint >= 128) as usize).read();
            width = width.wrapping_add(if flags & 8 != 0 { -advance } else { advance });
        }
        width
    }

    #[test]
    fn counted_multibyte_prefix_signed_counts_and_flag_byte() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        unsafe {
            let saved = DRAW_STATE_COUNTED_TEXT_WIDTH;
            DRAW_STATE_COUNTED_TEXT_WIDTH = measure;
            let mut state = [0u32; 17];
            state[8] = 7;
            state[9] = 19;
            state[10] = 0xffff_ff00;
            let before = state;
            let text = b"A\xc2\xa2Z\0";
            assert_eq!(draw_state_counted_text_width(state.as_mut_ptr(), text.as_ptr(), 1), 7);
            assert_eq!(draw_state_counted_text_width(state.as_mut_ptr(), text.as_ptr(), 2), 26);
            assert_eq!(draw_state_counted_text_width(state.as_mut_ptr(), core::ptr::null(), 0), 0);
            assert_eq!(draw_state_counted_text_width(state.as_mut_ptr(), core::ptr::null(), i32::MIN), 0);
            assert_eq!(state, before);
            state[10] = 8;
            assert_eq!(draw_state_counted_text_width(state.as_mut_ptr(), text.as_ptr(), 2), -26);
            DRAW_STATE_COUNTED_TEXT_WIDTH = saved;
        }
    }
}
