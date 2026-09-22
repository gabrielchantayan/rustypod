//! `draw_state_wrapped_text_height` — original: `FUN_08264054` @
//! **0x08264054** (76 bytes, `0x08264054..0x082640a0`; two plain `bl`,
//! zero predicated `bl`, verified from raw `osos.dec` A32 words). Ghidra's
//! third reported `bl` is not present in the raw function body; the next
//! function starts at `0x082640a0`.
//!
//! # Algorithm
//!
//! Count the NUL-terminated text with the resident permissive UTF-8 counter,
//! truncate that count to the low 16 bits, then call the resident text-layout
//! height routine with the two caller parameters and two trailing zero words.
//! The layout routine at `0x08263bb8` remains unported.
//!
//! # Deliberate deviations
//!
//! The unported layout call crosses a volatile typed boundary so host tests
//! can observe every ABI argument. Target builds call the resident routine.

use crate::util::utf8_codepoint_count_permissive::utf8_codepoint_count_permissive;

/// ABI of the unported text-layout height routine at `0x08263bb8`.
pub type TextLayoutHeight = unsafe extern "C" fn(
    draw_state: *mut u8,
    text: *const u8,
    codepoint_count: u32,
    layout_limit: i32,
    line_spacing: i32,
    trailing_zero: u32,
    out_maximum: *mut i32,
) -> i32;

/// RetailOS load address of the text-layout height routine.
pub const TEXT_LAYOUT_HEIGHT_ADDRESS: usize = 0x0826_3bb8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_text_layout_height(
    draw_state: *mut u8,
    text: *const u8,
    codepoint_count: u32,
    layout_limit: i32,
    line_spacing: i32,
    trailing_zero: u32,
    out_maximum: *mut i32,
) -> i32 {
    let layout_height: TextLayoutHeight = core::mem::transmute(TEXT_LAYOUT_HEIGHT_ADDRESS);
    layout_height(draw_state, text, codepoint_count, layout_limit, line_spacing, trailing_zero, out_maximum)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_text_layout_height(
    _draw_state: *mut u8,
    _text: *const u8,
    _codepoint_count: u32,
    _layout_limit: i32,
    _line_spacing: i32,
    _trailing_zero: u32,
    _out_maximum: *mut i32,
) -> i32 {
    panic!("draw_state_wrapped_text_height requires layout routine 0x08263bb8")
}

#[cfg(target_os = "none")]
pub static mut TEXT_LAYOUT_HEIGHT: TextLayoutHeight = firmware_text_layout_height;
#[cfg(not(target_os = "none"))]
pub static mut TEXT_LAYOUT_HEIGHT: TextLayoutHeight = missing_text_layout_height;

#[inline(always)]
unsafe fn text_layout_height_entry() -> TextLayoutHeight {
    core::ptr::addr_of!(TEXT_LAYOUT_HEIGHT).read_volatile()
}

/// Returns the resident layout height for `text` in `draw_state`.
///
/// `text` must be non-NULL and satisfy the permissive counter's readable
/// NUL-terminated-string contract. The original forwards `layout_limit` and
/// `line_spacing` unchanged and always passes zero and NULL as the final two
/// layout arguments.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.draw_state_wrapped_text_height_08264054")]
#[inline(never)]
pub unsafe extern "C" fn draw_state_wrapped_text_height(
    draw_state: *mut u8,
    text: *const u8,
    layout_limit: i32,
    line_spacing: i32,
) -> i32 {
    let codepoint_count = utf8_codepoint_count_permissive(text) & 0xffff;
    text_layout_height_entry()(draw_state, text, codepoint_count, layout_limit, line_spacing, 0, core::ptr::null_mut())
}

#[cfg(test)]
pub(crate) unsafe fn reset_text_layout_height() {
    core::ptr::addr_of_mut!(TEXT_LAYOUT_HEIGHT).write_volatile(missing_text_layout_height);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut RECEIVED_DRAW_STATE: *mut u8 = core::ptr::null_mut();
    static mut RECEIVED_TEXT: *const u8 = core::ptr::null();
    static mut RECEIVED_CODEPOINT_COUNT: u32 = 0;
    static mut RECEIVED_LAYOUT_LIMIT: i32 = 0;
    static mut RECEIVED_LINE_SPACING: i32 = 0;
    static mut RECEIVED_TRAILING_ZERO: u32 = 1;
    static mut RECEIVED_OUT_MAXIMUM: *mut i32 = 1usize as *mut i32;
    static mut RETURN_HEIGHT: i32 = 0;

    unsafe extern "C" fn recording_text_layout_height(
        draw_state: *mut u8,
        text: *const u8,
        codepoint_count: u32,
        layout_limit: i32,
        line_spacing: i32,
        trailing_zero: u32,
        out_maximum: *mut i32,
    ) -> i32 {
        RECEIVED_DRAW_STATE = draw_state;
        RECEIVED_TEXT = text;
        RECEIVED_CODEPOINT_COUNT = codepoint_count;
        RECEIVED_LAYOUT_LIMIT = layout_limit;
        RECEIVED_LINE_SPACING = line_spacing;
        RECEIVED_TRAILING_ZERO = trailing_zero;
        RECEIVED_OUT_MAXIMUM = out_maximum;
        RETURN_HEIGHT
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_text_layout_height();
                RECEIVED_DRAW_STATE = core::ptr::null_mut();
                RECEIVED_TEXT = core::ptr::null();
                RECEIVED_CODEPOINT_COUNT = 0;
                RECEIVED_LAYOUT_LIMIT = 0;
                RECEIVED_LINE_SPACING = 0;
                RECEIVED_TRAILING_ZERO = 1;
                RECEIVED_OUT_MAXIMUM = 1usize as *mut i32;
                RETURN_HEIGHT = 0;
            }
        }
    }

    #[test]
    fn forwards_permissive_count_and_layout_arguments() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let _reset = Reset;
        let text = [b'A', 0xc2, 0xff, 0xe2, 0x80, 0x80, 0];
        let mut draw_state = [0u8; 4];

        unsafe {
            RETURN_HEIGHT = -37;
            core::ptr::addr_of_mut!(TEXT_LAYOUT_HEIGHT).write_volatile(recording_text_layout_height);
            assert_eq!(draw_state_wrapped_text_height(draw_state.as_mut_ptr(), text.as_ptr(), -12, 34), -37);
            assert_eq!(RECEIVED_DRAW_STATE, draw_state.as_mut_ptr());
            assert_eq!(RECEIVED_TEXT, text.as_ptr());
            assert_eq!(RECEIVED_CODEPOINT_COUNT, 3);
            assert_eq!(RECEIVED_LAYOUT_LIMIT, -12);
            assert_eq!(RECEIVED_LINE_SPACING, 34);
            assert_eq!(RECEIVED_TRAILING_ZERO, 0);
            assert!(RECEIVED_OUT_MAXIMUM.is_null());
        }
    }

    #[test]
    fn truncates_codepoint_count_to_u16_before_layout() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let _reset = Reset;
        let mut text = std::vec![b'x'; 0x1_0001];
        text.push(0);

        unsafe {
            core::ptr::addr_of_mut!(TEXT_LAYOUT_HEIGHT).write_volatile(recording_text_layout_height);
            draw_state_wrapped_text_height(core::ptr::null_mut(), text.as_ptr(), 0, 0);
            assert_eq!(RECEIVED_CODEPOINT_COUNT, 1);
        }
    }
}
