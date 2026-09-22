//! `text_layout_render_counted` — original: `FUN_082633f0` @
//! **0x082633f0** (76 bytes, `0x082633f0..0x0826343b`; all code). The next
//! independently entered function begins at `0x0826343c`. Raw A32 decoding
//! finds two outgoing unconditional plain `bl` instructions and no predicated
//! `bl`; a whole-image decode finds three incoming plain `bl` instructions at
//! `0x081b3294`, `0x0820de3c`, and `0x08290c9c`, with no predicated calls.
//!
//! # Algorithm
//!
//! Count the NUL-terminated text with the resident permissive UTF-8 counter,
//! truncate that count to the low 16 bits, then call the resident text-layout
//! renderer with the original target, text, count, layout limit, and mode,
//! followed by two zero words.
//!
//! # Deliberate deviations
//!
//! `0x082631fc` has no established semantic identity or Rust port. Target
//! builds call that exact load address; host tests install a recording seam.
//! The wrapper has no NULL or bounds guards, matching the retail body.

use crate::util::utf8_codepoint_count_permissive::utf8_codepoint_count_permissive;

/// ABI of the unported text-layout renderer at `0x082631fc`.
pub type TextLayoutRender = unsafe extern "C" fn(*mut u8, *const u8, u32, i32, u32, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_text_layout_render(
    target: *mut u8,
    text: *const u8,
    codepoint_count: u32,
    layout_limit: i32,
    mode: u32,
    trailing_zero0: u32,
    trailing_zero1: u32,
) {
    let render: TextLayoutRender = core::mem::transmute(0x0826_31fcusize);
    render(target, text, codepoint_count, layout_limit, mode, trailing_zero0, trailing_zero1)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_text_layout_render(
    _target: *mut u8,
    _text: *const u8,
    _codepoint_count: u32,
    _layout_limit: i32,
    _mode: u32,
    _trailing_zero0: u32,
    _trailing_zero1: u32,
) {
    panic!("text layout renderer 0x082631fc is unavailable on the host")
}

#[cfg(target_os = "none")]
pub static mut TEXT_LAYOUT_RENDER: TextLayoutRender = firmware_text_layout_render;
#[cfg(not(target_os = "none"))]
pub static mut TEXT_LAYOUT_RENDER: TextLayoutRender = missing_text_layout_render;

#[inline(always)]
unsafe fn text_layout_render_entry() -> TextLayoutRender {
    core::ptr::addr_of!(TEXT_LAYOUT_RENDER).read_volatile()
}

/// Renders NUL-terminated `text` through the resident counted-text layout path.
///
/// # Safety
///
/// `text` must satisfy [`utf8_codepoint_count_permissive`]'s readable
/// NUL-terminated-string contract. The remaining arguments must satisfy the
/// unported renderer's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.text_layout_render_counted_082633f0")]
#[inline(never)]
pub unsafe extern "C" fn text_layout_render_counted(
    target: *mut u8,
    text: *const u8,
    layout_limit: i32,
    mode: u32,
) {
    let codepoint_count = utf8_codepoint_count_permissive(text) & 0xffff;
    text_layout_render_entry()(target, text, codepoint_count, layout_limit, mode, 0, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut RECEIVED: (*mut u8, *const u8, u32, i32, u32, u32, u32) =
        (core::ptr::null_mut(), core::ptr::null(), 0, 0, 0, 1, 1);

    unsafe extern "C" fn recording_text_layout_render(
        target: *mut u8,
        text: *const u8,
        codepoint_count: u32,
        layout_limit: i32,
        mode: u32,
        trailing_zero0: u32,
        trailing_zero1: u32,
    ) {
        RECEIVED = (target, text, codepoint_count, layout_limit, mode, trailing_zero0, trailing_zero1);
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                TEXT_LAYOUT_RENDER = missing_text_layout_render;
                RECEIVED = (core::ptr::null_mut(), core::ptr::null(), 0, 0, 0, 1, 1);
            }
        }
    }

    #[test]
    fn forwards_permissive_count_and_render_arguments() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let _reset = Reset;
        let text = [b'A', 0xc2, 0xff, 0xe2, 0x80, 0x80, 0];
        let mut target = [0u8; 1];

        unsafe {
            TEXT_LAYOUT_RENDER = recording_text_layout_render;
            text_layout_render_counted(target.as_mut_ptr(), text.as_ptr(), -12, 0x34);
            assert_eq!(RECEIVED, (target.as_mut_ptr(), text.as_ptr(), 3, -12, 0x34, 0, 0));
        }
    }

    #[test]
    fn truncates_codepoint_count_to_u16_before_rendering() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let _reset = Reset;
        let mut text = std::vec![b'x'; 0x1_0001];
        text.push(0);

        unsafe {
            TEXT_LAYOUT_RENDER = recording_text_layout_render;
            text_layout_render_counted(core::ptr::null_mut(), text.as_ptr(), 0, 0);
            assert_eq!(RECEIVED.2, 1);
        }
    }
}
