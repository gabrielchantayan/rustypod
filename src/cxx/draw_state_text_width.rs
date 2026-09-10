//! `draw_state_text_width` — original: `FUN_08263384` @ **0x08263384**
//! (20 bytes, 0x08263384..0x08263398; 10 verified direct `bl` call sites,
//! all unconditional).
//!
//! # Algorithm
//!
//! This five-instruction draw-state adapter selects the text renderer word at
//! draw-state word 7 (`+0x1c`), the embedded two-word layout state at words
//! 8–9 (`+0x20`), and the low byte of word 10 (`+0x28`).  It preserves the
//! caller's text pointer in `r1`, then tail-branches to the shared UTF-8 text
//! width accumulator at `0x080878d8`.  The accumulator remains unported: it
//! iterates through the NUL-terminated text with `utf8_next_codepoint_permissive`
//! and sums one glyph width per decoded codepoint.
//!
//! The raw next entry begins at 0x08263398, so the reported 20-byte extent has
//! no literal pool or swallowed sibling. A complete osos.dec ARM B/BL scan
//! found exactly 10 direct BL sites, with no predicated form and no plain B
//! references. No deliberate behavioral deviations: the Rust adapter reaches
//! the resident accumulator through a volatile typed boundary so host tests
//! can observe the exact ABI forwarding.

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

/// ABI of the unported shared accumulator at retailOS address `0x080878d8`.
pub type TextWidthAccumulator = unsafe extern "C" fn(
    renderer: *mut u8,
    text: *const u8,
    layout_state: *mut u8,
    flags: u32,
) -> u32;

/// RetailOS load address of the shared UTF-8 text-width accumulator.
pub const TEXT_WIDTH_ACCUMULATOR_ADDRESS: usize = 0x0808_78d8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_text_width_accumulator(
    renderer: *mut u8,
    text: *const u8,
    layout_state: *mut u8,
    flags: u32,
) -> u32 {
    let accumulator: TextWidthAccumulator = core::mem::transmute(TEXT_WIDTH_ACCUMULATOR_ADDRESS);
    accumulator(renderer, text, layout_state, flags)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_text_width_accumulator(
    _renderer: *mut u8,
    _text: *const u8,
    _layout_state: *mut u8,
    _flags: u32,
) -> u32 {
    panic!("draw_state_text_width requires accumulator 0x080878d8")
}

/// Active boundary for the unported text-width accumulator.
///
/// Target builds call the resident retailOS function; host tests install a
/// recorder that proves the adapter's field selection and byte widening.
#[cfg(target_os = "none")]
pub static mut TEXT_WIDTH_ACCUMULATOR: TextWidthAccumulator = firmware_text_width_accumulator;

/// Active host boundary for the unported text-width accumulator.
#[cfg(not(target_os = "none"))]
pub static mut TEXT_WIDTH_ACCUMULATOR: TextWidthAccumulator = missing_text_width_accumulator;

#[inline(always)]
unsafe fn text_width_accumulator_entry() -> TextWidthAccumulator {
    core::ptr::addr_of!(TEXT_WIDTH_ACCUMULATOR).read_volatile()
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
    text_width_accumulator_entry()(renderer, text, layout_state, flags)
}

#[cfg(test)]
pub(crate) unsafe fn reset_text_width_accumulator() {
    core::ptr::addr_of_mut!(TEXT_WIDTH_ACCUMULATOR).write_volatile(missing_text_width_accumulator);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static mut RECEIVED_RENDERER: usize = 0;
    static mut RECEIVED_TEXT: *const u8 = core::ptr::null();
    static mut RECEIVED_LAYOUT_STATE: *mut u8 = core::ptr::null_mut();
    static mut RECEIVED_FLAGS: u32 = 0;
    static mut RETURN_WIDTH: u32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_accumulator(
        renderer: *mut u8,
        text: *const u8,
        layout_state: *mut u8,
        flags: u32,
    ) -> u32 {
        RECEIVED_RENDERER = renderer as usize;
        RECEIVED_TEXT = text;
        RECEIVED_LAYOUT_STATE = layout_state;
        RECEIVED_FLAGS = flags;
        CALLS += 1;
        RETURN_WIDTH
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                reset_text_width_accumulator();
                RECEIVED_RENDERER = 0;
                RECEIVED_TEXT = core::ptr::null();
                RECEIVED_LAYOUT_STATE = core::ptr::null_mut();
                RECEIVED_FLAGS = 0;
                RETURN_WIDTH = 0;
                CALLS = 0;
            }
        }
    }

    #[test]
    fn forwards_renderer_text_and_embedded_layout_state() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let _reset = Reset;
        let text = b"A\xc2\xa2\0";
        let mut draw_state = DrawStateTextMeasureFields {
            opaque_prefix: [0; 7],
            renderer: 0x08a7_7c3c,
            layout_state: [0x1122_3344, 0x5566_7788],
            layout_flags: 0xdead_be8e,
        };

        unsafe {
            RETURN_WIDTH = 37;
            core::ptr::addr_of_mut!(TEXT_WIDTH_ACCUMULATOR).write_volatile(recording_accumulator);
            assert_eq!(draw_state_text_width(&mut draw_state, text.as_ptr()), 37);
            assert_eq!(CALLS, 1);
            assert_eq!(RECEIVED_RENDERER, 0x08a7_7c3c);
            assert_eq!(RECEIVED_TEXT, text.as_ptr());
            assert_eq!(
                RECEIVED_LAYOUT_STATE,
                core::ptr::addr_of_mut!(draw_state.layout_state).cast::<u8>(),
            );
            assert_eq!(RECEIVED_FLAGS, 0x8e);
        }
    }

    #[test]
    fn forwards_null_text_and_only_the_flag_low_byte() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let _reset = Reset;
        let mut draw_state = DrawStateTextMeasureFields {
            opaque_prefix: [0; 7],
            renderer: 0,
            layout_state: [0; 2],
            layout_flags: 0xff00_00a5,
        };

        unsafe {
            core::ptr::addr_of_mut!(TEXT_WIDTH_ACCUMULATOR).write_volatile(recording_accumulator);
            assert_eq!(draw_state_text_width(&mut draw_state, core::ptr::null()), 0);
            assert_eq!(CALLS, 1);
            assert!(RECEIVED_TEXT.is_null());
            assert_eq!(RECEIVED_FLAGS, 0xa5);
        }
    }
}
