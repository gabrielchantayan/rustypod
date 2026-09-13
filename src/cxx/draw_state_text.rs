//! `draw_state_draw_text` — original: `FUN_08262cbc` @ `0x08262cbc`
//! (124 bytes, `0x08262cbc..0x08262d38`; the next separately linked entry
//! opens at `0x08262d38`).
//!
//! A complete decode of ARM `B`/`BL` immediates in `osos.dec` finds seven
//! direct inbound call sites, all unconditional `bl` and no predicated form:
//! `0x0809074c`, `0x08140f84`, `0x08148c98`, `0x081ca6d0`, `0x08263a14`,
//! `0x08263a68`, and `0x08263a74`. No aligned data word references this entry.
//!
//! # Algorithm
//!
//! Reads the draw target, embedded tagged layout state, colors, style, origin,
//! and clip rectangle from the 0x44-byte draw-state record. It first obtains a
//! signed vertical adjustment from the tagged state, then calls the resident
//! text-range renderer with `x + x_offset` and
//! `y - vertical_adjustment + y_offset`. The renderer's returned x coordinate
//! minus `x_offset` becomes the record's new write position.
//!
//! Deliberate deviation: the tagged-layout helper at `0x0829be90` and the
//! text-range renderer at `0x08077170` are not ledger-ported. Target builds
//! enter their resident retailOS entries through absolute veneers; host builds
//! expose a volatile operation table to prove this wrapper's ABI and arithmetic.

use core::ptr;

/// The fully observed 0x44-byte draw-state record used for text drawing.
///
/// Pointer-like fields remain `u32`: the firmware record is target-width on
/// every build, so host pointers must not widen later fields.
#[repr(C)]
pub struct DrawStateTextDrawFields {
    /// +0x00: updated from the text-range renderer's returned x coordinate.
    pub write_position: u32,
    /// +0x04: vertical origin before the tagged payload adjustment.
    pub vertical_origin: u32,
    pub _unknown_08_0f: [u32; 2],
    /// +0x10: byte widened for the renderer's seventh ABI argument.
    pub style: u8,
    /// +0x11: four-byte foreground color forwarded by address.
    pub foreground_color: [u8; 4],
    /// +0x15: four-byte background color forwarded by address.
    pub background_color: [u8; 4],
    /// +0x1c: target-width text renderer identity.
    pub renderer: u32,
    /// +0x20: embedded tagged layout object; its first word is tagged.
    pub layout_state: [u32; 2],
    /// +0x28: byte widened for the renderer's fourth ABI argument.
    pub layout_flags: u8,
    pub _unknown_29_2b: [u8; 3],
    /// +0x2c: added to both the renderer input and returned x coordinate.
    pub x_offset: u32,
    /// +0x30: added after the signed tagged-layout vertical adjustment.
    pub y_offset: u32,
    /// +0x34: four-word clip rectangle forwarded by address.
    pub clip_rect: [u32; 4],
}

/// ABI of the unported tagged-layout vertical-adjustment helper @ `0x0829be90`.
pub type TaggedLayoutVerticalAdjustment = unsafe extern "C" fn(layout_state: *mut u32) -> i32;

/// ABI of the unported text-range renderer @ `0x08077170`.
pub type TextRangeRenderer = unsafe extern "C" fn(
    renderer: *mut u8,
    text: *const u8,
    layout_state: *mut u8,
    layout_flags: u32,
    foreground_color: *mut u8,
    background_color: *mut u8,
    style: u32,
    x: u32,
    y: u32,
    clip_rect: *mut u8,
) -> u32;

/// Host replacements for the two unported retailOS dependencies.
#[derive(Clone, Copy)]
pub struct DrawStateTextDrawOps {
    pub tagged_layout_vertical_adjustment: TaggedLayoutVerticalAdjustment,
    pub render_text_range: TextRangeRenderer,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tagged_layout_vertical_adjustment(_layout_state: *mut u32) -> i32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_text_range_renderer(
    _renderer: *mut u8,
    _text: *const u8,
    _layout_state: *mut u8,
    _layout_flags: u32,
    _foreground_color: *mut u8,
    _background_color: *mut u8,
    _style: u32,
    _x: u32,
    _y: u32,
    _clip_rect: *mut u8,
) -> u32 {
    0
}

/// Default host behavior before the two resident dependencies are ported.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DRAW_STATE_TEXT_DRAW_OPS: DrawStateTextDrawOps = DrawStateTextDrawOps {
    tagged_layout_vertical_adjustment: missing_tagged_layout_vertical_adjustment,
    render_text_range: missing_text_range_renderer,
};

/// Volatile host seam for the unported tagged-layout and text-renderer calls.
#[cfg(not(target_os = "none"))]
pub static mut DRAW_STATE_TEXT_DRAW_OPS: DrawStateTextDrawOps = DEFAULT_DRAW_STATE_TEXT_DRAW_OPS;

#[cfg(target_os = "none")]
unsafe extern "C" {
    fn retail_tagged_layout_vertical_adjustment(layout_state: *mut u32) -> i32;
    fn retail_text_range_renderer(
        renderer: *mut u8,
        text: *const u8,
        layout_state: *mut u8,
        layout_flags: u32,
        foreground_color: *mut u8,
        background_color: *mut u8,
        style: u32,
        x: u32,
        y: u32,
        clip_rect: *mut u8,
    ) -> u32;
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn tagged_layout_vertical_adjustment(layout_state: *mut u32) -> i32 {
    retail_tagged_layout_vertical_adjustment(layout_state)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn tagged_layout_vertical_adjustment(layout_state: *mut u32) -> i32 {
    let ops = ptr::read_volatile(ptr::addr_of!(DRAW_STATE_TEXT_DRAW_OPS));
    (ops.tagged_layout_vertical_adjustment)(layout_state)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn render_text_range(
    renderer: *mut u8,
    text: *const u8,
    layout_state: *mut u8,
    layout_flags: u32,
    foreground_color: *mut u8,
    background_color: *mut u8,
    style: u32,
    x: u32,
    y: u32,
    clip_rect: *mut u8,
) -> u32 {
    retail_text_range_renderer(
        renderer,
        text,
        layout_state,
        layout_flags,
        foreground_color,
        background_color,
        style,
        x,
        y,
        clip_rect,
    )
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn render_text_range(
    renderer: *mut u8,
    text: *const u8,
    layout_state: *mut u8,
    layout_flags: u32,
    foreground_color: *mut u8,
    background_color: *mut u8,
    style: u32,
    x: u32,
    y: u32,
    clip_rect: *mut u8,
) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(DRAW_STATE_TEXT_DRAW_OPS));
    (ops.render_text_range)(
        renderer,
        text,
        layout_state,
        layout_flags,
        foreground_color,
        background_color,
        style,
        x,
        y,
        clip_rect,
    )
}

/// Draw a text range through the state record's resident renderer.
///
/// # Safety
///
/// `draw_state` must be non-NULL, four-byte aligned, and address an initialized
/// [`DrawStateTextDrawFields`] record. `text` and every forwarded embedded
/// pointer must meet the resident renderer's contract. The retail code has no
/// NULL, bounds, or alignment checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.draw_state_draw_text")]
#[inline(never)]
pub unsafe extern "C" fn draw_state_draw_text(
    draw_state: *mut DrawStateTextDrawFields,
    text: *const u8,
) {
    let layout_state = ptr::addr_of_mut!((*draw_state).layout_state).cast::<u8>();
    let vertical_adjustment = tagged_layout_vertical_adjustment(layout_state.cast()) as u32;
    let x_offset = ptr::addr_of!((*draw_state).x_offset).read();
    let x = ptr::addr_of!((*draw_state).write_position).read().wrapping_add(x_offset);
    let y = ptr::addr_of!((*draw_state).vertical_origin)
        .read()
        .wrapping_sub(vertical_adjustment)
        .wrapping_add(ptr::addr_of!((*draw_state).y_offset).read());
    let rendered_x = render_text_range(
        ptr::addr_of!((*draw_state).renderer).read() as usize as *mut u8,
        text,
        layout_state,
        ptr::addr_of!((*draw_state).layout_flags).read() as u32,
        ptr::addr_of_mut!((*draw_state).foreground_color).cast(),
        ptr::addr_of_mut!((*draw_state).background_color).cast(),
        ptr::addr_of!((*draw_state).style).read() as u32,
        x,
        y,
        ptr::addr_of_mut!((*draw_state).clip_rect).cast(),
    );
    ptr::addr_of_mut!((*draw_state).write_position).write(rendered_x.wrapping_sub(x_offset));
}

// Both target veneers preserve r0-r3 and every stack argument exactly as a
// direct retail `bl` would; the renderer veneer therefore also preserves its
// ten-argument ARM C ABI.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_tagged_layout_vertical_adjustment
    .type retail_tagged_layout_vertical_adjustment, %function
retail_tagged_layout_vertical_adjustment:
    ldr     pc, [pc, #-4]
    .word   0x0829be90
    .size retail_tagged_layout_vertical_adjustment, . - retail_tagged_layout_vertical_adjustment

    .p2align 2
    .globl retail_text_range_renderer
    .type retail_text_range_renderer, %function
retail_text_range_renderer:
    ldr     pc, [pc, #-4]
    .word   0x08077170
    .size retail_text_range_renderer, . - retail_text_range_renderer
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ADJUSTMENT: i32 = 0;
    static mut ADJUSTMENT_LAYOUT: usize = 0;
    static mut RENDER_RETURN: u32 = 0;
    static mut RENDER_CALL: Option<RenderCall> = None;

    #[derive(Debug, PartialEq, Eq)]
    struct RenderCall {
        renderer: usize,
        text: usize,
        layout_state: usize,
        layout_flags: u32,
        foreground_color: usize,
        background_color: usize,
        style: u32,
        x: u32,
        y: u32,
        clip_rect: usize,
    }

    unsafe extern "C" fn record_adjustment(layout_state: *mut u32) -> i32 {
        ADJUSTMENT_LAYOUT = layout_state as usize;
        ADJUSTMENT
    }

    unsafe extern "C" fn record_renderer(
        renderer: *mut u8,
        text: *const u8,
        layout_state: *mut u8,
        layout_flags: u32,
        foreground_color: *mut u8,
        background_color: *mut u8,
        style: u32,
        x: u32,
        y: u32,
        clip_rect: *mut u8,
    ) -> u32 {
        RENDER_CALL = Some(RenderCall {
            renderer: renderer as usize,
            text: text as usize,
            layout_state: layout_state as usize,
            layout_flags,
            foreground_color: foreground_color as usize,
            background_color: background_color as usize,
            style,
            x,
            y,
            clip_rect: clip_rect as usize,
        });
        RENDER_RETURN
    }

    unsafe fn install_recorders(adjustment: i32, render_return: u32) {
        ADJUSTMENT = adjustment;
        ADJUSTMENT_LAYOUT = 0;
        RENDER_RETURN = render_return;
        RENDER_CALL = None;
        ptr::addr_of_mut!(DRAW_STATE_TEXT_DRAW_OPS).write_volatile(DrawStateTextDrawOps {
            tagged_layout_vertical_adjustment: record_adjustment,
            render_text_range: record_renderer,
        });
    }

    fn draw_state() -> DrawStateTextDrawFields {
        DrawStateTextDrawFields {
            write_position: 0xffff_fff0,
            vertical_origin: 0xffff_fff8,
            _unknown_08_0f: [0; 2],
            style: 0xa5,
            foreground_color: [1, 2, 3, 4],
            background_color: [5, 6, 7, 8],
            renderer: 0x1234_5678,
            layout_state: [0xfeed_beef, 0xc001_c0de],
            layout_flags: 0x81,
            _unknown_29_2b: [0; 3],
            x_offset: 0x30,
            y_offset: 0x20,
            clip_rect: [11, 22, 33, 44],
        }
    }

    #[test]
    fn forwards_target_layout_and_updates_position_with_wrapping_offsets() {
        let _guard = TEST_LOCK.lock();
        let mut state = draw_state();
        let text = b"wrap\0";
        unsafe {
            install_recorders(-3, 0x10);
            draw_state_draw_text(&mut state, text.as_ptr());

            assert_eq!(ADJUSTMENT_LAYOUT, state.layout_state.as_mut_ptr() as usize);
            assert_eq!(
                RENDER_CALL,
                Some(RenderCall {
                    renderer: 0x1234_5678,
                    text: text.as_ptr() as usize,
                    layout_state: state.layout_state.as_mut_ptr() as usize,
                    layout_flags: 0x81,
                    foreground_color: state.foreground_color.as_mut_ptr() as usize,
                    background_color: state.background_color.as_mut_ptr() as usize,
                    style: 0xa5,
                    x: 0x20,
                    y: 0x1b,
                    clip_rect: state.clip_rect.as_mut_ptr().cast::<u8>() as usize,
                }),
            );
            assert_eq!(state.write_position, 0xffff_ffe0);
        }
    }

    #[test]
    fn positive_adjustment_subtracts_before_y_offset() {
        let _guard = TEST_LOCK.lock();
        let mut state = draw_state();
        state.write_position = 7;
        state.vertical_origin = 100;
        state.x_offset = 9;
        state.y_offset = 13;
        unsafe {
            install_recorders(42, 99);
            draw_state_draw_text(&mut state, core::ptr::null());

            assert_eq!(RENDER_CALL.as_ref().unwrap().x, 16);
            assert_eq!(RENDER_CALL.as_ref().unwrap().y, 71);
            assert!(RENDER_CALL.as_ref().unwrap().text == 0);
            assert_eq!(state.write_position, 90);
        }
    }
}
