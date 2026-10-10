//! `draw_state_beveled_rect` — FUN_0808d9e4 @ 0x0808d9e4.
//! True size 140 bytes: 128 code + 12 literals, next function 0x0808da70.
//! Raw scan: 2 plain inbound BLs, 7 plain outbound BLs, no predicated BLs.
//!
//! Select background by a full-word nonzero flag, fill then stroke the original
//! bounds, copy the bounds after both draws, inset by (1,1), and draw a normal
//! or reversed two-color border. Finally set foreground to global 0x089cc8d0.
//! The pop into r0/r1 returns the inset top/left as a register-pair u64.
//!
//! Deliberate deviation: runtime palette addresses use the existing volatile
//! data-seam convention for host execution; target defaults match the literals.
//! All callees reuse existing ports and their renderer seams. No validation.

use crate::cxx::draw_state_color::{draw_state_set_background_color, draw_state_set_foreground_color};
use crate::cxx::draw_state_fill::draw_state_fill_rect_background;
use crate::cxx::draw_state_stroke::draw_state_stroke_rect;
use crate::cxx::draw_state_two_color_border::draw_state_two_color_border;
use crate::cxx::draw_state_reversed_two_color_border::draw_state_reversed_two_color_border;
use crate::ui::rect::{Rect, rect_inset};

/// Zero-flag background, nonzero-flag background, final foreground.
pub static mut BEVELED_RECT_PALETTE: [usize; 3] = [0x089c_c8c0, 0x089c_c8c4, 0x089c_c8d0];

/// # Safety
/// `state` is an aligned writable 0x44-byte draw record with valid renderer
/// inputs; `rect` is aligned and readable. All palette slots (including the
/// border palette) must address four readable bytes. Bounds are read after
/// filling and stroking, matching firmware even when they alias the record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_beveled_rect(
    state: *mut u8, rect: *const Rect, alternate_background: u32, normal_border: u32,
) -> u64 {
    let slot = if alternate_background == 0 { 0 } else { 1 };
    let background = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BEVELED_RECT_PALETTE[slot])) };
    unsafe {
        draw_state_set_background_color(state, background as *const u8);
        draw_state_fill_rect_background(state, rect);
        draw_state_stroke_rect(state, rect);
    }
    let mut inset = unsafe { rect.read() };
    unsafe {
        rect_inset(&mut inset, 1, 1);
        if normal_border == 0 {
            draw_state_reversed_two_color_border(state, &inset);
        } else {
            draw_state_two_color_border(state, &inset);
        }
        let foreground = core::ptr::read_volatile(core::ptr::addr_of!(BEVELED_RECT_PALETTE[2]));
        draw_state_set_foreground_color(state, foreground as *const u8);
    }
    (inset.top as u32 as u64) | ((inset.left as u32 as u64) << 32)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::draw_state_fill::{DrawStateFillOps, DRAW_STATE_FILL_OPS};
    use crate::cxx::draw_state_stroke::{DrawStateStrokeOps, DRAW_STATE_STROKE_OPS};
    use crate::cxx::draw_state_line::{DrawStateLineOps, DRAW_STATE_LINE_OPS, test_support};
    use crate::cxx::draw_state_two_color_border::TWO_COLOR_BORDER_PALETTE;
    use std::vec::Vec;

    #[derive(Debug, PartialEq)]
    enum Draw { Fill(Rect, [u8;4]), Stroke(Rect), Line([i32;4], [u8;4]) }
    static mut DRAWS: Vec<Draw> = Vec::new();
    unsafe fn color(p: *const u8) -> [u8;4] { unsafe { [p.read(), p.add(1).read(), p.add(2).read(), p.add(3).read()] } }
    unsafe extern "C" fn fill(_: usize, r: *const Rect, c: *const u8, _: u32, _: *const u8) {
        unsafe { (*core::ptr::addr_of_mut!(DRAWS)).push(Draw::Fill(*r, color(c))); }
    }
    unsafe extern "C" fn stroke(_: usize, r: *const Rect, _: i32, _: *const u8, _: u8, _: *const u8) {
        unsafe { (*core::ptr::addr_of_mut!(DRAWS)).push(Draw::Stroke(*r)); }
    }
    unsafe extern "C" fn line(_: usize, x1: i32, y1: i32, x2: i32, y2: i32,
        _: i32, c: *const u8, _: i32, _: *const u8, _: i32) {
        unsafe { (*core::ptr::addr_of_mut!(DRAWS)).push(Draw::Line([x1,y1,x2,y2], color(c))); }
    }
    struct Restore(DrawStateFillOps, DrawStateStrokeOps, DrawStateLineOps, [usize;3], [usize;2]);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            DRAW_STATE_FILL_OPS = self.0; DRAW_STATE_STROKE_OPS = self.1;
            DRAW_STATE_LINE_OPS = self.2; BEVELED_RECT_PALETTE = self.3;
            TWO_COLOR_BORDER_PALETTE = self.4;
        } }
    }

    #[test]
    fn flags_degenerate_bounds_and_final_state() {
        let _fill = crate::cxx::draw_state_fill::tests::OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _stroke = crate::cxx::draw_state_stroke::tests::OPS_LOCK.lock();
        let _line = test_support::DRAW_STATE_LINE_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let colors = [[1u8,2,3,4], [5,6,7,8], [9,10,11,12], [13,14,15,16]];
        let _restore = unsafe { Restore(DRAW_STATE_FILL_OPS, DRAW_STATE_STROKE_OPS,
            DRAW_STATE_LINE_OPS, BEVELED_RECT_PALETTE, TWO_COLOR_BORDER_PALETTE) };
        unsafe {
            DRAW_STATE_FILL_OPS = DrawStateFillOps { fill_engine: fill };
            DRAW_STATE_STROKE_OPS = DrawStateStrokeOps { stroke_engine: stroke };
            DRAW_STATE_LINE_OPS = DrawStateLineOps { line_engine: line };
            BEVELED_RECT_PALETTE = [colors[0].as_ptr() as usize, colors[1].as_ptr() as usize, colors[2].as_ptr() as usize];
            TWO_COLOR_BORDER_PALETTE = [colors[0].as_ptr() as usize, colors[3].as_ptr() as usize];
        }
        for (bounds, inset) in [
            ([2,3,8,10], [3,4,7,9]),
            ([2,3,4,5], [3,4,3,4]),
            ([2,3,3,4], [0,0,0,0]),
            ([9,8,2,1], [0,0,0,0]),
            ([i32::MAX,i32::MAX,i32::MIN,i32::MIN], [i32::MIN,i32::MIN,i32::MAX,i32::MAX]),
        ] {
            for background in [0, 1, 0x8000_0000] {
                for border in [0, 1, 0x8000_0000] {
                    let rect = Rect { top: bounds[0], left: bounds[1], bottom: bounds[2], right: bounds[3] };
                    let mut state = [0u32;17];
                    let p = state.as_mut_ptr() as *mut u8;
                    unsafe {
                        (*core::ptr::addr_of_mut!(DRAWS)).clear();
                        let result = draw_state_beveled_rect(p, &rect, background, border);
                        assert_eq!(result, inset[0] as u32 as u64 | ((inset[1] as u32 as u64) << 32));
                        let x = inset[1]; let y = inset[0];
                        let right = inset[3].wrapping_sub(1); let bottom = inset[2].wrapping_sub(1);
                        let (first, second) = if border == 0 { (colors[3], colors[0]) } else { (colors[0], colors[3]) };
                        assert_eq!(&*core::ptr::addr_of!(DRAWS), &std::vec![
                            Draw::Fill(rect, colors[usize::from(background != 0)]), Draw::Stroke(rect),
                            Draw::Line([x,y,right,y], first), Draw::Line([x,y,x,bottom], first),
                            Draw::Line([right,y.wrapping_add(1),right,bottom], second),
                            Draw::Line([x.wrapping_add(1),bottom,right,bottom], second)]);
                        assert_eq!(color(p.add(0x11)), colors[2]);
                        assert_eq!(color(p.add(0x15)), colors[usize::from(background != 0)]);
                        assert_eq!(&state[..2], &[right as u32, bottom as u32]);
                        assert_eq!(rect, Rect { top: bounds[0], left: bounds[1], bottom: bounds[2], right: bounds[3] });
                    }
                }
            }
        }
    }
}
