//! `draw_state_reversed_two_color_border` — `FUN_0826343c` @ 0x0826343c.
//! True extent: 164 bytes, 0x0826343c..0x082634e0 (156 code + 8 literals).
//! Raw A32 scan: 1 plain inbound BL and 1 predicated BL (BLEQ); outgoing:
//! 6 plain BLs, 0 predicated, to color_copy and draw_state_line.
//!
//! Capture top/left/bottom/right before writing the draw state. Convert bottom
//! and right to inclusive endpoints with wrapping subtraction, draw top/left
//! with runtime color 0x089cc8c0, then right/bottom with 0x089cc8cc. The latter
//! edges exclude their starting corner. Empty/inverted rectangles still draw;
//! foreground and current point retain the last color and endpoint.
//!
//! Deliberate deviation: reuse the existing TWO_COLOR_BORDER_PALETTE data
//! seam in reverse order instead of introducing duplicate addresses. Its
//! target defaults are the live firmware globals, not snapshots. Existing
//! color_copy and draw_state_line ports preserve byte access and renderer ABI.

use crate::cxx::color_copy::color_copy;
use crate::cxx::draw_state_line::draw_state_line;
use crate::cxx::draw_state_two_color_border::TWO_COLOR_BORDER_PALETTE;
use crate::ui::rect::Rect;

/// # Safety
/// `draw_state` is an aligned writable 0x44-byte record with valid renderer
/// inputs. `rect` is readable and aligned; it may alias the record. Both
/// palette pointers must address four readable bytes throughout the call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_reversed_two_color_border(draw_state: *mut u8, rect: *const Rect) {
    let top = unsafe { (*rect).top };
    let left = unsafe { (*rect).left };
    let bottom = unsafe { (*rect).bottom }.wrapping_sub(1);
    let right = unsafe { (*rect).right }.wrapping_sub(1);
    let first = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TWO_COLOR_BORDER_PALETTE[1])) };
    unsafe {
        color_copy(draw_state.add(0x11), first as *const u8);
        draw_state_line(draw_state, left, top, right, top);
        draw_state_line(draw_state, left, top, left, bottom);
    }
    let second = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TWO_COLOR_BORDER_PALETTE[0])) };
    unsafe {
        color_copy(draw_state.add(0x11), second as *const u8);
        draw_state_line(draw_state, right, top.wrapping_add(1), right, bottom);
        draw_state_line(draw_state, left.wrapping_add(1), bottom, right, bottom);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::draw_state_line::{DrawStateLineOps, DRAW_STATE_LINE_OPS, test_support};
    use std::vec::Vec;

    static mut LINES: Vec<([i32; 4], [u8; 4])> = Vec::new();

    unsafe extern "C" fn record(
        _surface: usize, x1: i32, y1: i32, x2: i32, y2: i32,
        _thickness: i32, foreground: *const u8, _style: i32,
        _clip: *const u8, _scaled: i32,
    ) {
        let color = unsafe { [foreground.read(), foreground.add(1).read(),
            foreground.add(2).read(), foreground.add(3).read()] };
        unsafe { (*core::ptr::addr_of_mut!(LINES)).push(([x1, y1, x2, y2], color)); }
    }

    struct Restore(DrawStateLineOps, [usize; 2]);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { DRAW_STATE_LINE_OPS = self.0; TWO_COLOR_BORDER_PALETTE = self.1; }
        }
    }

    #[test]
    fn reversed_border_preserves_aliasing_wrapping_and_corner_order() {
        let _lock = test_support::DRAW_STATE_LINE_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let first = [13u8, 29, 71, 255];
        let second = [97u8, 149, 211, 128];
        let _restore = unsafe { Restore(DRAW_STATE_LINE_OPS, TWO_COLOR_BORDER_PALETTE) };
        unsafe {
            DRAW_STATE_LINE_OPS = DrawStateLineOps { line_engine: record };
            TWO_COLOR_BORDER_PALETTE = [second.as_ptr() as usize, first.as_ptr() as usize];
        }
        for (coords, edges) in [
            ([2, 3, 8, 10], [[3,2,9,2], [3,2,3,7], [9,3,9,7], [4,7,9,7]]),
            ([5, 6, 6, 7], [[6,5,6,5], [6,5,6,5], [6,6,6,5], [7,5,6,5]]),
            ([4, 9, 4, 3], [[9,4,2,4], [9,4,9,3], [2,5,2,3], [10,3,2,3]]),
            ([i32::MAX, i32::MAX, i32::MIN, i32::MIN],
             [[i32::MAX;4], [i32::MAX;4],
              [i32::MAX,i32::MIN,i32::MAX,i32::MAX],
              [i32::MIN,i32::MAX,i32::MAX,i32::MAX]]),
        ] {
            let mut words = [0xa5a5_a5a5u32; 19];
            for i in 0..4 { words[i] = coords[i] as u32; }
            words[0x2c / 4] = 0;
            words[0x30 / 4] = 0;
            let before = words;
            let state = words.as_mut_ptr() as *mut u8;
            unsafe {
                (*core::ptr::addr_of_mut!(LINES)).clear();
                draw_state_reversed_two_color_border(state, state as *const Rect);
                assert_eq!(&*core::ptr::addr_of!(LINES), &std::vec![
                    (edges[0], first), (edges[1], first),
                    (edges[2], second), (edges[3], second)]);
                assert_eq!(core::slice::from_raw_parts(state.add(0x11), 4), &second);
            }
            assert_eq!(words[0] as i32, edges[3][2]);
            assert_eq!(words[1] as i32, edges[3][3]);
            let after_bytes = unsafe { core::slice::from_raw_parts(state, 76) };
            let before_bytes = unsafe { core::slice::from_raw_parts(before.as_ptr() as *const u8, 76) };
            for i in 8..76 {
                if !(0x11..0x15).contains(&i) { assert_eq!(after_bytes[i], before_bytes[i], "byte {i}"); }
            }
        }
    }
}
