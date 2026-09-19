//! `draw_horizontal_line` — original: `FUN_08087870` @ 0x08087870 (104 bytes,
//! 0x08087870..0x080878d8; 1 unconditional `bl`, 0 predicated `bl`; 4 inbound
//! unconditional `bl` call sites, 0 predicated), verified from raw `osos.dec`.
//!
//! Draws a horizontal line through the shared line-engine dispatcher: the
//! surface body is `surface + 4`, endpoints are `(left, baseline + 2)` and
//! `(right - 2, baseline + 2)`, and scaled rendering is disabled. A style value
//! of one is normalized to zero. Deliberate deviation: `FUN_080e7870` remains
//! the existing volatile `DRAW_STATE_LINE_OPS` seam; target builds still call
//! its retail address and host tests install a recorder.

use super::draw_state_line::{DrawStateLineEngine, DRAW_STATE_LINE_OPS};
#[cfg(test)]
use super::draw_state_line::DrawStateLineOps;

/// Draws a horizontal line with the retail endpoint adjustments.
///
/// # Safety
///
/// `surface`, `foreground`, and `clip_rect` must be valid for the unported
/// line engine. `surface` denotes its owning record; the engine receives
/// `surface + 4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_horizontal_line(
    surface: *const u8,
    left: i32,
    right: i32,
    baseline: i32,
    foreground: *const u8,
    style: i32,
    clip_rect: *const u8,
    thickness: i32,
) {
    let engine: DrawStateLineEngine = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_LINE_OPS.line_engine))
    };
    unsafe {
        engine(
            surface.wrapping_add(4) as usize,
            left,
            baseline.wrapping_add(2),
            right.wrapping_sub(2),
            baseline.wrapping_add(2),
            thickness,
            foreground,
            if style == 1 { 0 } else { style },
            clip_rect,
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::draw_state_line::test_support::DRAW_STATE_LINE_OPS_LOCK;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct Call {
        surface: usize,
        x1: i32,
        y1: i32,
        x2: i32,
        y2: i32,
        thickness: i32,
        foreground: usize,
        style: i32,
        clip: usize,
        scaled: i32,
    }

    static mut SEEN: Option<Call> = None;

    unsafe extern "C" fn recorder(
        surface: usize, x1: i32, y1: i32, x2: i32, y2: i32, thickness: i32,
        foreground: *const u8, style: i32, clip: *const u8, scaled: i32,
    ) {
        unsafe {
            SEEN = Some(Call {
                surface, x1, y1, x2, y2, thickness, foreground: foreground as usize,
                style, clip: clip as usize, scaled,
            });
        }
    }

    fn with_recorder(run: impl FnOnce()) {
        let _lock = DRAW_STATE_LINE_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { DRAW_STATE_LINE_OPS };
        unsafe {
            SEEN = None;
            DRAW_STATE_LINE_OPS = DrawStateLineOps { line_engine: recorder };
        }
        run();
        unsafe { DRAW_STATE_LINE_OPS = previous };
    }

    #[test]
    fn adjusts_endpoints_and_normalizes_style_one() {
        with_recorder(|| {
            let surface = [0u8; 8];
            let foreground = [0x5a];
            let clip = [0xc3; 16];
            unsafe {
                draw_horizontal_line(
                    surface.as_ptr(), -7, 99, i32::MAX, foreground.as_ptr(), 1, clip.as_ptr(), 3,
                );
            }
            assert_eq!(
                unsafe { SEEN }.as_ref(),
                Some(&Call {
                    surface: surface.as_ptr().wrapping_add(4) as usize,
                    x1: -7,
                    y1: i32::MIN + 1,
                    x2: 97,
                    y2: i32::MIN + 1,
                    thickness: 3,
                    foreground: foreground.as_ptr() as usize,
                    style: 0,
                    clip: clip.as_ptr() as usize,
                    scaled: 0,
                }),
            );
        });
    }
    #[test]
    fn preserves_non_one_style_word_and_wrapping_right_endpoint() {
        with_recorder(|| {
            unsafe {
                draw_horizontal_line(
                    core::ptr::null(), 0, i32::MIN, -3, core::ptr::null(), 0x123, core::ptr::null(), -1,
                );
            }
            let call = unsafe { SEEN }.expect("engine called");
            assert_eq!((call.surface, call.x1, call.y1, call.x2, call.y2), (4, 0, -1, i32::MAX - 1, -1));
            assert_eq!((call.style, call.thickness, call.foreground, call.clip, call.scaled), (0x123, -1, 0, 0, 0));
        });
    }
}
