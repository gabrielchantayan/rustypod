//! Element-local content bounds with the retail border inset.
//!
//! `ui_element_content_bounds` — original: `FUN_082a2604` @
//! **0x082a2604**, 84 bytes (`0x082a2604..0x082a2658`; the next function
//! starts at `0x082a2658`). Raw decoding finds 21 direct `bl` call sites.
//!
//! # Algorithm
//!
//! Copy the element's local bounds rectangle at +0x80 into the output,
//! move it to the origin, then shrink it by a 1- or 2-pixel inset chosen
//! from the flag word at +0x48. The inset selection is the same decision
//! tree the firmware uses at 0x082a2468: selected flag combinations ask
//! for a 1-pixel border, others for 2 pixels, and the rest for none.
//! Over-insetting clears the rectangle through the shared `rect_inset`
//! validity check.
//!
//! # Deliberate deviations
//!
//! The flag-to-inset decision is reproduced as a private Rust helper in
//! this module; the retail 0x082a2468 symbol stays unported rather than
//! becoming a second exported seam.

use core::mem::{offset_of, size_of};
use core::ptr;

use crate::ui::draw_state_setup::DRAW_STATE_RENDER_TRANSFORM;
#[cfg(test)]
use crate::ui::draw_state_setup::DrawStateRenderTransform;
use crate::ui::rect::{rect_inset, rect_move_to_origin, Rect};
use crate::ui::render_context::ui_element_resolve_render_context;


#[repr(C)]
struct ElementFields {
    _before_flags: [u8; 0x48],
    flags: u32,
    _before_bounds: [u8; 0x34],
    bounds: Rect,
}

const _: [u8; 0x90] = [0; size_of::<ElementFields>()];
const _: [u8; 0x48] = [0; offset_of!(ElementFields, flags)];
const _: [u8; 0x80] = [0; offset_of!(ElementFields, bounds)];

#[inline(never)]
fn content_inset_for_flags(flags: u32) -> i32 {
    match flags & 0x00e0_0000 {
        0x0020_0000 | 0x0040_0000 => 1,
        0x0060_0000 | 0x0080_0000 | 0x00a0_0000 => 2,
        _ if (flags & 0x001c_0000) != 0 => 1,
        _ => 0,
    }
}

/// ui_element_bounds — original: `FUN_082a24f4` @ 0x082a24f4
/// (24 bytes; `0x082a24f4..0x082a2508`; the next function starts at
/// 0x082a250c).
///
/// Copies the element's local bounds at +0x80 to `out`, then moves that
/// rectangle to the origin. Raw decoding finds exactly 18 direct, unconditional
/// `bl` call sites; no predicated `bl`, tail `b`, or data-word references
/// target this address. The closing `b 0x0826c2e8` tail-dispatches to
/// [`rect_move_to_origin`].
///
/// # Deliberate deviations
///
/// None. Rust represents the tail dispatch as an ordinary call; its only
/// observable result is the same normalized output rectangle.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_bounds(element: *const u8, out: *mut Rect) {
    let element = element.cast::<ElementFields>();
    ptr::write(out, ptr::addr_of!((*element).bounds).read());
    rect_move_to_origin(out);
}

/// ui_element_render_bounds — original: `FUN_082a25d8` @ 0x082a25d8
/// (36 bytes; `0x082a25d8..0x082a25fc`; the next function starts at
/// 0x082a25fc).
///
/// Copies the element's local bounds at +0x80 to `out`, resolves its render
/// context, then transforms `out` into that context's coordinates. Raw ARM
/// decoding finds exactly eight direct, unconditional `bl` call sites and no
/// predicated `bl` forms. Its one `bl` resolves the render context; the closing
/// `b 0x0828cb64` tail-dispatches the copied rectangle to the render-coordinate
/// transform.
///
/// # Deliberate deviations
///
/// Rust represents the tail dispatch as an ordinary call through the existing
/// [`DRAW_STATE_RENDER_TRANSFORM`] seam. Device builds retain the retail
/// 0x0828cb64 transform; host tests use its deterministic test model because
/// that target is not yet ported.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_render_bounds(element: *mut u8, out: *mut Rect) {
    let fields = element.cast::<ElementFields>();
    ptr::write(out, ptr::addr_of!((*fields).bounds).read());

    let render_context = ui_element_resolve_render_context(element);
    let transform = ptr::read_volatile(ptr::addr_of!(DRAW_STATE_RENDER_TRANSFORM));
    transform(render_context, out);
}

/// ui_element_content_bounds — original: `FUN_082a2604` @ 0x082a2604
/// (84 bytes; 21 direct `bl` call sites).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_content_bounds(element: *mut u8, out: *mut Rect) {
    let element = element.cast::<ElementFields>();
    ptr::write(out, ptr::addr_of!((*element).bounds).read());
    rect_move_to_origin(out);

    let inset = content_inset_for_flags(ptr::addr_of!((*element).flags).read());
    if inset > 0 {
        rect_inset(out, inset, inset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        _before_flags: [u8; 0x48],
        flags: u32,
        _before_bounds: [u8; 0x34],
        bounds: Rect,
    }

    const _: [u8; 0x90] = [0; size_of::<Fixture>()];
    const _: [u8; 0x48] = [0; offset_of!(Fixture, flags)];
    const _: [u8; 0x80] = [0; offset_of!(Fixture, bounds)];

    #[repr(C, packed)]
    struct ElementRenderContext {
        _before_render_context: [u8; 0x3c],
        render_context: *mut u8,
    }

    const _: [u8; 0x3c] = [0; offset_of!(ElementRenderContext, render_context)];

    static mut SEEN_RENDER_CONTEXT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_render_transform(render_context: *mut u8, rect: *mut Rect) {
        SEEN_RENDER_CONTEXT = render_context;
        (*rect).top = (*rect).top.wrapping_sub(4);
        (*rect).left = (*rect).left.wrapping_add(3);
        (*rect).bottom = (*rect).bottom.wrapping_sub(4);
        (*rect).right = (*rect).right.wrapping_add(3);
    }

    struct TransformGuard(DrawStateRenderTransform);

    impl Drop for TransformGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(DRAW_STATE_RENDER_TRANSFORM), self.0);
            }
        }
    }

    fn rect(top: i32, left: i32, bottom: i32, right: i32) -> Rect {
        Rect {
            top,
            left,
            bottom,
            right,
        }
    }

    fn expected(bounds: Rect, flags: u32) -> Rect {
        let inset = match flags & 0x00e0_0000 {
            0x0020_0000 | 0x0040_0000 => 1,
            0x0060_0000 | 0x0080_0000 | 0x00a0_0000 => 2,
            _ if (flags & 0x001c_0000) != 0 => 1,
            _ => 0,
        };

        let mut out = Rect {
            top: 0,
            left: 0,
            bottom: bounds.bottom.wrapping_sub(bounds.top),
            right: bounds.right.wrapping_sub(bounds.left),
        };

        if inset > 0 {
            out.top = out.top.wrapping_add(inset);
            out.left = out.left.wrapping_add(inset);
            out.bottom = out.bottom.wrapping_sub(inset);
            out.right = out.right.wrapping_sub(inset);
            if out.left > out.right || out.top > out.bottom {
                out = Rect::default();
            }
        }

        out
    }

    fn run_case(flags: u32, bounds: Rect, seed: Rect) -> Rect {
        let mut fixture = Fixture {
            _before_flags: [0xa5; 0x48],
            flags,
            _before_bounds: [0x5a; 0x34],
            bounds,
        };
        let mut out = seed;
        unsafe {
            ui_element_content_bounds(
                (&mut fixture as *mut Fixture).cast::<u8>(),
                &mut out,
            );
        }
        out
    }

    #[test]
    fn element_bounds_copies_then_normalizes_without_validity_filtering() {
        let bounds_cases = [
            rect(10, 20, 18, 34),
            rect(-5, 7, 5, 9),
            rect(30, 40, 10, 20),
            rect(i32::MIN, i32::MIN, i32::MAX, i32::MAX),
        ];

        for bounds in bounds_cases {
            let mut fixture = Fixture {
                _before_flags: [0xa5; 0x48],
                flags: 0xfeed_face,
                _before_bounds: [0x5a; 0x34],
                bounds,
            };
            let mut out = rect(-123, 456, -789, 1011);
            unsafe {
                ui_element_bounds(
                    (&mut fixture as *mut Fixture).cast::<u8>(),
                    &mut out,
                );
            }

            assert_eq!(out, expected(bounds, 0), "bounds={bounds:?}");
            assert_eq!(fixture._before_flags, [0xa5; 0x48]);
            assert_eq!(fixture.flags, 0xfeed_face);
            assert_eq!(fixture._before_bounds, [0x5a; 0x34]);
            assert_eq!(fixture.bounds, bounds);
        }
    }

    #[test]
    fn element_bounds_supports_output_aliasing_source_bounds() {
        let mut fixture = Fixture {
            _before_flags: [0xa5; 0x48],
            flags: 0,
            _before_bounds: [0x5a; 0x34],
            bounds: rect(-10, 20, 15, 50),
        };

        unsafe {
            ui_element_bounds(
                (&mut fixture as *mut Fixture).cast::<u8>(),
                core::ptr::addr_of_mut!(fixture.bounds),
            );
        }

        assert_eq!(fixture.bounds, rect(0, 0, 25, 30));
    }

    #[test]
    fn render_bounds_copies_before_transforming_with_direct_context() {
        let bounds_cases = [
            rect(10, 20, 18, 34),
            rect(i32::MIN, i32::MAX, -1, 0),
        ];
        let _transform_guard = unsafe {
            TransformGuard(ptr::read_volatile(ptr::addr_of!(DRAW_STATE_RENDER_TRANSFORM)))
        };
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(DRAW_STATE_RENDER_TRANSFORM),
                recording_render_transform,
            );
        }

        for bounds in bounds_cases {
            let mut fixture = Fixture {
                _before_flags: [0xa5; 0x48],
                flags: 0xfeed_face,
                _before_bounds: [0x5a; 0x34],
                bounds,
            };
            let mut context = 0_u8;

            unsafe {
                SEEN_RENDER_CONTEXT = ptr::null_mut();
                ptr::addr_of_mut!((*(&mut fixture as *mut Fixture).cast::<ElementRenderContext>()).render_context)
                    .write_unaligned(&mut context);
                ui_element_render_bounds(
                    (&mut fixture as *mut Fixture).cast::<u8>(),
                    core::ptr::addr_of_mut!(fixture.bounds),
                );
            }
            assert_eq!(unsafe { SEEN_RENDER_CONTEXT }, ptr::addr_of_mut!(context));

            assert_eq!(
                fixture.bounds,
                rect(
                    bounds.top.wrapping_sub(4),
                    bounds.left.wrapping_add(3),
                    bounds.bottom.wrapping_sub(4),
                    bounds.right.wrapping_add(3),
                ),
                "bounds={bounds:?}",
            );
        }
    }

    #[test]
    fn matches_reference_for_all_flag_classes_and_edge_rects() {
        let bounds = [
            rect(10, 20, 18, 34),   // width/height 14/8
            rect(-5, 7, 5, 9),      // negative origin, thin width
            rect(0, 0, 4, 4),       // degenerate after a 2px inset
            rect(3, -2, 6, 1),      // width/height 3/3
            rect(100, 200, 101, 201), // 1x1, over-inset clears
            rect(-20, -30, -10, -15), // entirely negative coordinates
        ];

        let flags = [
            0x0000_0000,
            0x0002_0000,
            0x0004_0000,
            0x0006_0000,
            0x0008_0000,
            0x000a_0000,
            0x000c_0000,
            0x000e_0000,
            0x001c_0000,
            0x001e_0000,
            0x0020_0000,
            0x0040_0000,
            0x0060_0000,
            0x0080_0000,
            0x00a0_0000,
            0x00c0_0000,
            0x00e0_0000,
            0x00c0_0000 | 0x001c_0000,
            0x00e0_0000 | 0x001c_0000,
        ];

        for &flags in &flags {
            for &bounds in &bounds {
                let seed = rect(-123, 456, -789, 1011);
                let got = run_case(flags, bounds, seed);
                let want = expected(bounds, flags);
                assert_eq!(got, want, "flags={flags:#010x} bounds={bounds:?}");
            }
        }
    }

    #[test]
    fn leaves_the_origin_and_copy_intact_when_no_inset_is_required() {
        let bounds = rect(7, -3, 11, 5);
        let got = run_case(0, bounds, rect(9, 9, 9, 9));
        assert_eq!(got, rect(0, 0, 4, 8));
    }

    #[test]
    fn preserves_degenerate_rectangles_but_clears_inverted_ones() {
        let degenerate = run_case(0x0060_0000, rect(0, 0, 4, 4), Rect::default());
        assert_eq!(degenerate, rect(2, 2, 2, 2));

        let cleared = run_case(0x0020_0000, rect(0, 0, 1, 1), Rect::default());
        assert_eq!(cleared, Rect::default());
    }
}
