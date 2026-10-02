//! Render-context bounds resize — `FUN_0828dcd0` @ **0x0828dcd0**.
//! True extent: 208 bytes, through 0x0828dd9f; next function: 0x0828dda0.
//! Raw whole-image decoding finds two inbound plain BLs (0x0817f65c,
//! 0x0826dd44), zero predicated inbound BLs. Body: two plain BLs, three
//! predicated BLs, and one conditional tail B to 0x0828c700.
//!
//! Disabled contexts return before reading bounds. Reject inverted signed
//! edges; an existing presentation with the same wrapping dimensions makes
//! this a no-op even if the origin changes. Otherwise copy bounds, move them
//! to the origin, mirror at +0xb4, release resource then presentation, and
//! ensure a presentation only for nonempty local bounds.
//!
//! Deliberate deviations: incidental r0 exit values are not exposed (callers
//! ignore them). Reuses the suspend module's verified resident setup seam;
//! Ghidra incorrectly inlines that tail target. Object slots remain u32,
//! preserving target offsets on hosts. No algorithmic deviation intended.

use crate::heap::veneers::heap_panic;
use crate::ui::rect::{Rect, rect_is_empty, rect_move_to_origin};
use crate::ui::render_context_release_resource::render_context_release_resource;
use crate::ui::render_context_release_presentation::render_context_release_presentation;
use crate::ui::render_context_suspend::render_context_ensure_presentation;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn render_context_resize(context: *mut u8, bounds: *const Rect) {
    if context.add(0x60).read() == 0 { return; }
    let requested = bounds.read();
    if requested.left > requested.right || requested.top > requested.bottom {
        heap_panic();
    }
    let local = context.add(0x20).cast::<Rect>();
    let previous = local.read();
    let presentation = context.add(0x54).cast::<u32>();
    if requested.right.wrapping_sub(requested.left) == previous.right.wrapping_sub(previous.left)
        && requested.bottom.wrapping_sub(requested.top) == previous.bottom.wrapping_sub(previous.top)
        && presentation.read() != 0 {
        return;
    }
    local.write(requested);
    rect_move_to_origin(local);
    context.add(0xb4).cast::<Rect>().write(local.read());
    let resource = context.add(0x48).cast::<u32>();
    if resource.read() != 0 { render_context_release_resource(context, resource); }
    if presentation.read() != 0 { render_context_release_presentation(context, presentation); }
    if rect_is_empty(local) == 0 { render_context_ensure_presentation(context); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_does_not_read_null_bounds_or_mutate_context() {
        use core::ptr;
        let mut storage = [0u32; 0x130 / 4];
        let original = storage;
        unsafe { render_context_resize(storage.as_mut_ptr().cast(), ptr::null()); }
        assert_eq!(storage, original);
    }

    #[test]
    fn same_size_presentation_preserves_origin_and_all_slots() {
        let mut storage = [0u32; 0x130 / 4];
        let context = storage.as_mut_ptr().cast::<u8>();
        unsafe {
            context.add(0x60).write(1);
            context.add(0x54).cast::<u32>().write(0x1234);
            context.add(0x20).cast::<Rect>().write(Rect { top: 0, left: 0, bottom: 20, right: 30 });
            let original = storage;
            render_context_resize(context, &Rect { top: -7, left: 3, bottom: 13, right: 33 });
            assert_eq!(storage, original);
        }
    }

    #[test]
    fn zero_extent_and_wrapping_signed_dimensions_are_mirrored() {
        for bounds in [
            Rect { top: -9, left: 8, bottom: -9, right: 11 },
            Rect { top: 7, left: -8, bottom: 12, right: -8 },
            Rect { top: i32::MIN, left: 0, bottom: i32::MAX, right: 1 },
        ] {
            let mut storage = [0u32; 0x130 / 4];
            let context = storage.as_mut_ptr().cast::<u8>();
            unsafe {
                context.add(0x60).write(1);
                render_context_resize(context, &bounds);
                let expected = Rect { top: 0, left: 0,
                    bottom: bounds.bottom.wrapping_sub(bounds.top),
                    right: bounds.right.wrapping_sub(bounds.left) };
                assert_eq!(context.add(0x20).cast::<Rect>().read(), expected);
                assert_eq!(context.add(0xb4).cast::<Rect>().read(), expected);
                assert_eq!(storage[0x54 / 4], 0);
            }
        }
    }
}
