//! UI-element dirty-region invalidation.
//!
//! - `ui_element_invalidate_region` — original: `FUN_0826ec14` @
//!   **0x0826ec14** (132 bytes, including the literal-pool word at
//!   0x0826ec98).
//! - `ui_element_invalidate` — original: `FUN_0826ec9c` @ 0x0826ec9c
//!   (8-byte whole-bounds thunk).
//!
//! # `ui_element_invalidate_region` algorithm
//!
//! This region form has no NULL guard. It returns immediately unless the
//! element is shown (its +0x48 flag field has state `0x800`), its +0xa0 byte
//! is clear, and the mutable global byte at 0x089cc888 is non-zero. It clips
//! the supplied rectangle to the element bounds at +0x80, then to the parent
//! clip rectangle at `parent + 0xd0` when there is a parent. For a resolved
//! render context, it transforms that stack-local clipped rectangle into
//! render coordinates (0x0828cb64) and adds it to the context's dirty region
//! (0x0828d9b4).
//!
//! Raw ARM decoding verifies the extent: `push {r0-r6,lr}` opens at
//! 0x0826ec14, the `pop {r0-r6,pc}` at 0x0826ec94 is followed by the
//! 0x089cc888 literal word, and the independent thunk begins at 0x0826ec9c.
//! Decoding every B/BL word in `osos.dec` finds 18 direct call sites
//! (17 unconditional `bl`, one `blne`) and six tail `b` references; there
//! are no data-word references. The lone predicated caller at 0x0826f228
//! checks its element pointer first, consistent with this body's immediate
//! dereferences.
//!
//! # Deliberate deviations
//!
//! The mutable global is read at its retail address on the device and uses a
//! host replacement for tests. The two unported rendering operations retain
//! their existing volatile seams in `draw_state_setup` and `coordinate_origin`;
//! this port adds no duplicate dispatch seam. The stock epilogue restores r0
//! to `element`; that observable result is exposed as the function return.

use core::ptr;

use crate::ui::coordinate_origin::RENDER_CONTEXT_INVALIDATE_RECT;
use crate::ui::draw_state_setup::DRAW_STATE_RENDER_TRANSFORM;
use crate::ui::rect::{rect_intersect, rect_intersect_into, Rect};
use crate::ui::render_context::ui_element_resolve_render_context;
use crate::ui::shown_state::ui_element_is_shown;

/// Byte offset of a UI element's parent pointer.
const PARENT_OFFSET: usize = 0x34;
/// Byte offset of a UI element's bounds rectangle.
const BOUNDS_OFFSET: usize = 0x80;
/// Byte which suppresses dirty-region accumulation when non-zero.
const INVALIDATE_SUPPRESSED_OFFSET: usize = 0xa0;
/// Parent-relative clip rectangle.
const PARENT_CLIP_OFFSET: usize = 0xd0;

/// Retail mutable redraw-enable byte, loaded through the literal pool at
/// 0x0826ec98.
#[cfg(target_os = "none")]
const REDRAW_ENABLED_ADDRESS: *const u8 = 0x089c_c888 as *const u8;

/// Host replacement for the retail redraw-enable byte.
#[cfg(not(target_os = "none"))]
static mut HOST_REDRAW_ENABLED: u8 = 1;

#[inline(always)]
fn redraw_enabled_ptr() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        REDRAW_ENABLED_ADDRESS
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of!(HOST_REDRAW_ENABLED)
    }
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn parent_element(element: *mut u8) -> *mut u8 {
    element.add(PARENT_OFFSET).cast::<u32>().read() as usize as *mut u8
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn parent_element(element: *mut u8) -> *mut u8 {
    element.add(PARENT_OFFSET).cast::<*mut u8>().read_unaligned()
}

/// Keep the two stock rectangle calls as out-of-line calls on device; their
/// dedicated retail entries are part of this function's recovered structure.
#[cfg(target_os = "none")]
type RectIntersect = unsafe extern "C" fn(*mut Rect, *const Rect);
#[cfg(target_os = "none")]
type RectIntersectInto = unsafe extern "C" fn(*mut Rect, *const Rect, *const Rect);
#[cfg(target_os = "none")]
static RECT_INTERSECT_INTO: RectIntersectInto = rect_intersect_into;
#[cfg(target_os = "none")]
static RECT_INTERSECT: RectIntersect = rect_intersect;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn intersect_into(out: *mut Rect, a: *const Rect, b: *const Rect) {
    ptr::read_volatile(ptr::addr_of!(RECT_INTERSECT_INTO))(out, a, b);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn intersect_into(out: *mut Rect, a: *const Rect, b: *const Rect) {
    rect_intersect_into(out, a, b);
}

#[inline(always)]
unsafe fn intersect(rect: *mut Rect, clip: *const Rect) {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(ptr::addr_of!(RECT_INTERSECT))(rect, clip);
    }
    #[cfg(not(target_os = "none"))]
    {
        rect_intersect(rect, clip);
    }
}

/// ui_element_invalidate_region — original: `FUN_0826ec14` @ 0x0826ec14
/// (132 bytes).
///
/// Clips `region` to the element and optional parent clip, transforms the
/// local copy into render coordinates, and submits it to the render context.
/// It returns `element`, restored by the original's `pop {r0-r6,pc}`. No
/// argument is nullable: callers use the lone predicated `blne` when needed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_invalidate_region(
    element: *mut u8,
    region: *const Rect,
) -> *mut u8 {
    if ui_element_is_shown(element) == 0
        || element.add(INVALIDATE_SUPPRESSED_OFFSET).read() != 0
        || ptr::read_volatile(redraw_enabled_ptr()) == 0
    {
        return element;
    }

    let parent = parent_element(element);
    let mut clipped = Rect::default();
    intersect_into(
        &mut clipped,
        region,
        element.add(BOUNDS_OFFSET).cast::<Rect>(),
    );
    if !parent.is_null() {
        intersect(
            &mut clipped,
            parent.add(PARENT_CLIP_OFFSET).cast::<Rect>(),
        );
    }

    let render_context = ui_element_resolve_render_context(element);
    if !render_context.is_null() {
        let transform = ptr::read_volatile(ptr::addr_of!(DRAW_STATE_RENDER_TRANSFORM));
        transform(render_context, &mut clipped);
        let invalidate = ptr::read_volatile(ptr::addr_of!(RENDER_CONTEXT_INVALIDATE_RECT));
        invalidate(render_context, &clipped);
    }

    element
}

/// ui_element_invalidate — original: `FUN_0826ec9c` @ 0x0826ec9c
/// (8 bytes).
///
/// Marks the element's entire bounds rectangle dirty. The retail thunk tail
/// branches to [`ui_element_invalidate_region`] with `region = element + 0x80`
/// and returns that body's restored `element` pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_invalidate(element: *mut u8) -> *mut u8 {
    ui_element_invalidate_region(element, element.wrapping_add(BOUNDS_OFFSET).cast())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::ui::coordinate_origin::RenderContextInvalidateRect;
    use crate::ui::draw_state_setup::DrawStateRenderTransform;
    use core::ptr;
    use std::sync::Mutex;

    const FLAGS_OFFSET: usize = 0x48;
    const RENDER_CONTEXT_OFFSET: usize = 0x3c;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut TRANSFORM_CALLS: u32 = 0;
    static mut INVALIDATE_CALLS: u32 = 0;
    static mut SEEN_TRANSFORM_CONTEXT: *mut u8 = ptr::null_mut();
    static mut SEEN_INVALIDATE_CONTEXT: *mut u8 = ptr::null_mut();
    static mut SEEN_RECT: Rect = Rect {
        top: 0,
        left: 0,
        bottom: 0,
        right: 0,
    };

    unsafe extern "C" fn recording_transform(context: *mut u8, rect: *mut Rect) {
        TRANSFORM_CALLS += 1;
        SEEN_TRANSFORM_CONTEXT = context;
        (*rect).top = (*rect).top.wrapping_add(2);
        (*rect).left = (*rect).left.wrapping_add(3);
        (*rect).bottom = (*rect).bottom.wrapping_add(2);
        (*rect).right = (*rect).right.wrapping_add(3);
    }

    unsafe extern "C" fn recording_invalidate(context: *mut u8, rect: *const Rect) {
        INVALIDATE_CALLS += 1;
        SEEN_INVALIDATE_CONTEXT = context;
        SEEN_RECT = *rect;
    }

    struct SeamGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        transform: DrawStateRenderTransform,
        invalidate: RenderContextInvalidateRect,
        redraw_enabled: u8,
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                DRAW_STATE_RENDER_TRANSFORM = self.transform;
                RENDER_CONTEXT_INVALIDATE_RECT = self.invalidate;
                HOST_REDRAW_ENABLED = self.redraw_enabled;
            }
        }
    }

    fn install_recorders() -> SeamGuard {
        let lock = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let guard = SeamGuard {
                _lock: lock,
                transform: ptr::read_volatile(ptr::addr_of!(DRAW_STATE_RENDER_TRANSFORM)),
                invalidate: ptr::read_volatile(ptr::addr_of!(RENDER_CONTEXT_INVALIDATE_RECT)),
                redraw_enabled: ptr::read_volatile(ptr::addr_of!(HOST_REDRAW_ENABLED)),
            };
            TRANSFORM_CALLS = 0;
            INVALIDATE_CALLS = 0;
            SEEN_TRANSFORM_CONTEXT = ptr::null_mut();
            SEEN_INVALIDATE_CONTEXT = ptr::null_mut();
            DRAW_STATE_RENDER_TRANSFORM = recording_transform;
            RENDER_CONTEXT_INVALIDATE_RECT = recording_invalidate;
            HOST_REDRAW_ENABLED = 1;
            guard
        }
    }

    #[repr(align(8))]
    struct ElementFixture {
        bytes: [u8; PARENT_CLIP_OFFSET + core::mem::size_of::<Rect>()],
    }

    impl ElementFixture {
        fn new(bounds: Rect) -> Self {
            let mut fixture = Self {
                bytes: [0; PARENT_CLIP_OFFSET + core::mem::size_of::<Rect>()],
            };
            unsafe {
                fixture
                    .ptr()
                    .add(BOUNDS_OFFSET)
                    .cast::<Rect>()
                    .write(bounds);
            }
            fixture
        }

        fn ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }

        unsafe fn set_flags(&mut self, flags: u32) {
            self.ptr().add(FLAGS_OFFSET).cast::<u32>().write(flags);
        }

        unsafe fn set_suppressed(&mut self, suppressed: bool) {
            self.ptr()
                .add(INVALIDATE_SUPPRESSED_OFFSET)
                .write(u8::from(suppressed));
        }

        unsafe fn set_parent(&mut self, parent: *mut u8) {
            self.ptr()
                .add(PARENT_OFFSET)
                .cast::<*mut u8>()
                .write_unaligned(parent);
        }

        unsafe fn set_render_context(&mut self, render_context: *mut u8) {
            self.ptr()
                .add(RENDER_CONTEXT_OFFSET)
                .cast::<*mut u8>()
                .write_unaligned(render_context);
        }

        unsafe fn set_clip(&mut self, clip: Rect) {
            self.ptr().add(PARENT_CLIP_OFFSET).cast::<Rect>().write(clip);
        }
    }

    #[test]
    fn indexed_invalidation_checks_signed_range_and_translates_before_clipping() {
        use crate::testing::{hints, try_map_u32_slab};
        use crate::ui::indexed_rect_invalidate::indexed_rect_invalidate;

        let _guard = install_recorders();
        let Some(memory) = try_map_u32_slab(hints::INDEXED_RECT_INVALIDATE, 4096) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let table = memory as *mut Rect;
        let mut element = [0u32; 0x100 / 4];
        let element_ptr = element.as_mut_ptr().cast::<u8>();
        let mut context = [0u8; 1];
        unsafe {
            element_ptr.add(0x3c).cast::<*mut u8>().write_unaligned(context.as_mut_ptr());
            element[0x48 / 4] = 0x800;
            element_ptr.add(0x80).cast::<Rect>().write(Rect {
                top: 10, left: 20, bottom: 100, right: 200,
            });
            element[0xb8 / 4] = 2;
            element[0xbc / 4] = 1;
            element[0xe8 / 4] = (-3i32) as u32;
            element[0xec / 4] = table as u32;
            element[0xf0 / 4] = 3;
            element[0xf4 / 4] = 4;
            table.write(Rect { top: -8, left: -10, bottom: 40, right: 50 });
            table.add(1).write(Rect { top: 5, left: 6, bottom: 7, right: 8 });

            // Lower and exclusive upper boundaries must not touch even a NULL table.
            let saved_table = element[0xec / 4];
            element[0xec / 4] = 0;
            for index in [-4i32, -1, i32::MIN, i32::MAX] {
                assert_eq!(indexed_rect_invalidate(element_ptr, index),
                    element_ptr as usize as u32 as u64 | ((index as u32 as u64) << 32));
            }
            assert_eq!(INVALIDATE_CALLS, 0);
            element[0xec / 4] = saved_table;

            assert_eq!(indexed_rect_invalidate(element_ptr, -3), 5 | (14u64 << 32));
            // Clip to bounds, then the existing renderer adds +2/+3.
            assert_eq!(SEEN_RECT, Rect { top: 12, left: 23, bottom: 55, right: 77 });
            assert_eq!(indexed_rect_invalidate(element_ptr, -2), 18 | (30u64 << 32));
            assert_eq!(SEEN_RECT, Rect { top: 20, left: 33, bottom: 22, right: 35 });
            assert_eq!(INVALIDATE_CALLS, 2);

            // Wrapping MLA changes the range; never normalize it to host arithmetic.
            element[0xb8 / 4] = i32::MAX as u32;
            element[0xbc / 4] = 2;
            assert_eq!(indexed_rect_invalidate(element_ptr, -3),
                element_ptr as usize as u32 as u64 | ((-3i32 as u32 as u64) << 32));
            assert_eq!(INVALIDATE_CALLS, 2);

            // Coordinate overflow must wrap in each translation, even if hidden.
            element[0xb8 / 4] = 2;
            element[0x48 / 4] = 0;
            table.write(Rect { top: i32::MAX, left: i32::MAX, bottom: 0, right: 0 });
            assert_eq!(indexed_rect_invalidate(element_ptr, -3),
                (i32::MIN.wrapping_add(12) as u32 as u64)
                    | ((i32::MIN.wrapping_add(23) as u32 as u64) << 32));
            assert_eq!(INVALIDATE_CALLS, 2);
        }
    }

    #[test]
    fn clips_then_transforms_and_invalidates_the_resolved_context() {
        let _guard = install_recorders();
        let mut context = [0u8; 1];
        let mut parent = ElementFixture::new(Rect::default());
        let mut element = ElementFixture::new(Rect {
            top: 10,
            left: 20,
            bottom: 60,
            right: 80,
        });
        unsafe {
            parent.set_clip(Rect {
                top: 15,
                left: 25,
                bottom: 50,
                right: 70,
            });
            element.set_flags(0x800);
            element.set_parent(parent.ptr());
            element.set_render_context(context.as_mut_ptr());
        }
        let region = Rect {
            top: 0,
            left: 0,
            bottom: 100,
            right: 100,
        };
        let element_ptr = element.ptr();

        let returned = unsafe { ui_element_invalidate_region(element_ptr, &region) };

        unsafe {
            assert_eq!(returned, element_ptr);
            assert_eq!(TRANSFORM_CALLS, 1);
            assert_eq!(INVALIDATE_CALLS, 1);
            assert_eq!(SEEN_TRANSFORM_CONTEXT, context.as_mut_ptr());
            assert_eq!(SEEN_INVALIDATE_CONTEXT, context.as_mut_ptr());
            assert_eq!(
                SEEN_RECT,
                Rect {
                    top: 17,
                    left: 28,
                    bottom: 52,
                    right: 73,
                },
                "the invalidator receives the parent-clipped rectangle after transform"
            );
        }
    }

    #[test]
    fn shown_suppression_and_global_gates_skip_every_render_operation() {
        let _guard = install_recorders();
        let mut element = ElementFixture::new(Rect::default());
        let element_ptr = element.ptr();

        unsafe {
            element.set_flags(0);
            ui_element_invalidate_region(element_ptr, &Rect::default());
            element.set_flags(0x800);
            element.set_suppressed(true);
            ui_element_invalidate_region(element_ptr, &Rect::default());
            element.set_suppressed(false);
            HOST_REDRAW_ENABLED = 0;
            ui_element_invalidate_region(element_ptr, &Rect::default());
            assert_eq!(TRANSFORM_CALLS, 0);
            assert_eq!(INVALIDATE_CALLS, 0);
        }
    }

    #[test]
    fn whole_bounds_thunk_returns_element_after_region_invalidation() {
        let _guard = install_recorders();
        let mut context = [0u8; 1];
        let mut element = ElementFixture::new(Rect {
            top: 1,
            left: 2,
            bottom: 3,
            right: 4,
        });
        unsafe {
            element.set_flags(0x800);
            element.set_render_context(context.as_mut_ptr());
        }
        let element_ptr = element.ptr();

        let returned = unsafe { ui_element_invalidate(element_ptr) };

        unsafe {
            assert_eq!(returned, element_ptr);
            assert_eq!(INVALIDATE_CALLS, 1);
            assert_eq!(
                SEEN_RECT,
                Rect {
                    top: 3,
                    left: 5,
                    bottom: 5,
                    right: 7,
                }
            );
        }
    }
}
