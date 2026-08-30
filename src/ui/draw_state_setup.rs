//! Configuring a scoped draw-state record from a UI element.
//!
//! `draw_state_configure_for_element` — original: `FUN_0826eb5c` @
//! **0x0826eb5c**, 184 bytes (`0x0826eb5c..0x0826ec14`; the next function
//! starts with `push {r0-r6,lr}` at 0x0826ec14). Raw decoding finds exactly
//! 32 direct, unconditional `bl` call sites and no predicated `bl` forms.
//!
//! # Algorithm
//!
//! Resolve the element's render context, then call its vtable +0x5c method
//! to obtain the render owner. A shown element contributes its +0x80 bounds,
//! transformed to render coordinates by `FUN_082a25d8`; its left/top are
//! copied to draw-state +0x2c/+0x30 before clipping. A non-zero byte at
//! render-owner +0x100 selects the render context's +0xb4 clip rectangle;
//! otherwise a non-NULL parent (+0x34) supplies its +0xd0 clip rectangle.
//! Finally, the render context's +0x5c surface and the resulting rectangle
//! are stored at draw-state +0x1c and +0x34 respectively. Hidden elements
//! retain their pre-existing origin but receive a zero clip rectangle.
//!
//! # Deliberate deviations
//!
//! `FUN_082a25d8` tail-calls the still-unported render-coordinate transform
//! at 0x0828cb64 after copying the bounds. The port performs that copy here
//! and reaches the retail transform through [`DRAW_STATE_RENDER_TRANSFORM`]
//! on the target. Host tests install a deterministic transform model. This
//! preserves the device call while avoiding a second port or a duplicate
//! implementation of the unresolved transform.

use core::mem::size_of;
use core::ptr;

use crate::ui::rect::{rect_intersect, Rect};
use crate::ui::render_context::ui_element_resolve_render_context;
use crate::ui::shown_state::ui_element_is_shown;

/// The unported render-coordinate transform called by `FUN_082a25d8`.
/// It translates a UI element bounds rectangle in the resolved context.
#[cfg(target_os = "none")]
static RENDER_CONTEXT_RECT_TRANSFORM_ADDRESS: usize = 0x0828_cb64;

/// ABI of `FUN_0828cb64`: mutate `rect` into `render_context` coordinates.
pub type DrawStateRenderTransform = unsafe extern "C" fn(render_context: *mut u8, rect: *mut Rect);

#[cfg(target_os = "none")]
type RectIntersect = unsafe extern "C" fn(*mut Rect, *const Rect);

/// Volatile indirection retains the separately ported `rect_intersect` as a
/// real ARM call target instead of allowing LLVM to inline its 132-byte body.
#[cfg(target_os = "none")]
static RECT_INTERSECT: RectIntersect = rect_intersect;
/// RetailOS's 32-bit layouts, used only on the ARM target so every accessed
/// word remains naturally aligned. Host fixtures use the packed views below.
#[cfg(target_os = "none")]
#[repr(C)]
struct TargetElement {
    vtable: u32,
    _before_parent: [u32; 12],
    parent: u32,
    _before_bounds: [u32; 18],
    bounds: Rect,
}

#[cfg(target_os = "none")]
#[repr(C)]
struct TargetElementVtable {
    _before_render_owner: [u32; 23],
    render_owner: u32,
}

#[cfg(target_os = "none")]
#[repr(C)]
struct TargetRenderOwner {
    _before_clip_flag: [u8; 0x100],
    uses_context_clip: u8,
}

#[cfg(target_os = "none")]
#[repr(C)]
struct TargetRenderContext {
    _before_surface: [u32; 23],
    surface: u32,
    _before_clip: [u32; 21],
    clip: Rect,
}

#[cfg(target_os = "none")]
#[repr(C)]
struct TargetParent {
    _before_clip: [u32; 52],
    clip: Rect,
}

#[cfg(target_os = "none")]
#[repr(C)]
struct TargetDrawState {
    _before_surface: [u32; 7],
    surface: u32,
    _before_origin: [u32; 3],
    origin_left: i32,
    origin_top: i32,
    clip: Rect,
}

#[cfg(target_os = "none")]
const _: () = assert!(size_of::<TargetDrawState>() == 0x44);


/// A UI element's leading vtable pointer.
#[repr(C, packed)]
struct ElementVtableLink {
    vtable: *const ElementVtable,
}

/// The vtable slot called at element +0x00, vtable +0x5c.
#[repr(C, packed)]
struct ElementVtable {
    _before_render_owner: [u8; 0x5c],
    render_owner: unsafe extern "C" fn(*mut u8) -> *mut u8,
}

/// A view of the element's local bounds at +0x80.
#[repr(C, packed)]
struct ElementBounds {
    _before_bounds: [u8; 0x80],
    bounds: Rect,
}

/// A view of the parent link at +0x34.
#[repr(C, packed)]
struct ElementParent {
    _before_parent: [u8; 0x34],
    parent: *mut u8,
}

/// Test-only owner link kept after the +0x80 bounds rectangle.
#[cfg(test)]
#[repr(C, packed)]
struct ElementTestRenderOwner {
    _before_owner: [u8; 0x94],
    owner: *mut u8,
}

/// The render-owner flag read at +0x100.
#[repr(C, packed)]
struct RenderOwnerClipFlag {
    _before_clip_flag: [u8; 0x100],
    uses_context_clip: u8,
}

/// The render owner's render-context pointer used by the already ported
/// context resolver's fallback path.
#[cfg(test)]
#[repr(C, packed)]
struct RenderOwnerContext {
    _before_context: [u8; 0x104],
    render_context: *mut u8,
}

/// The surface descriptor pointer at render-context +0x5c.
#[repr(C, packed)]
struct RenderContextSurface {
    _before_surface: [u8; 0x5c],
    surface: *mut u8,
}

/// The context clip rectangle at render-context +0xb4.
#[repr(C, packed)]
struct RenderContextClip {
    _before_clip: [u8; 0xb4],
    clip: Rect,
}

/// The fields of the 0x44-byte draw-state record written by this routine.
/// `surface` is pointer-sized in host fixtures, so the intervening padding
/// contracts by four bytes there while all following named fields retain
/// their retailOS byte positions.
#[repr(C, packed)]
struct DrawStateSetupFields {
    _before_surface: [u8; 0x1c],
    surface: *mut u8,
    _before_origin: [u8; 0x2c - 0x1c - size_of::<*mut u8>()],
    origin_left: i32,
    origin_top: i32,
    clip: Rect,
}

const _: () = assert!(size_of::<DrawStateSetupFields>() == 0x44);

/// Target default: invoke the original unported transform at 0x0828cb64.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_render_transform(render_context: *mut u8, rect: *mut Rect) {
    let address = ptr::read_volatile(ptr::addr_of!(RENDER_CONTEXT_RECT_TRANSFORM_ADDRESS));
    let transform: DrawStateRenderTransform = core::mem::transmute(address);
    transform(render_context, rect);
}

/// Host calls must explicitly supply a behavioral model for the unresolved
/// firmware transform rather than silently claiming an unverified result.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_render_transform(_render_context: *mut u8, _rect: *mut Rect) {
    panic!("FUN_0828cb64 is unported; install DRAW_STATE_RENDER_TRANSFORM")
}

#[cfg(test)]
unsafe extern "C" fn test_render_transform(_render_context: *mut u8, rect: *mut Rect) {
    (*rect).top = (*rect).top.wrapping_sub(4);
    (*rect).bottom = (*rect).bottom.wrapping_sub(4);
    (*rect).left = (*rect).left.wrapping_add(3);
    (*rect).right = (*rect).right.wrapping_add(3);
}


/// The render-coordinate transform called after copying a shown element's
/// bounds. Target builds dispatch directly to retailOS; host tests replace
/// the unavailable firmware body with a model.
#[cfg(target_os = "none")]
pub static mut DRAW_STATE_RENDER_TRANSFORM: DrawStateRenderTransform = firmware_render_transform;

/// Host default deliberately fails loudly because the real transform has not
/// yet been ported. Test builds substitute a deterministic coordinate model.
#[cfg(all(not(target_os = "none"), not(test)))]
pub static mut DRAW_STATE_RENDER_TRANSFORM: DrawStateRenderTransform = missing_render_transform;

#[cfg(all(not(target_os = "none"), test))]
pub static mut DRAW_STATE_RENDER_TRANSFORM: DrawStateRenderTransform = test_render_transform;

#[inline(always)]
unsafe fn render_transform() -> DrawStateRenderTransform {
    ptr::read_volatile(ptr::addr_of!(DRAW_STATE_RENDER_TRANSFORM))
}
/// ARM form of [`draw_state_configure_for_element`]. Its typed u32 layouts
/// keep all firmware word fields aligned, yielding `ldr`/`str` and `ldm`/`stm`
/// rather than bytewise host-fixture accesses.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_configure_for_element(element: *mut u8, draw_state: *mut u8) {
    let render_context = ui_element_resolve_render_context(element);
    let target_element = element.cast::<TargetElement>();
    let vtable_address = ptr::addr_of!((*target_element).vtable).read();
    let vtable = vtable_address as usize as *const TargetElementVtable;
    let render_owner_address = ptr::addr_of!((*vtable).render_owner).read();
    let render_owner: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(render_owner_address as usize);
    let owner = render_owner(element);

    let mut clip = Rect::default();
    if ui_element_is_shown(element) != 0 {
        clip = ptr::addr_of!((*target_element).bounds).read();
        render_transform()(render_context, &mut clip);

        let fields = draw_state.cast::<TargetDrawState>();
        ptr::addr_of_mut!((*fields).origin_left).write(clip.left);
        ptr::addr_of_mut!((*fields).origin_top).write(clip.top);

        let clip_source = if ptr::addr_of!((*owner.cast::<TargetRenderOwner>()).uses_context_clip).read() != 0 {
            let context = render_context.cast::<TargetRenderContext>();
            ptr::addr_of!((*context).clip)
        } else {
            let parent = ptr::addr_of!((*target_element).parent).read();
            if parent == 0 {
                ptr::null()
            } else {
                let parent = parent as usize as *const TargetParent;
                ptr::addr_of!((*parent).clip)
            }
        };
        if !clip_source.is_null() {
            let intersect = ptr::read_volatile(ptr::addr_of!(RECT_INTERSECT));
            intersect(&mut clip, clip_source);
        }
    }

    let context = render_context.cast::<TargetRenderContext>();
    let fields = draw_state.cast::<TargetDrawState>();
    ptr::addr_of_mut!((*fields).surface).write(ptr::addr_of!((*context).surface).read());
    ptr::addr_of_mut!((*fields).clip).write(clip);
}


/// draw_state_configure_for_element — original: `FUN_0826eb5c` @
/// 0x0826eb5c (184 bytes; 32 direct unconditional `bl` call sites).
///
/// Configure `draw_state` for `element` as described in the module header.
/// The original has no NULL guards: it dereferences the element, its vtable,
/// and the resolved render context unconditionally. It is `void`; all output
/// is written into the supplied draw-state record.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn draw_state_configure_for_element(element: *mut u8, draw_state: *mut u8) {
    let render_context = ui_element_resolve_render_context(element);
    let vtable = ptr::addr_of!((*element.cast::<ElementVtableLink>()).vtable).read_unaligned();
    let render_owner = (ptr::addr_of!((*vtable).render_owner).read_unaligned())(element);

    let mut clip = Rect::default();
    if ui_element_is_shown(element) != 0 {
        clip = ptr::addr_of!((*element.cast::<ElementBounds>()).bounds).read_unaligned();
        render_transform()(render_context, &mut clip);

        let fields = draw_state.cast::<DrawStateSetupFields>();
        ptr::addr_of_mut!((*fields).origin_left).write_unaligned(clip.left);
        ptr::addr_of_mut!((*fields).origin_top).write_unaligned(clip.top);

        let clip_source = if ptr::addr_of!((*render_owner.cast::<RenderOwnerClipFlag>()).uses_context_clip).read() != 0 {
            ptr::addr_of!((*render_context.cast::<RenderContextClip>()).clip).read_unaligned()
        } else {
            let parent = ptr::addr_of!((*element.cast::<ElementParent>()).parent).read_unaligned();
            if parent.is_null() {
                Rect::default()
            } else {
                #[repr(C, packed)]
                struct ParentClip {
                    _before_clip: [u8; 0xd0],
                    clip: Rect,
                }
                ptr::addr_of!((*parent.cast::<ParentClip>()).clip).read_unaligned()
            }
        };

        if ptr::addr_of!((*render_owner.cast::<RenderOwnerClipFlag>()).uses_context_clip).read() != 0
            || !ptr::addr_of!((*element.cast::<ElementParent>()).parent).read_unaligned().is_null() {
            rect_intersect(&mut clip, &clip_source);
        }
    }

    let fields = draw_state.cast::<DrawStateSetupFields>();
    let surface = ptr::addr_of!((*render_context.cast::<RenderContextSurface>()).surface).read_unaligned();
    ptr::addr_of_mut!((*fields).surface).write_unaligned(surface);
    ptr::addr_of_mut!((*fields).clip).write_unaligned(clip);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const ELEMENT_BYTES: usize = size_of::<ElementTestRenderOwner>();
    const OWNER_BYTES: usize = size_of::<RenderOwnerContext>();
    const CONTEXT_BYTES: usize = size_of::<RenderContextClip>();
    const PARENT_BYTES: usize = 0xd0 + size_of::<Rect>();

    unsafe extern "C" fn owner_from_element(element: *mut u8) -> *mut u8 {
        ptr::addr_of!((*element.cast::<ElementTestRenderOwner>()).owner).read_unaligned()
    }

    unsafe fn set_element(
        element: *mut u8,
        vtable: *const ElementVtable,
        owner: *mut u8,
        parent: *mut u8,
        flags: u32,
        bounds: Rect,
    ) {
        ptr::addr_of_mut!((*element.cast::<ElementVtableLink>()).vtable).write_unaligned(vtable);
        ptr::addr_of_mut!((*element.cast::<ElementTestRenderOwner>()).owner).write_unaligned(owner);
        ptr::addr_of_mut!((*element.cast::<ElementParent>()).parent).write_unaligned(parent);
        #[repr(C, packed)]
        struct ElementFlags {
            _before_flags: [u8; 0x48],
            flags: u32,
        }
        ptr::addr_of_mut!((*element.cast::<ElementFlags>()).flags).write_unaligned(flags);
        ptr::addr_of_mut!((*element.cast::<ElementBounds>()).bounds).write_unaligned(bounds);
    }

    unsafe fn set_owner(owner: *mut u8, uses_context_clip: u8, render_context: *mut u8) {
        ptr::addr_of_mut!((*owner.cast::<RenderOwnerClipFlag>()).uses_context_clip).write(uses_context_clip);
        ptr::addr_of_mut!((*owner.cast::<RenderOwnerContext>()).render_context).write_unaligned(render_context);
    }

    unsafe fn set_context(context: *mut u8, surface: *mut u8, clip: Rect) {
        ptr::addr_of_mut!((*context.cast::<RenderContextSurface>()).surface).write_unaligned(surface);
        ptr::addr_of_mut!((*context.cast::<RenderContextClip>()).clip).write_unaligned(clip);
    }

    unsafe fn draw_fields(draw_state: *mut u8) -> (*mut u8, i32, i32, Rect) {
        let fields = draw_state.cast::<DrawStateSetupFields>();
        (
            ptr::addr_of!((*fields).surface).read_unaligned(),
            ptr::addr_of!((*fields).origin_left).read_unaligned(),
            ptr::addr_of!((*fields).origin_top).read_unaligned(),
            ptr::addr_of!((*fields).clip).read_unaligned(),
        )
    }

    #[test]
    fn shown_element_transforms_sets_origin_and_clips_to_context() {
        unsafe {

            let vtable = ElementVtable { _before_render_owner: [0; 0x5c], render_owner: owner_from_element };
            let mut element = [0_u8; ELEMENT_BYTES];
            let mut owner = [0_u8; OWNER_BYTES];
            let mut context = [0_u8; CONTEXT_BYTES];
            let mut surface = 0_u8;
            let mut draw_state = [0xa5_u8; size_of::<DrawStateSetupFields>()];
            set_context(context.as_mut_ptr(), &mut surface, Rect { top: 11, left: 25, bottom: 60, right: 70 });
            set_owner(owner.as_mut_ptr(), 1, context.as_mut_ptr());
            set_element(
                element.as_mut_ptr(),
                &vtable,
                owner.as_mut_ptr(),
                ptr::null_mut(),
                0x800,
                Rect { top: 10, left: 20, bottom: 50, right: 80 },
            );

            draw_state_configure_for_element(element.as_mut_ptr(), draw_state.as_mut_ptr());

            assert_eq!(draw_fields(draw_state.as_mut_ptr()), (
                &mut surface as *mut u8,
                23,
                6,
                Rect { top: 11, left: 25, bottom: 46, right: 70 },
            ));
        }
    }

    #[test]
    fn hidden_element_preserves_origin_and_writes_empty_clip() {
        unsafe {

            let vtable = ElementVtable { _before_render_owner: [0; 0x5c], render_owner: owner_from_element };
            let mut element = [0_u8; ELEMENT_BYTES];
            let mut owner = [0_u8; OWNER_BYTES];
            let mut context = [0_u8; CONTEXT_BYTES];
            let mut surface = 0_u8;
            let mut draw_state = [0xa5_u8; size_of::<DrawStateSetupFields>()];
            set_context(context.as_mut_ptr(), &mut surface, Rect::default());
            set_owner(owner.as_mut_ptr(), 1, context.as_mut_ptr());
            set_element(element.as_mut_ptr(), &vtable, owner.as_mut_ptr(), ptr::null_mut(), 0, Rect::default());

            draw_state_configure_for_element(element.as_mut_ptr(), draw_state.as_mut_ptr());

            let (_, origin_left, origin_top, clip) = draw_fields(draw_state.as_mut_ptr());
            assert_eq!(origin_left, i32::from_ne_bytes([0xa5; 4]));
            assert_eq!(origin_top, i32::from_ne_bytes([0xa5; 4]));
            assert_eq!(clip, Rect::default());
            assert_eq!(draw_fields(draw_state.as_mut_ptr()).0, &mut surface as *mut u8);
        }
    }

    #[test]
    fn shown_element_clips_to_parent_when_owner_disables_context_clip() {
        unsafe {

            let vtable = ElementVtable { _before_render_owner: [0; 0x5c], render_owner: owner_from_element };
            let mut element = [0_u8; ELEMENT_BYTES];
            let mut element_owner = [0_u8; OWNER_BYTES];
            let mut parent = [0_u8; PARENT_BYTES];
            let mut parent_owner = [0_u8; OWNER_BYTES];
            let mut context = [0_u8; CONTEXT_BYTES];
            let mut surface = 0_u8;
            let mut draw_state = [0_u8; size_of::<DrawStateSetupFields>()];
            set_context(context.as_mut_ptr(), &mut surface, Rect::default());
            set_owner(element_owner.as_mut_ptr(), 0, ptr::null_mut());
            set_owner(parent_owner.as_mut_ptr(), 1, context.as_mut_ptr());
            ptr::addr_of_mut!((*parent.as_mut_ptr().cast::<ElementVtableLink>()).vtable).write_unaligned(&vtable);
            ptr::addr_of_mut!((*parent.as_mut_ptr().cast::<ElementTestRenderOwner>()).owner).write_unaligned(parent_owner.as_mut_ptr());
            #[repr(C, packed)]
            struct ParentClip {
                _before_clip: [u8; 0xd0],
                clip: Rect,
            }
            ptr::addr_of_mut!((*parent.as_mut_ptr().cast::<ParentClip>()).clip).write_unaligned(Rect { top: 8, left: 30, bottom: 40, right: 60 });
            set_element(
                element.as_mut_ptr(),
                &vtable,
                element_owner.as_mut_ptr(),
                parent.as_mut_ptr(),
                0x800,
                Rect { top: 10, left: 20, bottom: 50, right: 80 },
            );

            draw_state_configure_for_element(element.as_mut_ptr(), draw_state.as_mut_ptr());

            assert_eq!(draw_fields(draw_state.as_mut_ptr()), (
                &mut surface as *mut u8,
                23,
                6,
                Rect { top: 8, left: 30, bottom: 40, right: 60 },
            ));
        }
    }
}
