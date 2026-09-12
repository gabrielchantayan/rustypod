//! Setting a render owner's pending clip rectangle from a UI element.
//!
//! `ui_element_set_render_owner_clip` is retailOS `FUN_0826ed98` at
//! **0x0826ed98**. Raw `osos.dec` decoding establishes the 68-byte extent:
//! `push {r0-r6,lr}` opens the body and `pop {r0-r6,pc}` closes it at
//! 0x0826edd8; the next function begins at 0x0826eddc. Decoding every ARM
//! immediate `B`/`BL` word finds exactly eight direct, unconditional `bl`
//! call sites and no predicated forms. No aligned image word names the entry,
//! so it is not a known virtual-dispatch target.
//!
//! # Algorithm
//!
//! Obtain the element's render owner through its vtable +0x5c method,
//! intersect the supplied rectangle with the element's +0x80 bounds, and
//! write the resulting four-word rectangle at render-owner +0xec. The body
//! has no NULL guards for the element, vtable, input rectangle, returned
//! render owner, or their accessed fields.
//!
//! # Deliberate deviations
//!
//! Host fixtures use packed pointer views so the retailOS byte offsets survive
//! the host's wider pointers. The target uses aligned 32-bit layouts; both
//! forms retain the vtable-call, intersection, then four-word-store order.

use core::mem::size_of;
use core::ptr;

use crate::ui::rect::{rect_intersect_into, Rect};

/// ABI of the separately ported rectangle intersection at 0x0826c24c.
#[cfg(target_os = "none")]
type RectIntersectInto = unsafe extern "C" fn(*mut Rect, *const Rect, *const Rect);

/// A volatile function-pointer load prevents LLVM from inlining the existing
/// 156-byte port, retaining the original call boundary in this 68-byte body.
#[cfg(target_os = "none")]
static RECT_INTERSECT_INTO: RectIntersectInto = rect_intersect_into;

/// Target-only UI-element layout. Every accessed field is a naturally aligned
/// 32-bit word on ARMv5TE.
#[cfg(target_os = "none")]
#[repr(C)]
struct TargetUiElement {
    vtable: u32,
    _before_bounds: [u32; 31],
    bounds: Rect,
}

/// Target-only vtable layout for the method at +0x5c.
#[cfg(target_os = "none")]
#[repr(C)]
struct TargetUiElementVtable {
    _before_render_owner: [u32; 23],
    render_owner: u32,
}

/// Target-only render-owner layout for the pending clip rectangle at +0xec.
#[cfg(target_os = "none")]
#[repr(C)]
struct TargetRenderOwner {
    _before_clip: [u32; 59],
    clip: Rect,
}

#[cfg(target_os = "none")]
const _: () = assert!(size_of::<TargetUiElement>() == 0x90);
#[cfg(target_os = "none")]
const _: () = assert!(size_of::<TargetRenderOwner>() == 0xfc);

/// Host view of a UI element's vtable and local bounds.
#[cfg(not(target_os = "none"))]
#[repr(C, packed)]
struct UiElementFields {
    vtable: *const UiElementVtable,
    _before_bounds: [u8; 0x80 - size_of::<*const UiElementVtable>()],
    bounds: Rect,
}

/// Host view of the vtable slot at +0x5c.
#[cfg(not(target_os = "none"))]
#[repr(C, packed)]
struct UiElementVtable {
    _before_render_owner: [u8; 0x5c],
    render_owner: unsafe extern "C" fn(*mut u8) -> *mut u8,
}

/// Host view of the render owner's output rectangle.
#[cfg(not(target_os = "none"))]
#[repr(C, packed)]
struct RenderOwnerClip {
    _before_clip: [u8; 0xec],
    clip: Rect,
}

/// ui_element_set_render_owner_clip — original: `FUN_0826ed98` @
/// **0x0826ed98** (68 bytes; next function starts at 0x0826eddc).
///
/// Calls the element vtable's +0x5c render-owner method, intersects `region`
/// with the element's local +0x80 bounds, and copies the result into the
/// returned render owner's +0xec pending clip rectangle. There are eight
/// verified inbound plain `bl` calls, no predicated call forms, and no NULL
/// guard in the original.
///
/// # Deliberate deviations
///
/// Target builds use a volatile load of the already ported intersection entry
/// to retain the original call boundary; the resulting indirect `blx` is a
/// code-generation difference from retailOS's direct `bl`. The host branch
/// uses packed native-pointer fixtures while preserving retailOS byte offsets
/// and observable call/store ordering.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_set_render_owner_clip(element: *mut u8, region: *const Rect) {
    let fields = element.cast::<TargetUiElement>();
    let vtable_address = ptr::addr_of!((*fields).vtable).read();
    let vtable = vtable_address as usize as *const TargetUiElementVtable;
    let render_owner_address = ptr::addr_of!((*vtable).render_owner).read();
    let render_owner: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        core::mem::transmute(render_owner_address as usize);
    let owner = render_owner(element);

    let mut clip = Rect::default();
    let intersect = ptr::read_volatile(ptr::addr_of!(RECT_INTERSECT_INTO));
    intersect(&mut clip, region, ptr::addr_of!((*fields).bounds));
    ptr::addr_of_mut!((*owner.cast::<TargetRenderOwner>()).clip).write(clip);
}

/// Host form of [`ui_element_set_render_owner_clip`].
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn ui_element_set_render_owner_clip(element: *mut u8, region: *const Rect) {
    let fields = element.cast::<UiElementFields>();
    let vtable = ptr::addr_of!((*fields).vtable).read_unaligned();
    let owner = (ptr::addr_of!((*vtable).render_owner).read_unaligned())(element);

    let mut clip = Rect::default();
    let bounds = ptr::addr_of!((*fields).bounds).read_unaligned();
    rect_intersect_into(&mut clip, region, &bounds);
    ptr::addr_of_mut!((*owner.cast::<RenderOwnerClip>()).clip).write_unaligned(clip);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe extern "C" fn render_owner_from_element(element: *mut u8) -> *mut u8 {
        let owner = element.add(size_of::<UiElementFields>()).cast::<*mut u8>();
        owner.read_unaligned()
    }

    unsafe fn set_element(
        element: *mut u8,
        vtable: *const UiElementVtable,
        owner: *mut u8,
        bounds: Rect,
    ) {
        let fields = element.cast::<UiElementFields>();
        ptr::addr_of_mut!((*fields).vtable).write_unaligned(vtable);
        ptr::addr_of_mut!((*fields).bounds).write_unaligned(bounds);
        element.add(size_of::<UiElementFields>()).cast::<*mut u8>().write_unaligned(owner);
    }

    unsafe fn pending_clip(owner: *mut u8) -> Rect {
        ptr::addr_of!((*owner.cast::<RenderOwnerClip>()).clip).read_unaligned()
    }

    #[test]
    fn clips_region_to_element_bounds_and_uses_vtable_owner() {
        unsafe {
            let vtable = UiElementVtable {
                _before_render_owner: [0; 0x5c],
                render_owner: render_owner_from_element,
            };
            let mut element = [0_u8; size_of::<UiElementFields>() + size_of::<*mut u8>()];
            let mut owner = [0xa5_u8; size_of::<RenderOwnerClip>()];
            set_element(
                element.as_mut_ptr(),
                &vtable,
                owner.as_mut_ptr(),
                Rect { top: 10, left: 20, bottom: 50, right: 80 },
            );
            let region = Rect { top: 4, left: 30, bottom: 35, right: 90 };

            ui_element_set_render_owner_clip(element.as_mut_ptr(), &region);

            assert_eq!(pending_clip(owner.as_mut_ptr()), Rect { top: 10, left: 30, bottom: 35, right: 80 });
        }
    }

    #[test]
    fn stores_empty_clip_for_disjoint_or_empty_input() {
        unsafe {
            let vtable = UiElementVtable {
                _before_render_owner: [0; 0x5c],
                render_owner: render_owner_from_element,
            };
            let mut element = [0_u8; size_of::<UiElementFields>() + size_of::<*mut u8>()];
            let mut owner = [0xa5_u8; size_of::<RenderOwnerClip>()];
            set_element(
                element.as_mut_ptr(),
                &vtable,
                owner.as_mut_ptr(),
                Rect { top: 10, left: 20, bottom: 50, right: 80 },
            );
            let disjoint = Rect { top: 51, left: 20, bottom: 60, right: 80 };
            ui_element_set_render_owner_clip(element.as_mut_ptr(), &disjoint);
            assert_eq!(pending_clip(owner.as_mut_ptr()), Rect::default());

            let empty = Rect { top: 10, left: 20, bottom: 10, right: 80 };
            ui_element_set_render_owner_clip(element.as_mut_ptr(), &empty);
            assert_eq!(pending_clip(owner.as_mut_ptr()), Rect::default());
        }
    }
}
