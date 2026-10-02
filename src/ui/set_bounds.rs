//! Element bounds setter — `FUN_0826f1a4` @ 0x0826f1a4, 200 bytes.
//! Raw extent ends with pop at 0x0826f268; next push is at 0x0826f26c.
//! Verified inbound calls: two plain BL, zero predicated BL. Body: three
//! plain BL and three BLNE, followed by a virtual tail dispatch at +0x60.
//!
//! Skip equal bounds unless flags bit 4 forces an update. For nonzero redraw,
//! save the union of old and requested bounds before assignment. Bit 8 invokes
//! the stock parent-centering helper (0x0826c9a8); only if the resulting bounds
//! differ from the request does the redraw path invalidate that saved union.
//! Finally notify through vtable +0x60, including forced equal updates.
//!
//! Deviations: void return (both verified callers discard r0/r1); native host
//! vtable pointers with explicit byte padding preserve the target slot offset.
//! The unported centering helper remains a volatile retail-address seam.

use core::ptr;
use crate::ui::invalidate::ui_element_invalidate_region;
use crate::ui::rect::{rect_not_equals, rect_union, Rect};

type CenterInParent = unsafe extern "C" fn(*mut u8);
static mut CENTER_IN_PARENT: usize = 0x0826c9a8;

#[repr(C, packed)]
struct Vtable {
    before_changed: [u8; 0x60],
    changed: unsafe extern "C" fn(*mut u8),
}

/// Set the bounds and notify the element; inputs must be valid and aligned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_set_bounds(
    element: *mut u8,
    requested: *const Rect,
    redraw: u32,
) {
    let bounds = element.add(0x80).cast::<Rect>();
    let flags = element.add(0x48).cast::<u32>();
    if rect_not_equals(bounds, requested) == 0 && flags.read() & 0x10 == 0 {
        return;
    }
    let mut dirty = bounds.read();
    if redraw != 0 {
        rect_union(&mut dirty, requested);
    }
    // Load the complete request before writing, including when it aliases bounds.
    bounds.write(requested.read());
    if flags.read() & 0x100 != 0 {
        let center: CenterInParent = core::mem::transmute(
            ptr::read_volatile(ptr::addr_of!(CENTER_IN_PARENT)),
        );
        center(element);
    }
    if redraw != 0 && rect_not_equals(bounds, requested) != 0 {
        ui_element_invalidate_region(element, &dirty);
    }
    let vtable = element.cast::<*const Vtable>().read_unaligned();
    let changed = ptr::addr_of!((*vtable).changed).read_unaligned();
    changed(element);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        vtable: *const Vtable,
        pad: [u8; 0x48 - core::mem::size_of::<*const Vtable>()],
        flags: u32,
        middle: [u8; 0x80 - 0x4c],
        bounds: Rect,
        after: [u8; 0x20],
        notifications: u32,
        center_calls: u32,
    }
    unsafe extern "C" fn changed(element: *mut u8) {
        let f = &mut *element.cast::<Fixture>();
        f.notifications += 1;
    }
    unsafe extern "C" fn center(element: *mut u8) {
        let f = &mut *element.cast::<Fixture>();
        f.center_calls += 1;
        f.bounds.top = f.bounds.top.wrapping_add(3);
    }

    #[test]
    fn equal_forced_changed_centered_and_aliased_bounds() {
        unsafe {
            let saved = CENTER_IN_PARENT;
            CENTER_IN_PARENT = center as *const () as usize;
            let vtable = Vtable { before_changed: [0; 0x60], changed };
            let original = Rect { top: -10, left: 2, bottom: 20, right: 30 };
            let mut f = Fixture {
                vtable: &vtable, pad: [0; 0x48 - core::mem::size_of::<*const Vtable>()],
                flags: 0, middle: [0; 0x80 - 0x4c], bounds: original,
                after: [0; 0x20], notifications: 0, center_calls: 0,
            };
            let element = ptr::addr_of_mut!(f).cast::<u8>();
            ui_element_set_bounds(element, &original, 1);
            assert_eq!((f.notifications, f.center_calls), (0, 0));
            f.flags = 0x10;
            ui_element_set_bounds(element, &original, 0);
            assert_eq!((f.notifications, f.center_calls), (1, 0));
            let request = Rect { top: i32::MAX, left: -4, bottom: 0, right: 8 };
            f.flags = 0x100;
            ui_element_set_bounds(element, &request, 0);
            assert_eq!(f.bounds.top, i32::MIN + 2);
            assert_eq!((f.bounds.left, f.bounds.bottom, f.bounds.right), (-4, 0, 8));
            assert_eq!((f.notifications, f.center_calls), (2, 1));
            // Nonzero redraw takes the union path and centering makes the final
            // bounds differ. Flags deliberately leave the real shown-state gate off.
            ui_element_set_bounds(element, &original, u32::MAX);
            assert_eq!(f.bounds.top, -7);
            assert_eq!((f.notifications, f.center_calls), (3, 2));
            f.flags = 0x110;
            ui_element_set_bounds(element, ptr::addr_of!(f.bounds), 1);
            assert_eq!(f.bounds.top, -4);
            assert_eq!((f.notifications, f.center_calls), (4, 3));
            CENTER_IN_PARENT = saved;
        }
    }
}
