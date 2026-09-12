//! `view_base_set_x_extent` — original: `FUN_0826d87c` @ `0x0826d87c`
//! (184 bytes, `0x0826d87c..0x0826d930`; the separately linked next
//! function opens with `push {r4,r5,lr}` at `0x0826d934`).
//!
//! Raw ARM snapshots the four `ViewBase + 0x80` bounds words, then returns
//! immediately when `x_end - x_start == extent`. Otherwise it recognises the
//! high x rule at geometry word 7 or the low x rule at word 1 (with bit 5
//! ignored), adjusts the corresponding geometry value, forms a temporary
//! bounds rectangle, dispatches vtable slot `+0x68` with `(view, &bounds, 1)`,
//! and marks the view changed except for the generic-rule path.
//!
//! A whole-image ARM B/BL-word decode finds **8 direct `bl` call sites**:
//! five unconditional and three `blne`; no direct tail `b` reaches this
//! entry. The three predicated callers already gate an extent update, while
//! this body has no NULL guard and always calls its slot when the extent
//! differs.
//!
//! Deliberate host deviation: target builds dispatch the object's actual
//! `+0x68` vtable word. That word in the grand-base vtable is `0x08105d0c`,
//! which points into an instruction stream rather than a recoverable function
//! entry, so no callee identity is invented. Host builds instead expose the
//! same observed ABI through [`VIEW_BASE_SLOT_68`]. The unported redraw helper
//! at 0x0826db38 reuses the established geometry-changed seam.

use crate::ui::set_geometry::VIEW_BASE_GEOMETRY_CHANGED;
use crate::ui::view_base::{ViewBase, ViewBounds};
#[cfg(not(target_os = "none"))]
use crate::ui::view_base::ViewBaseSlot68;
#[cfg(target_os = "none")]
use crate::ui::view_base::ViewBaseVtable;

const X_START_MODE_WORD: usize = 1;
const X_START_VALUE_WORD: usize = 2;
const X_END_MODE_WORD: usize = 7;
const X_END_VALUE_WORD: usize = 8;
const RULE_FLAG_20: u32 = 0x20;
const X_END_FROM_START: u32 = 0x8000_0001;
const EXTENT_ABSOLUTE: u32 = 0x8000_0008;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_view_base_slot_68(
    _view: *mut ViewBase,
    _bounds: *mut ViewBounds,
    _redraw: u32,
) {
    panic!("view_base_set_x_extent requires a vtable slot +0x68 handler")
}

/// Host replacement for the view's unresolved runtime vtable slot `+0x68`.
///
/// The target word cannot hold a host-width function pointer. Tests install a
/// recorder here; target builds read the live vtable slot instead.
#[cfg(not(target_os = "none"))]
pub static mut VIEW_BASE_SLOT_68: ViewBaseSlot68 = missing_view_base_slot_68;

#[cfg(target_os = "none")]
unsafe fn view_base_dispatch_slot_68(view: *mut ViewBase, bounds: *mut ViewBounds) {
    let vtable = unsafe { (*view).vtable as usize as *const ViewBaseVtable };
    let callback = unsafe { core::ptr::addr_of!((*vtable).slot_68).read_volatile() };
    unsafe { callback(view, bounds, 1) };
}

#[cfg(not(target_os = "none"))]
unsafe fn view_base_dispatch_slot_68(view: *mut ViewBase, bounds: *mut ViewBounds) {
    let callback = unsafe { core::ptr::addr_of!(VIEW_BASE_SLOT_68).read_volatile() };
    unsafe { callback(view, bounds, 1) };
}

unsafe fn geometry_word(view: *mut ViewBase, word: usize) -> *mut u32 {
    unsafe { core::ptr::addr_of_mut!((*view).geometry).cast::<u32>().add(word) }
}

/// Sets the x-axis extent of a view's temporary bounds rectangle.
///
/// # Safety
///
/// `view` must be writable and its vtable's `+0x68` slot must implement the
/// observed `(ViewBase *, ViewBounds *, u32)` ABI when `extent` differs from
/// the current x extent.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_base_set_x_extent(
    view: *mut ViewBase,
    extent: u32,
) -> *mut ViewBase {
    let mut bounds = unsafe {
        ViewBounds {
            x_start: core::ptr::addr_of!((*view).bounds.x_start).read_volatile(),
            y_start: core::ptr::addr_of!((*view).bounds.y_start).read_volatile(),
            x_end: core::ptr::addr_of!((*view).bounds.x_end).read_volatile(),
            y_end: core::ptr::addr_of!((*view).bounds.y_end).read_volatile(),
        }
    };

    if bounds.x_end.wrapping_sub(bounds.x_start) == extent {
        return view;
    }

    let mut geometry_changed = true;
    let end_mode = unsafe { geometry_word(view, X_END_MODE_WORD).read_volatile() } & !RULE_FLAG_20;
    if end_mode == X_END_FROM_START {
        let end = bounds.x_start.wrapping_add(extent);
        unsafe { geometry_word(view, X_END_VALUE_WORD).write_volatile(end) };
        bounds.x_end = end;
    } else if end_mode == EXTENT_ABSOLUTE {
        unsafe { geometry_word(view, X_END_VALUE_WORD).write_volatile(extent) };
        bounds.x_end = bounds.x_start.wrapping_add(extent);
    } else {
        let start_mode = unsafe { geometry_word(view, X_START_MODE_WORD).read_volatile() } & !RULE_FLAG_20;
        if start_mode == EXTENT_ABSOLUTE {
            unsafe { geometry_word(view, X_START_VALUE_WORD).write_volatile(extent) };
            bounds.x_start = bounds.x_end.wrapping_sub(extent);
        } else {
            geometry_changed = false;
            bounds.x_end = bounds.x_start.wrapping_add(extent);
        }
    }

    unsafe { view_base_dispatch_slot_68(view, core::ptr::addr_of_mut!(bounds)) };
    if geometry_changed {
        let changed = unsafe { core::ptr::addr_of!(VIEW_BASE_GEOMETRY_CHANGED).read_volatile() };
        unsafe { changed(view) };
    }
    view
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::ui::set_geometry::VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK;
    use core::ptr;
    use std::sync::Mutex;

    const SLAB_LEN: usize = 0x1000;
    static SLOT_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOT_CALLS: u32 = 0;
    static mut SLOT_VIEW: *mut ViewBase = ptr::null_mut();
    static mut SLOT_BOUNDS: ViewBounds = ViewBounds { x_start: 0, y_start: 0, x_end: 0, y_end: 0 };
    static mut SLOT_REDRAW: u32 = 0;
    static mut GEOMETRY_CHANGED_CALLS: u32 = 0;

    unsafe extern "C" fn recording_slot_68(view: *mut ViewBase, bounds: *mut ViewBounds, redraw: u32) {
        unsafe {
            SLOT_CALLS += 1;
            SLOT_VIEW = view;
            SLOT_BOUNDS = bounds.read_volatile();
            SLOT_REDRAW = redraw;
        }
    }

    unsafe extern "C" fn recording_geometry_changed(_view: *mut ViewBase) {
        unsafe { GEOMETRY_CHANGED_CALLS += 1 };
    }

    struct Restore {
        previous_slot: ViewBaseSlot68,
        previous_geometry_changed: unsafe extern "C" fn(*mut ViewBase),
        _slot_lock: std::sync::MutexGuard<'static, ()>,
        _geometry_lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(VIEW_BASE_SLOT_68).write_volatile(self.previous_slot);
                ptr::addr_of_mut!(VIEW_BASE_GEOMETRY_CHANGED).write_volatile(self.previous_geometry_changed);
            }
        }
    }

    fn install_recorders() -> Restore {
        let slot_lock = SLOT_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let geometry_lock = VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let previous_slot = ptr::addr_of!(VIEW_BASE_SLOT_68).read_volatile();
            let previous_geometry_changed = ptr::addr_of!(VIEW_BASE_GEOMETRY_CHANGED).read_volatile();
            ptr::addr_of_mut!(VIEW_BASE_SLOT_68).write_volatile(recording_slot_68);
            ptr::addr_of_mut!(VIEW_BASE_GEOMETRY_CHANGED).write_volatile(recording_geometry_changed);
            SLOT_CALLS = 0;
            SLOT_VIEW = ptr::null_mut();
            SLOT_BOUNDS = ViewBounds { x_start: 0, y_start: 0, x_end: 0, y_end: 0 };
            SLOT_REDRAW = 0;
            GEOMETRY_CHANGED_CALLS = 0;
            Restore { previous_slot, previous_geometry_changed, _slot_lock: slot_lock, _geometry_lock: geometry_lock }
        }
    }

    unsafe fn reset(view: *mut ViewBase, end_mode: u32, start_mode: u32) {
        unsafe {
            ptr::write_bytes(view.cast::<u8>(), 0, core::mem::size_of::<ViewBase>());
            ptr::addr_of_mut!((*view).bounds).write_volatile(ViewBounds {
                x_start: 0xffff_fff0,
                y_start: 0x1111_2222,
                x_end: 0x0000_0010,
                y_end: 0x3333_4444,
            });
            geometry_word(view, X_END_MODE_WORD).write_volatile(end_mode);
            geometry_word(view, X_END_VALUE_WORD).write_volatile(0xa5a5_a5a5);
            geometry_word(view, X_START_MODE_WORD).write_volatile(start_mode);
            geometry_word(view, X_START_VALUE_WORD).write_volatile(0x5a5a_5a5a);
            SLOT_CALLS = 0;
            GEOMETRY_CHANGED_CALLS = 0;
        }
    }

    #[test]
    fn x_extent_preserves_each_rule_and_predicated_caller_contract() {
        let _restore = install_recorders();
        let Some(slab) = try_map_u32_slab(hints::VIEW_BASE_SET_X_EXTENT, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("ui/set_x_extent"));
            return;
        };
        let view = slab.cast::<ViewBase>();

        unsafe {
            reset(view, X_END_FROM_START | RULE_FLAG_20, 0);
            assert_eq!(view_base_set_x_extent(view, 0x30), view);
            assert_eq!(geometry_word(view, X_END_VALUE_WORD).read_volatile(), 0x20);
            assert_eq!(SLOT_BOUNDS, ViewBounds { x_start: 0xffff_fff0, y_start: 0x1111_2222, x_end: 0x20, y_end: 0x3333_4444 });
            assert_eq!((SLOT_CALLS, SLOT_VIEW, SLOT_REDRAW, GEOMETRY_CHANGED_CALLS), (1, view, 1, 1));

            reset(view, EXTENT_ABSOLUTE, 0);
            view_base_set_x_extent(view, 0x30);
            assert_eq!(geometry_word(view, X_END_VALUE_WORD).read_volatile(), 0x30);
            assert_eq!(SLOT_BOUNDS.x_end, 0x20);
            assert_eq!(GEOMETRY_CHANGED_CALLS, 1);

            reset(view, 0, EXTENT_ABSOLUTE | RULE_FLAG_20);
            view_base_set_x_extent(view, 0x30);
            assert_eq!(geometry_word(view, X_START_VALUE_WORD).read_volatile(), 0x30);
            assert_eq!(SLOT_BOUNDS.x_start, 0xffff_ffe0);
            assert_eq!(SLOT_BOUNDS.x_end, 0x10);
            assert_eq!(GEOMETRY_CHANGED_CALLS, 1);

            reset(view, 0, 0);
            view_base_set_x_extent(view, 0x30);
            assert_eq!(SLOT_BOUNDS.x_end, 0x20);
            assert_eq!(GEOMETRY_CHANGED_CALLS, 0, "generic rule omits the post-slot helper");
            assert_eq!(SLOT_CALLS, 1, "all changed extents still dispatch slot +0x68");

            reset(view, 0, 0);
            view_base_set_x_extent(view, 0x20);
            assert_eq!((SLOT_CALLS, GEOMETRY_CHANGED_CALLS), (0, 0), "equal extent returns before any mode read or dispatch");
            assert_eq!(geometry_word(view, X_END_VALUE_WORD).read_volatile(), 0xa5a5_a5a5);
        }
    }
}
