//! `view_base_set_y_extent` — original: `FUN_0826d6e8` @ `0x0826d6e8`
//! (184 bytes, `0x0826d6e8..0x0826d79c`; the separately linked empty
//! destructor at `0x0826d7a0` opens with `bx lr`).
//!
//! Raw ARM snapshots the four `ViewBase + 0x80` bounds words, then returns
//! immediately when `y_end - y_start == extent`. Otherwise it recognises the
//! high y rule at geometry word 10 or the low y rule at word 4 (with bit 5
//! ignored), adjusts the corresponding geometry value, forms a temporary
//! bounds rectangle, dispatches vtable slot `+0x68` with `(view, &bounds, 1)`,
//! and marks the view changed except for the generic-rule path. The ABI return
//! is the snapshot's `x_start`: the raw `pop {r0, ... pc}` restores that word,
//! not the incoming view pointer.
//!
//! A whole-image ARM B/BL-word decode finds **7 direct `bl` call sites**: six
//! unconditional and one `blgt` at `0x081f4310`; no direct tail `b` reaches
//! this entry. The predicated caller checks that its clamped extent is positive;
//! this body has no NULL guard and always calls its slot when the extent differs.
//!
//! Deliberate host deviation: target builds dispatch the object's actual
//! `+0x68` vtable word. That word in the grand-base vtable is `0x08105d0c`,
//! which points into an instruction stream rather than a recoverable function
//! entry, so no callee identity is invented. Host builds reuse the established
//! [`VIEW_BASE_SLOT_68`](crate::ui::set_x_extent::VIEW_BASE_SLOT_68) seam.
//! The unported redraw helper at `0x0826db38` reuses the established
//! geometry-changed seam.

use crate::ui::set_geometry::VIEW_BASE_GEOMETRY_CHANGED;
#[cfg(not(target_os = "none"))]
use crate::ui::set_x_extent::VIEW_BASE_SLOT_68;
use crate::ui::view_base::{ViewBase, ViewBounds};
#[cfg(target_os = "none")]
use crate::ui::view_base::ViewBaseVtable;

const Y_START_MODE_WORD: usize = 4;
const Y_START_VALUE_WORD: usize = 5;
const Y_END_MODE_WORD: usize = 10;
const Y_END_VALUE_WORD: usize = 11;
const RULE_FLAG_20: u32 = 0x20;
const Y_END_FROM_START: u32 = 0x8000_0001;
const EXTENT_ABSOLUTE: u32 = 0x8000_0004;

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

/// Sets the y-axis extent of a view's temporary bounds rectangle.
///
/// # Safety
///
/// `view` must be writable and its vtable's `+0x68` slot must implement the
/// observed `(ViewBase *, ViewBounds *, u32)` ABI when `extent` differs from
/// the current y extent.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn view_base_set_y_extent(
    view: *mut ViewBase,
    extent: u32,
) -> u32 {
    let mut bounds = unsafe {
        ViewBounds {
            x_start: core::ptr::addr_of!((*view).bounds.x_start).read_volatile(),
            y_start: core::ptr::addr_of!((*view).bounds.y_start).read_volatile(),
            x_end: core::ptr::addr_of!((*view).bounds.x_end).read_volatile(),
            y_end: core::ptr::addr_of!((*view).bounds.y_end).read_volatile(),
        }
    };

    if bounds.y_end.wrapping_sub(bounds.y_start) == extent {
        return bounds.x_start;
    }

    let mut geometry_changed = true;
    let end_mode = unsafe { geometry_word(view, Y_END_MODE_WORD).read_volatile() } & !RULE_FLAG_20;
    if end_mode == Y_END_FROM_START {
        let end = bounds.y_start.wrapping_add(extent);
        unsafe { geometry_word(view, Y_END_VALUE_WORD).write_volatile(end) };
        bounds.y_end = end;
    } else if end_mode == EXTENT_ABSOLUTE {
        unsafe { geometry_word(view, Y_END_VALUE_WORD).write_volatile(extent) };
        bounds.y_end = bounds.y_start.wrapping_add(extent);
    } else {
        let start_mode = unsafe { geometry_word(view, Y_START_MODE_WORD).read_volatile() } & !RULE_FLAG_20;
        if start_mode == EXTENT_ABSOLUTE {
            unsafe { geometry_word(view, Y_START_VALUE_WORD).write_volatile(extent) };
            bounds.y_start = bounds.y_end.wrapping_sub(extent);
        } else {
            geometry_changed = false;
            bounds.y_end = bounds.y_start.wrapping_add(extent);
        }
    }

    unsafe { view_base_dispatch_slot_68(view, core::ptr::addr_of_mut!(bounds)) };
    if geometry_changed {
        let changed = unsafe { core::ptr::addr_of!(VIEW_BASE_GEOMETRY_CHANGED).read_volatile() };
        unsafe { changed(view) };
    }
    bounds.x_start
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::ui::set_geometry::VIEW_BASE_GEOMETRY_CHANGED_TEST_LOCK;
    use crate::ui::set_x_extent::{VIEW_BASE_SLOT_68, VIEW_BASE_SLOT_68_TEST_LOCK};
    use crate::ui::view_base::ViewBaseSlot68;
    use core::ptr;

    const SLAB_LEN: usize = 0x1000;
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
        let slot_lock = VIEW_BASE_SLOT_68_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
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
                x_start: 0xdead_beef,
                y_start: 0xffff_fff0,
                x_end: 0xcafe_babe,
                y_end: 0x0000_0010,
            });
            geometry_word(view, Y_END_MODE_WORD).write_volatile(end_mode);
            geometry_word(view, Y_END_VALUE_WORD).write_volatile(0xa5a5_a5a5);
            geometry_word(view, Y_START_MODE_WORD).write_volatile(start_mode);
            geometry_word(view, Y_START_VALUE_WORD).write_volatile(0x5a5a_5a5a);
            SLOT_CALLS = 0;
            GEOMETRY_CHANGED_CALLS = 0;
        }
    }

    #[test]
    fn y_extent_preserves_each_rule_predicated_caller_contract_and_raw_return() {
        let _restore = install_recorders();
        let Some(slab) = try_map_u32_slab(hints::VIEW_BASE_SET_Y_EXTENT, SLAB_LEN) else {
            assert!(note_missing_u32_fixture("ui/set_y_extent"));
            return;
        };
        let view = slab.cast::<ViewBase>();

        unsafe {
            reset(view, Y_END_FROM_START | RULE_FLAG_20, 0);
            assert_eq!(view_base_set_y_extent(view, 0x30), 0xdead_beef);
            assert_eq!(geometry_word(view, Y_END_VALUE_WORD).read_volatile(), 0x20);
            assert_eq!(SLOT_BOUNDS, ViewBounds { x_start: 0xdead_beef, y_start: 0xffff_fff0, x_end: 0xcafe_babe, y_end: 0x20 });
            assert_eq!((SLOT_CALLS, SLOT_VIEW, SLOT_REDRAW, GEOMETRY_CHANGED_CALLS), (1, view, 1, 1));

            reset(view, EXTENT_ABSOLUTE, 0);
            view_base_set_y_extent(view, 0x30);
            assert_eq!(geometry_word(view, Y_END_VALUE_WORD).read_volatile(), 0x30);
            assert_eq!(SLOT_BOUNDS.y_end, 0x20);
            assert_eq!(GEOMETRY_CHANGED_CALLS, 1);

            reset(view, 0, EXTENT_ABSOLUTE | RULE_FLAG_20);
            view_base_set_y_extent(view, 0x30);
            assert_eq!(geometry_word(view, Y_START_VALUE_WORD).read_volatile(), 0x30);
            assert_eq!(SLOT_BOUNDS.y_start, 0xffff_ffe0);
            assert_eq!(SLOT_BOUNDS.y_end, 0x10);
            assert_eq!(GEOMETRY_CHANGED_CALLS, 1);

            reset(view, 0, 0);
            view_base_set_y_extent(view, 0x30);
            assert_eq!(SLOT_BOUNDS.y_end, 0x20);
            assert_eq!(GEOMETRY_CHANGED_CALLS, 0, "generic rule omits the post-slot helper");
            assert_eq!(SLOT_CALLS, 1, "all changed extents still dispatch slot +0x68");

            reset(view, 0, 0);
            assert_eq!(view_base_set_y_extent(view, 0x20), 0xdead_beef);
            assert_eq!((SLOT_CALLS, GEOMETRY_CHANGED_CALLS), (0, 0), "equal extent returns before any mode read or dispatch");
            assert_eq!(geometry_word(view, Y_END_VALUE_WORD).read_volatile(), 0xa5a5_a5a5);
        }
    }
}
