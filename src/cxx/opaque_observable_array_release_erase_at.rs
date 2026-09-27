//! `opaque_observable_array_release_erase_at` — retailOS `FUN_083d097c` @
//! `0x083d097c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` establishes twenty A32 words from `push {r4,r5,r6,lr}` at
//! `0x083d097c` through the tail branch at `0x083d09c8`: the true size is **80
//! bytes**. `0x083d09cc` is a veneer; the next independently entered function
//! begins at `0x083d09e4`. The body has no direct `bl` calls, one unconditional
//! virtual `blx` through array-vtable slot `+0x40`, and one predicated `blxne`
//! through element-vtable slot `+0x04`; it tail-dispatches
//! [`observable_array_erase_at`] @ `0x08271bec`. Whole-image A32 decoding finds
//! one inbound plain `bl` (0x0815dcf0) and one inbound predicated `blgt`
//! (0x081d0dec).
//!
//! ## Algorithm
//!
//! When the byte at `this + 0x10` is nonzero, obtain the requested cell through
//! vtable slot `+0x40`. If its element word is non-NULL, invoke that element's
//! vtable `+0x04` release operation. Then erase the same signed index through
//! the observable-array base implementation. Deliberate host deviation: native
//! pointers and callback fields stand in for target-width vtable words.

use super::observable_array::{observable_array_erase_at, ObservableArray};
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_dispose_elements::{HostElement, HostOpaqueObservableArray};

#[cfg(target_os = "none")]
type ElementAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u32;
#[cfg(target_os = "none")]
type ElementRelease = unsafe extern "C" fn(*mut u8);

/// Releases the selected populated element when enabled, then erases its slot.
///
/// # Safety
///
/// `this` must reference an observable-array-derived object. When its byte at
/// `+0x10` is nonzero, vtable slot `+0x40` must accept `(this, index)` and
/// return a readable cell; a non-NULL element must have a callable vtable
/// operation at `+0x04`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_release_erase_at(
    this: *mut ObservableArray,
    index: i32,
) -> i32 {
    #[cfg(target_os = "none")]
    if this.cast::<u8>().add(0x10).read_volatile() != 0 {
        let vtable = this.cast::<u32>().read_volatile() as usize as *const u32;
        let element_at: ElementAt = core::mem::transmute(vtable.add(0x40 / 4).read_volatile() as usize);
        let element = element_at(this.cast(), index).read_volatile() as usize as *mut u8;
        if !element.is_null() {
            let element_vtable = element.cast::<u32>().read_volatile() as usize as *const u32;
            let release: ElementRelease = core::mem::transmute(element_vtable.add(1).read_volatile() as usize);
            release(element);
        }
    }
    #[cfg(not(target_os = "none"))]
    if (*this.cast::<HostOpaqueObservableArray>()).enabled != 0 {
        let array = &*this.cast::<HostOpaqueObservableArray>();
        let element = ((*array.vtable).element_at)(this.cast(), index).read().element;
        if !element.is_null() {
            ((*(*element.cast::<HostElement>()).vtable).release)(element);
        }
    }
    observable_array_erase_at(this, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{ObservableArrayEraseFinish, ObservableArrayEraseMove, OBSERVABLE_ARRAY_NOTIFY_ERASE};
    use crate::cxx::opaque_observable_array_dispose_elements::{HostElementCell, HostElementVtable};
    use crate::cxx::opaque_observable_array_dispose_elements::HostElementAt;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CELLS: [HostElementCell; 2] = [HostElementCell { element: core::ptr::null_mut() }; 2];
    static mut RELEASED: usize = 0;
    static mut MOVES: usize = 0;
    static mut FINISHES: usize = 0;
    static mut NOTIFICATIONS: usize = 0;

    #[repr(C)]
    struct Vtable {
        unresolved_00_3c: [usize; 16],
        element_at: HostElementAt,
        unresolved_44_b4: [usize; 29],
        move_range: ObservableArrayEraseMove,
        finish_remove: ObservableArrayEraseFinish,
    }

    unsafe extern "C" fn element_at(_: *mut u8, index: i32) -> *mut HostElementCell {
        CELLS.as_mut_ptr().add(index as usize)
    }
    unsafe extern "C" fn release(element: *mut u8) { RELEASED = element as usize; }
    unsafe extern "C" fn move_range(_: *mut ObservableArray, _: i32, _: i32, _: i32) { MOVES += 1; }
    unsafe extern "C" fn finish_remove(_: *mut ObservableArray, _: i32) { FINISHES += 1; }
    unsafe extern "C" fn notify(_: *mut ObservableArray, _: i32) { NOTIFICATIONS += 1; }

    fn fixture(vtable: *const Vtable, len: i32, enabled: u8) -> HostOpaqueObservableArray {
        HostOpaqueObservableArray { vtable: vtable.cast(), count: len, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn releases_selected_element_before_base_erase() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = Vtable { unresolved_00_3c: [0; 16], element_at, unresolved_44_b4: [0; 29], move_range, finish_remove, };
            let element_vtable = HostElementVtable { unresolved_00: 0, release };
            let mut element = HostElement { vtable: &element_vtable };
            CELLS = [HostElementCell { element: core::ptr::addr_of_mut!(element).cast() }, HostElementCell { element: core::ptr::null_mut() }];
            RELEASED = 0; MOVES = 0; FINISHES = 0; NOTIFICATIONS = 0;
            OBSERVABLE_ARRAY_NOTIFY_ERASE = notify;
            let mut array = fixture(&vtable, 2, 1);
            assert_eq!(opaque_observable_array_release_erase_at((&mut array as *mut HostOpaqueObservableArray).cast(), 0), 0);
            assert_eq!(RELEASED, core::ptr::addr_of_mut!(element) as usize);
            assert_eq!((MOVES, FINISHES, NOTIFICATIONS), (1, 1, 1));
        }
    }

    #[test]
    fn disabled_or_empty_cells_skip_release_but_still_erase() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = Vtable { unresolved_00_3c: [0; 16], element_at, unresolved_44_b4: [0; 29], move_range, finish_remove, };
            CELLS = [HostElementCell { element: core::ptr::null_mut() }; 2];
            RELEASED = 0; MOVES = 0; FINISHES = 0; NOTIFICATIONS = 0;
            OBSERVABLE_ARRAY_NOTIFY_ERASE = notify;
            let mut disabled = fixture(&vtable, 1, 0);
            assert_eq!(opaque_observable_array_release_erase_at((&mut disabled as *mut HostOpaqueObservableArray).cast(), 0), 0);
            let mut empty = fixture(&vtable, 1, 1);
            assert_eq!(opaque_observable_array_release_erase_at((&mut empty as *mut HostOpaqueObservableArray).cast(), 0), 0);
            assert_eq!(RELEASED, 0);
            assert_eq!((MOVES, FINISHES, NOTIFICATIONS), (0, 2, 2));
        }
    }
}
