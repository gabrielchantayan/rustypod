//! `owned_observable_array_erase_at` — retailOS `FUN_083d1700` @ `0x083d1700`.
//!
//! Raw `osos.dec` establishes thirteen A32 words from `push {r4,r5,r6,lr}` at
//! `0x083d1700` through the tail branch at `0x083d1734`: the true size is **56
//! bytes** and `0x083d1738` begins the next independently entered function.
//! The body has two unconditional plain direct `bl` calls—
//! `container_element_at_alias_6b40` @ `0x083d6b40` and `operator_delete` @
//! `0x082aad24`—and no predicated direct `bl` calls. It then tail-dispatches
//! `observable_array_erase_at` @ `0x08271bec`.
//!
//! If the byte at `this + 0x10` enables ownership, fetch the indexed element
//! through vtable slot `+0x40` and pass that returned allocation directly to
//! NULL-safe tag-2 `operator_delete`; then erase the index. Deliberate host
//! deviation: native vtable pointers and a delete callback model target u32
//! pointers and retail-heap allocation respectively.

use super::observable_array::{observable_array_erase_at, ObservableArray};
#[cfg(not(target_os = "none"))]
use super::owned_element_array_delete_cells::OWNED_ELEMENT_ARRAY_DELETE;
use super::templates::container_element_at_alias_6b40;
#[cfg(target_os = "none")]
use crate::heap::veneers::operator_delete;

/// Erases one item, freeing its owned allocation first when enabled.
///
/// # Safety
///
/// `this` must be a readable observable-array-derived object with a byte at
/// `+0x10`. When enabled, vtable slot `+0x40` must yield the allocation for
/// `index`, and the object must satisfy [`observable_array_erase_at`]'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_observable_array_erase_at(this: *mut ObservableArray, index: i32) -> i32 {
    #[cfg(target_os = "none")]
    if this.cast::<u8>().add(0x10).read_volatile() != 0 {
        operator_delete(container_element_at_alias_6b40(this.cast(), index as usize));
    }
    #[cfg(not(target_os = "none"))]
    if (*this.cast::<HostOwnedObservableArrayErase>()).enabled != 0 {
        OWNED_ELEMENT_ARRAY_DELETE(container_element_at_alias_6b40(this.cast(), index as usize));
    }
    observable_array_erase_at(this, index)
}

/// Host-only target-prefix extension preserving the ownership-byte offset.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostOwnedObservableArrayErase {
    pub vtable: *const u8,
    pub len: i32,
    pub unresolved_08_0f: [u8; 8],
    pub enabled: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::observable_array::{ObservableArrayEraseFinish, ObservableArrayEraseMove, OBSERVABLE_ARRAY_NOTIFY_ERASE};
    use crate::cxx::templates::ElementSlotFn;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CELLS: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut LOOKUPS: [usize; 2] = [0; 2];
    static mut LOOKUP_COUNT: usize = 0;
    static mut DELETED: [usize; 2] = [0; 2];
    static mut DELETE_COUNT: usize = 0;
    static mut MOVES: usize = 0;
    static mut FINISHES: usize = 0;
    static mut NOTIFICATIONS: usize = 0;

    #[repr(C)]
    struct Vtable {
        unresolved_00_3c: [usize; 16],
        at: ElementSlotFn,
        unresolved_44_b4: [usize; 29],
        move_range: ObservableArrayEraseMove,
        finish_remove: ObservableArrayEraseFinish,
    }

    unsafe extern "C" fn element_at(_: *mut u8, index: usize) -> *mut *mut u8 {
        LOOKUPS[LOOKUP_COUNT] = index;
        LOOKUP_COUNT += 1;
        CELLS.as_mut_ptr().add(index)
    }
    unsafe extern "C" fn record_delete(ptr: *mut u8) { DELETED[DELETE_COUNT] = ptr as usize; DELETE_COUNT += 1; }
    unsafe extern "C" fn record_move(_: *mut ObservableArray, _: i32, _: i32, _: i32) { MOVES += 1; }
    unsafe extern "C" fn record_finish(_: *mut ObservableArray, _: i32) { FINISHES += 1; }
    unsafe extern "C" fn record_notify(_: *mut ObservableArray, _: i32) { NOTIFICATIONS += 1; }

    fn fixture(vtable: *const Vtable, len: i32, enabled: u8) -> HostOwnedObservableArrayErase {
        HostOwnedObservableArrayErase { vtable: vtable.cast(), len, unresolved_08_0f: [0; 8], enabled }
    }

    #[test]
    fn deletes_owned_element_before_erasing() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = Vtable { unresolved_00_3c: [0; 16], at: element_at, unresolved_44_b4: [0; 29], move_range: record_move, finish_remove: record_finish };
            CELLS = [0x1000usize as *mut u8, core::ptr::null_mut(), core::ptr::null_mut()];
            LOOKUP_COUNT = 0; DELETE_COUNT = 0; MOVES = 0; FINISHES = 0; NOTIFICATIONS = 0;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete; OBSERVABLE_ARRAY_NOTIFY_ERASE = record_notify;
            let mut array = fixture(&vtable, 2, 1);
            assert_eq!(owned_observable_array_erase_at((&mut array as *mut HostOwnedObservableArrayErase).cast(), 0), 0);
            assert_eq!(&LOOKUPS[..LOOKUP_COUNT], &[0]);
            assert_eq!(&DELETED[..DELETE_COUNT], &[0x1000]);
            assert_eq!((MOVES, FINISHES, NOTIFICATIONS), (1, 1, 1));
        }
    }

    #[test]
    fn disabled_and_invalid_indices_do_not_fetch_or_delete() {
        let _lock = LOCK.lock();
        unsafe {
            let vtable = Vtable { unresolved_00_3c: [0; 16], at: element_at, unresolved_44_b4: [0; 29], move_range: record_move, finish_remove: record_finish };
            CELLS = [0x1000usize as *mut u8, core::ptr::null_mut(), core::ptr::null_mut()];
            LOOKUP_COUNT = 0; DELETE_COUNT = 0; FINISHES = 0; NOTIFICATIONS = 0;
            OWNED_ELEMENT_ARRAY_DELETE = record_delete; OBSERVABLE_ARRAY_NOTIFY_ERASE = record_notify;
            let mut disabled = fixture(&vtable, 1, 0);
            assert_eq!(owned_observable_array_erase_at((&mut disabled as *mut HostOwnedObservableArrayErase).cast(), 0), 0);
            let mut invalid = fixture(&vtable, 1, 1);
            assert_eq!(owned_observable_array_erase_at((&mut invalid as *mut HostOwnedObservableArrayErase).cast(), 1), -1);
            assert_eq!(LOOKUP_COUNT, 1, "disabled ownership bypasses lookup");
            assert_eq!(DELETE_COUNT, 1, "retail deletes before erase validation");
            assert_eq!((FINISHES, NOTIFICATIONS), (1, 1));
        }
    }
}
