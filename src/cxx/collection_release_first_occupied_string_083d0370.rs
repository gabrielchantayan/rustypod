//! Releases the first occupied string object in an opaque polymorphic collection.
//!
//! `collection_release_first_occupied_string_083d0370` — retailOS `FUN_083d0370`
//! @ **0x083d0370**.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` establishes twenty-two A32 instructions from `push
//! {r4,r5,r6,lr}` at `0x083d0370` through `pop {r4,r5,r6,pc}` at `0x083d03c4`.
//! The `push {r4,r5,r6,lr}` at `0x083d03c8` starts the next real function, so
//! the true size is **88 bytes**. The body has two unconditional plain direct
//! `bl` calls, to [`string_object_destroy`] at `0x083d03b0` and
//! [`operator_delete`] at `0x083d03b4`; it has zero predicated direct `bl`
//! calls and one unconditional virtual `blx` through vtable slot `+0x40`.
//!
//! ## Algorithm
//!
//! If byte `+0x10` is zero, do nothing. Otherwise scan signed indices
//! `[0, count)` through vtable slot `+0x40`. The first returned cell with a
//! nonzero first word is a `StringObject`: destroy it, then tag-2-delete that
//! same object. Later cells are untouched.
//!
//! ## Deliberate deviations
//!
//! Host fixtures widen vtable and cell words to native width; target accesses
//! retain the verified 32-bit offsets. The runtime slot target has no recovered
//! concrete identity, so its observed slot operation is modeled as a callback.

use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::heap::veneers::operator_delete;

const CELL_AT_SLOT: usize = 0x40 / 4;
#[cfg(target_os = "none")]
type CellAt = unsafe extern "C" fn(*mut u8, i32) -> *mut u32;
#[cfg(not(target_os = "none"))]
type CellAt = unsafe extern "C" fn(*mut u8, i32) -> *mut usize;

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct CollectionReleaseFirstOccupiedString083d0370Vtable {
    pub unresolved_00_3c: [usize; 16],
    pub cell_at: CellAt,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostCollectionReleaseFirstOccupiedString083d0370 {
    pub vtable: *const CollectionReleaseFirstOccupiedString083d0370Vtable,
    pub count: i32,
    pub unresolved_0c_13: [u8; 8],
    pub enabled: u8,
}

/// Destroys and releases only the first occupied string object supplied by `array`.
///
/// # Safety
///
/// `array` must designate the target-layout collection. Its vtable slot `+0x40`
/// must accept `(array, index)` and return a readable cell; a nonzero cell word
/// must identify a [`StringObject`] accepted by [`operator_delete`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_release_first_occupied_string_083d0370(array: *mut u8) {
    #[cfg(target_os = "none")]
    {
        if unsafe { array.add(0x10).read_volatile() } == 0 { return; }
        let count = unsafe { array.add(0x04).cast::<i32>().read_volatile() };
        let vtable = unsafe { array.cast::<u32>().read_volatile() as usize as *const u32 };
        let cell_at: CellAt = unsafe { core::mem::transmute(vtable.add(CELL_AT_SLOT).read_volatile() as usize) };
        let mut index = 0;
        while index < count {
            let string = unsafe { cell_at(array, index).read_volatile() as usize as *mut StringObject };
            if !string.is_null() {
                unsafe { operator_delete(string_object_destroy(string).cast()) };
                return;
            }
            index += 1;
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let host = array.cast::<HostCollectionReleaseFirstOccupiedString083d0370>();
        if unsafe { (*host).enabled } == 0 { return; }
        let mut index = 0;
        while index < unsafe { (*host).count } {
            let string = unsafe { ((*(*host).vtable).cell_at)(array, index).read() as *mut StringObject };
            if !string.is_null() {
                unsafe { operator_delete(string_object_destroy(string).cast()) };
                return;
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CELLS: [usize; 3] = [0; 3];
    static mut LOOKUPS: [i32; 3] = [0; 3];
    static mut LOOKUP_COUNT: usize = 0;

    unsafe extern "C" fn cell_at(_: *mut u8, index: i32) -> *mut usize {
        unsafe { LOOKUPS[LOOKUP_COUNT] = index; LOOKUP_COUNT += 1; CELLS.as_mut_ptr().add(index as usize) }
    }
    struct Bench { _lock: MutexGuard<'static, ()>, _heap: MutexGuard<'static, ()> }
    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe { CELLS = [0; 3]; LOOKUPS = [0; 3]; LOOKUP_COUNT = 0; }
        Bench { _lock: lock, _heap: crate::heap::veneers::tests::mock_heap() }
    }

    #[test]
    fn skips_empty_cells_then_destroys_and_deletes_first_string() {
        let _bench = bench();
        let mut first = StringObject { vtable: core::ptr::null(), payload: core::ptr::null_mut() };
        let later = 0x1234usize as *mut StringObject;
        let vtable = CollectionReleaseFirstOccupiedString083d0370Vtable { unresolved_00_3c: [0; 16], cell_at };
        let mut array = HostCollectionReleaseFirstOccupiedString083d0370 { vtable: &vtable, count: 3, unresolved_0c_13: [0; 8], enabled: 1 };
        unsafe { CELLS = [0, (&mut first as *mut StringObject) as usize, later as usize]; }
        unsafe { collection_release_first_occupied_string_083d0370((&mut array as *mut HostCollectionReleaseFirstOccupiedString083d0370).cast()) };
        assert_eq!(unsafe { &LOOKUPS[..LOOKUP_COUNT] }, &[0, 1]);
        assert_eq!(crate::heap::veneers::tests::free_log(), (1, (&mut first as *mut StringObject).cast(), 2));
    }

    #[test]
    fn disabled_or_nonpositive_count_performs_no_lookup_or_delete() {
        let _bench = bench();
        let vtable = CollectionReleaseFirstOccupiedString083d0370Vtable { unresolved_00_3c: [0; 16], cell_at };
        let mut array = HostCollectionReleaseFirstOccupiedString083d0370 { vtable: &vtable, count: 2, unresolved_0c_13: [0; 8], enabled: 0 };
        unsafe { collection_release_first_occupied_string_083d0370((&mut array as *mut HostCollectionReleaseFirstOccupiedString083d0370).cast()) };
        array.enabled = 1; array.count = -1;
        unsafe { collection_release_first_occupied_string_083d0370((&mut array as *mut HostCollectionReleaseFirstOccupiedString083d0370).cast()) };
        assert_eq!(unsafe { LOOKUP_COUNT }, 0);
        assert_eq!(crate::heap::veneers::tests::free_log().0, 0);
    }
}
