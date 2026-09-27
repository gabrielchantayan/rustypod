//! `observable_array_release_cells_destruct` — retailOS `FUN_083d1ad0` @
//! **0x083d1ad0** (60 bytes: 56 bytes of code plus the vtable literal).
//!
//! Raw `osos.dec` decodes fourteen A32 instructions from `0x083d1ad0` through
//! the tail branch at `0x083d1b04`; `0x083d1b08` is vtable literal
//! `0x089a53b8`, and the next real function begins at `0x083d1b0c`. Full-image
//! ARM branch decoding finds two inbound plain `bl` sites and no predicated
//! inbound `bl` sites. The body has one plain direct `bl` to
//! `observable_array_release_cells_083d1a40` and one predicated indirect
//! `blxne` through the attached object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Plant the derived vtable, conditionally release the attached object at
//! `+0x14` through vtable slot `+0x1c`, release this derived array's cells
//! through `observable_array_release_cells_083d1a40`, then tail-chain into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds replace the target-width cell-release
//! and virtual-call dispatches with seams. ARM invokes the ported direct
//! target; Rust models the tail branch as a direct base-destructor call.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};
#[cfg(target_os = "none")]
use crate::cxx::observable_array_release_cells_083d1a40::{
    observable_array_release_cells_083d1a40, ObservableArrayReleaseCells083d1a40,
};


const VTABLE_WORD: u32 = 0x089a_53b8;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type ReleaseCells = unsafe extern "C" fn(*mut u8);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn release_cells(array: *mut u8) {
    unsafe { observable_array_release_cells_083d1a40(array.cast::<ObservableArrayReleaseCells083d1a40>()) };
}

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    let release: ReleaseAttachedObject = unsafe {
        core::mem::transmute(vtable.add(0x1c / 4).read_volatile() as usize)
    };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_cells(_array: *mut u8) {
    panic!("install observable-array release-cells destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array release-cells destructor host seams before calling this port")
}

/// Host replacement for the target-width vtable dispatch through ported
/// `observable_array_release_cells_083d1a40` and the attached object's vtable
/// slot `+0x1c`.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS: (ReleaseCells, ReleaseAttachedObject) =
    (missing_release_cells, missing_release_attached_object);

/// `observable_array_release_cells_destruct` — `FUN_083d1ad0` @ 0x083d1ad0.
///
/// # Safety
///
/// `array` must point to a writable derived observable array with a readable
/// attached-object word at `+0x14`. A nonzero attached object must have a
/// callable vtable slot at `+0x1c`; the cell release must accept the same array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_release_cells_destruct(array: *mut u8) -> *mut u8 {
    unsafe {
        array.cast::<u32>().write_volatile(VTABLE_WORD);
        let attached = array.add(ATTACHED_OBJECT_WORD * 4).cast::<u32>().read_volatile() as usize as *mut u8;

        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            release_cells(array);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release_cells, release_attached) = core::ptr::read_volatile(
                core::ptr::addr_of!(OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS),
            );
            if !attached.is_null() {
                release_attached(attached);
            }
            release_cells(array);
        }

        observable_array_destruct(array.cast::<ObservableArray>());
        array
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 2] = [0; 2];
    static mut RELEASE_RECEIVER: *mut u8 = core::ptr::null_mut();
    static mut ATTACHED_RECEIVER: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_release(array: *mut u8) {
        unsafe { CALLS[0] += 1; RELEASE_RECEIVER = array; }
    }

    unsafe extern "C" fn record_attached_release(object: *mut u8) {
        unsafe { CALLS[1] += 1; ATTACHED_RECEIVER = object; }
    }

    #[test]
    fn releases_attached_object_before_cells_and_base_teardown() {
        let _lock = LOCK.lock();
        let mut words = [0u32; 6];
        words[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        unsafe {
            let old = OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS;
            OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS = (record_release, record_attached_release);
            CALLS = [0; 2]; RELEASE_RECEIVER = core::ptr::null_mut(); ATTACHED_RECEIVER = core::ptr::null_mut();
            let result = observable_array_release_cells_destruct(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS = old;
            assert_eq!(result, words.as_mut_ptr().cast());
            assert_eq!(CALLS, [1, 1]);
            assert_eq!(ATTACHED_RECEIVER, 0x1234_5000usize as *mut u8);
            assert_eq!(RELEASE_RECEIVER, words.as_mut_ptr().cast());
            assert_eq!(words[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        }
    }

    #[test]
    fn null_attached_object_skips_virtual_release_but_releases_cells() {
        let _lock = LOCK.lock();
        let mut words = [0u32; 6];
        unsafe {
            let old = OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS;
            OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS = (record_release, record_attached_release);
            CALLS = [0; 2];
            observable_array_release_cells_destruct(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_RELEASE_CELLS_DESTRUCT_OPS = old;
            assert_eq!(CALLS, [1, 0]);
        }
    }
}
