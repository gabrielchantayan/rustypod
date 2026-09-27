//! `observable_array_checked_destruct` — retailOS `FUN_083d1bb4` @
//! **0x083d1bb4** (56 bytes: 52 bytes of code plus the vtable literal).
//!
//! Raw `osos.dec` decodes thirteen A32 instructions from `0x083d1bb4` through
//! the tail branch at `0x083d1be8`; `0x083d1bec` is vtable literal
//! `0x089a5490`, and the next real function begins at `0x083d1bf0`. Full-image
//! ARM branch decoding finds two inbound plain `bl` sites and no predicated
//! inbound `bl` sites. The body has one plain direct `bl` to unported
//! `FUN_083d1b0c` and one predicated indirect `blxne` through the attached
//! object's vtable slot `+0x1c`.
//!
//! # Algorithm
//!
//! Plant the derived vtable, conditionally release the attached object at
//! `+0x14` through vtable slot `+0x1c`, check the derived array through
//! `FUN_083d1b0c`, then tail-chain into `observable_array_destruct`.
//!
//! Deliberate deviations: host builds replace the unported check and
//! target-width virtual call with seams. ARM invokes their recovered addresses;
//! Rust models the tail branch as a direct base-destructor call.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};

const VTABLE_WORD: u32 = 0x089a_5490;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type CheckArray = unsafe extern "C" fn(*mut u8);
type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn check_array(array: *mut u8) {
    let check: CheckArray = unsafe { core::mem::transmute(0x083d_1b0cusize) };
    unsafe { check(array) };
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
unsafe extern "C" fn missing_check_array(_array: *mut u8) {
    panic!("install observable-array checked destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_object: *mut u8) {
    panic!("install observable-array checked destructor host seams before calling this port")
}

/// Host replacements for unported `FUN_083d1b0c` and the attached object's
/// vtable slot `+0x1c`.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS: (CheckArray, ReleaseAttachedObject) =
    (missing_check_array, missing_release_attached_object);

/// `observable_array_checked_destruct` — `FUN_083d1bb4` @ 0x083d1bb4.
///
/// # Safety
///
/// `array` must point to a writable derived observable array with a readable
/// attached-object word at `+0x14`. A nonzero attached object must have a
/// callable vtable slot at `+0x1c`; the check must accept the same array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_checked_destruct(array: *mut u8) -> *mut u8 {
    unsafe {
        array.cast::<u32>().write_volatile(VTABLE_WORD);
        let attached = array.add(ATTACHED_OBJECT_WORD * 4).cast::<u32>().read_volatile() as usize as *mut u8;

        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            check_array(array);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (check, release) = core::ptr::read_volatile(core::ptr::addr_of!(OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS));
            if !attached.is_null() {
                release(attached);
            }
            check(array);
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
    static mut CHECK_RECEIVER: *mut u8 = core::ptr::null_mut();
    static mut RELEASED_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_check(array: *mut u8) {
        unsafe { CALLS[0] += 1; CHECK_RECEIVER = array; }
    }

    unsafe extern "C" fn record_release(object: *mut u8) {
        unsafe { CALLS[1] += 1; RELEASED_OBJECT = object; }
    }

    #[test]
    fn releases_attached_object_before_checking_and_base_teardown() {
        let _lock = LOCK.lock();
        let mut words = [0u32; 6];
        words[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        unsafe {
            let old = OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS;
            OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS = (record_check, record_release);
            CALLS = [0; 2]; CHECK_RECEIVER = core::ptr::null_mut(); RELEASED_OBJECT = core::ptr::null_mut();
            let result = observable_array_checked_destruct(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS = old;
            assert_eq!(result, words.as_mut_ptr().cast());
            assert_eq!(CALLS, [1, 1]);
            assert_eq!(RELEASED_OBJECT, 0x1234_5000usize as *mut u8);
            assert_eq!(CHECK_RECEIVER, words.as_mut_ptr().cast());
            assert_eq!(words[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        }
    }

    #[test]
    fn null_attached_object_skips_virtual_release_but_checks_array() {
        let _lock = LOCK.lock();
        let mut words = [0u32; 6];
        unsafe {
            let old = OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS;
            OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS = (record_check, record_release);
            CALLS = [0; 2];
            observable_array_checked_destruct(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_CHECKED_DESTRUCT_OPS = old;
            assert_eq!(CALLS, [1, 0]);
        }
    }
}
