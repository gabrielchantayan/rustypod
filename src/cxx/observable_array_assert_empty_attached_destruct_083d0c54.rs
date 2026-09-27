//! `observable_array_assert_empty_attached_destruct_083d0c54` — retailOS
//! `FUN_083d0c54` @ **0x083d0c54** (56 bytes: 52 bytes of code plus one
//! vtable literal).
//!
//! Raw `osos.dec` decodes thirteen A32 words from `0x083d0c54` through the
//! tail branch at `0x083d0c88`; `0x083d0c8c` is the vtable literal
//! `0x089a4710`, and `push {r4,r5,r6,lr}` at `0x083d0c90` starts the next real
//! function. Full-image aligned A32 branch decoding finds two inbound plain
//! `bl` sites and no predicated inbound `bl` sites. The body makes one plain
//! direct `bl` to unported `FUN_083d0b2c`, one predicated indirect `blxne`
//! through the optional attached object's vtable slot `+0x1c`, and tail-branches
//! to `observable_array_destruct` @ `0x08271d2c`.
//!
//! # Algorithm
//!
//! Plant the derived vtable, conditionally release the attached object at
//! `+0x14`, assert that the indexed cells are empty, then tail-chain into the
//! observable-array destructor.
//!
//! Deliberate deviations: host tests replace the target-width virtual call and
//! unported assertion with seams. ARM calls the recovered fixed address; Rust
//! models the predicated `blx` and tail branch as ordinary control flow.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};

const VTABLE_WORD: u32 = 0x089a_4710;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
const ASSERT_EMPTY_ADDRESS: usize = 0x083d_0b2c;
type AttachedObjectRelease = unsafe extern "C" fn(u32);
type AssertEmpty = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn attached_object_release(attached_object: u32) {
    let vtable = unsafe { (attached_object as usize as *const u32).read_volatile() };
    let release: unsafe extern "C" fn() = unsafe {
        core::mem::transmute((vtable as usize as *const u32).add(0x1c / 4).read_volatile())
    };
    unsafe { release() };
}

#[cfg(target_os = "none")]
unsafe fn assert_empty(array: *mut u8) {
    let assert_empty: AssertEmpty = unsafe { core::mem::transmute(ASSERT_EMPTY_ADDRESS) };
    unsafe { assert_empty(array) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attached_object_release(_: u32) {
    panic!("host tests must replace OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS");
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assert_empty(_: *mut u8) {
    panic!("host tests must replace OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS");
}

/// Host replacements for attached-object release and the unported assertion.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS: (AttachedObjectRelease, AssertEmpty) =
    (missing_attached_object_release, missing_assert_empty);

/// `observable_array_assert_empty_attached_destruct_083d0c54` — `FUN_083d0c54` @
/// 0x083d0c54.
///
/// # Safety
///
/// `array` must point to a writable derived observable array with a readable
/// attached-object word at `+0x14`. A nonzero attached object must have a
/// callable vtable slot at `+0x1c`; the assertion must accept the same array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_assert_empty_attached_destruct_083d0c54(
    array: *mut u8,
) -> *mut u8 {
    unsafe {
        array.cast::<u32>().write_volatile(VTABLE_WORD);
        let attached_object = array.add(ATTACHED_OBJECT_WORD * 4).cast::<u32>().read_volatile();

        #[cfg(target_os = "none")]
        {
            if attached_object != 0 {
                attached_object_release(attached_object);
            }
            assert_empty(array);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, assertion) = core::ptr::read_volatile(core::ptr::addr_of!(
                OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS
            ));
            if attached_object != 0 {
                release(attached_object);
            }
            assertion(array);
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
    static mut ASSERTION_RECEIVER: *mut u8 = core::ptr::null_mut();
    static mut RELEASED_OBJECT: u32 = 0;

    unsafe extern "C" fn record_release(attached_object: u32) {
        unsafe { CALLS[0] += 1; RELEASED_OBJECT = attached_object; }
    }

    unsafe extern "C" fn record_assertion(array: *mut u8) {
        unsafe { CALLS[1] += 1; ASSERTION_RECEIVER = array; }
    }

    #[test]
    fn releases_attached_object_before_assertion_and_base_teardown() {
        let _lock = LOCK.lock();
        let mut words = [0u32; 6];
        words[ATTACHED_OBJECT_WORD] = 0x1234_5000;
        unsafe {
            let old = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS = (record_release, record_assertion);
            CALLS = [0; 2]; ASSERTION_RECEIVER = core::ptr::null_mut(); RELEASED_OBJECT = 0;
            let result = observable_array_assert_empty_attached_destruct_083d0c54(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS = old;
            assert_eq!(result, words.as_mut_ptr().cast());
            assert_eq!(CALLS, [1, 1]);
            assert_eq!(RELEASED_OBJECT, 0x1234_5000);
            assert_eq!(ASSERTION_RECEIVER, words.as_mut_ptr().cast());
            assert_eq!(words[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        }
    }

    #[test]
    fn null_attached_object_skips_release_but_runs_assertion() {
        let _lock = LOCK.lock();
        let mut words = [0; 6];
        unsafe {
            let old = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS = (record_release, record_assertion);
            CALLS = [0; 2];
            observable_array_assert_empty_attached_destruct_083d0c54(words.as_mut_ptr().cast());
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0C54_OPS = old;
            assert_eq!(CALLS, [0, 1]);
        }
    }
}
