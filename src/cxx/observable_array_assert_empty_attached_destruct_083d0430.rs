//! `observable_array_assert_empty_attached_destruct_083d0430` — retailOS
//! `FUN_083d0430` @ **0x083d0430** (56 bytes: 52 bytes of code plus one
//! vtable literal).
//!
//! Raw `osos.dec` decodes thirteen A32 words from `0x083d0430` through the
//! tail branch at `0x083d0464`; `0x083d0468` is the vtable literal
//! `0x089a4050`, and `push {r4,r5,r6,lr}` at `0x083d046c` starts the next real
//! function. Full-image aligned A32 branch decoding finds two inbound plain
//! `bl` sites and no predicated inbound `bl` sites. The body makes one plain
//! direct `bl` to unported `FUN_083d0370`, one predicated indirect `blxne`
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

const VTABLE_WORD: u32 = 0x089a_4050;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
const ASSERT_EMPTY_ADDRESS: usize = 0x083d_0370;
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
    panic!("host tests must replace OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS");
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_assert_empty(_: *mut u8) {
    panic!("host tests must replace OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS");
}

/// Host replacements for attached-object release and the unported assertion.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS: (AttachedObjectRelease, AssertEmpty) =
    (missing_attached_object_release, missing_assert_empty);

/// `observable_array_assert_empty_attached_destruct_083d0430` — `FUN_083d0430` @
/// 0x083d0430.
///
/// # Safety
///
/// `array` must point to a writable derived observable array with a readable
/// attached-object word at `+0x14`. A nonzero attached object must have a
/// callable vtable slot at `+0x1c`; the assertion must accept the same array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_assert_empty_attached_destruct_083d0430(
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
                OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS
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

    unsafe extern "C" fn record_release(object: u32) {
        unsafe { CALLS[0] = object; }
    }

    unsafe extern "C" fn record_assert_empty(array: *mut u8) {
        unsafe {
            assert_eq!(array.cast::<u32>().read_volatile(), VTABLE_WORD);
            CALLS[1] = 1;
        }
    }

    #[test]
    fn releases_attachment_before_asserting_and_destroying_base() {
        let _lock = LOCK.lock();
        unsafe {
            let old = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS =
                (record_release, record_assert_empty);
            let mut array = [0xfeed_face; 6];
            array[ATTACHED_OBJECT_WORD] = 0x1234_5000;
            array[3] = 0;
            array[2] = 0;
            CALLS = [0; 2];
            let result = observable_array_assert_empty_attached_destruct_083d0430(array.as_mut_ptr().cast());
            assert_eq!(result, array.as_mut_ptr().cast());
            assert_eq!(CALLS, [0x1234_5000, 1]);
            assert_eq!(array[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(array[1], 0);
            assert_eq!(array[2], 0);
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS = old;
        }
    }

    #[test]
    fn null_attachment_skips_release_but_asserts() {
        let _lock = LOCK.lock();
        unsafe {
            let old = OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS;
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS =
                (record_release, record_assert_empty);
            let mut array = [0; 6];
            CALLS = [0; 2];
            observable_array_assert_empty_attached_destruct_083d0430(array.as_mut_ptr().cast());
            assert_eq!(CALLS, [0, 1]);
            OBSERVABLE_ARRAY_ASSERT_EMPTY_ATTACHED_DESTRUCT_083D0430_OPS = old;
        }
    }
}
