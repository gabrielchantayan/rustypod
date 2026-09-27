//! `observable_array_attached_release_pre_destruct_083d0334` — retailOS
//! `FUN_083d0334` @ **0x083d0334** (56 bytes: 52 bytes of code plus one
//! vtable literal).
//!
//! Raw `osos.dec` decodes thirteen A32 words from `0x083d0334` through the
//! tail branch at `0x083d0368`; `0x083d036c` is the vtable literal
//! `0x089a3f78`, and `push {r4,r5,r6,lr}` at `0x083d0370` starts the next real
//! function. Full-image aligned A32 branch decoding finds two inbound plain
//! `bl` sites and no predicated inbound `bl` sites. The body makes one plain
//! direct `bl` to unported `FUN_083d028c`, one predicated indirect `blxne`
//! through the optional attached object's vtable slot `+0x1c`, and tail-branches
//! to `observable_array_destruct` @ `0x08271d2c`.
//!
//! # Algorithm
//!
//! Plant the derived vtable, conditionally release the attached object at
//! `+0x14`, run the pre-destructor check, then tail-chain into the
//! observable-array destructor.
//!
//! Deliberate deviations: host tests replace the target-width virtual call and
//! unported pre-destructor check with seams. ARM calls the recovered fixed
//! address; Rust models the predicated `blx` and tail branch as ordinary control
//! flow.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};

const VTABLE_WORD: u32 = 0x089a_3f78;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;
const PRE_DESTRUCT_ADDRESS: usize = 0x083d_028c;
type AttachedObjectRelease = unsafe extern "C" fn(u32);
type PreDestruct = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn attached_object_release(attached_object: u32) {
    let vtable = unsafe { (attached_object as usize as *const u32).read_volatile() };
    let release: AttachedObjectRelease = unsafe {
        core::mem::transmute((vtable as usize as *const u32).add(0x1c / 4).read_volatile())
    };
    unsafe { release(attached_object) };
}

#[cfg(target_os = "none")]
unsafe fn pre_destruct(array: *mut u8) {
    let pre_destruct: PreDestruct = unsafe { core::mem::transmute(PRE_DESTRUCT_ADDRESS) };
    unsafe { pre_destruct(array) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attached_object_release(_: u32) {
    panic!("host tests must replace OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS");
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pre_destruct(_: *mut u8) {
    panic!("host tests must replace OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS");
}

/// Host replacements for attached-object release and the unported pre-destructor check.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS: (AttachedObjectRelease, PreDestruct) =
    (missing_attached_object_release, missing_pre_destruct);

/// `observable_array_attached_release_pre_destruct_083d0334` — `FUN_083d0334` @
/// 0x083d0334.
///
/// # Safety
///
/// `array` must point to a writable derived observable array with a readable
/// attached-object word at `+0x14`. A nonzero attached object must have a
/// callable vtable slot at `+0x1c`; the pre-destructor check must accept the
/// same array.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_attached_release_pre_destruct_083d0334(
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
            pre_destruct(array);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, pre_destruct) = core::ptr::read_volatile(core::ptr::addr_of!(
                OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS
            ));
            if attached_object != 0 {
                release(attached_object);
            }
            pre_destruct(array);
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

    unsafe extern "C" fn record_pre_destruct(array: *mut u8) {
        unsafe {
            assert_eq!(array.cast::<u32>().read_volatile(), VTABLE_WORD);
            CALLS[1] = 1;
        }
    }

    #[test]
    fn releases_attachment_before_pre_destruct_and_base_destructor() {
        let _lock = LOCK.lock();
        unsafe {
            let old = OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS;
            OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS =
                (record_release, record_pre_destruct);
            let mut array = [0xfeed_face; 6];
            array[ATTACHED_OBJECT_WORD] = 0x1234_5000;
            array[3] = 0;
            array[2] = 0;
            CALLS = [0; 2];
            let result = observable_array_attached_release_pre_destruct_083d0334(array.as_mut_ptr().cast());
            assert_eq!(result, array.as_mut_ptr().cast());
            assert_eq!(CALLS, [0x1234_5000, 1]);
            assert_eq!(array[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(array[1], 0);
            assert_eq!(array[2], 0);
            OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS = old;
        }
    }

    #[test]
    fn null_attachment_skips_release_but_runs_pre_destruct() {
        let _lock = LOCK.lock();
        unsafe {
            let old = OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS;
            OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS =
                (record_release, record_pre_destruct);
            let mut array = [0; 6];
            CALLS = [0; 2];
            observable_array_attached_release_pre_destruct_083d0334(array.as_mut_ptr().cast());
            assert_eq!(CALLS, [0, 1]);
            OBSERVABLE_ARRAY_ATTACHED_RELEASE_PRE_DESTRUCT_083D0334_OPS = old;
        }
    }
}
