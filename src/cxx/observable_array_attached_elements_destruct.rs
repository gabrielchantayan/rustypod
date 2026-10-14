//! `observable_array_attached_elements_destruct` — `FUN_083d1380` @ 0x083d1380.
//!
//! True size: 60 bytes: fourteen A32 instructions (56 bytes), followed by
//! vtable literal 0x089a4cf8 at 0x083d13b8. The next real function's push is
//! at 0x083d13bc. Raw aligned-word decoding finds one inbound plain BL at
//! 0x0826b628 and zero predicated BL callers. Body: one plain BL to the ported
//! element release at 0x083d12d8, zero predicated BLs, one BLXNE through the
//! attached object's vtable +0x1c, and a tail B to 0x08271d2c.
//!
//! Install the derived vtable, release the non-NULL attached object at +0x14
//! with that object in r0, release enabled array elements, then destroy the
//! observable-array base, returning the original receiver for operator delete.
//! Deliberate deviations: ordinary Rust control flow models BLXNE and tail B.
//! Host seams replace virtual dispatch and element release because the latter's
//! native-pointer host layout cannot represent this target-width derived object.

use crate::cxx::observable_array::{observable_array_destruct, ObservableArray};
#[cfg(target_os = "none")]
use crate::cxx::observable_array_release_elements::observable_array_release_elements;

const VTABLE: u32 = 0x089a_4cf8;
type AttachedRelease = unsafe extern "C" fn(u32);
type ElementsRelease = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_attached_release(_: u32) {
    panic!("install OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS on host");
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_elements_release(_: *mut u8) {
    panic!("install OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS on host");
}

/// Host-only replacements retaining the derived object's 32-bit field layout.
#[cfg(not(target_os = "none"))]
pub static mut OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS: (AttachedRelease, ElementsRelease) =
    (missing_attached_release, missing_elements_release);

/// # Safety
/// `array` must be a writable, word-aligned derived array of at least 24 bytes.
/// A nonzero +0x14 object must have a callable +0x1c virtual release slot.
/// Enabled elements and base storage/observers must satisfy their destructors.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn observable_array_attached_elements_destruct(array: *mut u8) -> *mut u8 {
    unsafe {
        let words = array.cast::<u32>();
        words.write_volatile(VTABLE);
        let attached = words.add(5).read_volatile();
        #[cfg(target_os = "none")]
        {
            if attached != 0 {
                let vtable = (attached as usize as *const u32).read_volatile();
                let release: AttachedRelease = core::mem::transmute(
                    (vtable as usize as *const u32).add(7).read_volatile() as usize
                );
                release(attached);
            }
            observable_array_release_elements(array);
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, elements) = core::ptr::read_volatile(core::ptr::addr_of!(
                OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS
            ));
            if attached != 0 {
                release(attached);
            }
            elements(array);
        }
        observable_array_destruct(array.cast::<ObservableArray>()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVER: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn release(attached: u32) {
        unsafe {
            assert_eq!(attached, 0x1234_5000);
            assert_eq!(RECEIVER.read(), VTABLE);
            assert_eq!(RECEIVER.add(1).read(), 3);
            // A virtual callback may change the array before element cleanup.
            RECEIVER.add(1).write(2);
        }
    }

    unsafe extern "C" fn elements(array: *mut u8) {
        unsafe {
            let words = array.cast::<u32>();
            assert_eq!(words, RECEIVER);
            assert_eq!(words.read(), VTABLE);
            assert_eq!(words.add(1).read(), if words.add(5).read() == 0 { 3 } else { 2 });
            words.add(4).write(0x7654_3210);
        }
    }

    #[test]
    fn preserves_callback_order_and_base_teardown_for_optional_attachment() {
        let _lock = LOCK.lock();
        for attached in [0, 0x1234_5000] {
            let mut guarded = [0xfeed_beef, 0, 3, 0, 0, 1, attached, 0xdead_beef];
            unsafe {
                RECEIVER = guarded.as_mut_ptr().add(1);
                let old = OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS;
                OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS = (release, elements);
                let result = observable_array_attached_elements_destruct(RECEIVER.cast());
                OBSERVABLE_ARRAY_ATTACHED_ELEMENTS_DESTRUCT_OPS = old;
                assert_eq!(result, RECEIVER.cast());
            }
            assert_eq!(guarded, [0xfeed_beef,
                crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE,
                0, 0, 0, 0x7654_3210, attached, 0xdead_beef]);
        }
    }
}
