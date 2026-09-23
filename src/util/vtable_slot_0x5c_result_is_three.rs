//! vtable_slot_0x5c_result_is_three — original: `FUN_081cabe8` @
//! 0x081cabe8 (48 bytes; 3 `bl` call sites).
//!
//! Verified ARM words are `e92d4010 eb0242a3 e3500000 0a000005
//! e5901000 e591105c e12fff31 e3500003 03a00001 08bd8010
//! e3a00000 e8bd8010`; the next function starts at 0x081cac18.
//! The function obtains the ported lazy singleton at 0x0825b680, returns
//! false for NULL, otherwise invokes its vtable slot +0x5c with the object
//! in r0 and returns whether that method returns 3. There is one plain direct
//! `bl` (the getter), one indirect `blx`, and no predicated call instruction;
//! the three inbound plain `bl` sites are at 0x081cab04, 0x081cab50, and 0x081cad5c.
//!
//! Deliberate deviation: the getter is
//! [`lazy_singleton_0x40`](crate::app::singletons::lazy_singleton_0x40), whose
//! documented zeroing constructor default cannot install a vtable. Host tests
//! therefore place a target-width fixture in its cache and model the virtual
//! call through [`VTABLE_STATUS_METHOD`].

#[cfg(target_os = "none")]
use core::mem;

const VTABLE_STATUS_SLOT: usize = 0x5c / 4;
type StatusMethod = unsafe extern "C" fn(*mut u32) -> u32;

/// Host replacement for the vtable method at byte offset 0x5c.
///
/// The target reads its four-byte function-address slot and invokes it
/// directly. A host function pointer cannot occupy that slot on x86-64, so
/// tests model the indirect call through this seam.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_STATUS_METHOD: StatusMethod = null_status_method;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn null_status_method(_object: *mut u32) -> u32 {
    0
}

#[inline(always)]
unsafe fn singleton_get() -> *mut u32 {
    crate::app::singletons::lazy_singleton_0x40().cast()
}

#[inline(always)]
unsafe fn vtable_status(object: *mut u32) -> u32 {
    let vtable = *object as usize as *mut u32;
    let method_address = *vtable.add(VTABLE_STATUS_SLOT);
    #[cfg(target_os = "none")]
    {
        let method: StatusMethod = mem::transmute(method_address);
        method(object)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = method_address;
        VTABLE_STATUS_METHOD(object)
    }
}

/// vtable_slot_0x5c_result_is_three — original: `FUN_081cabe8` @ 0x081cabe8
/// (48 bytes).
///
/// Obtains the lazy 0x40 singleton and returns one exactly when its vtable
/// method at byte offset 0x5c returns 3; returns zero when no object exists
/// or the method reports any other value.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_0x5c_result_is_three() -> u32 {
    let object = singleton_get();
    if object.is_null() {
        return 0;
    }

    (vtable_status(object) == 3) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::singletons::{SINGLETON_0X40, SINGLETON_LOCK};
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};

    static mut METHOD_RESULT: u32 = 0;
    static mut METHOD_OBJECT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn status_method(object: *mut u32) -> u32 {
        METHOD_OBJECT = object;
        METHOD_RESULT
    }

    #[test]
    fn recognizes_only_status_three_and_forwards_the_object() {
        let _lock = SINGLETON_LOCK.lock().unwrap();
        let Some(slab) = try_map_u32_slab(
            crate::testing::hints::VTABLE_SLOT_0X5C_RESULT_IS_THREE,
            0x1000,
        ) else {
            assert!(note_missing_u32_fixture("vtable_slot_0x5c_result_is_three"));
            return;
        };

        unsafe {
            let object = slab.cast::<u32>();
            let vtable = object.add(1);
            *object = vtable as usize as u32;
            *vtable.add(VTABLE_STATUS_SLOT) = status_method as usize as u32;
            SINGLETON_0X40 = object.cast();
            VTABLE_STATUS_METHOD = status_method;

            METHOD_RESULT = 2;
            assert_eq!(vtable_slot_0x5c_result_is_three(), 0);
            assert_eq!(METHOD_OBJECT, object);

            METHOD_RESULT = 3;
            assert_eq!(vtable_slot_0x5c_result_is_three(), 1);
            assert_eq!(METHOD_OBJECT, object);

            SINGLETON_0X40 = core::ptr::null_mut();
            VTABLE_STATUS_METHOD = null_status_method;
        }
    }
}
