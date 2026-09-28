//! `string_object_opaque_base_validate` — retailOS `FUN_0839c8b0` @
//! `0x0839c8b0`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` words establish the exact 88-byte A32 body: twenty-two
//! instructions from `push {r4,r5,r6,lr}` at `0x0839c8b0` through `pop
//! {r4,r5,r6,pc}` at `0x0839c904`; `0x0839c908` begins the next independent
//! function. The body has two unconditional plain direct `bl` calls, to
//! [`string_object_opaque_base_destroy`] (`0x08291fb4`) and
//! [`crate::heap::veneers::operator_delete`] (`0x082aad24`), no predicated
//! direct `bl`, and one unconditional virtual `blx` through vtable `+0x40`.
//! Raw whole-image branch decoding finds two inbound unconditional plain `bl`
//! sites, at `0x0839c954` and `0x0839c978`, with no predicated inbound `bl`.
//!
//! ## Algorithm
//!
//! If byte `this+0x28` is enabled, scan signed indices `[0, this+4)`. The
//! vtable `+0x40` method supplies an element pointer; on the first nonzero
//! first word, destroy that word as a string-object/opaque-base owner and
//! tag-2 delete its returned pointer. A disabled object, an empty count, or a
//! negative count does nothing.
//!
//! ## Deliberate deviations
//!
//! The class and virtual method identities are not recovered, so this port
//! names only their observed roles. Host builds use seams because target
#[cfg(target_os = "none")]
use crate::cxx::string_object::StringObject;
#[cfg(target_os = "none")]
use crate::cxx::string_object_opaque_base_destroy::string_object_opaque_base_destroy;
#[cfg(target_os = "none")]
use crate::heap::veneers::operator_delete;


const ENABLED_OFFSET: usize = 0x28;
const COUNT_WORD: usize = 1;

#[cfg(not(target_os = "none"))]
pub type StringObjectOpaqueBaseValidateOps = (
    unsafe extern "C" fn(*mut u32, i32) -> *const u32,
    unsafe extern "C" fn(*mut u32) -> *mut u32,
    unsafe extern "C" fn(*mut u8),
);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_at(_this: *mut u32, _index: i32) -> *const u32 {
    panic!("install string-object opaque-base validate host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_owner: *mut u32) -> *mut u32 {
    panic!("install string-object opaque-base validate host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_allocation: *mut u8) {
    panic!("install string-object opaque-base validate host seams before calling this port")
}

/// Host substitutions for the target-width virtual call and direct destruction
/// and delete calls.
#[cfg(not(target_os = "none"))]
pub static mut STRING_OBJECT_OPAQUE_BASE_VALIDATE_OPS: StringObjectOpaqueBaseValidateOps = (
    missing_element_at,
    missing_destroy,
    missing_delete,
);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn element_at(this: *mut u32, index: i32) -> *const u32 {
    let vtable = unsafe { this.read() as usize as *const usize };
    let method: unsafe extern "C" fn(*mut u32, i32) -> *const u32 =
        unsafe { core::mem::transmute(vtable.add(0x40 / 4).read()) };
    unsafe { method(this, index) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn element_at(this: *mut u32, index: i32) -> *const u32 {
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_OPAQUE_BASE_VALIDATE_OPS)) };
    unsafe { ops.0(this, index) }
}

/// Validates that an enabled indexed object has no live string-object owners,
/// destroying and deleting the first one found.
///
/// Original: `FUN_0839c8b0` @ `0x0839c8b0` (88 bytes; two unconditional
/// direct `bl` callers, no predicated callers).
///
/// # Safety
///
/// `this` must point to the recovered target layout: count at `+4`, enabled
/// byte at `+0x28`, and a vtable whose `+0x40` method returns readable words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn string_object_opaque_base_validate(this: *mut u32) {
    if unsafe { this.cast::<u8>().add(ENABLED_OFFSET).read() } == 0 {
        return;
    }

    let count = unsafe { this.add(COUNT_WORD).read() as i32 };
    let mut index = 0i32;
    while index < count {
        let owner = unsafe { element_at(this, index).read() } as usize as *mut u32;
        if !owner.is_null() {
            #[cfg(target_os = "none")]
            unsafe {
                operator_delete(string_object_opaque_base_destroy(owner.cast::<StringObject>()).cast());
            }
            #[cfg(not(target_os = "none"))]
            unsafe {
                let ops = core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_OPAQUE_BASE_VALIDATE_OPS));
                ops.2(ops.1(owner).cast());
            }
            return;
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::vec::Vec;

    static LOCKED: AtomicBool = AtomicBool::new(false);
    static mut RESULTS: [u32; 4] = [0; 4];
    static mut ELEMENTS: Vec<u32> = Vec::new();
    static mut DESTROYED: Vec<usize> = Vec::new();
    static mut DELETED: Vec<usize> = Vec::new();

    struct Guard;
    impl Guard {
        fn acquire() -> Self {
            while LOCKED.swap(true, Ordering::Acquire) {}
            unsafe {
                ELEMENTS.clear(); DESTROYED.clear(); DELETED.clear(); RESULTS = [0; 4];
                STRING_OBJECT_OPAQUE_BASE_VALIDATE_OPS = (element_at_mock, destroy_mock, delete_mock);
            }
            Self
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) { LOCKED.store(false, Ordering::Release); }
    }

    unsafe extern "C" fn element_at_mock(_this: *mut u32, index: i32) -> *const u32 {
        unsafe { ELEMENTS.push(index as u32); core::ptr::addr_of!(RESULTS[index as usize]) }
    }
    unsafe extern "C" fn destroy_mock(owner: *mut u32) -> *mut u32 {
        unsafe { DESTROYED.push(owner as usize); owner.add(1) }
    }
    unsafe extern "C" fn delete_mock(allocation: *mut u8) { unsafe { DELETED.push(allocation as usize); } }

    #[test]
    fn disabled_skips_virtual_dispatch() {
        let _guard = Guard::acquire();
        let mut object = [0u32; 11];
        unsafe { string_object_opaque_base_validate(object.as_mut_ptr()); }
        unsafe { assert!(ELEMENTS.is_empty()); assert!(DESTROYED.is_empty()); assert!(DELETED.is_empty()); }
    }

    #[test]
    fn scans_until_first_live_owner_then_destroys_and_deletes_it() {
        let _guard = Guard::acquire();
        let mut object = [0u32; 11];
        object[1] = 4;
        unsafe { object.as_mut_ptr().cast::<u8>().add(ENABLED_OFFSET).write(1); RESULTS[2] = 0x1234_0000; }
        unsafe { string_object_opaque_base_validate(object.as_mut_ptr()); }
        unsafe {
            assert_eq!(ELEMENTS.as_slice(), &[0, 1, 2]);
            assert_eq!(DESTROYED.as_slice(), &[0x1234_0000]);
            assert_eq!(DELETED.as_slice(), &[0x1234_0004]);
        }
    }

    #[test]
    fn nonpositive_count_skips_virtual_dispatch() {
        let _guard = Guard::acquire();
        let mut object = [0u32; 11];
        object[1] = (-1i32) as u32;
        unsafe { object.as_mut_ptr().cast::<u8>().add(ENABLED_OFFSET).write(1); string_object_opaque_base_validate(object.as_mut_ptr()); }
        unsafe { assert!(ELEMENTS.is_empty()); }
    }
}
