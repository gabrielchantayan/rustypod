//! `owned_virtual_handle_release` — retailOS `FUN_0805e68c` @ `0x0805e68c`.
//!
//! ## Verified extent and calls
//!
//! Raw `osos.dec` words establish the 68-byte body from `0x0805e68c` through
//! `0x0805e6cc`; the next independently entered function begins at
//! `0x0805e6d0`. The body has no direct `bl`: it calls the held object's vtable
//! slot `+0x0c` with an unconditional `blx`, then, after reloading the handle,
//! calls slot `+0x04` with a predicated `blxne`. Whole-image A32 decoding finds
//! three inbound plain `bl` calls (`0x0813832c`, `0x0813835c`, `0x081383a0`) and
//! no predicated direct callers.
//!
//! ## Algorithm
//!
//! For a non-NULL handle, destroy its object through vtable slot `+0x0c`.
//! Reload the handle because destruction may change it; if still non-NULL,
//! release it through slot `+0x04`. Clear the handle and return zero.
//!
//! Deliberate deviation: the two virtual target identities are not established.
//! Target builds dispatch through the verified target-width vtable words; host
//! builds use native vtables because firmware u32 words cannot hold x86-64
//! callbacks.

use core::ffi::c_void;

/// ABI of the object's vtable slots `+0x0c` and `+0x04`.
pub type OwnedVirtualHandleMethod = unsafe extern "C" fn(*mut c_void);

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct OwnedVirtualHandleVtable {
    pub unresolved_00: usize,
    pub release: OwnedVirtualHandleMethod,
    pub unresolved_08: usize,
    pub destroy: OwnedVirtualHandleMethod,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn vtable_method(object: *mut c_void, slot: usize) -> OwnedVirtualHandleMethod {
    let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u32 };
    unsafe { core::mem::transmute(vtable.add(slot / 4).read_volatile() as usize) }
}

/// Destroys and then releases the object owned by `handle`, clearing `*handle`.
///
/// Original: `FUN_0805e68c` @ `0x0805e68c` (68 bytes; 3 inbound plain `bl`
/// calls and no predicated direct callers).
///
/// # Safety
///
/// `handle` may be NULL. Otherwise it must be writable and, when non-NULL,
/// point to an object with callable vtable slots `+0x0c` and `+0x04`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_virtual_handle_release(handle: *mut *mut c_void) -> i32 {
    #[cfg(target_os = "none")]
    {
        if handle.is_null() {
            return 0;
        }
        let object = unsafe { handle.cast::<u32>().read_volatile() as usize as *mut c_void };
        if object.is_null() {
            return 0;
        }
        unsafe { vtable_method(object, 0x0c)(object) };
        let object = unsafe { handle.cast::<u32>().read_volatile() as usize as *mut c_void };
        if !object.is_null() {
            unsafe { vtable_method(object, 0x04)(object) };
        }
        unsafe { handle.cast::<u32>().write_volatile(0) };
    }
    #[cfg(not(target_os = "none"))]
    {
        if handle.is_null() {
            return 0;
        }
        let object = unsafe { handle.read() };
        if object.is_null() {
            return 0;
        }
        let vtable = unsafe { *(object.cast::<*const OwnedVirtualHandleVtable>()) };
        unsafe { ((*vtable).destroy)(object) };
        let object = unsafe { handle.read() };
        if !object.is_null() {
            let vtable = unsafe { *(object.cast::<*const OwnedVirtualHandleVtable>()) };
            unsafe { ((*vtable).release)(object) };
        }
        unsafe { handle.write(core::ptr::null_mut()) };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 2] = [0; 2];
    static mut EVENT_COUNT: usize = 0;
    static mut HANDLE_TO_NULL: *mut *mut c_void = core::ptr::null_mut();

    unsafe extern "C" fn destroy(object: *mut c_void) {
        unsafe {
            EVENTS[EVENT_COUNT] = 1;
            EVENT_COUNT += 1;
            if !HANDLE_TO_NULL.is_null() {
                HANDLE_TO_NULL.write(core::ptr::null_mut());
            }
        }
        let _ = object;
    }

    unsafe extern "C" fn release(object: *mut c_void) {
        unsafe {
            EVENTS[EVENT_COUNT] = 2;
            EVENT_COUNT += 1;
        }
        let _ = object;
    }

    #[repr(C)]
    struct Object {
        vtable: *const OwnedVirtualHandleVtable,
    }

    fn reset() {
        unsafe {
            EVENTS = [0; 2];
            EVENT_COUNT = 0;
            HANDLE_TO_NULL = core::ptr::null_mut();
        }
    }

    #[test]
    fn ignores_null_handle_and_empty_handle() {
        let _lock = LOCK.lock();
        reset();
        let mut empty = core::ptr::null_mut();
        assert_eq!(unsafe { owned_virtual_handle_release(core::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { owned_virtual_handle_release(&mut empty) }, 0);
        assert!(empty.is_null());
        assert_eq!(unsafe { EVENT_COUNT }, 0);
    }

    #[test]
    fn destroys_releases_and_clears_live_handle() {
        let _lock = LOCK.lock();
        reset();
        let vtable = OwnedVirtualHandleVtable { unresolved_00: 0, release, unresolved_08: 0, destroy };
        let mut object = Object { vtable: &vtable };
        let mut handle = (&mut object as *mut Object).cast::<c_void>();
        assert_eq!(unsafe { owned_virtual_handle_release(&mut handle) }, 0);
        assert!(handle.is_null());
        assert_eq!(unsafe { &EVENTS[..EVENT_COUNT] }, &[1, 2]);
    }

    #[test]
    fn reload_after_destroy_skips_release_when_destroy_nulls_handle() {
        let _lock = LOCK.lock();
        reset();
        let vtable = OwnedVirtualHandleVtable { unresolved_00: 0, release, unresolved_08: 0, destroy };
        let mut object = Object { vtable: &vtable };
        let mut handle = (&mut object as *mut Object).cast::<c_void>();
        unsafe { HANDLE_TO_NULL = &mut handle };
        assert_eq!(unsafe { owned_virtual_handle_release(&mut handle) }, 0);
        assert!(handle.is_null());
        assert_eq!(unsafe { &EVENTS[..EVENT_COUNT] }, &[1]);
    }
}
