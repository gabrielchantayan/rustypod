//! `shared_handle_owner_destroy` — retailOS `FUN_082a94d0` @ `0x082a94d0`.
//!
//! ## Original
//!
//! The true extent is 72 bytes (`0x082a94d0..0x082a9514`): the next separately
//! linked destructor starts at `0x082a951c`; `0x082a9518` is this function's
//! vtable literal. Decoding every ARM branch word in `osos.dec` finds five
//! incoming plain `bl` call sites and no predicated `bl` forms. The body stores
//! vtable `0x089a8aac`, dispatches the object's callback list with zero event
//! arguments, deletes the three tag-3-owned words at +0x1c, +0x20, and +0x2c,
//! then releases the embedded shared handle at +0x18 and returns `this`.
//!
//! Deliberate deviations: callback dispatch (`FUN_082a8cc0`) and shared-handle
//! release (`FUN_082a8ba0`) are not ported, so target builds call their resident
//! addresses and host builds expose exact ABI seams. The tag-3 deletes call the
//! existing heap port rather than tail-branching to retailOS.

use crate::heap::veneers::operator_delete_tag3;

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_CALLBACK_DISPATCH: usize = 0x082a_8cc0;
const RETAIL_SHARED_HANDLE_RELEASE: usize = 0x082a_8ba0;
const RETAIL_VTABLE: u32 = 0x089a_8aac;
const SHARED_HANDLE_WORD: usize = 6;
const OWNED_WORDS: [usize; 3] = [7, 8, 11];

pub type CallbackDispatch = unsafe extern "C" fn(*mut u32, u32, u32);
pub type SharedHandleRelease = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_callbacks(owner: *mut u32) {
    let dispatch: CallbackDispatch = core::mem::transmute(RETAIL_CALLBACK_DISPATCH);
    dispatch(owner, 0, 0);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback_dispatch(_owner: *mut u32, _event: u32, _context: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_DISPATCH: CallbackDispatch = missing_callback_dispatch;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_callbacks(owner: *mut u32) {
    core::ptr::read_volatile(addr_of!(CALLBACK_DISPATCH))(owner, 0, 0);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_shared_handle(handle: *mut u32) -> *mut u32 {
    let release: SharedHandleRelease = core::mem::transmute(RETAIL_SHARED_HANDLE_RELEASE);
    release(handle)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_handle_release(handle: *mut u32) -> *mut u32 { handle }

#[cfg(not(target_os = "none"))]
pub static mut SHARED_HANDLE_RELEASE: SharedHandleRelease = missing_shared_handle_release;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_shared_handle(handle: *mut u32) -> *mut u32 {
    core::ptr::read_volatile(addr_of!(SHARED_HANDLE_RELEASE))(handle)
}

/// Destroys the callback owner in place and returns its original address.
///
/// `owner` must be valid, aligned, and writable through word eleven. Its words
/// six through eight and eleven are target-width pointers owned by their
/// respective callees; no NULL guard exists for `owner` itself.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_handle_owner_destroy(owner: *mut u32) -> *mut u32 {
    owner.write(RETAIL_VTABLE);
    dispatch_callbacks(owner);
    for word in OWNED_WORDS {
        operator_delete_tag3(owner.add(word).read() as usize as *mut u8);
    }
    release_shared_handle(owner.add(SHARED_HANDLE_WORD));
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const OWNER_WORDS: usize = 12;
    static OWNER: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SHARED_HANDLE_OWNER_DESTROY, OWNER_WORDS * 4).map(|pointer| pointer as usize)
    });
    static mut CALLBACK_OWNER: usize = 0;
    static mut CALLBACK_EVENT: u32 = 1;
    static mut CALLBACK_CONTEXT: u32 = 1;
    static mut RELEASE_HANDLE: usize = 0;

    unsafe extern "C" fn recording_callback(owner: *mut u32, event: u32, context: u32) {
        CALLBACK_OWNER = owner as usize;
        CALLBACK_EVENT = event;
        CALLBACK_CONTEXT = context;
    }

    unsafe extern "C" fn recording_release(handle: *mut u32) -> *mut u32 {
        RELEASE_HANDLE = handle as usize;
        handle
    }

    #[test]
    fn resets_vtable_dispatches_zero_arguments_and_releases_embedded_handle() {
        let Some(owner) = *OWNER else {
            assert!(note_missing_u32_fixture("cxx/shared_handle_owner_destroy"));
            return;
        };

        unsafe {
            let owner = owner as *mut u32;
            core::ptr::write_bytes(owner, 0, OWNER_WORDS);
            CALLBACK_DISPATCH = recording_callback;
            SHARED_HANDLE_RELEASE = recording_release;
            CALLBACK_OWNER = 0;
            CALLBACK_EVENT = 1;
            CALLBACK_CONTEXT = 1;
            RELEASE_HANDLE = 0;

            assert_eq!(shared_handle_owner_destroy(owner), owner);
            assert_eq!(owner.read(), RETAIL_VTABLE);
            assert_eq!(CALLBACK_OWNER, owner as usize);
            assert_eq!((CALLBACK_EVENT, CALLBACK_CONTEXT), (0, 0));
            assert_eq!(RELEASE_HANDLE, owner.add(SHARED_HANDLE_WORD) as usize);
        }
    }
}
