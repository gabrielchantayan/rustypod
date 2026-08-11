//! `string_owner_embedded_init` — original: `FUN_0827735c` @ 0x0827735c
//! (44 bytes: 40 code + the 4-byte vtable literal at 0x08277384).
//!
//! The StringObject constructor used by application StringOwner instances.
//! It plants the class vtable, clears the raw payload word, then forwards the
//! caller's C-string payload through `string_object_assign_payload` @
//! 0x08276474. ARM preserves `r1` from entry to the `bl`, although Ghidra's C
//! declaration omits it; the raw ABI is therefore `(StringObject *this, const
//! char *payload) -> StringObject *`. It returns its saved `this` after the
//! helper, rather than the helper's (void) result.
//!
//! `app_string_owner_initialize` @ 0x0811c138 owns the outer object: it
//! stores its vtable and owner word, invokes this constructor at its embedded
//! StringObject +8, then returns the result less eight. The application
//! operation seam below represents that entire already-ported constructor so
//! wrapper tests can record its ABI without substituting the payload helper.

use crate::app::string_owner::{APP_STRING_OWNER_STRING, APP_STRING_OWNER_VTABLE};
use crate::cxx::string_object::{
    string_object_assign_payload, StringObject, STRING_OBJECT_VTABLE,
};

/// string_owner_embedded_init — original: `FUN_0827735c` @ 0x0827735c
/// (44 bytes: 40 code + the 4-byte vtable literal at 0x08277384).
///
/// Initializes raw StringObject storage from `payload`: first plant the
/// 0x089a6044 class-vtable literal, then clear the payload word so the shared
/// assignment path cannot release uninitialized storage, then call
/// [`string_object_assign_payload`] @ 0x08276474. The saved `this` is
/// returned regardless of the assignment result.
///
/// Deviation: as elsewhere in `cxx/string_object.rs`, the ROM vtable literal
/// is represented by [`STRING_OBJECT_VTABLE`] so host tests have a valid
/// callable-object layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_owner_embedded_init(
    this: *mut StringObject,
    payload: *const u8,
) -> *mut StringObject {
    // Volatile preserves the firmware's vtable-then-payload store order; LLVM
    // otherwise legally swaps independent non-volatile field stores.
    core::ptr::addr_of_mut!((*this).vtable).write_volatile(&STRING_OBJECT_VTABLE);
    core::ptr::addr_of_mut!((*this).payload).write_volatile(core::ptr::null_mut());
    string_object_assign_payload(this, payload);
    this
}

/// ABI of the ported embedded-object constructor at 0x0827735c.
pub type StringObjectInitialize = unsafe extern "C" fn(
    string: *mut StringObject,
    argument: *mut u8,
) -> *mut StringObject;

/// Default embedded-object constructor: the exact port at 0x0827735c.
unsafe extern "C" fn default_string_object_initialize(
    string: *mut StringObject,
    argument: *mut u8,
) -> *mut StringObject {
    string_owner_embedded_init(string, argument)
}

/// External operation used by [`app_string_owner_initialize`].
#[derive(Clone, Copy)]
pub struct AppStringOwnerInitializeOps {
    pub initialize_string_object: StringObjectInitialize,
}

/// Active embedded-object constructor. Host tests install a recording
/// constructor to prove the wrapper ABI; firmware uses the exact port.
pub static mut APP_STRING_OWNER_INITIALIZE_OPS: AppStringOwnerInitializeOps =
    AppStringOwnerInitializeOps {
        initialize_string_object: default_string_object_initialize,
    };

#[inline(always)]
unsafe fn app_string_owner_initialize_ops() -> AppStringOwnerInitializeOps {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_STRING_OWNER_INITIALIZE_OPS))
}

/// app_string_owner_initialize — original: `FUN_0811c138` @ 0x0811c138
/// (32 bytes: 28 code + the 4-byte vtable literal at 0x0811c158).
///
/// Stores the outer vtable at +0 and `owner_word` at +4, then invokes the
/// embedded StringObject constructor with `argument` at +8. The helper's
/// returned pointer is adjusted by eight with wrapping subtraction. There is
/// no NULL guard, matching the first store in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_string_owner_initialize(
    this: *mut u8,
    owner_word: u32,
    argument: *mut u8,
) -> *mut u8 {
    (this as *mut u32).write(APP_STRING_OWNER_VTABLE);
    (this.add(4) as *mut u32).write(owner_word);
    let string = this.add(APP_STRING_OWNER_STRING) as *mut StringObject;
    let helper_result = (app_string_owner_initialize_ops().initialize_string_object)(string, argument);
    (helper_result as *mut u8).wrapping_sub(APP_STRING_OWNER_STRING)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut HELPER_STRING: usize = 0;
    static mut HELPER_ARGUMENT: usize = 0;
    static mut HELPER_RETURN: *mut StringObject = core::ptr::null_mut();

    unsafe extern "C" fn recording_initialize(
        string: *mut StringObject,
        argument: *mut u8,
    ) -> *mut StringObject {
        HELPER_STRING = string as usize;
        HELPER_ARGUMENT = argument as usize;
        HELPER_RETURN
    }

    struct RestoreOps;

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe {
                APP_STRING_OWNER_INITIALIZE_OPS = AppStringOwnerInitializeOps {
                    initialize_string_object: default_string_object_initialize,
                };
            }
        }
    }

    fn mock_initialize() -> (MutexGuard<'static, ()>, RestoreOps) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            HELPER_STRING = 0;
            HELPER_ARGUMENT = 0;
            HELPER_RETURN = core::ptr::null_mut();
            APP_STRING_OWNER_INITIALIZE_OPS = AppStringOwnerInitializeOps {
                initialize_string_object: recording_initialize,
            };
        }
        (lock, RestoreOps)
    }

    #[test]
    fn embedded_constructor_plants_the_vtable_clears_raw_payload_and_returns_this() {
        let mut storage = core::mem::MaybeUninit::<StringObject>::uninit();
        let this = storage.as_mut_ptr();
        unsafe {
            assert_eq!(
                string_owner_embedded_init(this, core::ptr::null()),
                this,
                "the post-call mov r0, r4 returns the saved receiver"
            );
            let object = storage.assume_init();
            assert_eq!(object.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!(object.payload.is_null(), "the payload clear precedes the NULL helper path");
        }
    }

    #[test]
    fn stores_the_outer_layout_and_forwards_the_embedded_constructor_arguments() {
        let (_lock, _restore) = mock_initialize();
        let mut bytes = [0xa5u8; 32];
        let this = bytes.as_mut_ptr().wrapping_add(8);
        let argument = 0x0123_4567usize as *mut u8;
        unsafe {
            HELPER_RETURN = this.add(APP_STRING_OWNER_STRING) as *mut StringObject;
            assert_eq!(app_string_owner_initialize(this, 0xdead_beef, argument), this);
            assert_eq!(HELPER_STRING, this.add(APP_STRING_OWNER_STRING) as usize);
            assert_eq!(HELPER_ARGUMENT, argument as usize);
        }
        assert_eq!(&bytes[8..12], &APP_STRING_OWNER_VTABLE.to_le_bytes());
        assert_eq!(&bytes[12..16], &0xdead_beefu32.to_le_bytes());
        assert_eq!(&bytes[..8], &[0xa5; 8]);
        assert_eq!(&bytes[16..], &[0xa5; 16], "the helper owns +0x08 onward");
    }

    #[test]
    fn helper_return_adjustment_wraps_at_address_zero() {
        let (_lock, _restore) = mock_initialize();
        let mut bytes = [0u8; 16];
        unsafe {
            HELPER_RETURN = core::ptr::null_mut();
            assert_eq!(
                app_string_owner_initialize(bytes.as_mut_ptr(), 7, core::ptr::null_mut()) as usize,
                usize::MAX - (APP_STRING_OWNER_STRING - 1)
            );
        }
    }
}
