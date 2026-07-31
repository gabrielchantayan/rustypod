//! `app_string_owner_initialize` — original: `FUN_0811c138` @ 0x0811c138
//! (32 bytes: 28 code + the 4-byte vtable literal at 0x0811c158).
//!
//! This is the initializer paired with `app_string_owner_destroy` at
//! 0x0811c15c: both plant the same outer vtable at +0, leave the opaque
//! caller-supplied word at +4, and operate on the embedded string-like object
//! at +8. It stores its second argument at +4, forwards its third argument to
//! the unported `FUN_0827735c` constructor for that embedded object, and
//! returns the helper result less eight. The subtraction uses ARM's wrapping
//! pointer arithmetic.
//!
//! `FUN_0827735c` is intentionally not ported here. Its operation slot is the
//! application-layer dispatch boundary: the default establishes the known
//! `StringObject` base layout, while a complete string-construction port can
//! replace the slot with the exact argument-consuming constructor. Sources:
//! `ipod-decomp/decomp/c/010/0811c138_FUN_0811c138.c`,
//! `ipod-decomp/decomp/c/026/0827735c_FUN_0827735c.c`, and the instruction
//! sequence at 0x0811c138 in `ipod-decomp/decomp/osos.asm`.

use crate::app::string_owner::{APP_STRING_OWNER_STRING, APP_STRING_OWNER_VTABLE};
use crate::cxx::string_object::{string_default_construct, StringObject};

/// ABI of the unported embedded-object constructor at 0x0827735c.
pub type StringObjectInitialize = unsafe extern "C" fn(
    string: *mut StringObject,
    argument: *mut u8,
) -> *mut StringObject;

/// Minimal default for the unported constructor: the verified base layout at
/// +0/+4 is established by the already-ported default constructor. Its
/// argument-consuming virtual dispatch remains owned by this operation seam.
unsafe extern "C" fn default_string_object_initialize(
    string: *mut StringObject,
    _argument: *mut u8,
) -> *mut StringObject {
    string_default_construct(string)
}

/// External operation used by [`app_string_owner_initialize`].
#[derive(Clone, Copy)]
pub struct AppStringOwnerInitializeOps {
    pub initialize_string_object: StringObjectInitialize,
}

/// Active embedded-object constructor. Host tests install a recording helper
/// to prove the wrapper ABI without claiming to port 0x0827735c.
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
