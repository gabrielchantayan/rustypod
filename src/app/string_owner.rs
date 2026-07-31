//! `app_string_owner_destroy` — original: `FUN_0811c15c` @ 0x0811c15c
//! (24 bytes: 20 code + the 4-byte vtable literal at 0x0811c174).
//!
//! The function is the plain, non-deleting destructor of an unidentified
//! application-framework object with an opaque word at +0x04 and an embedded
//! [`StringObject`] at +0x08. It plants the object's vtable literal
//! `0x089a7428` at +0x00, destroys that embedded string through
//! `string_object_destroy` @ 0x08277484, and derives its return from the
//! helper's result by subtracting eight bytes. There is no allocation, NULL
//! guard, or initialization of the opaque word.
//!
//! The original directly branches to the already-ported helper. The port uses
//! a volatile replaceable operation slot solely to make the helper ABI and its
//! returned-pointer adjustment observable in host tests; its target default is
//! exactly `string_object_destroy`.
//!
//! Sources: `ipod-decomp/decomp/c/010/0811c15c_FUN_0811c15c.c`,
//! `ipod-decomp/decomp/c/026/08277484_FUN_08277484.c`, and the instruction
//! sequence at 0x0811c15c in `ipod-decomp/decomp/osos.asm`.

use crate::cxx::string_object::{string_object_destroy, StringObject};

/// Target offset of the opaque embedded StringObject member.
pub const APP_STRING_OWNER_STRING: usize = 0x08;

/// The vtable address loaded from literal pool word 0x0811c174.
pub const APP_STRING_OWNER_VTABLE: u32 = 0x089a_7428;

/// ABI of the embedded StringObject plain destructor at 0x08277484.
pub type StringObjectDestroy = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;

/// External operation used by [`app_string_owner_destroy`].
#[derive(Clone, Copy)]
pub struct AppStringOwnerOps {
    pub destroy_string_object: StringObjectDestroy,
}

/// The target's normal direct helper call, made replaceable for host tests.
pub static mut APP_STRING_OWNER_OPS: AppStringOwnerOps = AppStringOwnerOps {
    destroy_string_object: string_object_destroy,
};

#[inline(always)]
unsafe fn app_string_owner_ops() -> AppStringOwnerOps {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_STRING_OWNER_OPS))
}

/// app_string_owner_destroy — original: `FUN_0811c15c` @ 0x0811c15c
/// (24 bytes: 20 code + the 4-byte vtable literal at 0x0811c174).
///
/// Destroys the embedded [`StringObject`] at `this + 8` after planting the
/// outer vtable word at `this + 0`. The return value is the helper result
/// adjusted with `wrapping_sub(8)`, exactly retaining the original ARM `sub`
/// behavior even when a mocked helper returns a value below eight. No NULL
/// guard is present: the literal store faults for NULL just as the retailOS
/// code does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_string_owner_destroy(this: *mut u8) -> *mut u8 {
    (this as *mut u32).write(APP_STRING_OWNER_VTABLE);
    let string = this.add(APP_STRING_OWNER_STRING) as *mut StringObject;
    let helper_result = (app_string_owner_ops().destroy_string_object)(string);
    (helper_result as *mut u8).wrapping_sub(APP_STRING_OWNER_STRING)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut HELPER_ARG: usize = 0;
    static mut HELPER_RETURN: *mut StringObject = core::ptr::null_mut();

    unsafe extern "C" fn recording_destroy(string: *mut StringObject) -> *mut StringObject {
        HELPER_ARG = string as usize;
        HELPER_RETURN
    }

    struct RestoreOps;

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe {
                APP_STRING_OWNER_OPS = AppStringOwnerOps {
                    destroy_string_object: string_object_destroy,
                };
            }
        }
    }

    fn mock_destroy() -> (MutexGuard<'static, ()>, RestoreOps) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            HELPER_ARG = 0;
            HELPER_RETURN = core::ptr::null_mut();
            APP_STRING_OWNER_OPS = AppStringOwnerOps {
                destroy_string_object: recording_destroy,
            };
        }
        (lock, RestoreOps)
    }

    #[test]
    fn plants_the_vtable_and_calls_the_embedded_string_at_plus_8() {
        let (_lock, _restore) = mock_destroy();
        let mut bytes = [0xa5u8; 32];
        let this = bytes.as_mut_ptr().wrapping_add(8);
        unsafe {
            HELPER_RETURN = this.add(APP_STRING_OWNER_STRING) as *mut StringObject;
            assert_eq!(app_string_owner_destroy(this), this);
            assert_eq!(HELPER_ARG, this.add(APP_STRING_OWNER_STRING) as usize);
        }
        assert_eq!(&bytes[8..12], &APP_STRING_OWNER_VTABLE.to_le_bytes());
        assert_eq!(&bytes[12..16], &[0xa5; 4], "opaque +0x04 is untouched");
        assert_eq!(&bytes[16..], &[0xa5; 16], "the helper mock leaves +0x08 onward untouched");
    }

    #[test]
    fn return_is_derived_from_the_helper_result() {
        let (_lock, _restore) = mock_destroy();
        let mut bytes = [0u8; 32];
        let this = bytes.as_mut_ptr();
        unsafe {
            HELPER_RETURN = this.add(APP_STRING_OWNER_STRING) as *mut StringObject;
            assert_eq!(app_string_owner_destroy(this), this);
        }
    }

    #[test]
    fn helper_return_adjustment_wraps_at_address_zero() {
        let (_lock, _restore) = mock_destroy();
        let mut bytes = [0u8; 16];
        unsafe {
            HELPER_RETURN = core::ptr::null_mut();
            assert_eq!(
                app_string_owner_destroy(bytes.as_mut_ptr()) as usize,
                usize::MAX - (APP_STRING_OWNER_STRING - 1)
            );
        }
    }
}
