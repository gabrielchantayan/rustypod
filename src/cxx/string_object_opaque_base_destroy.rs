//! `string_object_opaque_base_destroy` — original: `FUN_08291fb4` @ load
//! address `0x08291fb4` (24 bytes). Raw `osos.dec` establishes the body
//! through the tail `b 0x08277484` at `0x08291fc8`; the next function begins
//! at `0x08291fcc`.
//!
//! ```text
//! 08291fb4  push  {r4, lr}
//! 08291fb8  add   r0, r0, #8
//! 08291fbc  bl    0x083d0af0
//! 08291fc0  pop   {r4, lr}
//! 08291fc4  sub   r0, r0, #8
//! 08291fc8  b     0x08277484
//! ```
//!
//! Full-image ARM branch decoding finds four inbound direct `bl` call sites,
//! all unconditional and no predicated form. The body has one direct `bl`
//! (the unported base destructor) and one tail `b` to the ported
//! [`string_object_destroy`]. It first destroys an opaque base subobject at
//! target offset +8, rebases that callee's returned pointer by -8, then
//! destroys the leading StringObject. Deliberate deviation: the unknown base
//! destructor is a fixed-address target call and an injectable host seam.

use core::ffi::c_void;
#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::cxx::string_object::{string_object_destroy, StringObject};

/// Fixed retailOS address of the opaque base destructor, `FUN_083d0af0`.
const RETAIL_OPAQUE_BASE_DESTROY: usize = 0x083d_0af0;

/// Host boundary for the unported opaque-base destructor.
#[derive(Clone, Copy)]
pub struct OpaqueBaseDestroyOps {
    pub destroy: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_base_destroy(base: *mut c_void) -> *mut c_void {
    base
}

/// Host seam for `FUN_083d0af0`; target builds call the retailOS address.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_BASE_DESTROY_OPS: OpaqueBaseDestroyOps = OpaqueBaseDestroyOps {
    destroy: missing_opaque_base_destroy,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn opaque_base_destroy(base: *mut c_void) -> *mut c_void {
    let destroy: unsafe extern "C" fn(*mut c_void) -> *mut c_void =
        core::mem::transmute(RETAIL_OPAQUE_BASE_DESTROY);
    destroy(base)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn opaque_base_destroy(base: *mut c_void) -> *mut c_void {
    let destroy = ptr::read_volatile(ptr::addr_of!(OPAQUE_BASE_DESTROY_OPS.destroy));
    destroy(base)
}

/// string_object_opaque_base_destroy — original: `FUN_08291fb4` @ 0x08291fb4
/// (24 bytes; 4 unconditional direct `bl` call sites, no predicated forms).
///
/// Destroys the opaque base at target word index 2, then uses its returned
/// pointer to recover and destroy the leading [`StringObject`]. There is no
/// NULL guard; both callee calls receive the values derived by the ARM body.
///
/// # Safety
///
/// `owner` must point to an object with a leading [`StringObject`] and an
/// opaque base subobject at target offset +8.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_opaque_base_destroy(
    owner: *mut StringObject,
) -> *mut StringObject {
    let base = owner.cast::<u32>().add(2).cast::<c_void>();
    let owner = opaque_base_destroy(base).cast::<u32>().sub(2).cast::<StringObject>();
    string_object_destroy(owner)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    struct OpsRestore;

    impl Drop for OpsRestore {
        fn drop(&mut self) {
            unsafe {
                OPAQUE_BASE_DESTROY_OPS = OpaqueBaseDestroyOps {
                    destroy: missing_opaque_base_destroy,
                };
            }
        }
    }

    static mut CALL_COUNT: usize = 0;
    static mut SEEN_BASE: *mut c_void = ptr::null_mut();

    unsafe extern "C" fn recording_destroy(base: *mut c_void) -> *mut c_void {
        unsafe {
            CALL_COUNT += 1;
            SEEN_BASE = base;
        }
        base
    }

    #[test]
    fn destroys_base_then_leading_string_object() {
        let _guard = OPS_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            SEEN_BASE = ptr::null_mut();
            OPAQUE_BASE_DESTROY_OPS = OpaqueBaseDestroyOps {
                destroy: recording_destroy,
            };
        }
        let _restore = OpsRestore;
        let mut owner = StringObject {
            vtable: ptr::null(),
            payload: ptr::null_mut(),
        };

        let returned = unsafe { string_object_opaque_base_destroy(&mut owner) };

        assert_eq!(unsafe { CALL_COUNT }, 1, "one direct base-destructor bl");
        let expected_base = unsafe { (&mut owner as *mut StringObject).cast::<u32>().add(2).cast() };
        assert_eq!(unsafe { SEEN_BASE }, expected_base);
        assert!(core::ptr::eq(returned, &mut owner));
        assert!(core::ptr::eq(
            owner.vtable,
            &crate::cxx::string_object::STRING_OBJECT_VTABLE,
        ));
        assert!(owner.payload.is_null());
    }
}
