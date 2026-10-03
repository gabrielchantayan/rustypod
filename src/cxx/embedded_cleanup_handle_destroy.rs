//! Destroy an embedded cleanup handle — `FUN_08257d08` @ 0x08257d08.
//! True size: 28 bytes (0x08257d08..0x08257d24); the next function is
//! strb r1,[r0,#0x3c]; bx lr. Verified body: two plain BLs, zero predicated
//! BLs. One verified inbound plain BL is at 0x081d6744; a whole-image
//! scan also finds a predicated encoding at 0x089d8cc4, not a verified caller.
//!
//! Call 0x08261ff0 on this+0x10, subtract 12 from its returned pointer,
//! call the empty base destructor at 0x08261de4, then subtract 4 and return.
//! The first callee loads the handle's owner word, calls 0x082625e0 with
//! owner and handle, and returns the handle. Its cleanup checks the payload
//! at handle+4, removes it from the owner's collection, and releases it.
//!
//! Deliberate deviations: retain unported cleanup at its verified retail
//! address; hosts must supply an implementation. Elide the base destructor:
//! its sole raw word is e12fff1e (bx lr), preserving r0 with no side effects.
//! Keep the returned-pointer adjustment rather than assuming input identity.

#[cfg(not(target_os = "none"))]
pub static mut EMBEDDED_CLEANUP_HANDLE_DESTROY_OP: Option<
    unsafe extern "C" fn(*mut u8) -> *mut u8,
> = None;

#[inline(always)]
unsafe fn destroy_handle(handle: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let destroy: unsafe extern "C" fn(*mut u8) -> *mut u8 =
            core::mem::transmute(0x0826_1ff0usize);
        destroy(handle)
    }
    #[cfg(not(target_os = "none"))]
    {
        let destroy = core::ptr::read_volatile(
            core::ptr::addr_of!(EMBEDDED_CLEANUP_HANDLE_DESTROY_OP))
            .expect("retail embedded handle cleanup requires a host implementation");
        destroy(handle)
    }
}

/// Destroy the cleanup handle at target byte offset 0x10 and return this.
///
/// # Safety
/// `this+0x10` must satisfy the retail cleanup handle contract, including
/// valid owner and payload words when the payload is non-null.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destroy_embedded_cleanup_handle(this: *mut u8) -> *mut u8 {
    destroy_handle(this.wrapping_add(0x10)).wrapping_sub(12).wrapping_sub(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    // Host model of the retail payload-present decision. Use native pointer
    // fields only inside the seam; the wrapper's target offset stays 0x10.
    #[repr(C)]
    struct Handle { owner: *mut u32, payload: *mut u8 }
    #[repr(C)]
    struct Object { prefix: [u32; 4], handle: Handle, suffix: u32 }

    unsafe extern "C" fn cleanup_model(handle: *mut u8) -> *mut u8 {
        let fields = &mut *handle.cast::<Handle>();
        if !fields.payload.is_null() {
            *fields.owner -= 1;
            *fields.payload = 0;
        }
        handle
    }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { EMBEDDED_CLEANUP_HANDLE_DESTROY_OP = None; }
        }
    }

    #[test]
    fn live_and_null_payloads_preserve_surrounding_object() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        unsafe { EMBEDDED_CLEANUP_HANDLE_DESTROY_OP = Some(cleanup_model); }
        for live in [false, true] {
            let mut count = 3;
            let mut payload = 0x7fu8;
            let mut object = Object {
                prefix: [0x12345678; 4],
                handle: Handle {
                    owner: &mut count,
                    payload: if live { &mut payload } else { core::ptr::null_mut() },
                },
                suffix: 0xabcdef01,
            };
            let this = core::ptr::addr_of_mut!(object).cast::<u8>();
            unsafe { assert_eq!(destroy_embedded_cleanup_handle(this), this); }
            assert_eq!(count, if live { 2 } else { 3 });
            assert_eq!(payload, if live { 0 } else { 0x7f });
            assert_eq!(object.prefix, [0x12345678; 4]);
            assert_eq!(object.suffix, 0xabcdef01);
        }
    }
}
