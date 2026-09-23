//! `opaque_object_apply_mode_five` — original: `FUN_081a5a58` @ **0x081a5a58**.
//! True extent is 8 bytes, `0x081a5a58..0x081a5a60`: `mov r1, #5` then
//! `b 0x081de270`; the next function begins at 0x081a5a60. Raw decoding finds
//! two inbound plain `bl` call sites and zero predicated `bl` forms.
//!
//! # Algorithm
//!
//! Selects mode 5 for an opaque object, then tail-branches to the shared
//! mode-application routine at 0x081de270.
//!
//! # Deliberate deviations
//!
//! The shared target is not named or ported. Target builds call its verified
//! retail address; host tests install a recording seam. Rust uses an ordinary
//! call and return instead of the terminal ARM branch.

type OpaqueObjectApplyMode = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_opaque_object_apply_mode(object: *mut u8, mode: u32) {
    let apply_mode: OpaqueObjectApplyMode = core::mem::transmute(0x081d_e270usize);
    apply_mode(object, mode);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_object_apply_mode(_: *mut u8, _: u32) {}

static mut OPAQUE_OBJECT_APPLY_MODE: OpaqueObjectApplyMode = {
    #[cfg(target_os = "none")]
    { retail_opaque_object_apply_mode }
    #[cfg(not(target_os = "none"))]
    { missing_opaque_object_apply_mode }
};

/// Applies the retail mode-5 operation to `object`.
///
/// # Safety
///
/// `object` must satisfy the unported mode application's object-layout
/// requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_object_apply_mode_five(object: *mut u8) {
    OPAQUE_OBJECT_APPLY_MODE(object, 5);
}

#[cfg(test)]
pub static OPAQUE_OBJECT_APPLY_MODE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    static mut OBSERVED: (*mut u8, u32) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn record_opaque_object_apply_mode(object: *mut u8, mode: u32) {
        OBSERVED = (object, mode);
    }

    #[test]
    fn forwards_the_object_and_fixed_mode_five() {
        let _lock = OPAQUE_OBJECT_APPLY_MODE_TEST_LOCK.lock();
        let mut object = [0u8; 0x3c];
        unsafe {
            OPAQUE_OBJECT_APPLY_MODE = record_opaque_object_apply_mode;
            opaque_object_apply_mode_five(object.as_mut_ptr());
            assert_eq!(OBSERVED, (object.as_mut_ptr(), 5));
            OPAQUE_OBJECT_APPLY_MODE = missing_opaque_object_apply_mode;
        }
    }
}
