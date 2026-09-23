//! `byte_state_construct` — original: `FUN_081d28f4` @ `0x081d28f4`
//! (32 bytes, `0x081d28f4..0x081d2913`; the next independently entered
//! function begins at `0x081d2914`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM has one outbound plain unconditional `bl`, at `0x081d28fc` to
//! `0x081f72d0`, and no predicated `bl`. Three inbound call sites are plain
//! unconditional `bl`; none is predicated. It writes `initial_byte` at +0,
//! invokes the unported embedded-state constructor at +8, clears words +0x4c
//! and +0x50 through that constructor's returned pointer rebased by -8, and
//! returns the enclosing object pointer.
//!
//! # Deliberate deviations
//!
//! The embedded constructor has no recovered semantic identity. Target builds
//! call its verified retailOS address; host builds use a narrow callback seam.

/// ABI of the unported embedded-state constructor at `0x081f72d0`.
pub type EmbeddedStateConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_embedded_state_construct(state: *mut u8) -> *mut u8 {
    state
}

/// Host seam for the unported embedded-state constructor.
#[cfg(not(target_os = "none"))]
pub static mut EMBEDDED_STATE_CONSTRUCT: EmbeddedStateConstruct = missing_embedded_state_construct;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn embedded_state_construct_target() -> EmbeddedStateConstruct {
    core::mem::transmute(0x081f_72d0usize)
}

/// Initializes the leading byte and embedded state of a 0x5c-byte object.
///
/// # Safety
///
/// `object` must point to writable storage through offset `0x53`; the embedded
/// state constructor must accept `object + 8` and return that same address.
/// Stock code has no NULL or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_state_construct(object: *mut u8, initial_byte: u8) -> *mut u8 {
    object.write(initial_byte);
    #[cfg(target_os = "none")]
    let state = unsafe { embedded_state_construct_target()(object.add(8)) };
    #[cfg(not(target_os = "none"))]
    let state = unsafe { EMBEDDED_STATE_CONSTRUCT(object.add(8)) };
    let object = unsafe { state.sub(8) };
    unsafe {
        object.add(0x4c).cast::<u32>().write(0);
        object.add(0x50).cast::<u32>().write(0);
    }
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CONSTRUCTOR_ARGUMENT: usize = 0;

    unsafe extern "C" fn record_embedded_state_construct(state: *mut u8) -> *mut u8 {
        unsafe { CONSTRUCTOR_ARGUMENT = state as usize };
        state
    }

    #[test]
    fn initializes_only_the_observable_fields() {
        let _guard = TEST_LOCK.lock();
        unsafe { EMBEDDED_STATE_CONSTRUCT = record_embedded_state_construct };
        let mut object = [0xa5u8; 0x5c];

        let returned = unsafe { byte_state_construct(object.as_mut_ptr(), 0x3c) };

        assert_eq!(returned, object.as_mut_ptr());
        assert_eq!(unsafe { CONSTRUCTOR_ARGUMENT }, object.as_ptr() as usize + 8);
        assert_eq!(object[0], 0x3c);
        assert_eq!(&object[1..8], &[0xa5; 7]);
        assert_eq!(&object[8..0x4c], &[0xa5; 0x44]);
        assert_eq!(&object[0x4c..0x54], &[0; 8]);
        assert_eq!(&object[0x54..], &[0xa5; 8]);
    }

    #[test]
    fn overwrites_existing_byte_and_trailing_words() {
        let _guard = TEST_LOCK.lock();
        unsafe { EMBEDDED_STATE_CONSTRUCT = missing_embedded_state_construct };
        let mut object = [0u8; 0x5c];
        object[0] = 0xff;
        object[0x4c..0x54].fill(0x11);

        unsafe { byte_state_construct(object.as_mut_ptr(), 0) };

        assert_eq!(object[0], 0);
        assert_eq!(&object[0x4c..0x54], &[0; 8]);
    }
}
