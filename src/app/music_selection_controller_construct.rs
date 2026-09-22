//! Construction of the shared base for music-selection controllers.

/// `music_selection_controller_construct` — original: `FUN_082305a8` @
/// `0x082305a8` (**56 bytes**, `0x082305a8..0x082305e0`: 13 A32 words,
/// including the vtable literal at `0x082305dc`). The `cmp r0,#0` at
/// `0x082305e0` starts the next real function.
///
/// Raw A32 decoding finds **2 plain `bl` calls and 0 predicated `bl` calls**:
/// [`super::silver_controller::silver_controller_construct`] then
/// [`super::music_selection_state_reset::music_selection_state_reset`]. It
/// installs vtable `0x089a0e5c`, resets the music-selection fields, clears
/// bytes `+0xb0` and `+0xc5`, sets byte `+0xc4`, and returns the constructed
/// object. The host-only call seam is deliberate; target builds call both
/// verified ports directly, with no behavioral deviation.
///
/// # Safety
///
/// `this` and `name` must meet
/// [`super::silver_controller::silver_controller_construct`]'s requirements;
/// its result must be writable through offset `+0xc5`.
type ConstructBase = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;
type ResetSelection = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct MusicSelectionControllerConstructOps {
    pub construct_base: ConstructBase,
    pub reset_selection: ResetSelection,
}

#[cfg(not(target_os = "none"))]
pub static mut MUSIC_SELECTION_CONTROLLER_CONSTRUCT_OPS: MusicSelectionControllerConstructOps =
    MusicSelectionControllerConstructOps {
        construct_base: super::silver_controller::silver_controller_construct,
        reset_selection: super::music_selection_state_reset::music_selection_state_reset,
    };

#[inline(always)]
unsafe fn construct_base(this: *mut u8, name: *const u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    unsafe { super::silver_controller::silver_controller_construct(this, name) }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (core::ptr::read_volatile(core::ptr::addr_of!(MUSIC_SELECTION_CONTROLLER_CONSTRUCT_OPS.construct_base)))(this, name)
    }
}

#[inline(always)]
unsafe fn reset_selection(state: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { super::music_selection_state_reset::music_selection_state_reset(state); }
    #[cfg(not(target_os = "none"))]
    unsafe {
        (core::ptr::read_volatile(core::ptr::addr_of!(MUSIC_SELECTION_CONTROLLER_CONSTRUCT_OPS.reset_selection)))(state);
    }
}

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.music_selection_controller_construct")]
#[inline(never)]
pub unsafe extern "C" fn music_selection_controller_construct(
    this: *mut u8,
    name: *const u8,
) -> *mut u8 {
    unsafe {
        let this = construct_base(this, name);
        core::ptr::write_volatile(this.cast::<u32>(), 0x089a_0e5c);
        reset_selection(this);
        core::ptr::write_volatile(this.add(0xb0), 0);
        core::ptr::write_volatile(this.add(0xc5), 0);
        core::ptr::write_volatile(this.add(0xc4), 1);
        this
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCT_THIS: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_NAME: *const u8 = core::ptr::null();
    static mut RESET_STATE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn construct(this: *mut u8, name: *const u8) -> *mut u8 {
        unsafe { CONSTRUCT_THIS = this; CONSTRUCT_NAME = name; }
        this
    }

    unsafe extern "C" fn reset(state: *mut u8) -> *mut u8 {
        unsafe { RESET_STATE = state; }
        state
    }

    #[test]
    fn constructs_then_resets_and_writes_only_its_derived_fields() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MUSIC_SELECTION_CONTROLLER_CONSTRUCT_OPS)) };
        unsafe {
            MUSIC_SELECTION_CONTROLLER_CONSTRUCT_OPS = MusicSelectionControllerConstructOps { construct_base: construct, reset_selection: reset };
            CONSTRUCT_THIS = core::ptr::null_mut(); CONSTRUCT_NAME = core::ptr::null(); RESET_STATE = core::ptr::null_mut();
        }
        let mut object = [0xa5a5_a5a5u32; 50];
        let object = object.as_mut_ptr().cast::<u8>();
        let name = b"Music\0";
        let result = unsafe { music_selection_controller_construct(object, name.as_ptr()) };
        unsafe { MUSIC_SELECTION_CONTROLLER_CONSTRUCT_OPS = previous; }

        let bytes = unsafe { core::slice::from_raw_parts(object, 0xc6) };
        assert_eq!(result, object);
        assert_eq!(unsafe { CONSTRUCT_THIS }, object);
        assert_eq!(unsafe { CONSTRUCT_NAME }, name.as_ptr());
        assert_eq!(unsafe { RESET_STATE }, object);
        assert_eq!(&bytes[0..4], &0x089a_0e5cu32.to_le_bytes());
        assert_eq!(bytes[0xb0], 0);
        assert_eq!(bytes[0xc4], 1);
        assert_eq!(bytes[0xc5], 0);
        assert_eq!(bytes[0xb1], 0xa5);
        assert_eq!(bytes[0xc3], 0xa5);
    }
}
