//! `app_screen_update_position` — original: `FUN_0817794c` @ `0x0817794c`
//! (**124 bytes**, `0x0817794c..0x081779c8`; the next separately linked entry
//! starts at `0x081779c8`). Decoding every ARM `B`/`BL` immediate in
//! `work/firmware/osos.dec` finds exactly eight direct inbound `bl` calls,
//! all unconditional: `0x0822748c`, `0x08229d44`, `0x0822a0ec`, `0x0822a758`,
//! `0x08231050`, `0x08234168`, `0x08234294`, and `0x08260a10`. There are no
//! predicated call forms and no direct tail `b` transfers.
//!
//! The app-screen position update first obtains the validated singleton, then
//! compares the screen's active mode-selected position with its cached word at
//! `+0x2c`. Only when they match does it inspect the nullable two-level handle
//! at `+0x18`; it deliberately reads that handle a second time before calling
//! the returned object's unidentified virtual slot `+0x110`. A strict limit
//! above the cached position selects mode zero and forwards the wrapping delta
//! from the requested position. Every other path selects mode one and forwards
//! the request unchanged. The request is stored into `screen+0x2c` before the
//! selected mode/position pair is sent to the validated singleton, except the
//! `(mode = 0, position = 0)` pair suppresses that send. The tail setter's
//! return value is propagated.
//!
//! Deliberate deviations: the retail thunk at `0x0820a49c` tail-branches to the
//! already ported `mode_selected_position`; this port calls that canonical body
//! directly. The final retail tail branch reaches the existing unported
//! `0x0822ba50` setter seam, whose host replacement is shared with
//! `set_clamped_mode_position`. The virtual slot has no recovered identity, so
//! it is dispatched only by its observed vtable word index.

use super::{
    clamped_mode_position::set_mode_position,
    mode_selected_position::mode_selected_position,
    validated_singleton_0x89c::validated_singleton_0x89c_get,
};
use crate::cxx::handle::handle_deref_or_null;
use core::ptr::addr_of;

type HandleDeref = unsafe extern "C" fn(*const *const *mut u8) -> *mut u8;
static HANDLE_DEREF: HandleDeref = handle_deref_or_null;

#[inline(always)]
unsafe fn load_handle_deref(slot: *const *const *mut u8) -> *mut u8 {
    core::ptr::read_volatile(addr_of!(HANDLE_DEREF))(slot)
}


const HANDLE_OFFSET: usize = 0x18;
const CACHED_POSITION_OFFSET: usize = 0x2c;
const POSITION_LIMIT_VTABLE_INDEX: usize = 0x110 / 4;

type PositionLimit = unsafe extern "C" fn(*mut u8) -> u32;

/// Updates the app-screen cached position and, when needed, the validated
/// singleton's mode-selected position.
///
/// # Safety
///
/// `screen` must be non-NULL, four-byte aligned, and readable through `+0x5f8`;
/// its words at `+0x2ec`, `+0x5e4`, and `+0x2c` must be readable, with `+0x2c`
/// writable. Its `+0x18` handle slot must be readable. When that handle is
/// non-NULL, both reads must produce a live object whose vtable has a callable
/// word at target offset `+0x110`. The retail code performs none of these
/// checks, and it calls the virtual method with the object in `r0`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_update_position(screen: *mut u8, requested_position: u32) -> u32 {
    let singleton = validated_singleton_0x89c_get();
    let active_position = mode_selected_position(screen);
    let cached_position = screen.add(CACHED_POSITION_OFFSET).cast::<u32>().read();

    let (mode, position) = if active_position == cached_position
        && !load_handle_deref(screen.add(HANDLE_OFFSET).cast()).is_null()
    {
        // Retail calls this accessor again after its NULL test. Preserve the
        // second volatile function-pointer load: a mutable handle is observable
        // between the two calls.
        let object = load_handle_deref(screen.add(HANDLE_OFFSET).cast());
        let vtable = (object as *const *const usize).read();
        let limit: PositionLimit = core::mem::transmute(vtable.add(POSITION_LIMIT_VTABLE_INDEX).read());
        if limit(object) > cached_position {
            (0, requested_position.wrapping_sub(cached_position))
        } else {
            (1, requested_position)
        }
    } else {
        (1, requested_position)
    };

    screen.add(CACHED_POSITION_OFFSET).cast::<u32>().write(requested_position);
    if mode != 0 || position != 0 {
        set_mode_position(singleton, mode, position)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::clamped_mode_position::{
        ModePositionSetter, MODE_POSITION_SETTER, MODE_POSITION_SETTER_TEST_LOCK,
    };
    use crate::app::validated_singleton_0x89c::{
        VALIDATED_SINGLETON_0X89C, VALIDATED_SINGLETON_0X89C_TEST_LOCK,
    };

    const SCREEN_BYTES: usize = 0x5f9;
    const MODE_POSITION_OFFSET: usize = 0x2ec;
    const DEFAULT_POSITION_OFFSET: usize = 0x5e4;
    const MODE_FLAGS_OFFSET: usize = 0x5f8;
    const SETTER_RETURN: u32 = 0x51e7_0001;

    static mut SETTER_STATE: *mut u8 = core::ptr::null_mut();
    static mut SETTER_MODE: u32 = 0;
    static mut SETTER_POSITION: u32 = 0;
    static mut SETTER_CALLS: u32 = 0;
    static mut LIMIT_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut LIMIT_VALUE: u32 = 0;
    static mut LIMIT_CALLS: u32 = 0;

    #[repr(align(8))]
    struct Screen([u8; SCREEN_BYTES]);

    #[repr(C)]
    struct VirtualObject {
        vtable: *const usize,
    }

    struct Reset {
        old_setter: ModePositionSetter,
        old_singleton: *mut u8,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(MODE_POSITION_SETTER), self.old_setter);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(VALIDATED_SINGLETON_0X89C),
                    self.old_singleton,
                );
            }
        }
    }

    unsafe extern "C" fn record_setter(state: *mut u8, mode: u32, position: u32) -> u32 {
        SETTER_STATE = state;
        SETTER_MODE = mode;
        SETTER_POSITION = position;
        SETTER_CALLS += 1;
        SETTER_RETURN
    }

    unsafe extern "C" fn position_limit(object: *mut u8) -> u32 {
        LIMIT_OBJECT = object;
        LIMIT_CALLS += 1;
        LIMIT_VALUE
    }

    unsafe extern "C" fn wrong_position_limit(_object: *mut u8) -> u32 {
        panic!("called the wrong virtual slot")
    }

    unsafe fn install(singleton: *mut u8) -> Reset {
        let old_setter = core::ptr::read_volatile(core::ptr::addr_of!(MODE_POSITION_SETTER));
        let old_singleton = core::ptr::read_volatile(core::ptr::addr_of!(VALIDATED_SINGLETON_0X89C));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MODE_POSITION_SETTER), record_setter);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(VALIDATED_SINGLETON_0X89C), singleton);
        SETTER_STATE = core::ptr::null_mut();
        SETTER_MODE = 0;
        SETTER_POSITION = 0;
        SETTER_CALLS = 0;
        LIMIT_OBJECT = core::ptr::null_mut();
        LIMIT_VALUE = 0;
        LIMIT_CALLS = 0;
        Reset { old_setter, old_singleton }
    }

    unsafe fn write_word(screen: &mut Screen, offset: usize, value: u32) {
        screen.0.as_mut_ptr().add(offset).cast::<u32>().write(value);
    }

    unsafe fn install_handle(screen: &mut Screen, cell: *mut *mut u8) {
        screen.0.as_mut_ptr().add(HANDLE_OFFSET).cast::<*mut *mut u8>().write(cell);
    }

    unsafe fn initialize_screen(screen: &mut Screen, active: u32, cached: u32) {
        write_word(screen, DEFAULT_POSITION_OFFSET, active);
        write_word(screen, MODE_POSITION_OFFSET, !active);
        write_word(screen, CACHED_POSITION_OFFSET, cached);
        screen.0[MODE_FLAGS_OFFSET] = 0;
    }

    #[test]
    fn matching_position_and_strict_limit_send_wrapping_delta_in_mode_zero() {
        let _setter_guard = MODE_POSITION_SETTER_TEST_LOCK.lock();
        let _singleton_guard = VALIDATED_SINGLETON_0X89C_TEST_LOCK.lock();
        let mut screen = Screen([0; SCREEN_BYTES]);
        let mut singleton = [0u8; 1];
        let mut vtable = [wrong_position_limit as usize; POSITION_LIMIT_VTABLE_INDEX + 1];
        vtable[POSITION_LIMIT_VTABLE_INDEX] = position_limit as usize;
        let mut object = VirtualObject { vtable: vtable.as_ptr() };
        let mut implementation = (&mut object as *mut VirtualObject).cast::<u8>();
        let mut cell = &mut implementation as *mut *mut u8;

        unsafe {
            let _reset = install(singleton.as_mut_ptr());
            initialize_screen(&mut screen, 100, 100);
            install_handle(&mut screen, cell);
            LIMIT_VALUE = 170;

            assert_eq!(app_screen_update_position(screen.0.as_mut_ptr(), 130), SETTER_RETURN);
            assert_eq!(screen.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), 130);
            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_STATE, singleton.as_mut_ptr());
            assert_eq!(SETTER_MODE, 0);
            assert_eq!(SETTER_POSITION, 30);
            assert_eq!(LIMIT_CALLS, 1);
            assert_eq!(LIMIT_OBJECT, implementation);
        }
    }

    #[test]
    fn stale_active_position_or_null_handle_forwards_requested_position_in_mode_one() {
        let _setter_guard = MODE_POSITION_SETTER_TEST_LOCK.lock();
        let _singleton_guard = VALIDATED_SINGLETON_0X89C_TEST_LOCK.lock();
        let mut screen = Screen([0; SCREEN_BYTES]);
        let mut singleton = [0u8; 1];

        unsafe {
            let _reset = install(singleton.as_mut_ptr());
            initialize_screen(&mut screen, 99, 100);
            install_handle(&mut screen, core::ptr::null_mut());

            assert_eq!(app_screen_update_position(screen.0.as_mut_ptr(), 0), SETTER_RETURN);
            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_MODE, 1);
            assert_eq!(SETTER_POSITION, 0);
            assert_eq!(LIMIT_CALLS, 0);
            assert_eq!(screen.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), 0);

            SETTER_CALLS = 0;
            initialize_screen(&mut screen, 7, 7);
            install_handle(&mut screen, core::ptr::null_mut());
            assert_eq!(app_screen_update_position(screen.0.as_mut_ptr(), u32::MAX), SETTER_RETURN);
            assert_eq!(SETTER_CALLS, 1);
            assert_eq!(SETTER_MODE, 1);
            assert_eq!(SETTER_POSITION, u32::MAX);
            assert_eq!(LIMIT_CALLS, 0);
            assert_eq!(screen.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), u32::MAX);
        }
    }

    #[test]
    fn zero_delta_suppresses_setter_but_stores_position() {
        let _setter_guard = MODE_POSITION_SETTER_TEST_LOCK.lock();
        let _singleton_guard = VALIDATED_SINGLETON_0X89C_TEST_LOCK.lock();
        let mut screen = Screen([0; SCREEN_BYTES]);
        let mut singleton = [0u8; 1];
        let mut vtable = [wrong_position_limit as usize; POSITION_LIMIT_VTABLE_INDEX + 1];
        vtable[POSITION_LIMIT_VTABLE_INDEX] = position_limit as usize;
        let mut object = VirtualObject { vtable: vtable.as_ptr() };
        let mut implementation = (&mut object as *mut VirtualObject).cast::<u8>();
        let mut cell = &mut implementation as *mut *mut u8;

        unsafe {
            let _reset = install(singleton.as_mut_ptr());
            initialize_screen(&mut screen, 0, 0);
            install_handle(&mut screen, cell);
            LIMIT_VALUE = 1;

            assert_eq!(app_screen_update_position(screen.0.as_mut_ptr(), 0), 0);
            assert_eq!(SETTER_CALLS, 0);
            assert_eq!(LIMIT_CALLS, 1);
            assert_eq!(screen.0.as_ptr().add(CACHED_POSITION_OFFSET).cast::<u32>().read(), 0);
        }
    }
}
