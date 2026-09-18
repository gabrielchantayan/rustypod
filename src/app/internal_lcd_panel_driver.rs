//! The internal LCD panel-driver singleton accessor.
//!
//! Port: [`internal_lcd_panel_driver_get`] — original: `FUN_0814ece0` @
//! `0x0814ece0` (**92 bytes: 72 bytes of code plus its 20-byte literal
//! pool; four direct `bl` instructions, all unconditional and zero
//! predicated**).
//!
//! Raw ARM ends with `pop {r4, pc}` at `0x0814ed24`. The five literal words
//! at `0x0814ed28..0x0814ed38` identify the state prefix (`0x089cc974`, with
//! guard at `+4`), fixed panel driver (`0x08ac6d2c`), `__dso_handle`
//! (`0x089ca09c`), and destructor (`0x08144998`). The next real function
//! starts at `0x0814ed3c`; the raw extent is therefore 92 bytes, not
//! Ghidra's code-only 72 bytes.
//!
//! ## Algorithm
//!
//! This is the standard ADS function-local-static sequence: test guard bit 0,
//! acquire it when clear, construct the fixed internal LCD panel driver,
//! register the constructor's return with `cxa_atexit`, release the guard,
//! then return the fixed object literal rather than the constructor result.
//!
//! ## Deliberate deviations
//!
//! The fixed RAM object and guard are crate statics. The unported constructor
//! `FUN_0814f824` remains a target seam and has a host identity default. The
//! destructor is likewise an unported target entry; host shutdown registration
//! deliberately uses an inert handler.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

/// The constructor writes through object offset `0x1e4`.
pub const INTERNAL_LCD_PANEL_DRIVER_SIZE: usize = 0x1e8;
const INTERNAL_LCD_PANEL_DRIVER_CONSTRUCTOR_ADDRESS: usize = 0x0814_f824;
const DSO_HANDLE: i32 = 0x089c_a09c;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

static mut INTERNAL_LCD_PANEL_DRIVER_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut INTERNAL_LCD_PANEL_DRIVER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;
static mut INTERNAL_LCD_PANEL_DRIVER_GUARD: u32 = 0;

/// Fixed panel-driver storage (original: `0x08ac6d2c`).
pub static mut INTERNAL_LCD_PANEL_DRIVER: [u8; INTERNAL_LCD_PANEL_DRIVER_SIZE] = [0; INTERNAL_LCD_PANEL_DRIVER_SIZE];

/// ABI of the unported in-place panel-driver constructor `FUN_0814f824`.
pub type InternalLcdPanelDriverConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_internal_lcd_panel_driver_constructor(this: *mut u8) -> *mut u8 {
    let constructor: InternalLcdPanelDriverConstructor = core::mem::transmute(INTERNAL_LCD_PANEL_DRIVER_CONSTRUCTOR_ADDRESS);
    constructor(this)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_internal_lcd_panel_driver_constructor(this: *mut u8) -> *mut u8 {
    this
}

/// Constructor seam for the `bl` at `0x0814ecfc`.
pub static mut INTERNAL_LCD_PANEL_DRIVER_CTOR: InternalLcdPanelDriverConstructor = {
    #[cfg(target_os = "none")]
    {
        firmware_internal_lcd_panel_driver_constructor
    }
    #[cfg(not(target_os = "none"))]
    {
        host_internal_lcd_panel_driver_constructor
    }
};

unsafe extern "C" fn internal_lcd_panel_driver_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn internal_lcd_panel_driver_ctor() -> InternalLcdPanelDriverConstructor {
    core::ptr::read_volatile(core::ptr::addr_of!(INTERNAL_LCD_PANEL_DRIVER_CTOR))
}

#[inline(always)]
unsafe fn internal_lcd_panel_driver_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(INTERNAL_LCD_PANEL_DRIVER_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn internal_lcd_panel_driver_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(INTERNAL_LCD_PANEL_DRIVER_CXA_GUARD_RELEASE))
}

/// `internal_lcd_panel_driver_get` — original: `FUN_0814ece0` @ `0x0814ece0`.
///
/// Lazily constructs and returns the fixed internal LCD panel driver.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.internal_lcd_panel_driver_get")]
pub unsafe extern "C" fn internal_lcd_panel_driver_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(INTERNAL_LCD_PANEL_DRIVER_GUARD);
    let object = core::ptr::addr_of_mut!(INTERNAL_LCD_PANEL_DRIVER) as *mut u8;

    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let this = internal_lcd_panel_driver_ctor()(object);
        internal_lcd_panel_driver_cxa_atexit()(this.cast::<c_void>(), internal_lcd_panel_driver_destructor, DSO_HANDLE);
        internal_lcd_panel_driver_cxa_guard_release()(guard);
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    static INTERNAL_LCD_PANEL_DRIVER_LOCK: Mutex<()> = Mutex::new(());
    static mut CTOR_CALLS: usize = 0;
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn modeled_constructor(this: *mut u8) -> *mut u8 {
        CTOR_CALLS += 1;
        this.add(INTERNAL_LCD_PANEL_DRIVER_SIZE - 1).write_volatile(0x5a);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(), arg: ptr::null_mut(), handler: internal_lcd_panel_driver_destructor, key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn storage() -> *mut u8 {
        ptr::addr_of_mut!(INTERNAL_LCD_PANEL_DRIVER) as *mut u8
    }

    fn reset() -> MutexGuard<'static, ()> {
        let lock = INTERNAL_LCD_PANEL_DRIVER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            INTERNAL_LCD_PANEL_DRIVER_GUARD = 0;
            for offset in 0..INTERNAL_LCD_PANEL_DRIVER_SIZE {
                storage().add(offset).write(0xa5);
            }
            INTERNAL_LCD_PANEL_DRIVER_CTOR = host_internal_lcd_panel_driver_constructor;
            INTERNAL_LCD_PANEL_DRIVER_CXA_ATEXIT = cxa_atexit;
            INTERNAL_LCD_PANEL_DRIVER_CXA_GUARD_RELEASE = cxa_guard_release;
            CTOR_CALLS = 0;
            CTOR_RESULT = storage();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        lock
    }

    fn restore(lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            INTERNAL_LCD_PANEL_DRIVER_CTOR = host_internal_lcd_panel_driver_constructor;
            INTERNAL_LCD_PANEL_DRIVER_CXA_ATEXIT = cxa_atexit;
            INTERNAL_LCD_PANEL_DRIVER_CXA_GUARD_RELEASE = cxa_guard_release;
            INTERNAL_LCD_PANEL_DRIVER_GUARD = 0;
        }
        drop(lock);
    }

    #[test]
    fn first_call_constructs_registers_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            INTERNAL_LCD_PANEL_DRIVER_CTOR = modeled_constructor;
            assert_eq!(internal_lcd_panel_driver_get(), storage());
            assert_eq!(CTOR_CALLS, 1);
            assert_eq!(INTERNAL_LCD_PANEL_DRIVER_GUARD, 1);
            assert_eq!(storage().add(INTERNAL_LCD_PANEL_DRIVER_SIZE - 1).read(), 0x5a);
            let node = *shutdown_chain_head();
            assert!(!node.is_null());
            assert_eq!((*node).arg as *mut u8, storage());
            assert_eq!((*node).handler as usize, internal_lcd_panel_driver_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
        }
        restore(lock);
    }

    #[test]
    fn fast_path_returns_fixed_storage_without_second_registration() {
        let lock = reset();
        unsafe {
            INTERNAL_LCD_PANEL_DRIVER_CTOR = modeled_constructor;
            internal_lcd_panel_driver_get();
            storage().add(INTERNAL_LCD_PANEL_DRIVER_SIZE - 1).write(0x31);
            assert_eq!(internal_lcd_panel_driver_get(), storage());
            assert_eq!(CTOR_CALLS, 1);
            assert_eq!(storage().add(INTERNAL_LCD_PANEL_DRIVER_SIZE - 1).read(), 0x31);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(lock);
    }

    #[test]
    fn failed_guard_acquisition_skips_constructor_and_returns_fixed_storage() {
        let lock = reset();
        unsafe {
            INTERNAL_LCD_PANEL_DRIVER_GUARD = 2;
            INTERNAL_LCD_PANEL_DRIVER_CTOR = modeled_constructor;
            assert_eq!(internal_lcd_panel_driver_get(), storage());
            assert_eq!(CTOR_CALLS, 0);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(lock);
    }
}
