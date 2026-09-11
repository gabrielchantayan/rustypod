//! Access to the application framework root singleton.
//!
//! Port:
//! - [`framework_root_get`] — original: `FUN_0814b460` @ **0x0814b460**
//!   (**16 bytes**: 12 instruction bytes plus the literal-pool word at
//!   `0x0814b46c`; **10 direct `bl` call sites, all unconditional**).
//!
//! ## Stock algorithm
//!
//! Loads the pointer held by the live framework-root global word at
//! `0x089cb1e0` and returns it unchanged. There is no initialization or NULL
//! guard: a NULL global returns NULL.
//!
//! ## Deliberate deviation
//!
//! The `0x089cxxxx` RW page contains stale data in the decrypted image and is
//! initialized at runtime. Target builds therefore load that live word
//! directly; host builds use [`FRAMEWORK_ROOT`] to model its pre-init and
//! initialized states.

use core::ptr;

/// Firmware address of the word holding the application framework root.
pub const FRAMEWORK_ROOT_GLOBAL: usize = 0x089c_b1e0;

/// Host model of the runtime-initialized framework-root global.
#[cfg(not(target_os = "none"))]
pub static mut FRAMEWORK_ROOT: *mut u8 = ptr::null_mut();

/// `framework_root_get` — original: `FUN_0814b460` @ **0x0814b460**
/// (16 bytes including the literal pool; 10 unconditional `bl` callers).
///
/// Returns the framework-root global verbatim, including NULL. Whole-image
/// ARM B/BL decoding found callers at `0x081ba458`, `0x081f0738`,
/// `0x081f0898`, `0x081f1050`, `0x081f1580`, `0x08208798`, `0x082143a4`,
/// `0x082143b0`, `0x08280bac`, and `0x08280f1c`; none is predicated, and no
/// tail branch or aligned DATA word targets this entry.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.framework_root_get")]
pub unsafe extern "C" fn framework_root_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(FRAMEWORK_ROOT_GLOBAL as *const u32) as usize as *mut u8
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(FRAMEWORK_ROOT))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn returns_null_before_the_framework_initializes() {
        let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            FRAMEWORK_ROOT = ptr::null_mut();
            assert!(framework_root_get().is_null());
        }
    }

    #[test]
    fn returns_the_initialized_pointer_without_transforming_it() {
        let _guard = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let root = 0x2468_ace0usize as *mut u8;
        unsafe {
            FRAMEWORK_ROOT = root;
            assert_eq!(framework_root_get(), root);
            FRAMEWORK_ROOT = ptr::null_mut();
        }
    }
}
