//! `cxx_mutex_opaque_context_release_default` — original: `FUN_08262a3c` @
//! **0x08262a3c** (8 bytes).
//!
//! # Extent and calls, binary-verified
//!
//! The two raw ARM words are `e3a01000` (`mov r1,#0`) and `eaffffdf`
//! (`b 0x082629c4`). The `push {r4,r5,r6,lr}` at 0x082629c4 starts the
//! separately linked shared release implementation, proving the 8-byte extent
//! and no literal pool. Whole-image ARM B/BL-immediate decoding finds five
//! unconditional direct `bl` callers (0x080869dc, 0x0818a2fc, 0x081d69ec,
//! 0x081d7d90, and 0x081e6c00), with no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Clears the optional selector argument and tail-branches to the shared
//! release implementation at 0x082629c4. That implementation releases the
//! opaque context using its default (NULL-selector) path.
//!
//! # Deliberate deviation
//!
//! The separately linked 0x082629c4 body is not yet ported. Target builds call
//! its verified retail address indirectly; host builds use an injectable seam.
//! This replaces the stock tail `b` with an indirect call but preserves both
//! argument registers and the returned status.

use core::ptr;

const RETAIL_DEFAULT_RELEASE_TARGET: usize = 0x0826_29c4;

type DefaultReleaseTarget = unsafe extern "C" fn(*mut u32, *const u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_default_release_target(_this: *mut u32, _selector: *const u32) -> u32 {
    0
}

/// Host boundary for the unported shared release implementation.
#[cfg(not(target_os = "none"))]
pub static mut DEFAULT_RELEASE_TARGET: DefaultReleaseTarget = missing_default_release_target;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_default_release_target(this: *mut u32) -> u32 {
    let target: DefaultReleaseTarget = core::mem::transmute(RETAIL_DEFAULT_RELEASE_TARGET);
    target(this, ptr::null())
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn call_default_release_target(this: *mut u32) -> u32 {
    let target = ptr::read_volatile(ptr::addr_of!(DEFAULT_RELEASE_TARGET));
    target(this, ptr::null())
}

/// `cxx_mutex_opaque_context_release_default` — original: `FUN_08262a3c` @
/// **0x08262a3c** (8 bytes; 5 unconditional direct `bl` callers, no predicated
/// `bl` callers).
///
/// Selects the NULL-selector path of the separately linked opaque-context
/// release implementation and returns its status unchanged.
///
/// # Safety
///
/// `this` must satisfy the retail shared-release implementation's opaque object
/// contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_opaque_context_release_default(this: *mut u32) -> u32 {
    call_default_release_target(this)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_THIS: *mut u32 = ptr::null_mut();
    static mut SEEN_SELECTOR: *const u32 = ptr::null();

    struct TargetRestore;

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe {
                DEFAULT_RELEASE_TARGET = missing_default_release_target;
            }
        }
    }

    unsafe extern "C" fn recording_target(this: *mut u32, selector: *const u32) -> u32 {
        unsafe {
            SEEN_THIS = this;
            SEEN_SELECTOR = selector;
        }
        0x52
    }

    #[test]
    fn clears_selector_and_returns_shared_release_status() {
        let _lock = OPS_LOCK.lock();
        let _restore = TargetRestore;
        let mut object = 0u32;
        unsafe {
            SEEN_THIS = ptr::null_mut();
            SEEN_SELECTOR = 1usize as *const u32;
            DEFAULT_RELEASE_TARGET = recording_target;

            assert_eq!(cxx_mutex_opaque_context_release_default(&mut object), 0x52);
            assert_eq!(SEEN_THIS, &mut object as *mut u32);
            assert!(SEEN_SELECTOR.is_null());
        }
    }
}
