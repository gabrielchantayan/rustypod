//! `application_resource_provider` — original: `FUN_0819fe10` @
//! 0x0819fe10 (20 bytes: 16 bytes of code and its literal-pool word at
//! 0x0819fe20; the separately linked next function begins at 0x0819fe24).
//!
//! A complete `osos.dec` scan that decodes every ARM `B`/`BL` word finds
//! **18 direct inbound call sites**: all are unconditional `bl`; there are
//! no predicated `bl` forms or direct tail `b` callers.
//!
//! Algorithm: volatile-load and return the single global resource-provider
//! word at 0x089d0188. The immediately preceding `cmp r0, #0` only updates
//! condition flags and does not change the returned pointer. Callers hand the
//! result to the tagged resource-list lookup family (`FUN_08184fd4`) and one
//! sibling traverses its `+0x20` collection, establishing this as the global
//! application resource provider. There is no NULL guard; NULL is returned
//! verbatim before initialization.
//!
//! Deliberate deviation: host builds replace fixed runtime RAM with a private
//! zero-initialized word. Firmware builds load the original address directly.
use core::ptr;

/// Runtime global loaded by `FUN_0819fe10`'s literal pool word.
#[cfg(target_os = "none")]
const APPLICATION_RESOURCE_PROVIDER_ADDRESS: *const *mut u8 =
    0x089d_0188usize as *const *mut u8;

/// Host backing for the runtime-global provider word.
#[cfg(not(target_os = "none"))]
static mut HOST_APPLICATION_RESOURCE_PROVIDER: *mut u8 = ptr::null_mut();

/// Serializes host tests that replace the global provider word.
#[cfg(test)]
pub(crate) static APPLICATION_RESOURCE_PROVIDER_TEST_LOCK: parking_lot::Mutex<()> =
    parking_lot::Mutex::new(());

/// Installs a host test's replacement for the runtime provider word.
#[cfg(test)]
pub(crate) unsafe fn install_application_resource_provider_for_test(provider: *mut u8) {
    unsafe {
        ptr::addr_of_mut!(HOST_APPLICATION_RESOURCE_PROVIDER).write(provider);
    }
}

#[inline(always)]
pub(crate) unsafe fn application_resource_provider_word() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(APPLICATION_RESOURCE_PROVIDER_ADDRESS)
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_APPLICATION_RESOURCE_PROVIDER))
    }
}

/// application_resource_provider — original: `FUN_0819fe10` @ 0x0819fe10
/// (20 bytes including literal pool; 18 unconditional direct `bl` call
/// sites, binary-scanned).
///
/// Returns the global application resource provider, including NULL before
/// the application framework initializes it. It neither validates nor
/// dereferences the returned pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn application_resource_provider() -> *mut u8 {
    application_resource_provider_word()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::MutexGuard;

    fn install_provider() -> MutexGuard<'static, ()> {
        let guard = APPLICATION_RESOURCE_PROVIDER_TEST_LOCK.lock();
        unsafe {
            install_application_resource_provider_for_test(ptr::null_mut());
        }
        guard
    }

    #[test]
    fn returns_null_before_provider_initialization() {
        let _guard = install_provider();
        unsafe {
            assert!(application_resource_provider().is_null());
        }
    }

    #[test]
    fn returns_the_provider_word_verbatim_without_dereferencing_it() {
        let _guard = install_provider();
        let provider = 0x2468_ace0usize as *mut u8;
        unsafe {
            install_application_resource_provider_for_test(provider);
            assert_eq!(application_resource_provider(), provider);
            install_application_resource_provider_for_test(ptr::null_mut());
        }
    }
}

