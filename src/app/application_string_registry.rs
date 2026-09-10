//! `application_string_registry` — original: `FUN_0819fdb0` @
//! 0x0819fdb0 (36 bytes: 32 bytes of code plus the literal-pool word at
//! 0x0819fdd0; the separately linked next function begins at 0x0819fdd4).
//!
//! A complete `osos.dec` scan that decodes every ARM `B`/`BL` word finds
//! **11 direct inbound call sites**: all are unconditional `bl`; there are no
//! predicated `bl` forms or direct tail `b` callers.
//!
//! Algorithm: call [`application_resource_provider`]. If the returned global
//! provider is NULL, return NULL; otherwise reload the same global through its
//! literal-pool address and return that provider's 32-bit word at `+0x04`, the
//! application tagged-string registry. The registry word itself is allowed to
//! be NULL.
//!
//! Deliberate deviation: the host test fixture uses a low mapped slab because
//! retailOS stores the registry pointer as a 32-bit object word.
use core::ptr;

use super::application_resource_provider::{
    application_resource_provider, application_resource_provider_word,
};

/// application_string_registry — original: `FUN_0819fdb0` @ 0x0819fdb0
/// (36 bytes including literal pool; 11 unconditional direct `bl` call sites,
/// binary-scanned).
///
/// Returns the tagged-string registry held in the current application resource
/// provider, or NULL when no provider is installed. It does not validate either
/// the provider object's layout or its registry field.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn application_string_registry() -> *mut u8 {
    let provider = unsafe { application_resource_provider() };
    if provider.is_null() {
        ptr::null_mut()
    } else {
        unsafe {
            application_resource_provider_word()
                .cast::<u32>()
                .add(1)
                .read() as usize as *mut u8
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::application_resource_provider::{
        install_application_resource_provider_for_test, APPLICATION_RESOURCE_PROVIDER_TEST_LOCK,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    struct ProviderReset;

    impl Drop for ProviderReset {
        fn drop(&mut self) {
            unsafe {
                install_application_resource_provider_for_test(ptr::null_mut());
            }
        }
    }

    #[test]
    fn returns_null_without_dereferencing_an_absent_provider() {
        let _guard = APPLICATION_RESOURCE_PROVIDER_TEST_LOCK.lock();
        unsafe {
            install_application_resource_provider_for_test(ptr::null_mut());
            assert!(application_string_registry().is_null());
        }
    }

    #[test]
    fn returns_the_current_target_width_registry_field() {
        let _guard = APPLICATION_RESOURCE_PROVIDER_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::APPLICATION_STRING_REGISTRY, 0x40) else {
            assert!(note_missing_u32_fixture("app/application_string_registry"));
            return;
        };
        let first_registry = unsafe { slab.add(0x10) };
        let second_registry = unsafe { slab.add(0x20) };

        unsafe {
            slab.cast::<u32>().write(0x1234_5678);
            slab.add(4).cast::<u32>().write(0);
            install_application_resource_provider_for_test(slab);
            assert!(application_string_registry().is_null());

            slab.add(4).cast::<u32>().write(first_registry as usize as u32);
            assert_eq!(application_string_registry(), first_registry);

            slab.add(4).cast::<u32>().write(second_registry as usize as u32);
            assert_eq!(application_string_registry(), second_registry);
        }
    }
}
