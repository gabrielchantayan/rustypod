//! `resource_selector_index` — retailOS `FUN_0806fdec` @ `0x0806fdec`.
//!
//! Raw `osos.dec` establishes the 76-byte extent `0x0806fdec..0x0806fe38`:
//! the next separately linked function begins at `0x0806fe3c`. The body has
//! one plain direct `bl` (`namespace_provider_find`) and no predicated calls;
//! binary scanning finds three plain inbound `bl` sites (`0x08070274`,
//! `0x080702a4`, and `0x080708e0`) and no predicated inbound calls.
//!
//! Algorithm: selectors 1 through 8 map directly to indices 0 through 7.
//! Other selectors are looked up by address in the global namespace provider;
//! a found index is offset by eight, while a missing global provider or lookup
//! failure returns -1.
//!
//! Deliberate deviations: host builds replace the fixed global provider word
//! at `0x08a0eb64` with private storage. The separately ported
//! `namespace_provider_find` supplies the same target call on device and a
//! host-callable implementation for tests.

use core::ptr;

const RESOURCE_SELECTOR_PROVIDER_ADDRESS: *const *mut usize = 0x08a0_eb64usize as *const *mut usize;

#[cfg(not(target_os = "none"))]
static mut HOST_RESOURCE_SELECTOR_PROVIDER: *mut usize = ptr::null_mut();

#[inline(always)]
unsafe fn resource_selector_provider() -> *mut usize {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(RESOURCE_SELECTOR_PROVIDER_ADDRESS) }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::read_volatile(ptr::addr_of!(HOST_RESOURCE_SELECTOR_PROVIDER)) }
    }
}

/// Converts a resource selector to its provider-table index.
///
/// # Safety
///
/// On device, the global provider word and its namespace-provider object must
/// retain the retailOS layout. A non-direct selector is passed by address to
/// the provider comparator, exactly as in the original stack-local call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_selector_index(selector: i32) -> i32 {
    if (selector as u32).wrapping_sub(1) <= 7 {
        return selector.wrapping_sub(1);
    }

    let provider = unsafe { resource_selector_provider() };
    if provider.is_null() {
        return -1;
    }

    let selector_key = selector;
    let index = unsafe {
        crate::cxx::object_flags::namespace_provider_find(
            provider,
            ptr::addr_of!(selector_key) as usize,
        )
    };
    if index == -1 {
        -1
    } else {
        index.wrapping_add(8)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::object_flags::NAMESPACE_PROVIDER_SORT;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn no_op_sort(_providers: *mut usize) {}
    unsafe extern "C" fn equal_comparator(_entry: *const u8, _key: *const u8) -> i32 { 0 }

    struct ProviderReset {
        sorter: unsafe extern "C" fn(*mut usize),
    }
    impl Drop for ProviderReset {
        fn drop(&mut self) {
            unsafe {
                HOST_RESOURCE_SELECTOR_PROVIDER = ptr::null_mut();
                NAMESPACE_PROVIDER_SORT = self.sorter;
            }
        }
    }

    fn reset_provider() -> (MutexGuard<'static, ()>, ProviderReset) {
        let guard = TEST_LOCK.lock();
        let sorter = unsafe { NAMESPACE_PROVIDER_SORT };
        unsafe { HOST_RESOURCE_SELECTOR_PROVIDER = ptr::null_mut(); }
        (guard, ProviderReset { sorter })
    }

    #[test]
    fn direct_selectors_map_without_a_provider() {
        let (_guard, _reset) = reset_provider();
        assert_eq!(unsafe { resource_selector_index(1) }, 0);
        assert_eq!(unsafe { resource_selector_index(8) }, 7);
        assert_eq!(unsafe { resource_selector_index(0) }, -1);
        assert_eq!(unsafe { resource_selector_index(-1) }, -1);
    }

    #[test]
    fn provider_lookup_offsets_the_found_index() {
        let (_guard, _reset) = reset_provider();
        let table = [0usize];
        let mut provider = [1usize, table.as_ptr() as usize, 0, 1, equal_comparator as usize];
        unsafe {
            NAMESPACE_PROVIDER_SORT = no_op_sort;
            HOST_RESOURCE_SELECTOR_PROVIDER = provider.as_mut_ptr();
            assert_eq!(resource_selector_index(0x1234), 8);
        }
    }
}
