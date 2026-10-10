//! `resource_handler_selector_index` — `FUN_080706f4` @ `0x080706f4`.
//!
//! Raw extent: 76 instruction bytes, `[0x080706f4, 0x08070740)`, followed
//! by the literal `0x08a0eab4`; next real function starts at `0x08070744`.
//! One plain outgoing BL to `namespace_provider_find`, no predicated BLs.
//! Two plain incoming BLs at `0x080702cc` and `0x08070924`, none predicated.
//!
//! Selectors 1..=7 map to indices 0..=6. Other selectors are passed by
//! address to the namespace provider at global base +4 (`0x08a0eab8`).
//! Missing provider or lookup returns -1; a found index is offset by seven.
//! Deliberate deviations: host builds use private provider storage and the
//! existing pointer-sized namespace-provider layout; target words are four
//! bytes. The stock stack padding and unconditional frame are not retained.

use core::ptr;

#[cfg(target_os = "none")]
const HANDLER_SELECTOR_PROVIDER_ADDRESS: *const *mut usize = 0x08a0_eab8usize as *const *mut usize;

#[cfg(not(target_os = "none"))]
static mut HOST_HANDLER_SELECTOR_PROVIDER: *mut usize = ptr::null_mut();

#[inline(always)]
unsafe fn handler_selector_provider() -> *mut usize {
    #[cfg(target_os = "none")]
    { unsafe { HANDLER_SELECTOR_PROVIDER_ADDRESS.read_volatile() } }
    #[cfg(not(target_os = "none"))]
    { unsafe { ptr::addr_of!(HOST_HANDLER_SELECTOR_PROVIDER).read_volatile() } }
}

/// Converts a resource handler selector to its handler-table index.
///
/// # Safety
/// The global provider and its table/comparator must be valid retailOS
/// namespace-provider objects. Comparators must accept a pointer to the
/// stack-local i32 selector, passed through the provider's word-key ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_handler_selector_index(selector: i32) -> i32 {
    if (selector as u32).wrapping_sub(1) <= 6 {
        return selector.wrapping_sub(1);
    }
    let provider = unsafe { handler_selector_provider() };
    if provider.is_null() {
        return -1;
    }
    let selector_key = selector;
    let index = unsafe {
        crate::cxx::object_flags::namespace_provider_find(
            provider, ptr::addr_of!(selector_key) as usize,
        )
    };
    if index == -1 { -1 } else { index.wrapping_add(7) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    struct ProviderReset;
    impl Drop for ProviderReset {
        fn drop(&mut self) {
            unsafe { HOST_HANDLER_SELECTOR_PROVIDER = ptr::null_mut(); }
        }
    }

    unsafe extern "C" fn compare_selector(left: *const u8, right: *const u8) -> i32 {
        let entry = unsafe { (*(left.cast::<usize>()) as *const i32).read() };
        let key = unsafe { (*(right.cast::<usize>()) as *const i32).read() };
        match entry.cmp(&key) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }

    #[test]
    fn direct_range_and_missing_provider_boundaries() {
        let _guard = TEST_LOCK.lock();
        let _reset = ProviderReset;
        unsafe { HOST_HANDLER_SELECTOR_PROVIDER = ptr::null_mut(); }
        for selector in 1..=7 {
            assert_eq!(unsafe { resource_handler_selector_index(selector) }, selector - 1);
        }
        for selector in [i32::MIN, -1, 0, 8, i32::MAX] {
            assert_eq!(unsafe { resource_handler_selector_index(selector) }, -1);
        }
    }

    #[test]
    fn lookup_uses_selector_value_offsets_hits_and_preserves_misses() {
        let _guard = TEST_LOCK.lock();
        let _reset = ProviderReset;
        let selectors = [i32::MIN, -1, 0, 7, 8, 8, i32::MAX];
        let words = selectors.each_ref().map(|value| value as *const i32 as usize);
        let mut provider = [words.len(), words.as_ptr() as usize, 1, words.len(), compare_selector as usize];
        unsafe { HOST_HANDLER_SELECTOR_PROVIDER = provider.as_mut_ptr(); }
        for (selector, expected) in [(i32::MIN, 7), (-1, 8), (0, 9), (8, 11), (i32::MAX, 13), (9, -1)] {
            assert_eq!(unsafe { resource_handler_selector_index(selector) }, expected);
        }
        // A registered built-in selector must still bypass the provider.
        assert_eq!(unsafe { resource_handler_selector_index(7) }, 6);
        provider[0] = 0;
        assert_eq!(unsafe { resource_handler_selector_index(8) }, -1);
    }
}
