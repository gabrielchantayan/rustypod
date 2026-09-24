//! `resource_selector_record` — retailOS `FUN_0806fdb4` @ `0x0806fdb4`.
//!
//! Raw `osos.dec` words establish the 48-byte extent
//! `0x0806fdb4..0x0806fde3`; the next real function begins at `0x0806fdec`.
//! There are three inbound plain `bl` calls (`0x08070290`, `0x080702b0`, and
//! `0x080708ec`) and no predicated inbound calls. The non-direct path is a
//! tail branch, not a `bl`, to [`crate::cxx::object_flags::namespace_provider_at`].
//!
//! Algorithm: negative selectors return null. Selectors zero through seven
//! select one of eight 28-byte records at `0x08a0eb68`; later selectors use
//! the namespace-provider object pointer at `0x08a0eb64`, indexed after that
//! fixed prefix.
//!
//! Deliberate deviations: host builds replace both fixed firmware globals with
//! private storage. Target builds retain the exact word loads and seven-word
//! record stride.

use core::ptr;

const RESOURCE_SELECTOR_PROVIDER_ADDRESS: *const *const u32 = 0x08a0_eb64usize as *const *const u32;
const RESOURCE_SELECTOR_RECORDS_ADDRESS: *const u32 = 0x08a0_eb68usize as *const u32;
const FIXED_SELECTOR_COUNT: u32 = 8;
const RECORD_WORDS: usize = 7;

#[cfg(not(target_os = "none"))]
static mut HOST_RESOURCE_SELECTOR_PROVIDER: *const u32 = ptr::null();
#[cfg(not(target_os = "none"))]
static mut HOST_RESOURCE_SELECTOR_RECORDS: [[u32; RECORD_WORDS]; FIXED_SELECTOR_COUNT as usize] =
    [[0; RECORD_WORDS]; FIXED_SELECTOR_COUNT as usize];

#[inline(always)]
unsafe fn resource_selector_provider() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { RESOURCE_SELECTOR_PROVIDER_ADDRESS.read_volatile() }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::addr_of!(HOST_RESOURCE_SELECTOR_PROVIDER).read_volatile() }
    }
}

#[inline(always)]
unsafe fn fixed_selector_records() -> *const u32 {
    #[cfg(target_os = "none")]
    {
        RESOURCE_SELECTOR_RECORDS_ADDRESS
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of!(HOST_RESOURCE_SELECTOR_RECORDS).cast()
    }
}

/// Returns the record for a resource selector, or null for a negative selector.
///
/// # Safety
///
/// On device, the fixed record table and namespace-provider object must retain
/// their retailOS layouts. A non-null provider with an invalid table pointer
/// faults in the tail-called provider accessor, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_selector_record(selector: i32) -> *const u32 {
    if selector < 0 {
        return ptr::null();
    }

    let selector = selector as u32;
    if selector < FIXED_SELECTOR_COUNT {
        return unsafe { fixed_selector_records().add(selector as usize * RECORD_WORDS) };
    }

    unsafe {
        crate::cxx::object_flags::namespace_provider_at(
            resource_selector_provider(),
            selector - FIXED_SELECTOR_COUNT,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct ProviderReset;

    impl Drop for ProviderReset {
        fn drop(&mut self) {
            unsafe { HOST_RESOURCE_SELECTOR_PROVIDER = ptr::null(); }
        }
    }

    fn reset_provider() -> (MutexGuard<'static, ()>, ProviderReset) {
        let guard = TEST_LOCK.lock();
        unsafe { HOST_RESOURCE_SELECTOR_PROVIDER = ptr::null(); }
        (guard, ProviderReset)
    }

    #[test]
    fn negative_selectors_return_null() {
        let (_guard, _reset) = reset_provider();
        assert!(unsafe { resource_selector_record(-1) }.is_null());
        assert!(unsafe { resource_selector_record(i32::MIN) }.is_null());
    }

    #[test]
    fn fixed_selectors_use_seven_word_records() {
        let (_guard, _reset) = reset_provider();
        let records = unsafe { fixed_selector_records() };
        assert_eq!(unsafe { resource_selector_record(0) }, records);
        assert_eq!(unsafe { resource_selector_record(7) }, unsafe { records.add(7 * RECORD_WORDS) });
    }

    #[test]
    fn later_selectors_use_the_provider_after_the_fixed_prefix() {
        let (_guard, _reset) = reset_provider();
        let expected = [0xfeed_beefu32];
        let table = [expected.as_ptr()];
        let mut provider = [0u8; 4 + core::mem::size_of::<*const u32>()];
        unsafe {
            (provider.as_mut_ptr().add(4) as *mut *const *const u32).write_unaligned(table.as_ptr());
            HOST_RESOURCE_SELECTOR_PROVIDER = provider.as_ptr().cast();
            assert_eq!(resource_selector_record(8), expected.as_ptr());
        }
    }
}
