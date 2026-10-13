//! Serialized AES hardware submission — FUN_08039968 @ 0x08039968.
//! True extent [0x08039968, 0x080399e4): 124 bytes, including the
//! global-pointer literal at 0x080399e0 (120 instruction bytes).
//! Verified raw A32: two inbound plain BLs, five outbound plain BLs,
//! zero predicated BLs in either direction.
//!
//! Lazily allocate and construct an eight-byte mutex, publish it through
//! 0x089d0ea8, lock the reloaded pointer, submit all seven arguments to
//! the AES engine routine at 0x08039754, then unlock the reloaded pointer
//! and return the saved status. Initialization is deliberately NOT locked:
//! retain the original first-use race and lack of allocation failure checks.
//!
//! Deviations: existing Rust allocator/mutex ports replace their retailOS
//! callees. The unported AES submission routine uses its verified address
//! on target; host callers supply that operation explicitly. Host mutex
//! allocations use native layout size rather than the target's eight bytes.

use crate::kernel::sync_mutex::{Mutex, mutex_create, mutex_lock, mutex_unlock};

/// ABI verified from the wrapper's register saves and three stack words.
pub type AesSubmit = unsafe extern "C" fn(u32, u32, *const u8, *mut u8, *const u8, u32, *const u32) -> u32;

#[cfg(not(target_os = "none"))]
static mut HOST_MUTEX: *mut Mutex = core::ptr::null_mut();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_submit(_: u32, _: u32, _: *const u8, _: *mut u8, _: *const u8, _: u32, _: *const u32) -> u32 {
    panic!("install the host AES submission operation before calling")
}

#[cfg(not(target_os = "none"))]
pub static mut HOST_AES_SUBMIT: AesSubmit = unavailable_submit;

#[inline(always)]
unsafe fn serialized<T>(
    cache: *mut *mut T,
    create: impl FnOnce() -> *mut T,
    lock: impl FnOnce(*mut T),
    submit: impl FnOnce() -> u32,
    unlock: impl FnOnce(*mut T),
) -> u32 {
    if cache.read_volatile().is_null() {
        cache.write_volatile(create());
    }
    lock(cache.read_volatile());
    let status = submit();
    unlock(cache.read_volatile());
    status
}

/// Submit AES work under the shared engine mutex. Pointer validity and
/// asynchronous engine completion follow the original submission contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn aes_submit_serialized(
    decrypt: u32, key_source: u32, key: *const u8, output: *mut u8,
    input: *const u8, length: u32, iv: *const u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let cache = 0x089d_0ea8usize as *mut *mut Mutex;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::addr_of_mut!(HOST_MUTEX);
    #[cfg(target_os = "none")]
    let submit: AesSubmit = core::mem::transmute(0x0803_9754usize);
    #[cfg(not(target_os = "none"))]
    let submit = core::ptr::addr_of!(HOST_AES_SUBMIT).read();
    serialized(cache, || {
        let mutex = crate::heap::veneers::operator_new(core::mem::size_of::<Mutex>()).cast();
        mutex_create(mutex);
        mutex
    }, |mutex| mutex_lock(mutex),
    || submit(decrypt, key_source, key, output, input, length, iv),
    |mutex| mutex_unlock(mutex))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn initializes_once_and_releases_lock_on_success_and_errors() {
        let mut storage = 0u32;
        let pointer = &mut storage as *mut u32;
        let mut cache = core::ptr::null_mut();
        let creations = Cell::new(0);
        let held = Cell::new(false);
        let releases = Cell::new(0);
        for expected in [0, 9, 0x28, u32::MAX] {
            let result = unsafe { serialized(&mut cache, || {
                creations.set(creations.get() + 1);
                pointer
            }, |mutex| {
                assert_eq!(mutex, pointer);
                assert!(!held.replace(true));
            }, || {
                assert!(held.get());
                expected
            }, |mutex| {
                assert_eq!(mutex, pointer);
                assert!(held.replace(false));
                releases.set(releases.get() + 1);
            }) };
            assert_eq!(result, expected);
            assert!(!held.get());
        }
        assert_eq!(creations.get(), 1);
        assert_eq!(releases.get(), 4);
    }

    #[test]
    fn unlock_reloads_cache_changed_during_submission() {
        let mut first = 1u32;
        let mut second = 2u32;
        let first = &mut first as *mut u32;
        let second = &mut second as *mut u32;
        let mut cache = first;
        let cache_pointer = &mut cache as *mut *mut u32;
        unsafe { serialized(cache_pointer, || panic!("cached mutex must be reused"),
            |mutex| assert_eq!(mutex, first),
            || { cache_pointer.write(second); 9 },
            |mutex| assert_eq!(mutex, second)); }
        assert_eq!(cache, second);
    }
}
