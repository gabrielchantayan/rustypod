//! `tbm_app_client_cache_get` — original: `FUN_081249f4` @ 0x081249f4
//! (68 bytes: 60 bytes of code plus its two-word literal pool; Ghidra reports
//! only the 60-byte code body, and the separately linked next function starts
//! at 0x08124a38).
//!
//! A complete `osos.dec` scan that decodes every ARM `B`/`BL` word finds
//! **7 direct inbound call sites**: all are unconditional `bl`; there are no
//! predicated `bl` forms or direct tail `b` callers.
//!
//! Algorithm: return NULL while byte `0x089cb2c4` disables the TBM app-client
//! cache. Otherwise, volatile-load the indexed pointer from the two-word table
//! at `0x089cb2dc`; a NULL entry calls the real initializer at `0x081246d8`,
//! then is loaded again and returned. Like retail, the index is not validated.
//!
//! Deliberate deviation: host builds replace fixed runtime RAM and the
//! unported initializer with private test seams. Firmware builds use the
//! original RAM addresses and an ARM literal veneer to the real initializer.
use core::ptr;
use crate::app::singletons::app_controller_get;
use crate::heap::pool::{pool_destroy, PoolControl};
use crate::heap::veneers::operator_delete;

/// ABI of the unported application-controller helper at `0x0817f37c`.
pub type TbmAppClientControllerCleanup = unsafe extern "C" fn(controller: *mut u8);

/// ABI of the unported TBM-client detach helper at `0x08124814`.
pub type TbmAppClientCacheDetach = unsafe extern "C" fn();

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_tbm_app_client_controller_cleanup(_controller: *mut u8) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_tbm_app_client_cache_detach() {}

/// Host replacement for the direct controller helper call.
#[cfg(not(target_arch = "arm"))]
static mut TBM_APP_CLIENT_CONTROLLER_CLEANUP: TbmAppClientControllerCleanup =
    missing_tbm_app_client_controller_cleanup;

/// Host replacement for the direct TBM-client detach helper call.
#[cfg(not(target_arch = "arm"))]
static mut TBM_APP_CLIENT_CACHE_DETACH: TbmAppClientCacheDetach =
    missing_tbm_app_client_cache_detach;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_tbm_app_client_controller_cleanup(controller: *mut u8);
    fn retail_tbm_app_client_cache_detach();
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_tbm_app_client_controller_cleanup(controller: *mut u8) {
    ptr::read_volatile(ptr::addr_of!(TBM_APP_CLIENT_CONTROLLER_CLEANUP))(controller);
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_tbm_app_client_cache_detach() {
    ptr::read_volatile(ptr::addr_of!(TBM_APP_CLIENT_CACHE_DETACH))();
}

// The Rust payload cannot encode direct ARM `bl` instructions to these
// retail low-memory helpers, so retain both calls through literal veneers.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_tbm_app_client_controller_cleanup
    .type retail_tbm_app_client_controller_cleanup, %function
retail_tbm_app_client_controller_cleanup:
    ldr     pc, [pc, #-4]
    .word   0x0817f37c
    .size retail_tbm_app_client_controller_cleanup, . - retail_tbm_app_client_controller_cleanup

    .p2align 2
    .globl retail_tbm_app_client_cache_detach
    .type retail_tbm_app_client_cache_detach, %function
retail_tbm_app_client_cache_detach:
    ldr     pc, [pc, #-4]
    .word   0x08124814
    .size retail_tbm_app_client_cache_detach, . - retail_tbm_app_client_cache_detach
"#
);


/// ABI of the unported TBM app-client cache initializer at `0x081246d8`.
pub type TbmAppClientCacheFill = unsafe extern "C" fn(index: u32);

#[cfg(target_os = "none")]
const TBM_APP_CLIENT_CACHE_DISABLED: *const u8 = 0x089c_b2c4usize as *const u8;
#[cfg(target_os = "none")]
const TBM_APP_CLIENT_CACHE: *const *mut u8 = 0x089c_b2dcusize as *const *mut u8;

#[cfg(not(target_os = "none"))]
static mut HOST_TBM_APP_CLIENT_CACHE_DISABLED: u8 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_TBM_APP_CLIENT_CACHE: [*mut u8; 2] = [ptr::null_mut(); 2];

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_tbm_app_client_cache_fill(_index: u32) {}

/// Host replacement for the retail cache initializer.
#[cfg(not(target_arch = "arm"))]
static mut TBM_APP_CLIENT_CACHE_FILL: TbmAppClientCacheFill = missing_tbm_app_client_cache_fill;

#[cfg(test)]
static TBM_APP_CLIENT_CACHE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[inline(always)]
unsafe fn cache_is_disabled() -> bool {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(TBM_APP_CLIENT_CACHE_DISABLED) != 0
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(HOST_TBM_APP_CLIENT_CACHE_DISABLED)) != 0
    }
}

#[inline(always)]
unsafe fn cache_entry(index: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        ptr::read_volatile(TBM_APP_CLIENT_CACHE.add(index as usize))
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile((ptr::addr_of!(HOST_TBM_APP_CLIENT_CACHE) as *const *mut u8).add(index as usize))
    }
}

#[inline(always)]
unsafe fn clear_cache_entry(index: u32) {
    #[cfg(target_os = "none")]
    {
        ptr::write_volatile(TBM_APP_CLIENT_CACHE.add(index as usize) as *mut *mut u8, ptr::null_mut());
    }

    #[cfg(not(target_os = "none"))]
    {
        ptr::write_volatile(
            (ptr::addr_of_mut!(HOST_TBM_APP_CLIENT_CACHE) as *mut *mut u8).add(index as usize),
            ptr::null_mut(),
        );
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_tbm_app_client_cache_fill(index: u32);
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_tbm_app_client_cache_fill(index: u32) {
    ptr::read_volatile(ptr::addr_of!(TBM_APP_CLIENT_CACHE_FILL))(index);
}

// The Rust payload cannot encode a direct ARM `bl` to the retail low-memory
// initializer, so retain the call through a literal veneer.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_tbm_app_client_cache_fill
    .type retail_tbm_app_client_cache_fill, %function
retail_tbm_app_client_cache_fill:
    ldr     pc, [pc, #-4]
    .word   0x081246d8
    .size retail_tbm_app_client_cache_fill, . - retail_tbm_app_client_cache_fill
"#
);

/// Returns the requested lazily initialized TBM application-client pointer.
///
/// Original: `FUN_081249f4` @ 0x081249f4. It first honors the one-byte cache
/// disable flag, returns an already initialized entry without calling the
/// initializer, and reloads a NULL entry after initialization.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tbm_app_client_cache_get")]
pub unsafe extern "C" fn tbm_app_client_cache_get(index: u32) -> *mut u8 {
    if cache_is_disabled() {
        return ptr::null_mut();
    }

    let client = cache_entry(index);
    if !client.is_null() {
        return client;
    }

    retail_tbm_app_client_cache_fill(index);
    cache_entry(index)
}

/// Disables the TBM app-client cache and releases its active pool controls.
///
/// Original: `FUN_08124794` @ `0x08124794`. Raw ARM establishes a 128-byte
/// extent: 120 bytes of code (`0x08124794..0x08124808`) followed by its
/// two-word literal pool; `0x08124814` starts the distinct next function.
/// Decoding every `B`/`BL` word in `osos.dec` finds exactly seven direct
/// inbound calls — unconditional `bl` at `0x080fee38`, `0x080ff078`,
/// `0x080ff0e0`, `0x0810bf34`, `0x08115134`, `0x08217c30`, and `0x0821df40`;
/// there are no predicated forms or direct tail branches.
///
/// A nonzero `full_cleanup` first asks the application controller to release
/// its TBM-client state. Every invocation then runs the TBM-client detach
/// helper. Slot 0 is always destroyed and cleared; slot 1 is only destroyed
/// and cleared during full cleanup. Finally, the byte cache gate is set, so
/// future cache gets return NULL.
///
/// Deliberate deviation: the two unported low-memory helpers are literal
/// veneers on firmware and private host seams for tests. The ported
/// `pool_destroy` and `operator_delete` calls remain direct.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tbm_app_client_cache_disable")]
pub unsafe extern "C" fn tbm_app_client_cache_disable(full_cleanup: u32) {
    if cache_is_disabled() {
        return;
    }

    if full_cleanup != 0 {
        retail_tbm_app_client_controller_cleanup(app_controller_get());
    }
    retail_tbm_app_client_cache_detach();

    for index in 0..2 {
        if full_cleanup == 0 && index == 1 {
            continue;
        }

        let client = cache_entry(index);
        if !client.is_null() {
            operator_delete(pool_destroy(client as *mut PoolControl) as *mut u8);
        }
        clear_cache_entry(index);
    }

    #[cfg(target_os = "none")]
    ptr::write_volatile(TBM_APP_CLIENT_CACHE_DISABLED as *mut u8, 1);
    #[cfg(not(target_os = "none"))]
    ptr::write_volatile(ptr::addr_of_mut!(HOST_TBM_APP_CLIENT_CACHE_DISABLED), 1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::MutexGuard;

    static mut FILL_CALL_COUNT: u32 = 0;
    static mut FILL_INDEX: u32 = u32::MAX;
    static mut FILL_RESULT: *mut u8 = ptr::null_mut();
    static mut DETACH_CALL_COUNT: u32 = 0;
    static mut CONTROLLER_CLEANUP_CALLS: u32 = 0;
    static mut CONTROLLER_CLEANUP_ARG: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_controller_cleanup(controller: *mut u8) {
        CONTROLLER_CLEANUP_CALLS += 1;
        CONTROLLER_CLEANUP_ARG = controller;
    }



    unsafe extern "C" fn recording_detach() {
        DETACH_CALL_COUNT += 1;
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = TBM_APP_CLIENT_CACHE_TEST_LOCK.lock();
        unsafe {
            HOST_TBM_APP_CLIENT_CACHE_DISABLED = 0;
            HOST_TBM_APP_CLIENT_CACHE = [ptr::null_mut(); 2];
            TBM_APP_CLIENT_CACHE_FILL = recording_fill;
            TBM_APP_CLIENT_CACHE_DETACH = recording_detach;
            FILL_CALL_COUNT = 0;
            FILL_INDEX = u32::MAX;
            FILL_RESULT = ptr::null_mut();
            TBM_APP_CLIENT_CONTROLLER_CLEANUP = recording_controller_cleanup;
            CONTROLLER_CLEANUP_CALLS = 0;
            CONTROLLER_CLEANUP_ARG = ptr::null_mut();

            DETACH_CALL_COUNT = 0;
        }
        guard
    }

    #[test]
    fn nonfull_disable_detaches_and_leaves_second_cache_slot_untouched() {
        let _guard = install();
        let second = 0x2468_ace0usize as *mut u8;
        unsafe {
            HOST_TBM_APP_CLIENT_CACHE[1] = second;
            tbm_app_client_cache_disable(0);

            assert_eq!(DETACH_CALL_COUNT, 1);
            assert_eq!(HOST_TBM_APP_CLIENT_CACHE_DISABLED, 1);
            assert!(HOST_TBM_APP_CLIENT_CACHE[0].is_null());
            assert_eq!(HOST_TBM_APP_CLIENT_CACHE[1], second);
        }
    }

    #[test]
    fn disabled_cache_disable_is_an_idempotent_noop() {
        let _guard = install();
        let first = 0x1357_9bdfusize as *mut u8;
        let second = 0x0bad_c0deusize as *mut u8;
        unsafe {
            HOST_TBM_APP_CLIENT_CACHE_DISABLED = 1;
            HOST_TBM_APP_CLIENT_CACHE = [first, second];
            tbm_app_client_cache_disable(1);

            assert_eq!(DETACH_CALL_COUNT, 0);
            assert_eq!(HOST_TBM_APP_CLIENT_CACHE, [first, second]);
        }
    }

    #[test]
    fn full_disable_passes_the_cached_controller_to_the_cleanup_helper() {
        let _singleton_guard = crate::app::singletons::SINGLETON_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _cache_guard = install();
        let controller = 0x0ddc_0ffeusize as *mut u8;
        unsafe {
            crate::app::singletons::APP_CONTROLLER = controller;
            tbm_app_client_cache_disable(1);

            assert_eq!(CONTROLLER_CLEANUP_CALLS, 1);
            assert_eq!(CONTROLLER_CLEANUP_ARG, controller);
            assert_eq!(DETACH_CALL_COUNT, 1);
            assert_eq!(HOST_TBM_APP_CLIENT_CACHE_DISABLED, 1);
            crate::app::singletons::APP_CONTROLLER = ptr::null_mut();
        }
    }


    unsafe extern "C" fn recording_fill(index: u32) {
        FILL_CALL_COUNT += 1;
        FILL_INDEX = index;
        HOST_TBM_APP_CLIENT_CACHE[index as usize] = FILL_RESULT;
    }


    #[test]
    fn disabled_cache_returns_null_without_filling_a_cached_entry() {
        let _guard = install();
        let cached = 0x2468_ace0usize as *mut u8;
        unsafe {
            HOST_TBM_APP_CLIENT_CACHE_DISABLED = 1;
            HOST_TBM_APP_CLIENT_CACHE[0] = cached;
            assert!(tbm_app_client_cache_get(0).is_null());
            assert_eq!(FILL_CALL_COUNT, 0);
        }
    }

    #[test]
    fn initialized_entry_returns_verbatim_without_initializer_call() {
        let _guard = install();
        let cached = 0x1357_9bdfusize as *mut u8;
        unsafe {
            HOST_TBM_APP_CLIENT_CACHE[1] = cached;
            assert_eq!(tbm_app_client_cache_get(1), cached);
            assert_eq!(FILL_CALL_COUNT, 0);
        }
    }

    #[test]
    fn missing_entry_fills_then_reloads_the_requested_slot() {
        let _guard = install();
        let filled = 0x0bad_c0deusize as *mut u8;
        unsafe {
            FILL_RESULT = filled;
            assert_eq!(tbm_app_client_cache_get(1), filled);
            assert_eq!(FILL_CALL_COUNT, 1);
            assert_eq!(FILL_INDEX, 1);
            assert_eq!(HOST_TBM_APP_CLIENT_CACHE[1], filled);
        }
    }

    #[test]
    fn missing_entry_can_remain_null_after_initializer() {
        let _guard = install();
        unsafe {
            assert!(tbm_app_client_cache_get(0).is_null());
            assert_eq!(FILL_CALL_COUNT, 1);
            assert_eq!(FILL_INDEX, 0);
        }
    }
}
