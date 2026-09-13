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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::MutexGuard;

    static mut FILL_CALL_COUNT: u32 = 0;
    static mut FILL_INDEX: u32 = u32::MAX;
    static mut FILL_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn recording_fill(index: u32) {
        FILL_CALL_COUNT += 1;
        FILL_INDEX = index;
        HOST_TBM_APP_CLIENT_CACHE[index as usize] = FILL_RESULT;
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = TBM_APP_CLIENT_CACHE_TEST_LOCK.lock();
        unsafe {
            HOST_TBM_APP_CLIENT_CACHE_DISABLED = 0;
            HOST_TBM_APP_CLIENT_CACHE = [ptr::null_mut(); 2];
            TBM_APP_CLIENT_CACHE_FILL = recording_fill;
            FILL_CALL_COUNT = 0;
            FILL_INDEX = u32::MAX;
            FILL_RESULT = ptr::null_mut();
        }
        guard
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
