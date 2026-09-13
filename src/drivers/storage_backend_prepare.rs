//! Lazy storage-backend selection.
//!
//! `storage_backend_prepare` — retailOS `FUN_080e4b6c` at load address
//! **0x080e4b6c**. Raw ARM runs from `push {r4,lr}` through `pop {r4,pc}` at
//! `0x080e4bb4`: **76 bytes** (19 words). The two following words,
//! `0x089caae4` and `0x089cab24`, are its literal pool; the independently
//! entered next function starts at `0x080e4bc0`.
//!
//! Decoding every immediate ARM B/BL word in `osos.dec` finds exactly **seven**
//! inbound direct calls, all unconditional `bl`: `0x082bcb04`, `0x082bcc10`,
//! `0x082bcc50`, `0x082bcc94`, `0x082bccec`, `0x082bcda0`, and `0x082bce54`.
//! There are no predicated direct calls or direct tail branches.
//!
//! # Algorithm
//!
//! If the active backend word in the state object at `0x089caae4` is zero,
//! query `FUN_082bc7c4`. Status 2 installs the state object's embedded backend
//! at +0x0c; status 3 installs the fallback object at `0x089cab24`; status 4
//! succeeds without changing the word; every other status returns 0x13. Once
//! active backend is nonzero, it does not query or overwrite it.
//!
//! # Deliberate deviation
//!
//! The queried selector is still unported. Firmware builds invoke its verified
//! retail entry address; host builds expose a replacement seam and model both
//! fixed RAM objects with target-width words. The routine only stores pointer
//! words, so the host model never dereferences a narrowed host address.

use core::ptr;

/// Target RAM state object read through the literal at `0x080e4bb8`.
#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_STATE: usize = 0x089c_aae4;
/// Target RAM fallback object read through the literal at `0x080e4bbc`.
#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_FALLBACK: usize = 0x089c_ab24;
/// Unported selector called by the original's single direct `bl`.
#[cfg(target_os = "none")]
const RETAIL_STORAGE_BACKEND_STATUS: usize = 0x082b_c7c4;

/// Four target-width words at `0x089caae4`; the active-backend pointer is +4
/// and the embedded backend begins at +0x0c on the 32-bit firmware target.
#[repr(C)]
struct StorageBackendState {
    unknown_0: u32,
    active_backend: u32,
    unknown_8: u32,
    embedded_backend: u32,
}

#[cfg(not(target_os = "none"))]
static mut STORAGE_BACKEND_STATE: StorageBackendState = StorageBackendState {
    unknown_0: 0,
    active_backend: 0,
    unknown_8: 0,
    embedded_backend: 0,
};

#[cfg(not(target_os = "none"))]
static mut STORAGE_BACKEND_FALLBACK: [u32; 1] = [0];

/// ABI of `FUN_082bc7c4`, whose status selects the backend location.
#[cfg(not(target_os = "none"))]
pub type StorageBackendStatus = unsafe extern "C" fn() -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_backend_status() -> u32 {
    panic!("storage backend status selector is unported")
}

/// Host replacement for the unported backend-status selector.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_BACKEND_STATUS: StorageBackendStatus = missing_storage_backend_status;

#[inline(always)]
unsafe fn storage_backend_state() -> *mut StorageBackendState {
    #[cfg(target_os = "none")]
    {
        RETAIL_STORAGE_BACKEND_STATE as *mut StorageBackendState
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(STORAGE_BACKEND_STATE)
    }
}

#[inline(always)]
unsafe fn storage_backend_fallback() -> u32 {
    #[cfg(target_os = "none")]
    {
        RETAIL_STORAGE_BACKEND_FALLBACK as u32
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::addr_of_mut!(STORAGE_BACKEND_FALLBACK).cast::<u8>() as usize as u32
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn storage_backend_status() -> u32 {
    let status: unsafe extern "C" fn() -> u32 = core::mem::transmute(RETAIL_STORAGE_BACKEND_STATUS);
    status()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn storage_backend_status() -> u32 {
    ptr::read_volatile(ptr::addr_of!(STORAGE_BACKEND_STATUS))()
}

/// Selects and caches the active storage backend — retailOS `FUN_080e4b6c` @
/// `0x080e4b6c` (76 bytes; seven direct unconditional `bl` call sites).
///
/// # Safety
///
/// Firmware builds dereference the fixed state object at `0x089caae4`. The
/// status selector and the selected backend object retain their retailOS
/// contracts; this routine itself only reads and writes the state object's
/// target-width active-backend word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_backend_prepare")]
pub unsafe extern "C" fn storage_backend_prepare() -> u32 {
    let state = storage_backend_state();
    let active_backend = ptr::addr_of_mut!((*state).active_backend);
    if active_backend.read_volatile() == 0 {
        let selected = match storage_backend_status() {
            2 => ptr::addr_of_mut!((*state).embedded_backend) as usize as u32,
            3 => storage_backend_fallback(),
            4 => return 0,
            _ => return 0x13,
        };
        active_backend.write_volatile(selected);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut STATUS: u32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn record_status() -> u32 {
        CALLS += 1;
        STATUS
    }

    unsafe fn reset() -> StorageBackendStatus {
        let saved = STORAGE_BACKEND_STATUS;
        STORAGE_BACKEND_STATUS = record_status;
        STORAGE_BACKEND_STATE = StorageBackendState {
            unknown_0: 0xa5a5_a5a5,
            active_backend: 0,
            unknown_8: 0x5a5a_5a5a,
            embedded_backend: 0xdead_beef,
        };
        STORAGE_BACKEND_FALLBACK = [0xcafe_babe];
        STATUS = 0;
        CALLS = 0;
        saved
    }

    unsafe fn restore(saved: StorageBackendStatus) {
        STORAGE_BACKEND_STATUS = saved;
    }

    fn status_two_installs_embedded_backend_once() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = reset();
            STATUS = 2;

            assert_eq!(storage_backend_prepare(), 0);
            assert_eq!(CALLS, 1);
            assert_eq!(
                STORAGE_BACKEND_STATE.active_backend,
                ptr::addr_of_mut!(STORAGE_BACKEND_STATE.embedded_backend) as usize as u32
            );
            assert_eq!(STORAGE_BACKEND_STATE.unknown_0, 0xa5a5_a5a5);
            assert_eq!(STORAGE_BACKEND_STATE.unknown_8, 0x5a5a_5a5a);

            assert_eq!(storage_backend_prepare(), 0);
            assert_eq!(CALLS, 1, "a cached backend suppresses the query");
            restore(saved);
        }
    }

    fn status_three_installs_fallback_backend() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = reset();
            STATUS = 3;

            assert_eq!(storage_backend_prepare(), 0);
            assert_eq!(CALLS, 1);
            assert_eq!(
                STORAGE_BACKEND_STATE.active_backend,
                ptr::addr_of_mut!(STORAGE_BACKEND_FALLBACK).cast::<u8>() as usize as u32
            );
            restore(saved);
        }
    }

    fn status_four_succeeds_without_caching() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved = reset();
            STATUS = 4;

            assert_eq!(storage_backend_prepare(), 0);
            assert_eq!(STORAGE_BACKEND_STATE.active_backend, 0);
            assert_eq!(CALLS, 1);
            assert_eq!(storage_backend_prepare(), 0);
            assert_eq!(CALLS, 2, "status 4 leaves the cache empty");
            restore(saved);
        }
    }

    fn other_statuses_return_error_and_preserve_empty_cache() {
        let _lock = TEST_LOCK.lock();
        for status in [0, 1, 5, u32::MAX] {
            unsafe {
                let saved = reset();
                STATUS = status;

                assert_eq!(storage_backend_prepare(), 0x13, "status {status}");
                assert_eq!(STORAGE_BACKEND_STATE.active_backend, 0);
                assert_eq!(CALLS, 1);
                restore(saved);
            }
        }
    }
}
