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

/// Callback ABI for the active backend's target-width vtable slot at +0x28.
#[cfg(not(target_os = "none"))]
pub type StorageBackendSlot28 = unsafe extern "C" fn(*mut u32);

/// Host replacement for the active backend's unported +0x28 callback.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_BACKEND_SLOT_28: Option<StorageBackendSlot28> = None;

/// Invokes active storage backend vtable slot +0x28 — retailOS `FUN_082bcc08`
/// at `0x082bcc08` (64 bytes including its literal-pool word; five direct,
/// unconditional inbound `bl` call sites and no predicated inbound calls).
///
/// The raw body runs through `pop {r4,pc}` at `0x082bcc44`; its literal at
/// `0x082bcc48` is the shared storage-backend state object, and `0x082bcc4c`
/// is the next separately entered function. It first prepares the active
/// backend, propagating a nonzero error. With no backend it returns 0x11;
/// otherwise it invokes the optional target-width callback at backend +0x28
/// with `output`, then returns zero.
///
/// # Deliberate deviation
///
/// Firmware builds load and call the literal target pointer at +0x28.
/// Host builds cannot dereference its narrowed 32-bit address, so they use
/// `STORAGE_BACKEND_SLOT_28` as a faithful optional-callback seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_backend_slot_28_invoke")]
pub unsafe extern "C" fn storage_backend_slot_28_invoke(output: *mut u32) -> u32 {
    let status = storage_backend_prepare();
    if status != 0 {
        return status;
    }

    let backend = ptr::addr_of!((*storage_backend_state()).active_backend).read_volatile();
    if backend == 0 {
        return 0x11;
    }

    #[cfg(target_os = "none")]
    {
        let callback_address = ((backend as *const u32).add(10)).read_volatile();
        if callback_address != 0 {
            let callback: unsafe extern "C" fn(*mut u32) = core::mem::transmute(callback_address as usize);
            callback(output);
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        if let Some(callback) = ptr::read_volatile(ptr::addr_of!(STORAGE_BACKEND_SLOT_28)) {
            callback(output);
        }
    }

    0
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

    static mut SLOT_28_CALLS: u32 = 0;

    unsafe extern "C" fn record_slot_28(output: *mut u32) {
        SLOT_28_CALLS += 1;
        output.write_volatile(0xfeed_beef);
    }

    #[test]
    fn slot_28_invocation_prepares_and_forwards_output() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved_status = reset();
            let saved_slot = STORAGE_BACKEND_SLOT_28;
            STATUS = 2;
            SLOT_28_CALLS = 0;
            STORAGE_BACKEND_SLOT_28 = Some(record_slot_28);
            let mut output = 0;

            assert_eq!(storage_backend_slot_28_invoke(&mut output), 0);
            assert_eq!(CALLS, 1);
            assert_eq!(SLOT_28_CALLS, 1);
            assert_eq!(output, 0xfeed_beef);

            STORAGE_BACKEND_SLOT_28 = saved_slot;
            restore(saved_status);
        }
    }

    #[test]
    fn slot_28_invocation_returns_prepare_errors_without_dispatching() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved_status = reset();
            let saved_slot = STORAGE_BACKEND_SLOT_28;
            STATUS = u32::MAX;
            SLOT_28_CALLS = 0;
            STORAGE_BACKEND_SLOT_28 = Some(record_slot_28);
            let mut output = 0x1234_5678;

            assert_eq!(storage_backend_slot_28_invoke(&mut output), 0x13);
            assert_eq!(CALLS, 1);
            assert_eq!(SLOT_28_CALLS, 0);
            assert_eq!(output, 0x1234_5678);

            STORAGE_BACKEND_SLOT_28 = saved_slot;
            restore(saved_status);
        }
    }

    #[test]
    fn slot_28_invocation_succeeds_when_callback_is_absent() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved_status = reset();
            let saved_slot = STORAGE_BACKEND_SLOT_28;
            STATUS = 2;
            SLOT_28_CALLS = 0;
            STORAGE_BACKEND_SLOT_28 = None;
            let mut output = 0x1234_5678;

            assert_eq!(storage_backend_slot_28_invoke(&mut output), 0);
            assert_eq!(CALLS, 1);
            assert_eq!(SLOT_28_CALLS, 0);
            assert_eq!(output, 0x1234_5678);

            STORAGE_BACKEND_SLOT_28 = saved_slot;
            restore(saved_status);
        }
    }

    #[test]
    fn slot_28_invocation_reports_missing_backend() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            let saved_status = reset();
            let saved_slot = STORAGE_BACKEND_SLOT_28;
            STATUS = 4;
            SLOT_28_CALLS = 0;
            STORAGE_BACKEND_SLOT_28 = Some(record_slot_28);
            let mut output = 0x1234_5678;

            assert_eq!(storage_backend_slot_28_invoke(&mut output), 0x11);
            assert_eq!(CALLS, 1);
            assert_eq!(SLOT_28_CALLS, 0);
            assert_eq!(output, 0x1234_5678);

            STORAGE_BACKEND_SLOT_28 = saved_slot;
            restore(saved_status);
        }
    }
}
