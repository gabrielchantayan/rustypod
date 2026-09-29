//! `storage_backend_deactivate` — retailOS `FUN_0836bc9c` at load address
//! `0x0836bc9c`.
//!
//! True extent: 80 bytes (`0x0836bc9c..0x0836bcec`): 19 instruction words
//! followed by the `"Ide1"` tag and runtime-global literals; the next real
//! function starts at `0x0836bcf4`. Raw ARM decoding finds two incoming plain
//! direct `bl` calls (0x0836be40 and 0x0836ce54) and no incoming predicated
//! `bl` calls. Its sole outgoing call is predicated (`blne 0x080564ec`).
//!
//! Algorithm: a non-null, ready `"Ide1"` storage backend has its ready word
//! at +0x44 cleared. If the runtime-global object's +0x10 waiter id is
//! nonzero, it is deleted through `waiter_delete`; success returns zero.
//! Every other input returns seven without stores or calls.
//!
//! Deliberate deviation: host builds use private backing for the fixed RAM
//! object at 0x089d0438. The global's subsystem role is not recovered, so its
//! observed waiter-id field is named only by its effect.

use crate::kernel::kobj::waiter_delete;
use core::ptr;

const IDE1_TAG: u32 = 0x3165_6449;
const READY_WORD: usize = 0x44 / 4;
const GLOBAL_WAITER_WORD: usize = 0x10 / 4;
const STATUS_INVALID: u32 = 7;

#[cfg(target_os = "none")]
const RETAIL_BACKEND_RUNTIME_GLOBAL: *const u32 = 0x089d_0438usize as *const u32;

#[cfg(not(target_os = "none"))]
static mut HOST_BACKEND_RUNTIME_GLOBAL: [u32; GLOBAL_WAITER_WORD + 1] = [0; GLOBAL_WAITER_WORD + 1];

#[inline(always)]
unsafe fn runtime_global_waiter_id() -> u32 {
    #[cfg(target_os = "none")]
    {
        unsafe { ptr::read_volatile(RETAIL_BACKEND_RUNTIME_GLOBAL.add(GLOBAL_WAITER_WORD)) }
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe {
            ptr::read_volatile(ptr::addr_of!(HOST_BACKEND_RUNTIME_GLOBAL[GLOBAL_WAITER_WORD]))
        }
    }
}

/// Clears a ready `Ide1` backend's active waiter state.
///
/// # Safety
///
/// A non-null `backend` must address at least 0x48 readable and writable bytes
/// in the 32-bit firmware layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_backend_deactivate(backend: *mut u32) -> u32 {
    if backend.is_null()
        || unsafe { backend.read() } != IDE1_TAG
        || unsafe { backend.add(READY_WORD).read() } == 0
    {
        return STATUS_INVALID;
    }

    unsafe { backend.add(READY_WORD).write(0) };
    let waiter_id = unsafe { runtime_global_waiter_id() };
    if waiter_id != 0 {
        unsafe { waiter_delete(waiter_id) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe fn install_runtime_waiter(id: u32) {
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(HOST_BACKEND_RUNTIME_GLOBAL[GLOBAL_WAITER_WORD]),
                id,
            );
        }
    }

    #[test]
    fn invalid_backends_preserve_the_ready_word() {
        let _guard = TEST_LOCK.lock();
        let mut backend = [0u32; READY_WORD + 1];

        unsafe {
            assert_eq!(storage_backend_deactivate(core::ptr::null_mut()), STATUS_INVALID);
            backend[READY_WORD] = 1;
            assert_eq!(storage_backend_deactivate(backend.as_mut_ptr()), STATUS_INVALID);
            assert_eq!(backend[READY_WORD], 1);
            backend[0] = IDE1_TAG;
            backend[READY_WORD] = 0;
            assert_eq!(storage_backend_deactivate(backend.as_mut_ptr()), STATUS_INVALID);
        }
    }

    #[test]
    fn ready_backend_is_cleared_even_when_the_global_waiter_is_absent() {
        let _guard = TEST_LOCK.lock();
        let mut backend = [0u32; READY_WORD + 1];
        backend[0] = IDE1_TAG;
        backend[READY_WORD] = 0xfeed_beef;
        unsafe {
            install_runtime_waiter(0);
            assert_eq!(storage_backend_deactivate(backend.as_mut_ptr()), 0);
        }
        assert_eq!(backend[READY_WORD], 0);
    }

    #[test]
    fn ready_backend_accepts_a_runtime_waiter() {
        let _guard = TEST_LOCK.lock();
        let mut backend = [0u32; READY_WORD + 1];
        backend[0] = IDE1_TAG;
        backend[READY_WORD] = 1;
        unsafe {
            install_runtime_waiter(0x1234);
            assert_eq!(storage_backend_deactivate(backend.as_mut_ptr()), 0);
            install_runtime_waiter(0);
        }
        assert_eq!(backend[READY_WORD], 0);
    }
}
