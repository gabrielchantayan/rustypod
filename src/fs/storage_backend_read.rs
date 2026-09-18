//! Storage-backend virtual-read dispatch.
//!
//! `storage_backend_read` — retailOS `FUN_08149de8` at load address
//! **0x08149de8**, 40 raw bytes (ten ARM words; the next independently linked
//! function begins at 0x08149e10). There are four inbound direct calls, all
//! plain unconditional `bl`; there are no predicated direct calls. Its body
//! makes one unconditional indirect `blx` through vtable slot `+0x08`.
//!
//! The dispatcher holds its backend pointer at `+0x04`. The backend's first
//! word is its vtable, whose third word is invoked with the backend as `r0`
//! and the caller's block, count, buffer, and fifth argument unchanged.
//!
//! Deliberate deviation: host pointers cannot inhabit the target's 32-bit
//! dispatcher and vtable words, so host tests use a replaceable callback. The
//! target path performs the recovered volatile 32-bit word loads directly.

use core::ptr;

type StorageBackendRead = unsafe extern "C" fn(*mut u8, u32, u32, *mut u8, u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_backend_read(
    _backend: *mut u8,
    _block: u32,
    _count: u32,
    _buffer: *mut u8,
    _flags: u32,
) -> i32 {
    2
}

#[cfg(not(target_os = "none"))]
static mut HOST_STORAGE_BACKEND_READ: StorageBackendRead = missing_storage_backend_read;

/// Dispatches a storage read through the backend vtable's slot two.
///
/// # Safety
///
/// On target, `dispatcher + 4`, its backend, and the backend vtable's third
/// word must be readable target addresses, and the selected method must accept
/// these five arguments. This deliberately preserves retailOS's unchecked
/// pointer contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_backend_read")]
#[inline(never)]
pub unsafe extern "C" fn storage_backend_read(
    dispatcher: *mut u8,
    block: u32,
    count: u32,
    buffer: *mut u8,
    flags: u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let backend = ptr::read_volatile(dispatcher.cast::<u32>().add(1)) as *mut u8;
        let vtable = ptr::read_volatile(backend.cast::<u32>()) as *const u32;
        let method: StorageBackendRead = core::mem::transmute(
            ptr::read_volatile(vtable.add(2)) as usize,
        );
        let status = method(backend, block, count, buffer, flags);
        // The original uses `blx` and returns after the callback; do not tail-call it.
        core::hint::black_box(status)
    }

    #[cfg(not(target_os = "none"))]
    {
        let method = ptr::read_volatile(ptr::addr_of!(HOST_STORAGE_BACKEND_READ));
        method(dispatcher, block, count, buffer, flags)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: LazyLock<Mutex<std::vec::Vec<(usize, u32, u32, usize, u32)>>> =
        LazyLock::new(|| Mutex::new(std::vec::Vec::new()));
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn record_read(
        backend: *mut u8,
        block: u32,
        count: u32,
        buffer: *mut u8,
        flags: u32,
    ) -> i32 {
        CALLS.lock().push((backend as usize, block, count, buffer as usize, flags));
        STATUS
    }

    unsafe fn install_recorder(status: i32) {
        HOST_STORAGE_BACKEND_READ = record_read;
        STATUS = status;
        CALLS.lock().clear();
    }

    unsafe fn reset_recorder() {
        HOST_STORAGE_BACKEND_READ = missing_storage_backend_read;
        CALLS.lock().clear();
    }

    #[test]
    fn forwards_all_arguments_and_backend_status() {
        let _lock = TEST_LOCK.lock();
        unsafe { install_recorder(-0x34) };

        let status = unsafe {
            storage_backend_read(
                0x1234_5678usize as *mut u8,
                0xffff_fffe,
                0,
                core::ptr::null_mut(),
                0xa5a5_5a5a,
            )
        };

        assert_eq!(status, -0x34);
        assert_eq!(
            *CALLS.lock(),
            std::vec![(0x1234_5678, 0xffff_fffe, 0, 0, 0xa5a5_5a5a)],
        );
        unsafe { reset_recorder() };
    }

    #[test]
    fn does_not_transform_nonzero_request_values() {
        let _lock = TEST_LOCK.lock();
        unsafe { install_recorder(7) };

        let status = unsafe {
            storage_backend_read(
                0x8765_4321usize as *mut u8,
                0x1020_3040,
                0x5060_7080,
                0x2233_4455usize as *mut u8,
                1,
            )
        };

        assert_eq!(status, 7);
        assert_eq!(
            *CALLS.lock(),
            std::vec![(0x8765_4321, 0x1020_3040, 0x5060_7080, 0x2233_4455, 1)],
        );
        unsafe { reset_recorder() };
    }
}
