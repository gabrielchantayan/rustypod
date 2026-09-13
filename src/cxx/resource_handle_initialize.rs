//! `resource_handle_initialize_for_current_thread` — retailOS `FUN_08262110`
//! at `0x08262110` (40 bytes; `0x08262110..0x08262138`).
//!
//! Raw ARM establishes the extent: `pop {r4,pc}` at `0x08262134` is followed
//! immediately by the distinct `push {r4,lr}` entry at `0x08262138`; there is
//! no literal pool. Decoding every ARM B/BL word in `osos.dec` finds six direct
//! call sites, all unconditional plain `bl` (at `0x08165310`, `0x081654a0`,
//! `0x08193990`, `0x081d7768`, `0x081d77d8`, and `0x0820117c`). There are no
//! predicated B/BL calls and no word-aligned DATA references to this address.
//!
//! The constructor gets the running-thread object through the 0x082e8530
//! tail veneer to the ROM query at 0x080a3e68, stores its target address at
//! +0x00, clears the operation-status word at +0x04, sets the skip-release
//! byte at +0x08, and returns the original handle pointer.
//!
//! Deliberate deviation: host builds route the unavailable ROM query through
//! the pre-existing `kernel::posix_mutex::POSIX_MUTEX_OPS.current_thread`
//! seam. Target builds invoke the verified ROM entry directly; bypassing the
//! pure 0x082e8530 tail veneer does not change its result.
//! Field writes are volatile solely to preserve the raw +0/+4/+8 store order
//! rather than allowing LLVM to combine or reorder them; values are unchanged.


#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

#[cfg(not(target_os = "none"))]
use crate::kernel::posix_mutex::POSIX_MUTEX_OPS;

use super::resource_handle_release::ResourceHandle;

#[cfg(target_os = "none")]
const RETAIL_CURRENT_THREAD: usize = 0x080a_3e68;

#[cfg(target_os = "none")]
type CurrentThread = unsafe extern "C" fn() -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn current_thread() -> u32 {
    let query: CurrentThread = core::mem::transmute(RETAIL_CURRENT_THREAD);
    query()
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn current_thread() -> u32 {
    let ops = core::ptr::read_volatile(addr_of!(POSIX_MUTEX_OPS));
    (ops.current_thread)()
}

/// Initializes a handle associated with the current running thread.
///
/// `handle` must be valid and writable through +0x08. The raw implementation
/// has no NULL guard. Its returned pointer is exactly `handle`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_handle_initialize_for_current_thread(
    handle: *mut ResourceHandle,
) -> *mut ResourceHandle {
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*handle).resource_address), current_thread());
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*handle).operation_status), 0);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*handle).skip_release), 1);
    handle
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::posix_mutex::{
        PosixMutexOps, DEFAULT_POSIX_MUTEX_OPS, POSIX_MUTEX_OPS,
    };
    use crate::testing::POSIX_MUTEX_OPS_TEST_LOCK;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;

    static mut CURRENT_THREAD_CALLS: u32 = 0;

    unsafe extern "C" fn record_current_thread() -> u32 {
        CURRENT_THREAD_CALLS += 1;
        0xfedc_ba98
    }

    fn install_current_thread_recorder() -> MutexGuard<'static, ()> {
        let guard = POSIX_MUTEX_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CURRENT_THREAD_CALLS).write(0);
            addr_of_mut!(POSIX_MUTEX_OPS).write(PosixMutexOps {
                current_thread: record_current_thread,
                ..DEFAULT_POSIX_MUTEX_OPS
            });
        }
        guard
    }

    struct ResetPosixMutexOps;

    impl Drop for ResetPosixMutexOps {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(POSIX_MUTEX_OPS).write(DEFAULT_POSIX_MUTEX_OPS) };
        }
    }

    #[test]
    fn initializes_target_layout_and_returns_the_original_handle() {
        let _guard = install_current_thread_recorder();
        let _reset = ResetPosixMutexOps;
        let mut handle = ResourceHandle {
            resource_address: 0,
            operation_status: u32::MAX,
            skip_release: 0,
        };

        let result = unsafe { resource_handle_initialize_for_current_thread(&mut handle) };

        assert_eq!(result, addr_of_mut!(handle));
        assert_eq!(handle.resource_address, 0xfedc_ba98);
        assert_eq!(handle.operation_status, 0);
        assert_eq!(handle.skip_release, 1);
        unsafe { assert_eq!(addr_of!(CURRENT_THREAD_CALLS).read(), 1) };
    }

    #[test]
    fn reinitializing_each_handle_queries_the_current_thread_each_time() {
        let _guard = install_current_thread_recorder();
        let _reset = ResetPosixMutexOps;
        let mut first = ResourceHandle {
            resource_address: 1,
            operation_status: 2,
            skip_release: 3,
        };
        let mut second = ResourceHandle {
            resource_address: 4,
            operation_status: 5,
            skip_release: 6,
        };

        unsafe {
            resource_handle_initialize_for_current_thread(&mut first);
            resource_handle_initialize_for_current_thread(&mut second);
        }

        assert_eq!((first.resource_address, first.operation_status, first.skip_release),
                   (0xfedc_ba98, 0, 1));
        assert_eq!((second.resource_address, second.operation_status, second.skip_release),
                   (0xfedc_ba98, 0, 1));
        unsafe { assert_eq!(addr_of!(CURRENT_THREAD_CALLS).read(), 2) };
    }
}
