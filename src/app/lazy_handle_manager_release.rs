//! Lazy shared-handle manager release.
//!
//! `lazy_handle_manager_release` — original: `switchD_082962e8::default` @
//! `0x081bc07c` (72 bytes, `0x081bc07c..0x081bc0c4`; the distinct constructor
//! prologue begins at `0x081bc0c4`). Whole-image ARM B/BL decoding finds four
//! inbound plain, unconditional `bl` callers (`0x0817f254`, `0x081f5c14`,
//! `0x081f5fcc`, and `0x082058d4`) and no predicated `bl` callers. The body
//! has one unconditional direct `bl` to `mutex_lock` and a tail `b` to
//! `mutex_unlock`.
//!
//! After locking the manager, clears its cached handle and initialized byte
//! only when initialization is exactly one, the cached handle matches the
//! supplied handle, and that handle is not the `-1` sentinel. It always
//! unlocks. Deliberate deviations: none.

use crate::app::lazy_handle_manager::LazyHandleManager;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// lazy_handle_manager_release — original: `switchD_082962e8::default` @
/// `0x081bc07c` (72 bytes; four unconditional inbound `bl` callers, no
/// predicated inbound `bl` callers).
///
/// # Safety
/// `manager` must point to a live [`LazyHandleManager`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.lazy_handle_manager_release")]
#[inline(never)]
pub unsafe extern "C" fn lazy_handle_manager_release(
    manager: *mut LazyHandleManager,
    handle: u32,
) {
    let mutex = manager.cast::<Mutex>();
    mutex_lock(mutex);

    let initialized = core::ptr::read_volatile(core::ptr::addr_of!((*manager).initialized));
    if initialized == 1 {
        let cached_handle =
            core::ptr::read_volatile(core::ptr::addr_of!((*manager).cached_handle)) as u32;
        if cached_handle == handle && cached_handle != u32::MAX {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*manager).cached_handle), -1);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*manager).initialized), 0);
        }
    }

    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex as HostMutex, MutexGuard};

    static TEST_LOCK: HostMutex<()> = HostMutex::new(());

    fn manager(cached_handle: i32, initialized: u8) -> LazyHandleManager {
        LazyHandleManager {
            mutex_words: [0; 2],
            cached_handle,
            initialized,
            padding: [0xa5; 3],
        }
    }

    #[test]
    fn matching_initialized_handle_is_released() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut manager = manager(0x1234_5678, 1);
        unsafe { lazy_handle_manager_release(&mut manager, 0x1234_5678) };
        assert_eq!(manager.cached_handle, -1);
        assert_eq!(manager.initialized, 0);
        assert_eq!(manager.padding, [0xa5; 3]);
    }

    #[test]
    fn sentinel_and_nonmatching_or_non_one_states_remain_live() {
        let _lock: MutexGuard<'_, ()> = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut sentinel = manager(-1, 1);
        let mut mismatch = manager(7, 1);
        let mut non_one = manager(7, 2);
        unsafe {
            lazy_handle_manager_release(&mut sentinel, u32::MAX);
            lazy_handle_manager_release(&mut mismatch, 8);
            lazy_handle_manager_release(&mut non_one, 7);
        }
        assert_eq!((sentinel.cached_handle, sentinel.initialized), (-1, 1));
        assert_eq!((mismatch.cached_handle, mismatch.initialized), (7, 1));
        assert_eq!((non_one.cached_handle, non_one.initialized), (7, 2));
    }
}
