//! `lazy_handle_manager_is_initialized` — original: `FUN_081bbf78` @
//! `0x081bbf78` (32 bytes, `0x081bbf78..0x081bbf98`; the next independently
//! decoded function starts at `0x081bbf98`).
//!
//! Raw ARM decoding verifies two direct, unconditional plain `bl` instructions
//! (`mutex_lock` and `mutex_unlock`) and no predicated `bl` instructions.
//! Ghidra identifies three inbound `bl` call sites.
//!
//! Locks the lazy handle manager, captures its initialized byte at `+0x0c`,
//! unlocks it, then returns that byte as an ARM ABI integer. No deliberate
//! deviations: the existing [`LazyHandleManager`] layout supplies the observed
//! target words, and the already ported mutex calls preserve the lock boundary.

use crate::app::lazy_handle_manager::LazyHandleManager;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Reads the lazy handle manager's initialized byte while holding its mutex.
///
/// # Safety
///
/// `manager` must point to a valid [`LazyHandleManager`] whose leading words
/// are a valid [`Mutex`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn lazy_handle_manager_is_initialized(
    manager: *mut LazyHandleManager,
) -> u32 {
    unsafe {
        mutex_lock(manager.cast::<Mutex>());
        let initialized = core::ptr::read_volatile(core::ptr::addr_of!((*manager).initialized));
        mutex_unlock(manager.cast::<Mutex>());
        u32::from(initialized)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn returns_each_initialized_byte_without_changing_manager_state() {
        for initialized in [0, 1, 0x7f, 0xff] {
            let mut manager = LazyHandleManager {
                mutex_words: [0; 2],
                cached_handle: -1,
                initialized,
                padding: [0xa5; 3],
            };

            assert_eq!(
                unsafe { lazy_handle_manager_is_initialized(&mut manager) },
                u32::from(initialized),
            );
            assert_eq!(manager.cached_handle, -1);
            assert_eq!(manager.initialized, initialized);
            assert_eq!(manager.padding, [0xa5; 3]);
        }
    }
}
