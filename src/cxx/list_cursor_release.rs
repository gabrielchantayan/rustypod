//! `list_cursor_release` — original: `FUN_081f0530` @ `0x081f0530` (48
//! bytes; exact extent `0x081f0530..0x081f0560`, where the separately linked
//! `FUN_081f0560` opens with `push {r4-r9,sl,lr}`). Decoding every ARM B/BL
//! immediate in `osos.dec` finds **eight direct `bl` call sites**: one
//! unconditional `bl` at `0x0821435c`, six `blne` at `0x0822ac14`,
//! `0x0822b164`, `0x0822b2f8`, `0x0822b560`, `0x0822b6e8`, and `0x0822b80c`,
//! and one `bleq` at `0x0822b660`. There are no tail branches or aligned DATA
//! words targeting this entry. The predicated calls establish that callers
//! commonly gate this member operation themselves; this routine has no NULL
//! guard.
//!
//! Locks the list object's mutex at `+0x50`. When the byte at `+0x70` is zero,
//! it clears the active cursor through `FUN_081f10a0`; it then unlocks. The
//! flag suppresses only the cursor-clear call, never the lock/unlock pair.
//!
//! # Deliberate deviations
//!
//! `FUN_081f10a0` is not yet ported, so this port uses a volatile dispatch
//! seam: target builds reach its fixed retailOS address and host tests install
//! a recorder. The stock unlock is a tail branch; calling the already ported
//! `mutex_unlock` normally is equivalent after the cleanup call returns.

use core::ptr::addr_of;

#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const RETAIL_CLEAR_ACTIVE_CURSOR_ADDRESS: usize = 0x081f_10a0;

/// Target-width prefix of the list object touched by [`list_cursor_release`].
///
/// The mutex remains two 32-bit words rather than [`Mutex`] because that type
/// contains a host-width pointer. This preserves both target offsets and host
/// fixture layout.
#[repr(C)]
pub struct ListCursorReleaseState {
    /// +0x00..+0x4c: fields untouched here.
    pub unresolved_00: [u32; 20],
    /// +0x50: target-width storage of the embedded kernel mutex.
    pub mutex_words: [u32; 2],
    /// +0x58..+0x6c: fields untouched here.
    pub unresolved_58: [u32; 6],
    /// +0x70: nonzero skips the active-cursor clear.
    pub cursor_clear_suppressed: u8,
    /// +0x71..+0x73: trailing fields outside this routine's scope.
    pub unresolved_71: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<ListCursorReleaseState>() == 0x74);
const _: () = assert!(core::mem::offset_of!(ListCursorReleaseState, mutex_words) == 0x50);
const _: () = assert!(core::mem::offset_of!(ListCursorReleaseState, cursor_clear_suppressed) == 0x70);

/// ABI of the still-unported active-cursor clear routine at `0x081f10a0`.
pub type ClearActiveCursor = unsafe extern "C" fn(*mut ListCursorReleaseState);

#[derive(Clone, Copy)]
pub struct ListCursorReleaseOps {
    pub clear_active_cursor: ClearActiveCursor,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_clear_active_cursor(state: *mut ListCursorReleaseState) {
    let clear: ClearActiveCursor = core::mem::transmute(RETAIL_CLEAR_ACTIVE_CURSOR_ADDRESS);
    clear(state)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clear_active_cursor(_state: *mut ListCursorReleaseState) {
    panic!("install list-cursor-release host operations before clearing a cursor")
}

#[cfg(target_os = "none")]
pub const DEFAULT_LIST_CURSOR_RELEASE_OPS: ListCursorReleaseOps = ListCursorReleaseOps {
    clear_active_cursor: retail_clear_active_cursor,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_LIST_CURSOR_RELEASE_OPS: ListCursorReleaseOps = ListCursorReleaseOps {
    clear_active_cursor: missing_clear_active_cursor,
};

/// Active implementation of the unported cursor-clear callee.
pub static mut LIST_CURSOR_RELEASE_OPS: ListCursorReleaseOps = DEFAULT_LIST_CURSOR_RELEASE_OPS;

#[inline(always)]
fn list_cursor_release_ops() -> ListCursorReleaseOps {
    unsafe { core::ptr::read_volatile(addr_of!(LIST_CURSOR_RELEASE_OPS)) }
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn lock_list_mutex(state: *mut ListCursorReleaseState) {
    mutex_lock((*state).mutex_words.as_mut_ptr().cast::<Mutex>());
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn lock_list_mutex(_state: *mut ListCursorReleaseState) {}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_list_mutex(state: *mut ListCursorReleaseState) {
    mutex_unlock((*state).mutex_words.as_mut_ptr().cast::<Mutex>());
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn unlock_list_mutex(_state: *mut ListCursorReleaseState) {}


/// `list_cursor_release` — original: `FUN_081f0530` @ `0x081f0530` (48 bytes).
///
/// Locks the embedded mutex, clears the active cursor only while the
/// suppression byte is zero, and then unlocks. The state pointer itself is
/// never NULL-checked, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_release(state: *mut ListCursorReleaseState) {
    lock_list_mutex(state);
    if (*state).cursor_clear_suppressed == 0 {
        (list_cursor_release_ops().clear_active_cursor)(state);
    }
    unlock_list_mutex(state);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex as HostMutex, MutexGuard};

    static OPS_LOCK: HostMutex<()> = HostMutex::new(());
    static mut CLEARED_STATE: *mut ListCursorReleaseState = core::ptr::null_mut();

    unsafe extern "C" fn record_clear_active_cursor(state: *mut ListCursorReleaseState) {
        CLEARED_STATE = state;
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CLEARED_STATE).write(core::ptr::null_mut());
            addr_of_mut!(LIST_CURSOR_RELEASE_OPS).write(ListCursorReleaseOps {
                clear_active_cursor: record_clear_active_cursor,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(LIST_CURSOR_RELEASE_OPS).write(DEFAULT_LIST_CURSOR_RELEASE_OPS);
        }
        drop(guard);
    }

    fn state(cursor_clear_suppressed: u8) -> ListCursorReleaseState {
        ListCursorReleaseState {
            unresolved_00: [0; 20],
            mutex_words: [0; 2],
            unresolved_58: [0; 6],
            cursor_clear_suppressed,
            unresolved_71: [0; 3],
        }
    }

    #[test]
    fn clears_the_active_cursor_when_not_suppressed() {
        let guard = install_recorder();
        let mut list = state(0);

        unsafe { list_cursor_release(addr_of_mut!(list)) };

        unsafe {
            assert_eq!(addr_of!(CLEARED_STATE).read(), addr_of_mut!(list));
        }
        restore_default(guard);
    }

    #[test]
    fn skips_the_clear_when_suppressed() {
        let guard = install_recorder();
        let mut list = state(1);

        unsafe { list_cursor_release(addr_of_mut!(list)) };

        unsafe {
            assert!(addr_of!(CLEARED_STATE).read().is_null());
        }
        restore_default(guard);
    }
}
