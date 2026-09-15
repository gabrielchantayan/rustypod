//! `list_cursor_release` — original: `FUN_081f0530` @ `0x081f0530` (48
//! bytes; exact extent `0x081f0530..0x081f0560`, where the separately linked
//! `FUN_081f0560` opens with `push {r4-r9,sl,lr}`). Decoding every ARM B/BL
//! immediate in `osos.dec` finds **eight direct `bl` call sites**: one
//! unconditional `bl` at `0x0821435c`, six `blne` at `0x0822ac14`,
//! `0x0822b164`, `0x0822b2f8`, `0x0822b560`, `0x0822b6e8`, and `0x0822b80c`,
//! and one `bleq` at `0x0822b660`. There are no tail branches or aligned DATA
//! words targeting this entry.
//!
//! Locks the list object's mutex at `+0x50`. When the byte at `+0x70` is zero,
//! it clears the active cursor; it then unlocks. The flag suppresses only the
//! cursor-clear call, never the lock/unlock pair.
//!
//! # Deliberate deviations
//!
//! The stock unlock is a tail branch; calling the already ported `mutex_unlock`
//! normally is equivalent after `list_cursor_clear` returns.

use crate::cxx::list_cursor_clear::{list_cursor_clear, ListCursorState};
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

pub type ListCursorReleaseState = ListCursorState;

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

/// Releases the active cursor unless cursor clearing is suppressed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_release(state: *mut ListCursorReleaseState) {
    lock_list_mutex(state);
    if (*state).cursor_clear_suppressed == 0 {
        list_cursor_clear(state);
    }
    unlock_list_mutex(state);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::list_cursor_clear::{
        tests::TEST_OPS_LOCK, CursorCleanup, ListCursorClearOps,
        DEFAULT_LIST_CURSOR_CLEAR_OPS, LIST_CURSOR_CLEAR_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};

    static mut CLEANED_CURSOR: u32 = 0;

    unsafe extern "C" fn record_cursor_cleanup(cursor: u32) {
        CLEANED_CURSOR = cursor;
    }

    fn state(cursor_clear_suppressed: u8) -> ListCursorReleaseState {
        ListCursorReleaseState {
            unresolved_00: [0; 12], active_cursor: 0x1234, range_scale: 0,
            range_start: 0, range_end: 0, cursor_position: 0, cursor_limit: 0,
            unresolved_48: [0; 2], mutex_words: [0; 2], range_valid: 0,
            cursor_active: 1, unresolved_5a: [0; 22], cursor_clear_suppressed,
            unresolved_71: [0; 3],
        }
    }

    #[test]
    fn clears_the_active_cursor_when_not_suppressed() {
        let guard = TEST_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CLEANED_CURSOR).write(0);
            addr_of_mut!(LIST_CURSOR_CLEAR_OPS).write(ListCursorClearOps {
                cursor_cleanup: record_cursor_cleanup as CursorCleanup,
            });
        }
        let mut list = state(0);

        unsafe { list_cursor_release(addr_of_mut!(list)) };

        unsafe { assert_eq!(addr_of!(CLEANED_CURSOR).read(), 0x1234) };
        assert_eq!(list.active_cursor, 0);
        unsafe { addr_of_mut!(LIST_CURSOR_CLEAR_OPS).write(DEFAULT_LIST_CURSOR_CLEAR_OPS) };
        drop(guard);
    }

    #[test]
    fn skips_the_clear_when_suppressed() {
        let guard = TEST_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut list = state(1);

        unsafe { list_cursor_release(addr_of_mut!(list)) };

        assert_eq!(list.active_cursor, 0x1234);
        drop(guard);
    }
}
