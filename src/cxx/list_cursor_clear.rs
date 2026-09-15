//! `list_cursor_clear` — original: `FUN_081f10a0` @ `0x081f10a0` (60 bytes;
//! exact extent `0x081f10a0..0x081f10dc`, where `0x081f10dc` opens the next
//! separately linked function with `push {r4,lr}`). Raw ARM decoding finds
//! five inbound `bl` sites (four plain, one predicated); the body has one plain
//! `bl` (`0x081f10b4 -> 0x081fcea0`) and no predicated `bl`.
//!
//! If an active cursor is attached at `+0x30`, release it through the retailOS
//! cursor-cleanup routine, clear its attachment and cursor-range sentinels, and
//! reset the cached visible range at `+0x38/+0x3c`. The terminal branch to
//! `FUN_081f036c` receives a zero mode after the attachment clear, so its only
//! observable action is those two zero stores.
//!
//! # Deliberate deviations
//!
//! `FUN_081fcea0` is unported and has no recovered semantic name. It remains a
//! fixed-address target dispatch on-device and a volatile host seam. The tail
//! call to `FUN_081f036c` is inlined because the zeroed attachment makes its
//! range calculation and mode-dependent dispatch unreachable.

use core::ptr::addr_of;

const RETAIL_CURSOR_CLEANUP_ADDRESS: usize = 0x081f_cea0;

/// Target-width prefix of the list object accessed by [`list_cursor_clear`].
#[repr(C)]
pub struct ListCursorState {
    /// +0x00..+0x2c: fields untouched here.
    pub unresolved_00: [u32; 12],
    /// +0x30: active cursor target pointer.
    pub active_cursor: u32,
    /// +0x34: fields used only by the tail-called range calculator.
    pub range_scale: u32,
    /// +0x38/+0x3c: cached visible range.
    pub range_start: u32,
    pub range_end: u32,
    /// +0x40/+0x44: cursor position sentinels.
    pub cursor_position: u32,
    pub cursor_limit: u32,
    /// +0x48..+0x4c: fields untouched here.
    pub unresolved_48: [u32; 2],
    /// +0x50: target-width storage of the embedded kernel mutex.
    pub mutex_words: [u32; 2],
    /// +0x58: cursor range validity flag.
    pub range_valid: u8,
    /// +0x59: active cursor state flag.
    pub cursor_active: u8,
    /// +0x5a..+0x6f: fields untouched here.
    pub unresolved_5a: [u8; 22],
    /// +0x70: nonzero suppresses cursor clear in `list_cursor_release`.
    pub cursor_clear_suppressed: u8,
    pub unresolved_71: [u8; 3],
}

const _: () = assert!(core::mem::size_of::<ListCursorState>() == 0x74);
const _: () = assert!(core::mem::offset_of!(ListCursorState, active_cursor) == 0x30);
const _: () = assert!(core::mem::offset_of!(ListCursorState, range_start) == 0x38);
const _: () = assert!(core::mem::offset_of!(ListCursorState, cursor_position) == 0x40);
const _: () = assert!(core::mem::offset_of!(ListCursorState, cursor_active) == 0x59);

pub type CursorCleanup = unsafe extern "C" fn(u32);

#[derive(Clone, Copy)]
pub struct ListCursorClearOps {
    pub cursor_cleanup: CursorCleanup,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_cursor_cleanup(cursor: u32) {
    let cleanup: CursorCleanup = core::mem::transmute(RETAIL_CURSOR_CLEANUP_ADDRESS);
    cleanup(cursor)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_cleanup(_cursor: u32) {
    panic!("install list-cursor-clear host operations before clearing a cursor")
}

#[cfg(target_os = "none")]
pub const DEFAULT_LIST_CURSOR_CLEAR_OPS: ListCursorClearOps = ListCursorClearOps {
    cursor_cleanup: retail_cursor_cleanup,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_LIST_CURSOR_CLEAR_OPS: ListCursorClearOps = ListCursorClearOps {
    cursor_cleanup: missing_cursor_cleanup,
};

pub static mut LIST_CURSOR_CLEAR_OPS: ListCursorClearOps = DEFAULT_LIST_CURSOR_CLEAR_OPS;

#[inline(always)]
fn list_cursor_clear_ops() -> ListCursorClearOps {
    unsafe { core::ptr::read_volatile(addr_of!(LIST_CURSOR_CLEAR_OPS)) }
}

/// Clears the attached cursor and resets its cached list state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_cursor_clear(state: *mut ListCursorState) {
    let cursor = (*state).active_cursor;
    if cursor == 0 {
        return;
    }

    (list_cursor_clear_ops().cursor_cleanup)(cursor);
    (*state).cursor_position = u32::MAX;
    (*state).active_cursor = 0;
    (*state).cursor_limit = u32::MAX;
    (*state).cursor_active = 0;
    (*state).range_start = 0;
    (*state).range_end = 0;
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    pub(crate) static TEST_OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CLEANED_CURSOR: u32 = 0;

    unsafe extern "C" fn record_cursor_cleanup(cursor: u32) {
        CLEANED_CURSOR = cursor;
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = TEST_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(CLEANED_CURSOR).write(0);
            addr_of_mut!(LIST_CURSOR_CLEAR_OPS).write(ListCursorClearOps {
                cursor_cleanup: record_cursor_cleanup,
            });
        }
        guard
    }

    fn state(active_cursor: u32) -> ListCursorState {
        ListCursorState {
            unresolved_00: [0; 12], active_cursor, range_scale: 3, range_start: 4,
            range_end: 5, cursor_position: 6, cursor_limit: 7, unresolved_48: [0; 2],
            mutex_words: [0; 2], range_valid: 1, cursor_active: 1,
            unresolved_5a: [0; 22], cursor_clear_suppressed: 0, unresolved_71: [0; 3],
        }
    }

    #[test]
    fn null_cursor_leaves_state_untouched() {
        let guard = install_recorder();
        let mut list = state(0);

        unsafe { list_cursor_clear(addr_of_mut!(list)) };

        assert_eq!(list.range_start, 4);
        assert_eq!(list.cursor_position, 6);
        unsafe { assert_eq!(addr_of!(CLEANED_CURSOR).read(), 0) };
        unsafe { addr_of_mut!(LIST_CURSOR_CLEAR_OPS).write(DEFAULT_LIST_CURSOR_CLEAR_OPS) };
        drop(guard);
    }

    #[test]
    fn cursor_cleanup_precedes_state_reset() {
        let guard = install_recorder();
        let mut list = state(0x1234_5678);

        unsafe { list_cursor_clear(addr_of_mut!(list)) };

        unsafe { assert_eq!(addr_of!(CLEANED_CURSOR).read(), 0x1234_5678) };
        assert_eq!(list.active_cursor, 0);
        assert_eq!(list.range_start, 0);
        assert_eq!(list.range_end, 0);
        assert_eq!(list.cursor_position, u32::MAX);
        assert_eq!(list.cursor_limit, u32::MAX);
        assert_eq!(list.cursor_active, 0);
        unsafe { addr_of_mut!(LIST_CURSOR_CLEAR_OPS).write(DEFAULT_LIST_CURSOR_CLEAR_OPS) };
        drop(guard);
    }
}
