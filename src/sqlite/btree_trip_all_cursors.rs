//! Mark every cursor in a B-tree as faulted.
//!
//! `btree_trip_all_cursors` is retailOS `FUN_08372d8c` at load address
//! `0x08372d8c`. Raw ARM establishes the 72-byte extent
//! `0x08372d8c..0x08372dd4`: its tail branch to `btree_leave` ends the body,
//! and the following `push {r4-r10,lr}` starts a separate function. There are
//! no inbound plain `bl` calls and two inbound predicated `blne` calls
//! (`0x082d6cf0`, `0x08372b84`). The body has two unconditional plain `bl`
//! calls, to `btree_enter` and `btree_clear_cursor`, plus a tail branch to
//! `btree_leave`; no predicated calls.
//!
//! SQLite's `sqlite3BtreeTripAllCursors`: enter the B-tree, clear each
//! cursor's saved state, mark it FAULT, and retain the supplied SQLite error
//! code in its skip-result word before leaving. Deliberate deviation: none;
//! Btree and BtCursor links remain target-width words on host and device.

use crate::sqlite::btree_clear_cursor::btree_clear_cursor;
use crate::sqlite::btree_lock::{btree_enter, btree_leave};

const BTREE_SHARED: usize = 0x04;
const SHARED_CURSOR_LIST: usize = 0x08;
const CURSOR_NEXT: usize = 0x08;
const CURSOR_E_STATE: usize = 0x43;
const CURSOR_SKIP: usize = 0x50;
const CURSOR_FAULT: u8 = 3;

#[inline(always)]
unsafe fn target_pointer(base: *const u8, offset: usize) -> *mut u8 {
    base.add(offset).cast::<u32>().read() as usize as *mut u8
}

/// `sqlite3BtreeTripAllCursors` — retailOS `FUN_08372d8c` @ `0x08372d8c`
/// (72 bytes; two inbound predicated `blne` calls, two outbound plain `bl`
/// calls, and one tail branch).
///
/// `btree` and its target-layout shared B-tree and cursor list must be valid.
/// Every cursor reachable through its +0x08 next link is cleared, faulted, and
/// assigned `error_code`, including the final cursor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_trip_all_cursors(btree: *mut u8, error_code: i32) {
    btree_enter(btree);
    let shared = target_pointer(btree, BTREE_SHARED);
    let mut cursor = target_pointer(shared, SHARED_CURSOR_LIST);
    while !cursor.is_null() {
        let next = target_pointer(cursor, CURSOR_NEXT);
        btree_clear_cursor(cursor);
        cursor.add(CURSOR_E_STATE).write_volatile(CURSOR_FAULT);
        cursor.add(CURSOR_SKIP).cast::<i32>().write_volatile(error_code);
        cursor = next;
    }
    btree_leave(btree);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const SHARED: usize = 0x100;
    const FIRST_CURSOR: usize = 0x200;
    const SECOND_CURSOR: usize = 0x300;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::BTREE_TRIP_ALL_CURSORS, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u8> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        Some(base)
    }

    unsafe fn set_pointer(base: *mut u8, offset: usize, value: *mut u8) {
        base.add(offset).cast::<u32>().write(value as usize as u32);
    }

    #[test]
    fn faults_every_cursor_and_preserves_lock_depth() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(btree) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_trip_all_cursors"));
            return;
        };
        unsafe {
            let shared = btree.add(SHARED);
            let first = btree.add(FIRST_CURSOR);
            let second = btree.add(SECOND_CURSOR);
            set_pointer(btree, BTREE_SHARED, shared);
            set_pointer(shared, SHARED_CURSOR_LIST, first);
            set_pointer(first, CURSOR_NEXT, second);
            set_pointer(second, CURSOR_NEXT, core::ptr::null_mut());
            btree.add(0x09).write(1);
            btree.add(0x0a).write(1);
            btree.add(0x0c).cast::<i32>().write(0);

            btree_trip_all_cursors(btree, 4);

            for cursor in [first, second] {
                assert_eq!(cursor.add(CURSOR_E_STATE).read(), CURSOR_FAULT);
                assert_eq!(cursor.add(CURSOR_SKIP).cast::<i32>().read(), 4);
                assert_eq!(cursor.add(0x44).cast::<u32>().read(), 0);
            }
            assert_eq!(btree.add(0x0c).cast::<i32>().read(), 0);
            assert_eq!(btree.add(0x0a).read(), 0);
        }
    }

    #[test]
    fn empty_list_leaves_nonshared_lock_fields_untouched() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(btree) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/btree_trip_all_cursors"));
            return;
        };
        unsafe {
            let shared = btree.add(SHARED);
            set_pointer(btree, BTREE_SHARED, shared);
            set_pointer(shared, SHARED_CURSOR_LIST, core::ptr::null_mut());
            btree.add(0x09).write(0);
            btree.add(0x0a).write(7);
            btree.add(0x0c).cast::<i32>().write(-3);

            btree_trip_all_cursors(btree, -1);

            assert_eq!(btree.add(0x0a).read(), 7);
            assert_eq!(btree.add(0x0c).cast::<i32>().read(), -3);
        }
    }
}
