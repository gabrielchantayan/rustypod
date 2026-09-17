//! Close a SQLite B-tree cursor.
//!
//! `btree_close_cursor` is retailOS `FUN_08370b40` at load address
//! `0x08370b40`. Raw ARM words establish its 128-byte extent
//! `0x08370b40..0x08370bc0`: the next separately linked function starts with
//! `push {r4,lr}` at `0x08370bc0`. It has four inbound direct call sites:
//! two plain unconditional `bl` (`0x08368748`, `0x0837b9bc`) and two
//! predicated calls (`bleq` at `0x08370a50`, `blne` at `0x0838b014`).
//!
//! SQLite's `sqlite3BtreeCloseCursor` enters the owning B-tree, refreshes the
//! shared B-tree's database pointer, clears the cursor, unlinks it from the
//! shared cursor list, releases its page owner, unlocks the shared B-tree if
//! unused, clears overflow-cache state, and leaves the B-tree. Deliberate
//! host-only deviation: the three unported boundaries use a private dispatch
//! table because host pointers widen; target builds call their retailOS
//! addresses directly. The already ported enter, leave, and owner-release
//! helpers remain direct calls on target.

use crate::cxx::release::release_via_field_0x48;
use crate::sqlite::btree_lock::{btree_enter, btree_leave};

const WORD: usize = core::mem::size_of::<*mut u8>();
const CURSOR_BTREE: usize = 0x00;
const CURSOR_PREV: usize = 0x08;
const CURSOR_NEXT: usize = 0x0c;
const CURSOR_PAGE_OWNER: usize = 0x18;
const BTREE_SHARED: usize = 0x04;
const BTREE_DATABASE: usize = 0x00;
const SHARED_DATABASE: usize = 0x04;
const SHARED_CURSOR: usize = 0x08;

type CursorBoundary = unsafe extern "C" fn(*mut u8);

#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize {
    target_offset / 4 * WORD
}

#[inline(always)]
unsafe fn pointer_at(base: *mut u8, target_offset: usize) -> *mut u8 {
    (base.add(pointer_offset(target_offset)) as *const *mut u8).read()
}

#[inline(always)]
unsafe fn set_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
    (base.add(pointer_offset(target_offset)) as *mut *mut u8).write(value);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_cursor(cursor: *mut u8) {
    let operation: CursorBoundary = core::mem::transmute(0x082c_3528usize);
    operation(cursor);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_if_unused(shared: *mut u8) {
    let operation: CursorBoundary = core::mem::transmute(0x0839_60e8usize);
    operation(shared);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_overflow_cache(cursor: *mut u8) {
    let operation: CursorBoundary = core::mem::transmute(0x082d_6d08usize);
    operation(cursor);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_cursor_boundary(_pointer: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeCloseCursorOps {
    enter: CursorBoundary,
    clear_cursor: CursorBoundary,
    unlock_if_unused: CursorBoundary,
    clear_overflow_cache: CursorBoundary,
    leave: CursorBoundary,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_CLOSE_CURSOR_OPS: BtreeCloseCursorOps = BtreeCloseCursorOps {
    enter: unavailable_cursor_boundary,
    clear_cursor: unavailable_cursor_boundary,
    unlock_if_unused: unavailable_cursor_boundary,
    clear_overflow_cache: unavailable_cursor_boundary,
    leave: unavailable_cursor_boundary,
};
#[cfg(not(target_os = "none"))]
static mut BTREE_CLOSE_CURSOR_OPS: BtreeCloseCursorOps = DEFAULT_BTREE_CLOSE_CURSOR_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeCloseCursorOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CLOSE_CURSOR_OPS))
}

/// `sqlite3BtreeCloseCursor` — retailOS `FUN_08370b40` @ `0x08370b40` (128
/// bytes; 2 inbound unconditional plain-`bl` and 2 predicated call sites).
///
/// A null `cursor->pBtree` returns zero without further access. Otherwise all
/// linked cursor fields and the page-owner pointer must be valid target-layout
/// pointer slots. The raw code writes `pBt->db` before clearing the cursor,
/// then repairs both list directions before releasing the page and dropping the
/// B-tree lease.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_close_cursor(cursor: *mut u8) -> i32 {
    let btree = pointer_at(cursor, CURSOR_BTREE);
    if btree.is_null() {
        return 0;
    }

    #[cfg(target_os = "none")]
    btree_enter(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);

    let shared = pointer_at(btree, BTREE_SHARED);
    set_pointer(shared, SHARED_DATABASE, pointer_at(btree, BTREE_DATABASE));

    #[cfg(target_os = "none")]
    clear_cursor(cursor);
    #[cfg(not(target_os = "none"))]
    (host_ops().clear_cursor)(cursor);

    let previous = pointer_at(cursor, CURSOR_PREV);
    let next = pointer_at(cursor, CURSOR_NEXT);
    if previous.is_null() {
        set_pointer(shared, SHARED_CURSOR, next);
    } else {
        set_pointer(previous, CURSOR_NEXT, next);
    }
    if !next.is_null() {
        set_pointer(next, CURSOR_PREV, previous);
    }

    release_via_field_0x48(pointer_at(cursor, CURSOR_PAGE_OWNER));

    #[cfg(target_os = "none")]
    unlock_if_unused(shared);
    #[cfg(not(target_os = "none"))]
    (host_ops().unlock_if_unused)(shared);

    #[cfg(target_os = "none")]
    clear_overflow_cache(cursor);
    #[cfg(not(target_os = "none"))]
    (host_ops().clear_overflow_cache)(cursor);

    #[cfg(target_os = "none")]
    btree_leave(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().leave)(btree);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 5] = [0; 5];
    static mut EVENT_COUNT: usize = 0;

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_enter(_pointer: *mut u8) { record(1); }
    unsafe extern "C" fn record_clear(_pointer: *mut u8) { record(2); }
    unsafe extern "C" fn record_unlock(_pointer: *mut u8) { record(3); }
    unsafe extern "C" fn record_overflow(_pointer: *mut u8) { record(4); }
    unsafe extern "C" fn record_leave(_pointer: *mut u8) { record(5); }

    struct Bench { _guard: MutexGuard<'static, ()> }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_CLOSE_CURSOR_OPS), DEFAULT_BTREE_CLOSE_CURSOR_OPS); }
        }
    }

    fn bench() -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENTS = [0; 5];
            EVENT_COUNT = 0;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_CLOSE_CURSOR_OPS), BtreeCloseCursorOps {
                enter: record_enter, clear_cursor: record_clear, unlock_if_unused: record_unlock,
                clear_overflow_cache: record_overflow, leave: record_leave,
            });
        }
        Bench { _guard: guard }
    }

    unsafe fn set_slot(base: *mut u8, offset: usize, value: *mut u8) {
        set_pointer(base, offset, value);
    }

    #[test]
    fn unlinks_head_refreshes_database_and_preserves_call_order() {
        let _bench = bench();
        let mut cursor = [0usize; 16];
        let mut next = [0usize; 16];
        let mut btree = [0usize; 4];
        let mut shared = [0usize; 4];
        let mut database = [0u8; 1];
        unsafe {
            set_slot(cursor.as_mut_ptr().cast(), CURSOR_BTREE, btree.as_mut_ptr().cast());
            set_slot(cursor.as_mut_ptr().cast(), CURSOR_NEXT, next.as_mut_ptr().cast());
            set_slot(btree.as_mut_ptr().cast(), BTREE_DATABASE, database.as_mut_ptr());
            set_slot(btree.as_mut_ptr().cast(), BTREE_SHARED, shared.as_mut_ptr().cast());
            set_slot(shared.as_mut_ptr().cast(), SHARED_CURSOR, cursor.as_mut_ptr().cast());
            btree_close_cursor(cursor.as_mut_ptr().cast());
            assert_eq!(pointer_at(shared.as_mut_ptr().cast(), SHARED_DATABASE), database.as_mut_ptr());
            assert_eq!(pointer_at(shared.as_mut_ptr().cast(), SHARED_CURSOR), next.as_mut_ptr().cast());
            assert!(pointer_at(next.as_mut_ptr().cast(), CURSOR_PREV).is_null());
            assert_eq!(EVENTS, [1, 2, 3, 4, 5]);
        }
    }

    #[test]
    fn unlinks_middle_cursor_and_null_btree_does_nothing() {
        let _bench = bench();
        let mut cursor = [0usize; 16];
        let mut previous = [0usize; 16];
        let mut next = [0usize; 16];
        let mut btree = [0usize; 4];
        let mut shared = [0usize; 4];
        unsafe {
            btree_close_cursor(cursor.as_mut_ptr().cast());
            assert_eq!(EVENT_COUNT, 0);
            set_slot(cursor.as_mut_ptr().cast(), CURSOR_BTREE, btree.as_mut_ptr().cast());
            set_slot(cursor.as_mut_ptr().cast(), CURSOR_PREV, previous.as_mut_ptr().cast());
            set_slot(cursor.as_mut_ptr().cast(), CURSOR_NEXT, next.as_mut_ptr().cast());
            set_slot(btree.as_mut_ptr().cast(), BTREE_SHARED, shared.as_mut_ptr().cast());
            btree_close_cursor(cursor.as_mut_ptr().cast());
            assert_eq!(pointer_at(previous.as_mut_ptr().cast(), CURSOR_NEXT), next.as_mut_ptr().cast());
            assert_eq!(pointer_at(next.as_mut_ptr().cast(), CURSOR_PREV), previous.as_mut_ptr().cast());
        }
    }
}
