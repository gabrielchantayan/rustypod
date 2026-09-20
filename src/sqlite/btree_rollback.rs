//! Roll back a SQLite B-tree transaction.
//!
//! `btree_rollback` is retailOS `FUN_08372b50` at load address `0x08372b50`.
//! Raw ARM establishes the 200-byte extent `0x08372b50..0x08372c18`: the
//! following `push {r4-r6,lr}` starts a distinct function. It has three
//! inbound unconditional plain-`bl` calls (`0x082bd938`, `0x08370a60`, and
//! `0x08382500`). Its body has seven unconditional plain `bl` instructions
//! and two predicated calls (`blne 0x08372d8c`, `bleq 0x0836761c`).
//!
//! SQLite's `sqlite3BtreeRollback` saves active cursors, trips them if saving
//! fails, rolls the pager back for a write transaction, refreshes page one,
//! updates transaction counts, and releases an unused shared B-tree. The
//! pager, cursor-save/trip, and unlock helpers are still retailOS boundaries;
//! host builds dispatch those three calls through a private table because their
//! target-layout pointers are 32-bit. The direct ports remain direct calls.

use crate::cxx::context_child_handle::context_child_handle_acquire;
use crate::cxx::release::release_via_field_0x48;
use crate::sqlite::btree_lock::{btree_enter, btree_leave};

const WORD: usize = core::mem::size_of::<*mut u8>();
const BTREE_DATABASE: usize = 0x00;
const BTREE_SHARED: usize = 0x04;
#[cfg(target_os = "none")]
const BTREE_IN_TRANS: usize = 0x08;
#[cfg(not(target_os = "none"))]
const BTREE_IN_TRANS: usize = 0x10;
const SHARED_DATABASE: usize = 0x04;
const SHARED_PAGER: usize = 0x00;
const SHARED_ROLLBACK_MARK: usize = 0x18;
const SHARED_IN_TRANS: usize = 0x30;
const SHARED_TRANSACTION_COUNT: usize = 0x34;
const SHARED_UNLOCK_GUARD: usize = 0x10;
const TRANS_WRITE: u8 = 2;

type SaveCursors = unsafe extern "C" fn(*mut u8, u32, u32) -> i32;
type TripCursors = unsafe extern "C" fn(*mut u8, i32);
type PagerRollback = unsafe extern "C" fn(*mut u8) -> i32;
type UnlockIfUnused = unsafe extern "C" fn(*mut u8);
type BtreeLock = unsafe extern "C" fn(*mut u8);

#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize { target_offset / 4 * WORD }

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
unsafe fn save_all_cursors(shared: *mut u8) -> i32 {
    let operation: SaveCursors = core::mem::transmute(0x0836_84fcusize);
    operation(shared, 0, 0)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn trip_all_cursors(btree: *mut u8, rc: i32) {
    let operation: TripCursors = core::mem::transmute(0x0837_2d8cusize);
    operation(btree, rc);
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_rollback(pager: *mut u8) -> i32 {
    let operation: PagerRollback = core::mem::transmute(0x0837_ea84usize);
    operation(pager)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_if_unused(shared: *mut u8) {
    let operation: UnlockIfUnused = core::mem::transmute(0x0839_60e8usize);
    operation(shared);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_save(_shared: *mut u8, _filter: u32, _except: u32) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_trip(_btree: *mut u8, _rc: i32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager_rollback(_pager: *mut u8) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_unlock(_shared: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_btree_lock(_btree: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeRollbackOps {
    save_cursors: SaveCursors,
    trip_cursors: TripCursors,
    pager_rollback: PagerRollback,
    unlock_if_unused: UnlockIfUnused,
    enter: BtreeLock,
    leave: BtreeLock,
}
#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_ROLLBACK_OPS: BtreeRollbackOps = BtreeRollbackOps {
    save_cursors: unavailable_save, trip_cursors: unavailable_trip,
    pager_rollback: unavailable_pager_rollback, unlock_if_unused: unavailable_unlock,
    enter: unavailable_btree_lock, leave: unavailable_btree_lock,
};
#[cfg(not(target_os = "none"))]
static mut BTREE_ROLLBACK_OPS: BtreeRollbackOps = DEFAULT_BTREE_ROLLBACK_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeRollbackOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_ROLLBACK_OPS))
}

/// `sqlite3BtreeRollback` — retailOS `FUN_08372b50` @ `0x08372b50` (200
/// bytes; three inbound unconditional plain-`bl` calls, seven plain outbound
/// `bl` instructions, and `blne`/`bleq` predicated calls).
///
/// `btree` and its target-layout shared B-tree pointer must be valid. A cursor
/// save error is returned unless pager rollback reports a nonzero error, which
/// replaces it. The page-one acquire error is deliberately ignored; its handle
/// is released only on success, exactly as the raw conditional `bleq` does.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_rollback(btree: *mut u8) -> i32 {
    let shared = pointer_at(btree, BTREE_SHARED);
    #[cfg(target_os = "none")]
    btree_enter(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);
    set_pointer(shared, SHARED_DATABASE, pointer_at(btree, BTREE_DATABASE));

    #[cfg(target_os = "none")]
    let mut rc = save_all_cursors(shared);
    #[cfg(not(target_os = "none"))]
    let mut rc = (host_ops().save_cursors)(shared, 0, 0);
    if rc != 0 {
        #[cfg(target_os = "none")]
        trip_all_cursors(btree, rc);
        #[cfg(not(target_os = "none"))]
        (host_ops().trip_cursors)(btree, rc);
    }

    if btree.add(BTREE_IN_TRANS).read() == TRANS_WRITE {
        shared.add(SHARED_ROLLBACK_MARK).cast::<u32>().write(0);
        let pager = pointer_at(shared, SHARED_PAGER);
        #[cfg(target_os = "none")]
        let pager_rc = pager_rollback(pager);
        #[cfg(not(target_os = "none"))]
        let pager_rc = (host_ops().pager_rollback)(pager);
        if pager_rc != 0 { rc = pager_rc; }

        let mut page = core::ptr::null_mut();
        if context_child_handle_acquire(shared, 1, &mut page, 0) == 0 {
            release_via_field_0x48(page);
        }
        shared.add(SHARED_IN_TRANS).write(1);
    }

    if btree.add(BTREE_IN_TRANS).read() != 0 {
        let transactions = shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>();
        let remaining = transactions.read().wrapping_sub(1);
        transactions.write(remaining);
        if remaining == 0 { shared.add(SHARED_IN_TRANS).write(0); }
    }
    btree.add(BTREE_IN_TRANS).write(0);
    shared.add(SHARED_UNLOCK_GUARD).write(0);
    #[cfg(target_os = "none")]
    unlock_if_unused(shared);
    #[cfg(not(target_os = "none"))]
    (host_ops().unlock_if_unused)(shared);
    #[cfg(target_os = "none")]
    btree_leave(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().leave)(btree);
    rc
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 4] = [0; 4];
    static mut EVENT_COUNT: usize = 0;
    static mut SAVE_RESULT: i32 = 0;
    static mut PAGER_RESULT: i32 = 0;

    unsafe fn event(value: u8) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn save(_shared: *mut u8, filter: u32, except: u32) -> i32 {
        assert_eq!((filter, except), (0, 0)); event(1); SAVE_RESULT
    }
    unsafe extern "C" fn trip(_btree: *mut u8, rc: i32) { assert_eq!(rc, SAVE_RESULT); event(2); }
    unsafe extern "C" fn rollback(_pager: *mut u8) -> i32 { event(3); PAGER_RESULT }
    unsafe extern "C" fn unlock(_shared: *mut u8) { event(4); }
    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench { fn drop(&mut self) { unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_ROLLBACK_OPS), DEFAULT_BTREE_ROLLBACK_OPS); } } }
    fn bench(save_result: i32, pager_result: i32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENTS = [0; 4]; EVENT_COUNT = 0; SAVE_RESULT = save_result; PAGER_RESULT = pager_result;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_ROLLBACK_OPS), BtreeRollbackOps { save_cursors: save, trip_cursors: trip, pager_rollback: rollback, unlock_if_unused: unlock, enter: unavailable_btree_lock, leave: unavailable_btree_lock });
        }
        Bench { _guard: guard }
    }
    unsafe fn initialize_fixture(btree: *mut u8, shared: *mut u8, database: *mut u8) {
        set_pointer(btree, BTREE_SHARED, shared);
        set_pointer(btree, BTREE_DATABASE, database);
    }
    #[test]
    fn write_rollback_trips_cursors_and_pager_error_wins() {
        let _bench = bench(7, 13);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16]; let mut database = [0u8; 1];
        unsafe { initialize_fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), database.as_mut_ptr()); }
        unsafe {
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(TRANS_WRITE);
            shared.as_mut_ptr().cast::<u8>().add(SHARED_TRANSACTION_COUNT).cast::<u32>().write(1);
            assert_eq!(btree_rollback(btree.as_mut_ptr().cast()), 13);
            assert_eq!(EVENTS, [1, 2, 3, 4]);
            assert_eq!(shared.as_ptr().cast::<u8>().add(pointer_offset(SHARED_DATABASE)).cast::<*mut u8>().read(), database.as_mut_ptr());
            assert_eq!(shared.as_ptr().cast::<u8>().add(SHARED_IN_TRANS).read(), 0);
            assert_eq!(btree.as_ptr().cast::<u8>().add(BTREE_IN_TRANS).read(), 0);
        }
    }
    #[test]
    fn read_transaction_skips_pager_and_preserves_save_error() {
        let _bench = bench(7, 0);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16]; let mut database = [0u8; 1];
        unsafe { initialize_fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), database.as_mut_ptr()); }
        unsafe {
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(1);
            shared.as_mut_ptr().cast::<u8>().add(SHARED_TRANSACTION_COUNT).cast::<u32>().write(2);
            assert_eq!(btree_rollback(btree.as_mut_ptr().cast()), 7);
            assert_eq!(EVENTS, [1, 2, 4, 0]);
            assert_eq!(shared.as_ptr().cast::<u8>().add(SHARED_TRANSACTION_COUNT).cast::<u32>().read(), 1);
            assert_eq!(shared.as_ptr().cast::<u8>().add(SHARED_IN_TRANS).read(), 0);
        }
    }
}
