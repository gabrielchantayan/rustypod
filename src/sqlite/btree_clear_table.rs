//! Clear a SQLite B-tree table — retailOS `FUN_0837098c` at `0x0837098c`
//! (148 bytes).
//!
//! Raw ARM establishes the extent `0x0837098c..0x08370a20`: the next
//! separately linked function starts with `push {r4,r5,r6,lr}` at
//! `0x08370a20`. Decoding every ARM B/BL-immediate word finds five plain,
//! unconditional `bl` instructions and no predicated `bl`: `btree_enter` @
//! `0x0837118c`, `check_read_locks` @ `0x082c28a0`,
//! `btree_save_all_cursors` @ `0x083684fc`, the still-unidentified retail
//! worker @ `0x082c3548`, and `btree_leave` @ `0x08371da4`.
//!
//! This is SQLite 3.5.x's `sqlite3BtreeClearTable`. It enters the B-tree,
//! publishes the owning database to the shared cache, rejects non-write
//! transactions with `SQLITE_ERROR` or `SQLITE_READONLY`, then checks read
//! locks, saves cursor positions, and asks the retail worker to clear the
//! root page. It leaves the B-tree on every path. Deliberate deviation: the
//! worker at `0x082c3548` has no `names.yaml` identity yet, so target builds
//! retain its verified absolute call and host tests substitute that boundary.

use crate::sqlite::btree_lock::{btree_enter, btree_leave};
use crate::sqlite::check_read_locks::check_read_locks;
use crate::sqlite::save_cursor_position::btree_save_all_cursors;

const BTREE_DB: usize = 0x00;
const BTREE_SHARED: usize = 0x04;
const BTREE_IN_TRANS: usize = 0x08;
const SHARED_DB: usize = 0x04;
const SHARED_READ_ONLY: usize = 0x11;
const TRANS_WRITE: u8 = 2;
const SQLITE_ERROR: i32 = 1;
const SQLITE_READONLY: i32 = 8;

type BtreeBoundary = unsafe extern "C" fn(*mut u8);
type CheckReadLocks = unsafe extern "C" fn(*mut u8, u32, *mut u8) -> i32;
type SaveAllCursors = unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> i32;
type ClearRetailTable = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> i32;

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    base.add(offset).cast::<u32>().read()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn clear_retail_table(shared: *mut u8, root_page: u32) -> i32 {
    let worker: ClearRetailTable = core::mem::transmute(0x082c_3548usize);
    worker(shared, root_page, 0, 0)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_btree_boundary(_btree: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_check_read_locks(_btree: *mut u8, _root: u32, _exclude: *mut u8) -> i32 { 11 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_save_all_cursors(_shared: *mut u8, _only: *mut u8, _except: *mut u8) -> i32 { 11 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_clear_retail_table(_shared: *mut u8, _root: u32, _free: u32, _changes: u32) -> i32 { 11 }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeClearTableOps {
    enter: BtreeBoundary,
    check_read_locks: CheckReadLocks,
    save_all_cursors: SaveAllCursors,
    clear_retail_table: ClearRetailTable,
    leave: BtreeBoundary,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_CLEAR_TABLE_OPS: BtreeClearTableOps = BtreeClearTableOps {
    enter: unavailable_btree_boundary,
    check_read_locks: unavailable_check_read_locks,
    save_all_cursors: unavailable_save_all_cursors,
    clear_retail_table: unavailable_clear_retail_table,
    leave: unavailable_btree_boundary,
};
#[cfg(not(target_os = "none"))]
static mut BTREE_CLEAR_TABLE_OPS: BtreeClearTableOps = DEFAULT_BTREE_CLEAR_TABLE_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeClearTableOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_CLEAR_TABLE_OPS))
}

/// `sqlite3BtreeClearTable` — original: `FUN_0837098c` @ `0x0837098c`
/// (148 bytes; 5 plain `bl`, 0 predicated `bl`).
///
/// Clears `root_page` in a write transaction. Returns the first lock, cursor,
/// or retail-worker error unchanged; a non-write transaction returns
/// `SQLITE_ERROR` (1) or `SQLITE_READONLY` (8). `btree` and its target-layout
/// shared object must be live and non-null.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.btree_clear_table")]
#[inline(never)]
pub unsafe extern "C" fn btree_clear_table(btree: *mut u8, root_page: u32) -> i32 {
    #[cfg(target_os = "none")]
    btree_enter(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);

    let shared = read_u32(btree, BTREE_SHARED) as usize as *mut u8;
    shared.add(SHARED_DB).cast::<u32>().write(read_u32(btree, BTREE_DB));

    let status = if btree.add(BTREE_IN_TRANS).read() != TRANS_WRITE {
        if shared.add(SHARED_READ_ONLY).read() == 0 { SQLITE_ERROR } else { SQLITE_READONLY }
    } else {
        #[cfg(target_os = "none")]
        let mut status = check_read_locks(btree, root_page, core::ptr::null_mut());
        #[cfg(not(target_os = "none"))]
        let mut status = (host_ops().check_read_locks)(btree, root_page, core::ptr::null_mut());
        if status == 0 {
            #[cfg(target_os = "none")]
            { status = btree_save_all_cursors(shared, core::ptr::null_mut(), core::ptr::null_mut()); }
            #[cfg(not(target_os = "none"))]
            { status = (host_ops().save_all_cursors)(shared, core::ptr::null_mut(), core::ptr::null_mut()); }
        }
        if status == 0 {
            #[cfg(target_os = "none")]
            { status = clear_retail_table(shared, root_page); }
            #[cfg(not(target_os = "none"))]
            { status = (host_ops().clear_retail_table)(shared, root_page, 0, 0); }
        }
        status
    };

    #[cfg(target_os = "none")]
    btree_leave(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().leave)(btree);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut LOCK_STATUS: i32 = 0;
    static mut SAVE_STATUS: i32 = 0;
    static mut CLEAR_STATUS: i32 = 0;
    static mut CALLS: [u8; 5] = [0; 5];
    static mut CALL_LEN: usize = 0;
    static mut CLEAR_ARGS: (u32, u32, u32) = (0, 0, 0);

    unsafe fn note(call: u8) { CALLS[CALL_LEN] = call; CALL_LEN += 1; }
    unsafe extern "C" fn enter(_btree: *mut u8) { note(1); }
    unsafe extern "C" fn locks(_btree: *mut u8, _root: u32, _exclude: *mut u8) -> i32 { note(2); LOCK_STATUS }
    unsafe extern "C" fn save(_shared: *mut u8, _only: *mut u8, _except: *mut u8) -> i32 { note(3); SAVE_STATUS }
    unsafe extern "C" fn clear(shared: *mut u8, root: u32, free: u32, changes: u32) -> i32 { note(4); CLEAR_ARGS = (shared as u32, root, free | changes); CLEAR_STATUS }
    unsafe extern "C" fn leave(_btree: *mut u8) { note(5); }

    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench { fn drop(&mut self) { unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_CLEAR_TABLE_OPS), DEFAULT_BTREE_CLEAR_TABLE_OPS); } } }
    fn bench(lock: i32, save_status: i32, clear_status: i32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            LOCK_STATUS = lock; SAVE_STATUS = save_status; CLEAR_STATUS = clear_status; CALL_LEN = 0; CLEAR_ARGS = (0, 0, 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_CLEAR_TABLE_OPS), BtreeClearTableOps { enter, check_read_locks: locks, save_all_cursors: save, clear_retail_table: clear, leave });
        }
        Bench { _guard: guard }
    }

    #[test]
    fn handles_transaction_and_service_failures_in_retail_order() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_BTREE_CLEAR_TABLE, 0x200) else { return; };
        unsafe {
            slab.write_bytes(0, 0x200);
            let btree = slab;
            let shared = slab.add(0x80);
            btree.add(BTREE_SHARED).cast::<u32>().write(shared as u32);
            btree.cast::<u32>().write(0x1234_5678);

            let _bench = bench(0, 0, 0);
            btree.add(BTREE_IN_TRANS).write(1); shared.add(SHARED_READ_ONLY).write(0);
            assert_eq!(btree_clear_table(btree, 7), SQLITE_ERROR);
            assert_eq!(&CALLS[..CALL_LEN], &[1, 5]);
            assert_eq!(shared.add(SHARED_DB).cast::<u32>().read(), 0x1234_5678);

            CALL_LEN = 0; shared.add(SHARED_READ_ONLY).write(1);
            assert_eq!(btree_clear_table(btree, 7), SQLITE_READONLY);
            assert_eq!(&CALLS[..CALL_LEN], &[1, 5]);

            CALL_LEN = 0; btree.add(BTREE_IN_TRANS).write(TRANS_WRITE);
            LOCK_STATUS = 6;
            assert_eq!(btree_clear_table(btree, 9), 6);
            assert_eq!(&CALLS[..CALL_LEN], &[1, 2, 5]);

            CALL_LEN = 0; LOCK_STATUS = 0; SAVE_STATUS = 7;
            assert_eq!(btree_clear_table(btree, 9), 7);
            assert_eq!(&CALLS[..CALL_LEN], &[1, 2, 3, 5]);

            CALL_LEN = 0; SAVE_STATUS = 0; CLEAR_STATUS = 11;
            assert_eq!(btree_clear_table(btree, 9), 11);
            assert_eq!(&CALLS[..CALL_LEN], &[1, 2, 3, 4, 5]);
            assert_eq!(CLEAR_ARGS, (shared as u32, 9, 0));
        }
    }
}
