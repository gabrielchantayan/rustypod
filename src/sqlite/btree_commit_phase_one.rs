//! Commit the first phase of a SQLite B-tree transaction.
//!
//! `btree_commit_phase_one` is retailOS `FUN_08370bfc` at load address
//! `0x08370bfc`. Raw ARM establishes the 144-byte extent
//! `0x08370bfc..0x08370c8c`: `pop {r3-r7,pc}` at `0x08370c88` is immediately
//! followed by a distinct `push {r4-r8,lr}`. It has three unconditional plain
//! `bl` instructions (btree_enter, auto_vacuum_commit, btree_leave twice) and
//! no predicated calls.
//!
//! SQLite 3.5.9's `sqlite3BtreeCommitPhaseOne` enters a write B-tree, records
//! its database in the shared B-tree, optionally prepares auto-vacuum, then
//! commits the pager. The two unported calls remain retailOS boundaries.
//! Deliberate host-only deviation: a dispatch table models all boundaries,
//! since target-width pointer fields widen on the host.

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
const SHARED_AUTO_VACUUM: usize = 0x16;
const TRANS_WRITE: u8 = 2;

type AutoVacuumCommit = unsafe extern "C" fn(*mut u8, *mut u32) -> i32;
type PagerCommitPhaseOne = unsafe extern "C" fn(*mut u8, *const u8, u32, i32) -> i32;
type BtreeOperation = unsafe extern "C" fn(*mut u8);

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
unsafe fn auto_vacuum_commit(shared: *mut u8, truncation: *mut u32) -> i32 {
    let operation: AutoVacuumCommit = core::mem::transmute(0x082b_58a4usize);
    operation(shared, truncation)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pager_commit_phase_one(pager: *mut u8, master: *const u8, truncation: u32) -> i32 {
    let operation: PagerCommitPhaseOne = core::mem::transmute(0x0837_de5cusize);
    operation(pager, master, truncation, 0)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_auto_vacuum(_shared: *mut u8, _truncation: *mut u32) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_pager(_pager: *mut u8, _master: *const u8, _truncation: u32, _flags: i32) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_operation(_value: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeCommitPhaseOneOps {
    auto_vacuum_commit: AutoVacuumCommit,
    pager_commit_phase_one: PagerCommitPhaseOne,
    enter: BtreeOperation,
    leave: BtreeOperation,
}
#[cfg(not(target_os = "none"))]
const DEFAULT_OPS: BtreeCommitPhaseOneOps = BtreeCommitPhaseOneOps {
    auto_vacuum_commit: unavailable_auto_vacuum,
    pager_commit_phase_one: unavailable_pager,
    enter: unavailable_operation,
    leave: unavailable_operation,
};
#[cfg(not(target_os = "none"))]
static mut OPS: BtreeCommitPhaseOneOps = DEFAULT_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeCommitPhaseOneOps { core::ptr::read_volatile(core::ptr::addr_of!(OPS)) }

/// `sqlite3BtreeCommitPhaseOne` — retailOS `FUN_08370bfc` @ `0x08370bfc`
/// (144 bytes; three plain inbound calls, four plain outbound `bl` instructions,
/// no predicated outbound call).
///
/// `btree` and its target-layout shared-B-tree pointer must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_commit_phase_one(btree: *mut u8, master: *const u8) -> i32 {
    if btree.add(BTREE_IN_TRANS).read() != TRANS_WRITE { return 0; }
    let shared = pointer_at(btree, BTREE_SHARED);
    let mut truncation = 0u32;
    #[cfg(target_os = "none")]
    btree_enter(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);
    set_pointer(shared, SHARED_DATABASE, pointer_at(btree, BTREE_DATABASE));
    if shared.add(SHARED_AUTO_VACUUM).read() != 0 {
        #[cfg(target_os = "none")]
        let rc = auto_vacuum_commit(shared, &mut truncation);
        #[cfg(not(target_os = "none"))]
        let rc = (host_ops().auto_vacuum_commit)(shared, &mut truncation);
        if rc != 0 {
            #[cfg(target_os = "none")]
            btree_leave(btree);
            #[cfg(not(target_os = "none"))]
            (host_ops().leave)(btree);
            return rc;
        }
    }
    #[cfg(target_os = "none")]
    let rc = pager_commit_phase_one(pointer_at(shared, SHARED_PAGER), master, truncation);
    #[cfg(not(target_os = "none"))]
    let rc = (host_ops().pager_commit_phase_one)(pointer_at(shared, SHARED_PAGER), master, truncation, 0);
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
    static mut AUTO_RESULT: i32 = 0;
    static mut PAGER_RESULT: i32 = 0;
    static mut TRUNCATION: u32 = 0;
    unsafe fn event(value: u8) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn auto(_shared: *mut u8, truncation: *mut u32) -> i32 { event(1); truncation.write(TRUNCATION); AUTO_RESULT }
    unsafe extern "C" fn pager(_pager: *mut u8, _master: *const u8, truncation: u32, flags: i32) -> i32 { event(2); assert_eq!(truncation, TRUNCATION); assert_eq!(flags, 0); PAGER_RESULT }
    unsafe extern "C" fn enter(_btree: *mut u8) { event(3); }
    unsafe extern "C" fn leave(_btree: *mut u8) { event(4); }
    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench { fn drop(&mut self) { unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(OPS), DEFAULT_OPS); } } }
    fn bench(auto_result: i32, pager_result: i32, truncation: u32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENTS = [0; 4]; EVENT_COUNT = 0; AUTO_RESULT = auto_result; PAGER_RESULT = pager_result; TRUNCATION = truncation;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(OPS), BtreeCommitPhaseOneOps { auto_vacuum_commit: auto, pager_commit_phase_one: pager, enter, leave });
        }
        Bench { _guard: guard }
    }
    unsafe fn fixture(btree: *mut u8, shared: *mut u8, database: *mut u8, pager_value: *mut u8) {
        set_pointer(btree, BTREE_DATABASE, database); set_pointer(btree, BTREE_SHARED, shared); set_pointer(shared, SHARED_PAGER, pager_value);
    }
    #[test]
    fn write_commit_runs_auto_vacuum_and_propagates_pager_status() {
        let _bench = bench(0, 7, 99);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16]; let mut database = [0u8; 1]; let mut pager_value = [0u8; 1];
        unsafe {
            fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), database.as_mut_ptr(), pager_value.as_mut_ptr());
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(TRANS_WRITE); shared.as_mut_ptr().cast::<u8>().add(SHARED_AUTO_VACUUM).write(1);
            assert_eq!(btree_commit_phase_one(btree.as_mut_ptr().cast(), core::ptr::null()), 7);
            assert_eq!(EVENTS, [3, 1, 2, 4]);
            assert_eq!(pointer_at(shared.as_mut_ptr().cast(), SHARED_DATABASE), database.as_mut_ptr());
        }
    }
    #[test]
    fn auto_vacuum_error_skips_pager_and_leaves() {
        let _bench = bench(11, 0, 0);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16];
        unsafe {
            fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), core::ptr::null_mut(), core::ptr::null_mut());
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(TRANS_WRITE); shared.as_mut_ptr().cast::<u8>().add(SHARED_AUTO_VACUUM).write(1);
            assert_eq!(btree_commit_phase_one(btree.as_mut_ptr().cast(), core::ptr::null()), 11);
            assert_eq!(EVENTS, [3, 1, 4, 0]);
        }
    }
    #[test]
    fn non_write_transaction_is_inert() {
        let _bench = bench(0, 0, 0);
        let mut btree = [0usize; 8];
        unsafe { assert_eq!(btree_commit_phase_one(btree.as_mut_ptr().cast(), core::ptr::null()), 0); assert_eq!(EVENTS, [0; 4]); }
    }
}
