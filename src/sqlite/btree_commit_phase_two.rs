//! Finish a SQLite B-tree commit.
//!
//! `btree_commit_phase_two` is retailOS `FUN_08370c8c` at load address
//! `0x08370c8c`. Raw ARM establishes the 148-byte extent
//! `0x08370c8c..0x08370d20`: `pop {r4-r8,pc}` at `0x08370d1c` is followed by
//! a distinct `push {r4-r6,lr}`. Binary decoding finds three direct callers:
//! plain `bl` at `0x08370be4` and `0x083971c8`, plus predicated `blne` at
//! `0x0839748c`. The body has six unconditional plain `bl` instructions and
//! no predicated calls.
//!
//! SQLite 3.5.9's `sqlite3BtreeCommitPhaseTwo` commits the pager for a write
//! transaction, releases its B-tree locks, decrements the shared transaction
//! count for every active transaction, then unlocks an unused shared B-tree.
//! Pager commit and lock release remain retailOS boundaries. Host builds use a
//! private dispatch table because target 32-bit pointer slots widen on the host;
//! target builds call the original boundaries directly.

use crate::sqlite::btree_lock::{btree_enter, btree_leave};

const WORD: usize = core::mem::size_of::<*mut u8>();
const BTREE_DATABASE: usize = 0x00;
const BTREE_SHARED: usize = 0x04;
#[cfg(target_os = "none")]
const BTREE_IN_TRANS: usize = 0x08;
#[cfg(not(target_os = "none"))]
const BTREE_IN_TRANS: usize = 0x10;
const SHARED_DATABASE: usize = 0x04;
const SHARED_IN_TRANS: usize = 0x30;
const SHARED_TRANSACTION_COUNT: usize = 0x34;
const SHARED_UNLOCK_GUARD: usize = 0x10;
const TRANS_WRITE: u8 = 2;

type PagerCommitPhaseTwo = unsafe extern "C" fn(*mut u8) -> i32;
type ReleaseBtreeLocks = unsafe extern "C" fn(*mut u8);
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
unsafe fn pager_commit_phase_two(pager: *mut u8) -> i32 {
    let operation: PagerCommitPhaseTwo = core::mem::transmute(0x0837_e02cusize);
    operation(pager)
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_btree_locks(btree: *mut u8) {
    let operation: ReleaseBtreeLocks = core::mem::transmute(0x0839_6098usize);
    operation(btree);
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn unlock_if_unused(shared: *mut u8) {
    let operation: BtreeOperation = core::mem::transmute(0x0839_60e8usize);
    operation(shared);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_commit(_pager: *mut u8) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release(_btree: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_operation(_value: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeCommitOps {
    pager_commit_phase_two: PagerCommitPhaseTwo,
    release_btree_locks: ReleaseBtreeLocks,
    unlock_if_unused: BtreeOperation,
    enter: BtreeOperation,
    leave: BtreeOperation,
}
#[cfg(not(target_os = "none"))]
const DEFAULT_BTREE_COMMIT_OPS: BtreeCommitOps = BtreeCommitOps {
    pager_commit_phase_two: unavailable_commit,
    release_btree_locks: unavailable_release,
    unlock_if_unused: unavailable_operation,
    enter: unavailable_operation,
    leave: unavailable_operation,
};
#[cfg(not(target_os = "none"))]
static mut BTREE_COMMIT_OPS: BtreeCommitOps = DEFAULT_BTREE_COMMIT_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeCommitOps {
    core::ptr::read_volatile(core::ptr::addr_of!(BTREE_COMMIT_OPS))
}

/// `sqlite3BtreeCommitPhaseTwo` — retailOS `FUN_08370c8c` @ `0x08370c8c`
/// (148 bytes; two plain and one `blne` inbound calls, six plain outbound
/// `bl` instructions, no predicated outbound call).
///
/// `btree` and its target-layout shared-B-tree pointer must be valid. A pager
/// commit error leaves the B-tree lock held only until this function's required
/// leave; it does not release locks or change transaction state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_commit_phase_two(btree: *mut u8) -> i32 {
    let shared = pointer_at(btree, BTREE_SHARED);
    #[cfg(target_os = "none")]
    btree_enter(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);
    set_pointer(shared, SHARED_DATABASE, pointer_at(btree, BTREE_DATABASE));

    if btree.add(BTREE_IN_TRANS).read() == TRANS_WRITE {
        #[cfg(target_os = "none")]
        let rc = pager_commit_phase_two(pointer_at(shared, 0));
        #[cfg(not(target_os = "none"))]
        let rc = (host_ops().pager_commit_phase_two)(pointer_at(shared, 0));
        if rc != 0 {
            #[cfg(target_os = "none")]
            btree_leave(btree);
            #[cfg(not(target_os = "none"))]
            (host_ops().leave)(btree);
            return rc;
        }
        shared.add(SHARED_IN_TRANS).write(1);
        shared.add(SHARED_UNLOCK_GUARD).write(0);
    }

    #[cfg(target_os = "none")]
    release_btree_locks(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().release_btree_locks)(btree);
    if btree.add(BTREE_IN_TRANS).read() != 0 {
        let transactions = shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>();
        let remaining = transactions.read().wrapping_sub(1);
        transactions.write(remaining);
        if remaining == 0 { shared.add(SHARED_IN_TRANS).write(0); }
    }
    btree.add(BTREE_IN_TRANS).write(0);
    #[cfg(target_os = "none")]
    unlock_if_unused(shared);
    #[cfg(not(target_os = "none"))]
    (host_ops().unlock_if_unused)(shared);
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
    static mut COMMIT_RESULT: i32 = 0;

    unsafe fn event(value: u8) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn commit(_pager: *mut u8) -> i32 { event(1); COMMIT_RESULT }
    unsafe extern "C" fn release(_btree: *mut u8) { event(2); }
    unsafe extern "C" fn unlock(_shared: *mut u8) { event(3); }
    unsafe extern "C" fn enter(_btree: *mut u8) { event(4); }
    unsafe extern "C" fn leave(_btree: *mut u8) { event(5); }
    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_COMMIT_OPS), DEFAULT_BTREE_COMMIT_OPS); }
        }
    }
    fn bench(commit_result: i32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENTS = [0; 5]; EVENT_COUNT = 0; COMMIT_RESULT = commit_result;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(BTREE_COMMIT_OPS), BtreeCommitOps {
                pager_commit_phase_two: commit, release_btree_locks: release,
                unlock_if_unused: unlock, enter, leave,
            });
        }
        Bench { _guard: guard }
    }
    unsafe fn initialize_fixture(btree: *mut u8, shared: *mut u8, database: *mut u8, pager: *mut u8) {
        set_pointer(btree, BTREE_SHARED, shared);
        set_pointer(btree, BTREE_DATABASE, database);
        set_pointer(shared, 0, pager);
    }
    #[test]
    fn write_commit_completes_and_releases_last_transaction() {
        let _bench = bench(0);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16];
        let mut database = [0u8; 1]; let mut pager = [0u8; 1];
        unsafe {
            initialize_fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), database.as_mut_ptr(), pager.as_mut_ptr());
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(TRANS_WRITE);
            shared.as_mut_ptr().cast::<u8>().add(SHARED_TRANSACTION_COUNT).cast::<u32>().write(1);
            assert_eq!(btree_commit_phase_two(btree.as_mut_ptr().cast()), 0);
            assert_eq!(EVENTS, [4, 1, 2, 3, 5]);
            assert_eq!(shared.as_ptr().cast::<u8>().add(pointer_offset(SHARED_DATABASE)).cast::<*mut u8>().read(), database.as_mut_ptr());
            assert_eq!(shared.as_ptr().cast::<u8>().add(SHARED_IN_TRANS).read(), 0);
            assert_eq!(btree.as_ptr().cast::<u8>().add(BTREE_IN_TRANS).read(), 0);
        }
    }
    #[test]
    fn pager_error_only_leaves_btree() {
        let _bench = bench(7);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16]; let mut pager = [0u8; 1];
        unsafe {
            initialize_fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), core::ptr::null_mut(), pager.as_mut_ptr());
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(TRANS_WRITE);
            assert_eq!(btree_commit_phase_two(btree.as_mut_ptr().cast()), 7);
            assert_eq!(EVENTS, [4, 1, 5, 0, 0]);
            assert_eq!(btree.as_ptr().cast::<u8>().add(BTREE_IN_TRANS).read(), TRANS_WRITE);
        }
    }
    #[test]
    fn read_transaction_skips_pager_commit() {
        let _bench = bench(0);
        let mut btree = [0usize; 8]; let mut shared = [0usize; 16]; let mut pager = [0u8; 1];
        unsafe {
            initialize_fixture(btree.as_mut_ptr().cast(), shared.as_mut_ptr().cast(), core::ptr::null_mut(), pager.as_mut_ptr());
            btree.as_mut_ptr().cast::<u8>().add(BTREE_IN_TRANS).write(1);
            shared.as_mut_ptr().cast::<u8>().add(SHARED_TRANSACTION_COUNT).cast::<u32>().write(2);
            assert_eq!(btree_commit_phase_two(btree.as_mut_ptr().cast()), 0);
            assert_eq!(EVENTS, [4, 2, 3, 5, 0]);
            assert_eq!(shared.as_ptr().cast::<u8>().add(SHARED_TRANSACTION_COUNT).cast::<u32>().read(), 1);
        }
    }
}
