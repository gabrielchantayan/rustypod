//! Complete a SQLite B-tree transaction — retailOS `FUN_08370bc0` at
//! `0x08370bc0` (56 bytes).
//!
//! Raw ARM establishes the exact `0x08370bc0..0x08370bfc` extent: the body
//! begins with `push {r4,lr}`, ends with `pop {r4,pc}`, and the next distinct
//! function begins with `push {r3-r7,lr}`. It contains four unconditional
//! plain `bl` instructions (`btree_enter` @ `0x0837118c`,
//! `btree_commit_phase_one` @ `0x08370bfc`, `btree_commit_phase_two` @
//! `0x08370c8c`, and `btree_leave` @ `0x08371da4`) and no predicated `bl`.
//!
//! SQLite 3.5.9's `sqlite3BtreeCommit` enters the B-tree, runs phase one,
//! runs phase two only after phase-one success, then always leaves and returns
//! the selected status. Deliberate host-only deviation: phase boundaries use
//! a private dispatch table so tests can prove their ordering and errors while
//! target builds directly call the ported phase functions.

use crate::sqlite::btree_commit_phase_one::btree_commit_phase_one;
use crate::sqlite::btree_commit_phase_two::btree_commit_phase_two;
use crate::sqlite::btree_lock::{btree_enter, btree_leave};

type CommitPhase = unsafe extern "C" fn(*mut u8) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn phase_one(btree: *mut u8) -> i32 {
    btree_commit_phase_one(btree, core::ptr::null())
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn phase_two(btree: *mut u8) -> i32 { btree_commit_phase_two(btree) }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeCommitOps {
    phase_one: CommitPhase,
    phase_two: CommitPhase,
}
#[cfg(not(target_os = "none"))]
const DEFAULT_OPS: BtreeCommitOps = BtreeCommitOps { phase_one, phase_two };
#[cfg(not(target_os = "none"))]
static mut OPS: BtreeCommitOps = DEFAULT_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeCommitOps { core::ptr::read_volatile(core::ptr::addr_of!(OPS)) }

/// `sqlite3BtreeCommit` — retailOS `FUN_08370bc0` @ `0x08370bc0`.
///
/// `btree` must name a valid Btree. The phase functions receive the original
/// pointer; `btree_leave` runs after either phase-one result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_commit(btree: *mut u8) -> i32 {
    btree_enter(btree);
    #[cfg(target_os = "none")]
    let mut status = btree_commit_phase_one(btree, core::ptr::null());
    #[cfg(not(target_os = "none"))]
    let mut status = (host_ops().phase_one)(btree);
    if status == 0 {
        #[cfg(target_os = "none")]
        { status = btree_commit_phase_two(btree); }
        #[cfg(not(target_os = "none"))]
        { status = (host_ops().phase_two)(btree); }
    }
    btree_leave(btree);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 2] = [0; 2];
    static mut EVENT_COUNT: usize = 0;
    static mut PHASE_ONE_STATUS: i32 = 0;
    static mut PHASE_TWO_STATUS: i32 = 0;

    unsafe extern "C" fn test_phase_one(_btree: *mut u8) -> i32 {
        EVENTS[EVENT_COUNT] = 1; EVENT_COUNT += 1; PHASE_ONE_STATUS
    }
    unsafe extern "C" fn test_phase_two(_btree: *mut u8) -> i32 {
        EVENTS[EVENT_COUNT] = 2; EVENT_COUNT += 1; PHASE_TWO_STATUS
    }
    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(OPS), DEFAULT_OPS); }
        }
    }
    fn bench(phase_one_status: i32, phase_two_status: i32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENTS = [0; 2]; EVENT_COUNT = 0;
            PHASE_ONE_STATUS = phase_one_status; PHASE_TWO_STATUS = phase_two_status;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(OPS), BtreeCommitOps {
                phase_one: test_phase_one, phase_two: test_phase_two,
            });
        }
        Bench { _guard: guard }
    }

    #[test]
    fn commits_both_phases_and_returns_phase_two_status() {
        let _bench = bench(0, 7);
        let mut btree = [0u8; 16];
        btree[9] = 1;
        unsafe {
            assert_eq!(btree_commit(btree.as_mut_ptr()), 7);
            assert_eq!(EVENTS, [1, 2]);
            assert_eq!((btree.as_ptr().add(12) as *const i32).read(), 0);
        }
    }

    #[test]
    fn phase_one_error_skips_phase_two_and_releases_lock() {
        let _bench = bench(11, 0);
        let mut btree = [0u8; 16];
        btree[9] = 1;
        unsafe {
            assert_eq!(btree_commit(btree.as_mut_ptr()), 11);
            assert_eq!(EVENTS, [1, 0]);
            assert_eq!((btree.as_ptr().add(12) as *const i32).read(), 0);
        }
    }
}
