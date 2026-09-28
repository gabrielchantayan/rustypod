//! Begin a SQLite B-tree transaction — retailOS `FUN_08370d7c` at
//! `0x08370d7c` (52 bytes).
//!
//! Raw ARM establishes the exact extent: `push {r4,lr}` starts at
//! `0x08370d7c`, `pop {r4,pc}` ends at `0x08370db0`, and the next distinct
//! function begins with `push {r3-r7,lr}` at `0x08370db4`. The body contains
//! three unconditional plain `bl` instructions (`btree_enter` @ `0x0837118c`,
//! the unported transaction worker @ `0x082bd954`, and `btree_leave` @
//! `0x08371da4`) and no predicated `bl` instructions.
//!
//! SQLite 3.5.9's `sqlite3BtreeBeginTrans` enters the B-tree, refreshes the
//! shared cache's database pointer from the handle, delegates the requested
//! read/write transaction to its internal worker, then leaves and returns the
//! worker's status. Deliberate host-only deviation: target-width pointer slots
//! widen on the host, so the worker and lock boundaries use a private dispatch
//! table there; target builds call the existing lock ports and retail worker.

use crate::sqlite::btree_lock::{btree_enter, btree_leave};

const WORD: usize = core::mem::size_of::<*mut u8>();
const BTREE_DATABASE: usize = 0x00;
const BTREE_SHARED: usize = 0x04;
const SHARED_DATABASE: usize = 0x04;

type BeginTransactionWorker = unsafe extern "C" fn(*mut u8, i32) -> i32;
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
unsafe fn begin_transaction_worker(btree: *mut u8, write_flag: i32) -> i32 {
    let operation: BeginTransactionWorker = core::mem::transmute(0x082b_d954usize);
    operation(btree, write_flag)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_worker(_btree: *mut u8, _write_flag: i32) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_operation(_btree: *mut u8) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct BtreeBeginTransOps {
    worker: BeginTransactionWorker,
    enter: BtreeOperation,
    leave: BtreeOperation,
}
#[cfg(not(target_os = "none"))]
const DEFAULT_OPS: BtreeBeginTransOps = BtreeBeginTransOps {
    worker: unavailable_worker,
    enter: unavailable_operation,
    leave: unavailable_operation,
};
#[cfg(not(target_os = "none"))]
static mut OPS: BtreeBeginTransOps = DEFAULT_OPS;
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> BtreeBeginTransOps {
    core::ptr::read_volatile(core::ptr::addr_of!(OPS))
}

/// `sqlite3BtreeBeginTrans` — retailOS `FUN_08370d7c` @ `0x08370d7c`.
///
/// `btree` must name a valid target-layout Btree with readable database and
/// shared-cache pointer slots; that shared cache must be writable at +0x04.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_begin_trans(btree: *mut u8, write_flag: i32) -> i32 {
    #[cfg(target_os = "none")]
    btree_enter(btree);
    #[cfg(not(target_os = "none"))]
    (host_ops().enter)(btree);

    let shared = pointer_at(btree, BTREE_SHARED);
    set_pointer(shared, SHARED_DATABASE, pointer_at(btree, BTREE_DATABASE));

    #[cfg(target_os = "none")]
    let status = begin_transaction_worker(btree, write_flag);
    #[cfg(not(target_os = "none"))]
    let status = (host_ops().worker)(btree, write_flag);

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
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;
    static mut RESULT: i32 = 0;
    static mut EXPECTED_BTREE: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_FLAG: i32 = 0;

    unsafe fn event(value: u8) { EVENTS[EVENT_COUNT] = value; EVENT_COUNT += 1; }
    unsafe extern "C" fn worker(btree: *mut u8, write_flag: i32) -> i32 {
        event(2);
        assert_eq!(btree, EXPECTED_BTREE);
        assert_eq!(write_flag, EXPECTED_FLAG);
        RESULT
    }
    unsafe extern "C" fn enter(_btree: *mut u8) { event(1); }
    unsafe extern "C" fn leave(_btree: *mut u8) { event(3); }

    struct Bench { _guard: MutexGuard<'static, ()> }
    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(OPS), DEFAULT_OPS); }
        }
    }
    fn bench(btree: *mut u8, write_flag: i32, result: i32) -> Bench {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            EVENTS = [0; 3]; EVENT_COUNT = 0; RESULT = result;
            EXPECTED_BTREE = btree; EXPECTED_FLAG = write_flag;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(OPS), BtreeBeginTransOps { worker, enter, leave });
        }
        Bench { _guard: guard }
    }

    #[test]
    fn refreshes_shared_database_and_returns_worker_status() {
        let mut btree = [0usize; 4];
        let mut shared = [0usize; 4];
        let mut database = [0u8; 1];
        let btree_ptr = btree.as_mut_ptr().cast::<u8>();
        let _bench = bench(btree_ptr, 1, 7);
        unsafe {
            set_pointer(btree_ptr, BTREE_DATABASE, database.as_mut_ptr());
            set_pointer(btree_ptr, BTREE_SHARED, shared.as_mut_ptr().cast());
            assert_eq!(btree_begin_trans(btree_ptr, 1), 7);
            assert_eq!(pointer_at(shared.as_mut_ptr().cast(), SHARED_DATABASE), database.as_mut_ptr());
            assert_eq!(EVENTS, [1, 2, 3]);
        }
    }

    #[test]
    fn leaves_btree_after_worker_error_and_preserves_read_request() {
        let mut btree = [0usize; 4];
        let mut shared = [0usize; 4];
        let btree_ptr = btree.as_mut_ptr().cast::<u8>();
        let _bench = bench(btree_ptr, 0, 8);
        unsafe {
            set_pointer(btree_ptr, BTREE_SHARED, shared.as_mut_ptr().cast());
            assert_eq!(btree_begin_trans(btree_ptr, 0), 8);
            assert_eq!(EVENTS, [1, 2, 3]);
        }
    }
}
