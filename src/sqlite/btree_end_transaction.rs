//! End a SQLite B-tree transaction — retailOS `FUN_082d8520` at `0x082d8520`.
//!
//! Raw ARM establishes the exact 84-byte extent `0x082d8520..0x082d8573`:
//! `push {r4-r6,lr}` begins the body and `push {r4-r8,lr}` at `0x082d8574`
//! begins the next real function. It has one plain `bl` to `FUN_083707f0` and
//! no predicated `bl` instructions. The function preserves BtShared's current
//! transaction byte across the transaction worker, clears `Btree.inTrans`, and
//! decrements BtShared's transaction count only on success. Deliberate
//! host-only deviation: the unported worker is a typed seam because target
//! pointer fields are four-byte words while host pointers may be wider.

const BTREE_SHARED: usize = 0x04;
const BTREE_IN_TRANS: usize = 0x08;
const SHARED_IN_TRANS: usize = 0x30;
const SHARED_TRANSACTION_COUNT: usize = 0x34;

type EndTransactionWorker = unsafe extern "C" fn(*mut u8, i32) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn end_transaction_worker(btree: *mut u8) -> i32 {
    let worker: EndTransactionWorker = core::mem::transmute(0x0837_07f0usize);
    worker(btree, 0)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_worker(_: *mut u8, _: i32) -> i32 {
    panic!("btree_end_transaction requires an end-transaction worker seam on host")
}

#[cfg(not(target_os = "none"))]
pub static mut BTREE_END_TRANSACTION_WORKER: EndTransactionWorker = unavailable_worker;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn end_transaction_worker(btree: *mut u8) -> i32 {
    BTREE_END_TRANSACTION_WORKER(btree, 0)
}

/// `sqlite3BtreeEndTrans` — retailOS `FUN_082d8520` @ `0x082d8520`.
///
/// `btree` must be a valid target-layout Btree with a writable `inTrans` byte
/// and a valid target-width BtShared pointer at +0x04.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_end_transaction(btree: *mut u8) -> i32 {
    if btree.add(BTREE_IN_TRANS).read() != 0 {
        let shared = btree.add(BTREE_SHARED).cast::<u32>().read() as usize as *mut u8;
        let in_trans = shared.add(SHARED_IN_TRANS).read();
        let status = end_transaction_worker(btree);
        shared.add(SHARED_IN_TRANS).write(in_trans);
        btree.add(BTREE_IN_TRANS).write(0);
        if status == 0 {
            let count = shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>();
            count.write(count.read().wrapping_sub(1));
        }
        return status;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut STATUS: i32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn worker(btree: *mut u8, mode: i32) -> i32 {
        assert_eq!(mode, 0);
        CALLS += 1;
        let shared = btree.add(BTREE_SHARED).cast::<u32>().read() as usize as *mut u8;
        shared.add(SHARED_IN_TRANS).write(0xff);
        STATUS
    }

    #[test]
    fn clears_transaction_restores_shared_state_and_decrements_on_success() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_BTREE_END_TRANSACTION_SUCCESS, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let btree = slab;
            let shared = slab.add(0x100);
            btree.add(BTREE_SHARED).cast::<u32>().write(shared as usize as u32);
            btree.add(BTREE_IN_TRANS).write(2);
            shared.add(SHARED_IN_TRANS).write(2);
            shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>().write(7);
            STATUS = 0; CALLS = 0; BTREE_END_TRANSACTION_WORKER = worker;
            assert_eq!(btree_end_transaction(btree), 0);
            assert_eq!(CALLS, 1);
            assert_eq!(btree.add(BTREE_IN_TRANS).read(), 0);
            assert_eq!(shared.add(SHARED_IN_TRANS).read(), 2);
            assert_eq!(shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>().read(), 6);
            BTREE_END_TRANSACTION_WORKER = unavailable_worker;
        }
    }

    #[test]
    fn preserves_count_on_worker_error_and_skips_inactive_btree() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_BTREE_END_TRANSACTION_ERROR, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!())); return;
        };
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let btree = slab;
            let shared = slab.add(0x100);
            btree.add(BTREE_SHARED).cast::<u32>().write(shared as usize as u32);
            btree.add(BTREE_IN_TRANS).write(1);
            shared.add(SHARED_IN_TRANS).write(1);
            shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>().write(0);
            STATUS = 5; CALLS = 0; BTREE_END_TRANSACTION_WORKER = worker;
            assert_eq!(btree_end_transaction(btree), 5);
            assert_eq!(CALLS, 1);
            assert_eq!(shared.add(SHARED_TRANSACTION_COUNT).cast::<u32>().read(), 0);
            btree.add(BTREE_IN_TRANS).write(0);
            assert_eq!(btree_end_transaction(btree), 0);
            assert_eq!(CALLS, 1);
            BTREE_END_TRANSACTION_WORKER = unavailable_worker;
        }
    }
}
