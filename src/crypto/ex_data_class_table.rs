//! Lazy initialization of the OpenSSL ex-data class hash table.
//!
//! `FUN_080847b4` @ 0x080847b4: 108 bytes (96 code, 12 literal pool),
//! next real function at 0x08084820. Whole-image A32 word decoding finds
//! two incoming plain BLs (0x080782e4, 0x08084474), no predicated BLs;
//! the body has three plain BLs and no predicated BLs.
//!
//! Acquire resource 2 with operation 9, inspect singleton 0x08a0e9e0
//! word +8, and create its hash table only when that word is zero. Store
//! the constructor result even on failure, release with operation 10,
//! and return exactly 0 or 1. Allocation failure is retryable.
//!
//! Deliberate deviations: host builds reuse the ported resource_op_dispatch
//! seam and replace fixed storage and the constructor with explicit services.
//! Target builds call the stock dispatcher and unported lhash constructor
//! at their verified entries. Constructor arguments 0x0806a740 and 0x080e9a94
//! remain opaque firmware words, not invented callback identities.

const HASH_CALLBACK_WORD: u32 = 0x0806_a740;
const COMPARE_CALLBACK_WORD: u32 = 0x080e_9a94;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ExDataClassTableOps {
    pub table_slot: *mut u32,
    pub create: unsafe extern "C" fn(u32, u32) -> u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_create(_hash: u32, _compare: u32) -> u32 {
    panic!("ex_data_class_table_ensure requires installed host services")
}

#[cfg(not(target_os = "none"))]
pub static mut EX_DATA_CLASS_TABLE_OPS: ExDataClassTableOps = ExDataClassTableOps {
    table_slot: core::ptr::null_mut(),
    create: missing_create,
};

/// Ensure the fixed ex-data singleton's class table exists; return 0 on
/// constructor failure, otherwise 1. Original load address 0x080847b4,
/// true size 108 bytes; two incoming and three outgoing plain BLs.
///
/// # Safety
/// The singleton slot and configured resource dispatcher must be valid.
/// Host services must supply writable aligned storage for one u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ex_data_class_table_ensure() -> u32 {
    #[cfg(target_os = "none")]
    let dispatch = core::mem::transmute::<usize, unsafe extern "C" fn(u32, i32, u32, u32)>(0x0804_3b94);
    #[cfg(not(target_os = "none"))]
    let dispatch = crate::resource_op::resource_op_dispatch;
    dispatch(9, 2, 0, 0);
    #[cfg(target_os = "none")]
    let (slot, create) = (
        0x08a0_e9e8 as *mut u32,
        core::mem::transmute::<usize, unsafe extern "C" fn(u32, u32) -> u32>(0x082d_7d08),
    );
    #[cfg(not(target_os = "none"))]
    let (slot, create) = {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(EX_DATA_CLASS_TABLE_OPS));
        (ops.table_slot, ops.create)
    };
    let mut success = 1;
    if core::ptr::read_volatile(slot) == 0 {
        let table = create(HASH_CALLBACK_WORD, COMPARE_CALLBACK_WORD);
        core::ptr::write_volatile(slot, table);
        success = (table != 0) as u32;
    }
    dispatch(10, 2, 0, 0);
    success
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::resource_op::{RESOURCE_OP_HOOKS, RESOURCE_OP_HOOKS_TEST_LOCK};
    use std::sync::atomic::{AtomicU32, Ordering};

    static PHASE: AtomicU32 = AtomicU32::new(0);
    static RESULT: AtomicU32 = AtomicU32::new(0);
    static RELEASED_VALUE: AtomicU32 = AtomicU32::new(0);
    static ACQUIRE_VALUE: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn dispatch(op: u32, resource: i32, a: u32, b: u32) {
        assert_eq!((resource, a, b), (2, 0, 0));
        let slot = core::ptr::read(core::ptr::addr_of!(EX_DATA_CLASS_TABLE_OPS)).table_slot;
        if op == 9 {
            assert_eq!(PHASE.swap(1, Ordering::SeqCst), 0);
            // An initializer in the lock-acquire path must be observed.
            *slot = ACQUIRE_VALUE.load(Ordering::SeqCst);
        } else {
            assert_eq!(op, 10);
            let phase = PHASE.swap(3, Ordering::SeqCst);
            assert!(phase == 1 || phase == 2);
            RELEASED_VALUE.store(*slot, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn create(hash: u32, compare: u32) -> u32 {
        assert_eq!((hash, compare), (HASH_CALLBACK_WORD, COMPARE_CALLBACK_WORD));
        assert_eq!(PHASE.swap(2, Ordering::SeqCst), 1);
        RESULT.load(Ordering::SeqCst)
    }

    #[test]
    fn existing_failed_retry_and_acquire_side_initialization() {
        let _guard = RESOURCE_OP_HOOKS_TEST_LOCK.lock();
        unsafe {
            let old_hooks = core::ptr::read(core::ptr::addr_of!(RESOURCE_OP_HOOKS));
            let old_ops = core::ptr::read(core::ptr::addr_of!(EX_DATA_CLASS_TABLE_OPS));
            let mut slot = 0u32;
            EX_DATA_CLASS_TABLE_OPS = ExDataClassTableOps { table_slot: &mut slot, create };
            RESOURCE_OP_HOOKS.static_op = Some(dispatch);
            // Reference: existing table succeeds without construction; absent
            // table succeeds iff the constructor returns a nonzero word.
            for (existing, allocated) in [(0, 0), (0, 0x8123400), (0x8123400, 0), (u32::MAX, 0)] {
                PHASE.store(0, Ordering::SeqCst);
                ACQUIRE_VALUE.store(existing, Ordering::SeqCst);
                RESULT.store(allocated, Ordering::SeqCst);
                let expected_slot = if existing == 0 { allocated } else { existing };
                assert_eq!(ex_data_class_table_ensure(), (expected_slot != 0) as u32);
                assert_eq!(slot, expected_slot);
                assert_eq!(RELEASED_VALUE.load(Ordering::SeqCst), expected_slot);
                assert_eq!(PHASE.load(Ordering::SeqCst), 3);
            }
            RESOURCE_OP_HOOKS = old_hooks;
            EX_DATA_CLASS_TABLE_OPS = old_ops;
        }
    }
}
