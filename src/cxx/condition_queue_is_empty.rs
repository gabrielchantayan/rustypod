//! Tests whether a condition queue's linked-item list is empty — `FUN_0839e540` @
//! 0x0839e540.
//!
//! Raw `osos.dec` establishes the true 48-byte extent
//! 0x0839e540..0x0839e570: twelve ARM words from `push {r4,r5,r6,lr}`
//! through `pop {r4,r5,r6,pc}`; the separate condition-queue constructor
//! begins at 0x0839e570. Whole-image A32 branch decoding finds three direct
//! unconditional `bl` callers (0x0819bf10, 0x0819bf64, 0x0819c128) and no
//! predicated callers.
//!
//! Algorithm: lock the embedded mutex at target offset +0x0c, call the
//! queue's unported list-empty predicate on the original object, unlock the
//! same mutex, then return the predicate result. The predicate at 0x0839e488
//! calls the list-count helper at queue+4 and returns one only for a zero
//! count.
//!
//! Deliberate deviation: the unported predicate is a fixed-address target
//! call; host builds expose it through an injectable seam. The lock pair uses
//! the ported mutex functions on target, while host builds use matching
//! injectable calls because target-width pointer fields are four bytes apart.

#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const MUTEX_WORD_OFFSET: usize = 3;
const RETAIL_QUEUE_LIST_IS_EMPTY: usize = 0x0839_e488;

type QueueListIsEmpty = unsafe extern "C" fn(*mut u8) -> u32;
type MutexCall = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub struct ConditionQueueIsEmptyOps {
    pub lock: MutexCall,
    pub list_is_empty: QueueListIsEmpty,
    pub unlock: MutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mutex_call(_mutex: *mut u8) {
    panic!("condition_queue_is_empty mutex operation was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_is_empty(_queue: *mut u8) -> u32 {
    panic!("condition_queue_is_empty list predicate was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut CONDITION_QUEUE_IS_EMPTY_OPS: ConditionQueueIsEmptyOps = ConditionQueueIsEmptyOps {
    lock: missing_mutex_call,
    list_is_empty: missing_list_is_empty,
    unlock: missing_mutex_call,
};

#[inline(always)]
unsafe fn lock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_lock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe {
        let call = core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_IS_EMPTY_OPS.lock));
        call(mutex);
    }
}

#[inline(always)]
unsafe fn list_is_empty(queue: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let call: QueueListIsEmpty = core::mem::transmute(RETAIL_QUEUE_LIST_IS_EMPTY);
        return call(queue);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let call = core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_IS_EMPTY_OPS.list_is_empty));
        call(queue)
    }
}

#[inline(always)]
unsafe fn unlock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_unlock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe {
        let call = core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_IS_EMPTY_OPS.unlock));
        call(mutex);
    }
}

/// # Safety
/// `queue` must point to the retail condition-queue layout, with its mutex at
/// target word index 3. It is neither nullable nor synchronized by this API.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condition_queue_is_empty(queue: *mut u8) -> u32 {
    let mutex = unsafe { queue.add(MUTEX_WORD_OFFSET * core::mem::size_of::<u32>()) };
    unsafe { lock(mutex) };
    let result = unsafe { list_is_empty(queue) };
    unsafe { unlock(mutex) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex as StdMutex;

    static OPS_LOCK: StdMutex<()> = StdMutex::new(());
    static mut CALLS: [u8; 3] = [0; 3];
    static mut CALL_COUNT: usize = 0;
    static mut EXPECTED_QUEUE: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_MUTEX: *mut u8 = core::ptr::null_mut();
    static mut RESULT: u32 = 0;

    unsafe fn record(call: u8, pointer: *mut u8, expected: *mut u8) {
        assert_eq!(pointer, expected);
        CALLS[CALL_COUNT] = call;
        CALL_COUNT += 1;
    }

    unsafe extern "C" fn record_lock(mutex: *mut u8) {
        unsafe { record(1, mutex, EXPECTED_MUTEX) };
    }

    unsafe extern "C" fn record_list_is_empty(queue: *mut u8) -> u32 {
        unsafe {
            record(2, queue, EXPECTED_QUEUE);
            RESULT
        }
    }

    unsafe extern "C" fn record_unlock(mutex: *mut u8) {
        unsafe { record(3, mutex, EXPECTED_MUTEX) };
    }

    #[test]
    fn locks_queries_unlocks_and_returns_empty_result() {
        let _guard = OPS_LOCK.lock();
        let mut queue = [0u32; 5];
        unsafe {
            EXPECTED_QUEUE = queue.as_mut_ptr().cast();
            EXPECTED_MUTEX = queue.as_mut_ptr().add(MUTEX_WORD_OFFSET).cast();
            CALLS = [0; 3];
            CALL_COUNT = 0;
            RESULT = 1;
            addr_of_mut!(CONDITION_QUEUE_IS_EMPTY_OPS).write(ConditionQueueIsEmptyOps {
                lock: record_lock,
                list_is_empty: record_list_is_empty,
                unlock: record_unlock,
            });
            assert_eq!(condition_queue_is_empty(EXPECTED_QUEUE), 1);
            assert_eq!(CALLS, [1, 2, 3]);
        }
    }

    #[test]
    fn preserves_nonempty_result_after_unlock() {
        let _guard = OPS_LOCK.lock();
        let mut queue = [0u32; 5];
        unsafe {
            EXPECTED_QUEUE = queue.as_mut_ptr().cast();
            EXPECTED_MUTEX = queue.as_mut_ptr().add(MUTEX_WORD_OFFSET).cast();
            CALLS = [0; 3];
            CALL_COUNT = 0;
            RESULT = 0;
            addr_of_mut!(CONDITION_QUEUE_IS_EMPTY_OPS).write(ConditionQueueIsEmptyOps {
                lock: record_lock,
                list_is_empty: record_list_is_empty,
                unlock: record_unlock,
            });
            assert_eq!(condition_queue_is_empty(EXPECTED_QUEUE), 0);
            assert_eq!(CALLS, [1, 2, 3]);
        }
    }
}
