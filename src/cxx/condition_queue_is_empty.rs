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
//! ported queue-list-empty predicate on the original object, unlock the same
//! mutex, then return the predicate result.
//!
//! Deliberate deviation: host lock calls are injectable because target-width
//! pointer fields are four bytes apart.

#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const MUTEX_WORD_OFFSET: usize = 3;
type MutexCall = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub struct ConditionQueueIsEmptyOps {
    pub lock: MutexCall,
    pub unlock: MutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mutex_call(_mutex: *mut u8) {
    panic!("condition_queue_is_empty mutex operation was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut CONDITION_QUEUE_IS_EMPTY_OPS: ConditionQueueIsEmptyOps = ConditionQueueIsEmptyOps {
    lock: missing_mutex_call,
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
    unsafe { crate::cxx::condition_queue_list_is_empty::condition_queue_list_is_empty(queue) }
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

    unsafe fn record(call: u8, pointer: *mut u8, expected: *mut u8) {
        assert_eq!(pointer, expected);
        CALLS[CALL_COUNT] = call;
        CALL_COUNT += 1;
    }

    unsafe extern "C" fn record_lock(mutex: *mut u8) {
        unsafe { record(1, mutex, EXPECTED_MUTEX) };
    }

    unsafe extern "C" fn record_unlock(mutex: *mut u8) {
        unsafe { record(3, mutex, EXPECTED_MUTEX) };
    }


    #[test]
    fn locks_queries_unlocks_and_returns_empty_result() {
        let _guard = OPS_LOCK.lock();
        let Some(queue) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONDITION_QUEUE_LIST_IS_EMPTY,
            0x1000,
        ) else {
            return;
        };
        unsafe {
            EXPECTED_QUEUE = queue;
            EXPECTED_MUTEX = queue.add(MUTEX_WORD_OFFSET * core::mem::size_of::<u32>());
            queue.add(4).cast::<u32>().write(0);
            CALLS = [0; 3];
            CALL_COUNT = 0;
            addr_of_mut!(CONDITION_QUEUE_IS_EMPTY_OPS).write(ConditionQueueIsEmptyOps {
                lock: record_lock,
                unlock: record_unlock,
            });
            assert_eq!(condition_queue_is_empty(EXPECTED_QUEUE), 1);
            assert_eq!(CALLS, [1, 3, 0]);
        }
    }

    #[test]
    fn preserves_nonempty_result_after_unlock() {
        let _guard = OPS_LOCK.lock();
        let Some(queue) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONDITION_QUEUE_LIST_IS_EMPTY_CALLER,
            0x1000,
        ) else {
            return;
        };
        unsafe {
            EXPECTED_QUEUE = queue;
            EXPECTED_MUTEX = queue.add(MUTEX_WORD_OFFSET * core::mem::size_of::<u32>());
            queue.add(4).cast::<u32>().write(queue.add(0x20) as usize as u32);
            queue.add(0x20).cast::<u32>().write(0);
            CALLS = [0; 3];
            CALL_COUNT = 0;
            addr_of_mut!(CONDITION_QUEUE_IS_EMPTY_OPS).write(ConditionQueueIsEmptyOps {
                lock: record_lock,
                unlock: record_unlock,
            });
            assert_eq!(condition_queue_is_empty(EXPECTED_QUEUE), 0);
            assert_eq!(CALLS, [1, 3, 0]);
        }
    }
}
