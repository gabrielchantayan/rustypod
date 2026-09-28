//! Drains a condition queue — `FUN_0839e688` @ 0x0839e688.
//!
//! Raw `osos.dec` establishes the true 60-byte extent
//! 0x0839e688..0x0839e6c4: fifteen ARM words from `push {r4,r5,lr}` through
//! the tail branch to `mutex_unlock`; 0x0839e6c4 begins the distinct dequeue
//! helper. The body has three unconditional direct `bl` calls and no
//! predicated `bl` calls. Its two inbound calls are plain unconditional `bl`.
//!
//! Algorithm: lock queue+0x0c, repeatedly dequeue while the helper at
//! 0x0839e670 reports that the list at queue+4 is nonempty, then unlock.
//!
//! Deliberate deviation: the two local helpers remain fixed-address target
//! calls. Host builds inject them and the mutex operations because target
//! pointer fields are four bytes apart.

#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const MUTEX_OFFSET: usize = 12;
const RETAIL_CONDITION_QUEUE_IS_EMPTY: usize = 0x0839_e670;
const RETAIL_CONDITION_QUEUE_DEQUEUE: usize = 0x0839_e6c4;

type QueueIsEmpty = unsafe extern "C" fn(*mut u8) -> u32;
type QueueDequeue = unsafe extern "C" fn(*mut u8) -> *mut u8;
type MutexCall = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub struct ConditionQueueDrainOps {
    pub lock: MutexCall,
    pub is_empty: QueueIsEmpty,
    pub dequeue: QueueDequeue,
    pub unlock: MutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mutex_call(_mutex: *mut u8) {
    panic!("condition_queue_drain mutex operation was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_is_empty(_queue: *mut u8) -> u32 {
    panic!("condition_queue_drain empty predicate was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dequeue(_queue: *mut u8) -> *mut u8 {
    panic!("condition_queue_drain dequeue operation was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut CONDITION_QUEUE_DRAIN_OPS: ConditionQueueDrainOps = ConditionQueueDrainOps {
    lock: missing_mutex_call,
    is_empty: missing_is_empty,
    dequeue: missing_dequeue,
    unlock: missing_mutex_call,
};

#[inline(always)]
unsafe fn lock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_lock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DRAIN_OPS.lock))(mutex) };
}

#[inline(always)]
unsafe fn is_empty(queue: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, QueueIsEmpty>(RETAIL_CONDITION_QUEUE_IS_EMPTY)(queue) }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DRAIN_OPS.is_empty))(queue) }
}

#[inline(always)]
unsafe fn dequeue(queue: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, QueueDequeue>(RETAIL_CONDITION_QUEUE_DEQUEUE)(queue) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DRAIN_OPS.dequeue))(queue) };
}

#[inline(always)]
unsafe fn unlock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_unlock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DRAIN_OPS.unlock))(mutex) };
}

/// # Safety
/// `queue` must point to the retail condition-queue layout and remain valid
/// for every helper call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condition_queue_drain(queue: *mut u8) {
    let mutex = unsafe { queue.add(MUTEX_OFFSET) };
    unsafe { lock(mutex) };
    while unsafe { is_empty(queue) } == 0 {
        unsafe { dequeue(queue) };
    }
    unsafe { unlock(mutex) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use parking_lot::Mutex as StdMutex;

    static OPS_LOCK: StdMutex<()> = StdMutex::new(());
    static mut QUEUE: *mut u8 = core::ptr::null_mut();
    static mut EMPTY_RESULTS: [u32; 3] = [0; 3];
    static mut EMPTY_CALLS: usize = 0;
    static mut CALLS: [u8; 8] = [0; 8];
    static mut CALL_COUNT: usize = 0;

    unsafe fn record(call: u8, pointer: *mut u8, expected: *mut u8) {
        assert_eq!(pointer, expected);
        unsafe { CALLS[CALL_COUNT] = call; CALL_COUNT += 1 };
    }

    unsafe extern "C" fn record_lock(pointer: *mut u8) { unsafe { record(1, pointer, QUEUE.add(MUTEX_OFFSET)) } }
    unsafe extern "C" fn record_empty(pointer: *mut u8) -> u32 {
        unsafe { record(2, pointer, QUEUE); let result = EMPTY_RESULTS[EMPTY_CALLS]; EMPTY_CALLS += 1; result }
    }
    unsafe extern "C" fn record_dequeue(pointer: *mut u8) -> *mut u8 {
        unsafe { record(3, pointer, QUEUE); core::ptr::null_mut() }
    }
    unsafe extern "C" fn record_unlock(pointer: *mut u8) { unsafe { record(4, pointer, QUEUE.add(MUTEX_OFFSET)) } }

    unsafe fn install_ops() {
        unsafe { addr_of_mut!(CONDITION_QUEUE_DRAIN_OPS).write(ConditionQueueDrainOps {
            lock: record_lock, is_empty: record_empty, dequeue: record_dequeue, unlock: record_unlock,
        }) };
    }

    #[test]
    fn drains_each_nonempty_queue_item_then_unlocks() {
        let _guard = OPS_LOCK.lock();
        let mut queue = [0u32; 4];
        unsafe {
            QUEUE = queue.as_mut_ptr().cast(); EMPTY_RESULTS = [0, 0, 1]; EMPTY_CALLS = 0;
            CALLS = [0; 8]; CALL_COUNT = 0; install_ops();
            condition_queue_drain(QUEUE);
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 3, 2, 3, 2, 4]);
        }
    }

    #[test]
    fn unlocks_without_dequeuing_an_empty_queue() {
        let _guard = OPS_LOCK.lock();
        let mut queue = [0u32; 4];
        unsafe {
            QUEUE = queue.as_mut_ptr().cast(); EMPTY_RESULTS = [1, 0, 0]; EMPTY_CALLS = 0;
            CALLS = [0; 8]; CALL_COUNT = 0; install_ops();
            condition_queue_drain(QUEUE);
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 4]);
        }
    }
}
