//! Waits for and removes a condition-queue allocation — `FUN_0839e4a0` @
//! 0x0839e4a0.
//!
//! Raw `osos.dec` words establish the true 88-byte extent
//! `0x0839e4a0..0x0839e4f8`: twenty-two A32 words from
//! `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`; the next separately
//! linked function begins at 0x0839e4f8. The body has five plain direct `bl`
//! calls (mutex_lock, the queue-empty predicate, condvar_wait_forever,
//! list_pop_front, and mutex_unlock) and one predicated `blne` to
//! operator_delete. Whole-image A32 decoding finds two inbound plain `bl`
//! calls (0x0819bf3c and 0x0819c06c) and no predicated inbound calls.
//!
//! Algorithm: lock queue+0x0c, wait on queue+0x14 while its list at +4 is
//! empty, then pop a node. If one was returned, retain its target-width word
//! at +4, delete that allocation, unlock, and return the retained word.
//!
//! Deliberate deviations: the conditional delete is a normal Rust branch;
//! target builds call the already ported queue, mutex, condvar, list, and heap
//! operations while host tests inject the call sequence.

#[cfg(target_os = "none")]
use crate::{
    cxx::condition_queue_is_empty::condition_queue_is_empty,
    heap::veneers::operator_delete,
    kernel::{
        condvar::{condvar_wait_forever, list_pop_front, CondVar, ListHead},
        sync_mutex::{mutex_lock, mutex_unlock, Mutex},
    },
};

const LIST_OFFSET: usize = 4;
const MUTEX_OFFSET: usize = 12;
const CONDVAR_OFFSET: usize = 20;
const NODE_ALLOCATION_OFFSET: usize = 4;
type QueueListIsEmpty = unsafe fn(*mut u8) -> u32;
type MutexCall = unsafe fn(*mut u8);
type CondvarWait = unsafe fn(*mut u8);
type ListPop = unsafe fn(*mut u8) -> *mut u8;
type Delete = unsafe fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub struct ConditionQueueDequeueAllocationOps {
    pub lock: MutexCall,
    pub list_is_empty: QueueListIsEmpty,
    pub wait: CondvarWait,
    pub pop_front: ListPop,
    pub delete: Delete,
    pub unlock: MutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe fn missing_call(_: *mut u8) { panic!("condition_queue_dequeue_allocation operation was not installed") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_list_is_empty(_: *mut u8) -> u32 { panic!("condition_queue_dequeue_allocation list predicate was not installed") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_pop_front(_: *mut u8) -> *mut u8 { panic!("condition_queue_dequeue_allocation list pop was not installed") }

#[cfg(not(target_os = "none"))]
pub static mut CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS: ConditionQueueDequeueAllocationOps = ConditionQueueDequeueAllocationOps {
    lock: missing_call, list_is_empty: missing_list_is_empty, wait: missing_call,
    pop_front: missing_pop_front, delete: missing_call, unlock: missing_call,
};

#[inline(always)]
unsafe fn lock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_lock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS.lock))(mutex) };
}
#[inline(always)]
unsafe fn list_is_empty(queue: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    unsafe { condition_queue_is_empty(queue) }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS.list_is_empty))(queue) }
}
#[inline(always)]
unsafe fn wait(condvar: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { condvar_wait_forever(condvar.cast::<CondVar>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS.wait))(condvar) };
}
#[inline(always)]
unsafe fn pop_front(list: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    unsafe { list_pop_front(list.cast::<ListHead>()).cast() }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS.pop_front))(list) }
}
#[inline(always)]
unsafe fn delete(allocation: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { operator_delete(allocation) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS.delete))(allocation) };
}
#[inline(always)]
unsafe fn unlock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_unlock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_ALLOCATION_OPS.unlock))(mutex) };
}

/// # Safety
/// `queue` must have the retail target layout and a functioning condition queue.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condition_queue_dequeue_allocation(queue: *mut u8) -> *mut u8 {
    unsafe { condition_queue_dequeue_allocation_with(queue, lock, list_is_empty, wait, pop_front, delete, unlock) }
}

#[inline(always)]
unsafe fn condition_queue_dequeue_allocation_with(
    queue: *mut u8, lock_call: MutexCall, empty: QueueListIsEmpty, wait_call: CondvarWait,
    pop: ListPop, delete_call: Delete, unlock_call: MutexCall,
) -> *mut u8 {
    unsafe {
        let mutex = queue.add(MUTEX_OFFSET);
        lock_call(mutex);
        while empty(queue) != 0 { wait_call(queue.add(CONDVAR_OFFSET)); }
        let node = pop(queue.add(LIST_OFFSET));
        let allocation = if node.is_null() { core::ptr::null_mut() } else {
            let allocation = node.add(NODE_ALLOCATION_OFFSET).cast::<u32>().read() as usize as *mut u8;
            delete_call(allocation);
            allocation
        };
        unlock_call(mutex);
        allocation
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex as StdMutex;

    static OPS_LOCK: StdMutex<()> = StdMutex::new(());
    static mut CALLS: [u8; 8] = [0; 8];
    static mut CALL_COUNT: usize = 0;
    static mut QUEUE: *mut u8 = core::ptr::null_mut();
    static mut NODE: *mut u8 = core::ptr::null_mut();
    static mut EMPTY_RESULTS: [u32; 2] = [0; 2];
    static mut EMPTY_CALLS: usize = 0;

    unsafe fn record(call: u8, pointer: *mut u8, expected: *mut u8) {
        assert_eq!(pointer, expected);
        CALLS[CALL_COUNT] = call;
        CALL_COUNT += 1;
    }
    unsafe fn lock(pointer: *mut u8) { unsafe { record(1, pointer, QUEUE.add(MUTEX_OFFSET)) } }
    unsafe fn empty(pointer: *mut u8) -> u32 {
        unsafe { record(2, pointer, QUEUE); let result = EMPTY_RESULTS[EMPTY_CALLS]; EMPTY_CALLS += 1; result }
    }
    unsafe fn wait(pointer: *mut u8) { unsafe { record(3, pointer, QUEUE.add(CONDVAR_OFFSET)) } }
    unsafe fn pop(pointer: *mut u8) -> *mut u8 { unsafe { record(4, pointer, QUEUE.add(LIST_OFFSET)); NODE } }
    unsafe fn delete(pointer: *mut u8) {
        unsafe { record(5, pointer, NODE.add(NODE_ALLOCATION_OFFSET).cast::<u32>().read() as usize as *mut u8) }
    }
    unsafe fn unlock(pointer: *mut u8) { unsafe { record(6, pointer, QUEUE.add(MUTEX_OFFSET)) } }

    #[test]
    fn waits_deletes_popped_allocation_and_returns_it() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONDITION_QUEUE_DEQUEUE_ALLOCATION, 0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("cxx::condition_queue_dequeue_allocation");
            return;
        };
        unsafe {
            QUEUE = slab; NODE = slab.add(0x40);
            NODE.add(4).cast::<u32>().write(slab.add(0x80) as usize as u32);
            EMPTY_RESULTS = [1, 0]; EMPTY_CALLS = 0; CALLS = [0; 8]; CALL_COUNT = 0;
            assert_eq!(condition_queue_dequeue_allocation_with(QUEUE, lock, empty, wait, pop, delete, unlock), slab.add(0x80));
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 3, 2, 4, 5, 6]);
        }
    }

    #[test]
    fn unlocks_and_returns_null_when_pop_races_empty() {
        let _guard = OPS_LOCK.lock();
        let mut queue = [0u32; 6];
        unsafe {
            QUEUE = queue.as_mut_ptr().cast(); NODE = core::ptr::null_mut();
            EMPTY_RESULTS = [0, 0]; EMPTY_CALLS = 0; CALLS = [0; 8]; CALL_COUNT = 0;
            assert!(condition_queue_dequeue_allocation_with(QUEUE, lock, empty, wait, pop, delete, unlock).is_null());
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 4, 6]);
        }
    }
}
