//! Waits for and removes a condition-queue item — `FUN_0839e3d4` @
//! 0x0839e3d4.
//!
//! Raw `osos.dec` establishes the true 88-byte extent
//! 0x0839e3d4..0x0839e42c: twenty-two ARM words from `push {r4,r5,r6,lr}`
//! through `pop {r4,r5,r6,pc}`; the alternate empty predicate begins at
//! 0x0839e42c. Whole-image A32 branch decoding finds three direct,
//! unconditional `bl` callers (0x0819bf30, 0x0819c054, 0x0819c144) and no
//! predicated `bl` calls.
//!
//! Algorithm: lock queue+0x0c, wait on the CondVar at queue+0x14 while the
//! unported queue-list-empty predicate says queue+4 is empty, then pop the
//! list's first node. When a node is present, preserve its word at +4, delete
//! the node, unlock, and return the preserved item; an empty pop returns null.
//!
//! Deliberate deviation: the list-empty predicate remains an unported
//! fixed-address target call. Host builds inject it and the other operations,
//! because target pointer fields are four bytes apart.

#[cfg(target_os = "none")]
use crate::{
    heap::veneers::operator_delete,
    kernel::{
        condvar::{condvar_wait_forever, list_pop_front, CondVar, ListHead},
        sync_mutex::{mutex_lock, mutex_unlock, Mutex},
    },
};

const LIST_OFFSET: usize = 4;
const MUTEX_OFFSET: usize = 12;
const CONDVAR_OFFSET: usize = 20;
const RETAIL_QUEUE_LIST_IS_EMPTY: usize = 0x0839_e3bc;

type QueueListIsEmpty = unsafe extern "C" fn(*mut u8) -> u32;
type MutexCall = unsafe extern "C" fn(*mut u8);
type CondvarWait = unsafe extern "C" fn(*mut u8);
type ListPop = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Delete = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
pub struct ConditionQueueDequeueOps {
    pub lock: MutexCall,
    pub list_is_empty: QueueListIsEmpty,
    pub wait: CondvarWait,
    pub pop_front: ListPop,
    pub delete: Delete,
    pub unlock: MutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_call(_pointer: *mut u8) {
    panic!("condition_queue_dequeue operation was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_is_empty(_queue: *mut u8) -> u32 {
    panic!("condition_queue_dequeue list predicate was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pop_front(_list: *mut u8) -> *mut u8 {
    panic!("condition_queue_dequeue list pop was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut CONDITION_QUEUE_DEQUEUE_OPS: ConditionQueueDequeueOps = ConditionQueueDequeueOps {
    lock: missing_call,
    list_is_empty: missing_list_is_empty,
    wait: missing_call,
    pop_front: missing_pop_front,
    delete: missing_call,
    unlock: missing_call,
};

#[inline(always)]
unsafe fn lock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_lock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_OPS.lock))(mutex) };
}

#[inline(always)]
unsafe fn list_is_empty(queue: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    unsafe { core::mem::transmute::<usize, QueueListIsEmpty>(RETAIL_QUEUE_LIST_IS_EMPTY)(queue) }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_OPS.list_is_empty))(queue) }
}

#[inline(always)]
unsafe fn wait(condvar: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { condvar_wait_forever(condvar.cast::<CondVar>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_OPS.wait))(condvar) };
}

#[inline(always)]
unsafe fn pop_front(list: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    unsafe { list_pop_front(list.cast::<ListHead>()).cast::<u8>() }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_OPS.pop_front))(list) }
}

#[inline(always)]
unsafe fn delete(node: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { operator_delete(node) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_OPS.delete))(node) };
}

#[inline(always)]
unsafe fn unlock(mutex: *mut u8) {
    #[cfg(target_os = "none")]
    unsafe { mutex_unlock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDITION_QUEUE_DEQUEUE_OPS.unlock))(mutex) };
}

/// # Safety
/// `queue` must point to the retail condition-queue layout. This call waits
/// until its item list is nonempty, so it requires a functioning CondVar.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condition_queue_dequeue(queue: *mut u8) -> *mut u8 {
    let mutex = unsafe { queue.add(MUTEX_OFFSET) };
    unsafe { lock(mutex) };
    while unsafe { list_is_empty(queue) } != 0 {
        unsafe { wait(queue.add(CONDVAR_OFFSET)) };
    }
    let node = unsafe { pop_front(queue.add(LIST_OFFSET)) };
    let item = if node.is_null() {
        core::ptr::null_mut()
    } else {
        let item = unsafe { core::ptr::read_unaligned(node.add(4).cast::<u32>()) as usize as *mut u8 };
        unsafe { delete(node) };
        item
    };
    unsafe { unlock(mutex) };
    item
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
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

    unsafe extern "C" fn record_lock(pointer: *mut u8) { unsafe { record(1, pointer, QUEUE.add(MUTEX_OFFSET)) } }
    unsafe extern "C" fn record_empty(pointer: *mut u8) -> u32 {
        unsafe { record(2, pointer, QUEUE); let result = EMPTY_RESULTS[EMPTY_CALLS]; EMPTY_CALLS += 1; result }
    }
    unsafe extern "C" fn record_wait(pointer: *mut u8) { unsafe { record(3, pointer, QUEUE.add(CONDVAR_OFFSET)) } }
    unsafe extern "C" fn record_pop(pointer: *mut u8) -> *mut u8 { unsafe { record(4, pointer, QUEUE.add(LIST_OFFSET)); NODE } }
    unsafe extern "C" fn record_delete(pointer: *mut u8) { unsafe { record(5, pointer, NODE) } }
    unsafe extern "C" fn record_unlock(pointer: *mut u8) { unsafe { record(6, pointer, QUEUE.add(MUTEX_OFFSET)) } }

    unsafe fn install_ops() {
        unsafe { addr_of_mut!(CONDITION_QUEUE_DEQUEUE_OPS).write(ConditionQueueDequeueOps {
            lock: record_lock, list_is_empty: record_empty, wait: record_wait,
            pop_front: record_pop, delete: record_delete, unlock: record_unlock,
        }) };
    }

    #[test]
    fn waits_until_an_item_is_available_then_returns_and_deletes_it() {
        let _guard = OPS_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONDITION_QUEUE_DEQUEUE, 0x1000,
        ) else {
            crate::testing::note_missing_u32_fixture("cxx::condition_queue_dequeue");
            return;
        };
        let queue = slab;
        let node = unsafe { slab.add(0x40) };
        let item = unsafe { slab.add(0x80) };
        unsafe {
            QUEUE = queue;
            NODE = node;
            node.add(4).cast::<u32>().write(item as usize as u32);
            EMPTY_RESULTS = [1, 0]; EMPTY_CALLS = 0; CALLS = [0; 8]; CALL_COUNT = 0;
            install_ops();
            assert_eq!(condition_queue_dequeue(QUEUE), item);
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
            install_ops();
            assert!(condition_queue_dequeue(QUEUE).is_null());
            assert_eq!(&CALLS[..CALL_COUNT], &[1, 2, 4, 6]);
        }
    }
}
