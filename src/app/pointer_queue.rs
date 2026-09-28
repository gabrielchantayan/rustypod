//! `pointer_queue_enqueue` — original: `FUN_0839e5f8` @ **0x0839e5f8**
//! (**72 bytes**, 0x0839e5f8..0x0839e640; the next separately linked function
//! opens with `push {r4, r5, r6, lr}` at 0x0839e640). **10 `bl` call sites**,
//! verified by decoding every ARM B/BL word in osos.dec: all ten are plain,
//! unconditional `bl` (at 0x081decfc, 0x081df084, 0x081df0bc, 0x081df10c,
//! 0x081df14c, 0x081df184, 0x081df1bc, 0x081df1f4, 0x081df230, and
//! 0x081df26c); there are no predicated call forms or direct tail branches.
//! A complete data-word scan finds no reference to this entry, so it is not
//! dispatched virtually.
//!
//! A synchronized FIFO of opaque pointers. Under the mutex at +0x0c it
//! allocates an 8-byte intrusive node, records the incoming pointer at +0x04,
//! appends that node to the list anchor at +0x04, wakes one waiter through the
//! condition variable at +0x14, then unlocks. The 10 callers construct
//! 12-byte command records (kind at +0x00, optional data at +0x04/+0x08) and
//! pass each record here; this helper only owns the 8-byte wrapper node.
//!
//! Deliberate deviations: none semantically. The original tail-branches to
//! `mutex_unlock` after restoring registers; Rust calls the already ported
//! function directly and discards its scratch return. `repr(C)` fields model
//! the target's 32-bit layout without host byte offsets.

use core::ffi::c_void;
#[cfg(test)]
use core::ptr::null_mut;

use crate::heap::veneers::operator_new;
use crate::kernel::condvar::{condvar_signal, list_push_back, CondVar, ListHead, ListNode};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// The retailOS allocation request for one list-link word and one payload
/// pointer word (`mov r0,#8` before `operator_new`). This is deliberately a
/// target ABI constant rather than `size_of::<PointerQueueNode>()`, which is
/// larger on 64-bit test hosts.
const POINTER_QUEUE_NODE_TARGET_SIZE: usize = 8;

const RETAIL_POINTER_QUEUE_LIST_IS_EMPTY: usize = 0x0839_e5e0;

type PointerQueueListIsEmpty = unsafe extern "C" fn(*mut PointerQueue) -> u32;
type PointerQueueMutexCall = unsafe extern "C" fn(*mut Mutex);

#[cfg(not(target_os = "none"))]
pub struct PointerQueueIsEmptyOps {
    pub lock: PointerQueueMutexCall,
    pub list_is_empty: PointerQueueListIsEmpty,
    pub unlock: PointerQueueMutexCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pointer_queue_mutex_call(_mutex: *mut Mutex) {
    panic!("pointer_queue_is_empty mutex operation was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pointer_queue_list_is_empty(_queue: *mut PointerQueue) -> u32 {
    panic!("pointer_queue_is_empty list predicate was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut POINTER_QUEUE_IS_EMPTY_OPS: PointerQueueIsEmptyOps = PointerQueueIsEmptyOps {
    lock: missing_pointer_queue_mutex_call,
    list_is_empty: missing_pointer_queue_list_is_empty,
    unlock: missing_pointer_queue_mutex_call,
};

#[inline(always)]
unsafe fn pointer_queue_lock(mutex: *mut Mutex) {
    #[cfg(target_os = "none")]
    unsafe { mutex_lock(&mut *mutex) };
    #[cfg(not(target_os = "none"))]
    unsafe {
        let call = core::ptr::read_volatile(core::ptr::addr_of!(POINTER_QUEUE_IS_EMPTY_OPS.lock));
        call(mutex);
    }
}

#[inline(always)]
unsafe fn pointer_queue_list_is_empty(queue: *mut PointerQueue) -> u32 {
    #[cfg(target_os = "none")]
    unsafe {
        let call: PointerQueueListIsEmpty = core::mem::transmute(RETAIL_POINTER_QUEUE_LIST_IS_EMPTY);
        return call(queue);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let call = core::ptr::read_volatile(core::ptr::addr_of!(POINTER_QUEUE_IS_EMPTY_OPS.list_is_empty));
        call(queue)
    }
}

#[inline(always)]
unsafe fn pointer_queue_unlock(mutex: *mut Mutex) {
    #[cfg(target_os = "none")]
    unsafe { mutex_unlock(&mut *mutex) };
    #[cfg(not(target_os = "none"))]
    unsafe {
        let call = core::ptr::read_volatile(core::ptr::addr_of!(POINTER_QUEUE_IS_EMPTY_OPS.unlock));
        call(mutex);
    }
}

/// Tests whether a pointer queue's pending list is empty — `FUN_0839e640` @
/// 0x0839e640.
///
/// Raw `osos.dec` establishes the true 48-byte extent
/// 0x0839e640..0x0839e670: twelve A32 words from `push {r4,r5,r6,lr}` through
/// `pop {r4,r5,r6,pc}`. Whole-image A32 decoding finds two inbound plain,
/// unconditional `bl` calls (0x081ded5c and 0x081def7c) and zero predicated
/// `bl` calls. It locks `queue.mutex`, calls the stock list-empty predicate
/// at 0x0839e5e0, unlocks, and returns that predicate's result.
///
/// Deliberate deviation: the list predicate remains an unported fixed-address
/// target call; host builds inject it and the mutex operations because target
/// pointer fields are four bytes apart.
///
/// # Safety
///
/// `queue` must point to a live retail [`PointerQueue`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pointer_queue_is_empty(queue: *mut PointerQueue) -> u32 {
    let mutex = unsafe { core::ptr::addr_of_mut!((*queue).mutex) };
    unsafe { pointer_queue_lock(mutex) };
    let result = unsafe { pointer_queue_list_is_empty(queue) };
    unsafe { pointer_queue_unlock(mutex) };
    result
}

/// Pointer FIFO object. Its target fields occupy +0x00..+0x20: vtable,
/// head/tail anchor, mutex, then condition variable.
#[repr(C)]
pub struct PointerQueue {
    pub vtable: u32,
    pub pending: ListHead,
    pub mutex: Mutex,
    pub ready: CondVar,
}

/// The dynamically allocated node: its link is necessarily first because
/// `list_push_back` receives this address as a `ListNode *`.
#[repr(C)]
struct PointerQueueNode {
    link: ListNode,
    value: *mut c_void,
}

/// Appends `value` to `this` and wakes one waiting consumer.
///
/// Original: `FUN_0839e5f8` @ 0x0839e5f8 (72 bytes; 10 unconditional direct
/// `bl` callers, binary-verified — see the module header).
///
/// # Safety
///
/// `this` must point to a live [`PointerQueue`] whose mutex and condition
/// variable were initialized. `value` is stored but not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pointer_queue_enqueue(this: *mut PointerQueue, value: *mut c_void) {
    mutex_lock(&mut (*this).mutex);

    let node = operator_new(POINTER_QUEUE_NODE_TARGET_SIZE).cast::<PointerQueueNode>();
    (*node).value = value;
    list_push_back(&mut (*this).pending, &mut (*node).link);

    condvar_signal(&mut (*this).ready);
    mutex_unlock(&mut (*this).mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use crate::kernel::condvar::WaitNode;
    use core::ptr;

    #[repr(C)]
    struct NodeStorage([usize; 2]);

    static EMPTY_OPS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut EMPTY_CALLS: [u8; 3] = [0; 3];
    static mut EMPTY_CALL_COUNT: usize = 0;
    static mut EXPECTED_QUEUE: *mut PointerQueue = core::ptr::null_mut();
    static mut EXPECTED_MUTEX: *mut Mutex = core::ptr::null_mut();
    static mut EMPTY_RESULT: u32 = 0;

    unsafe fn record_empty_call(call: u8, actual: *mut u8, expected: *mut u8) {
        assert_eq!(actual, expected);
        EMPTY_CALLS[EMPTY_CALL_COUNT] = call;
        EMPTY_CALL_COUNT += 1;
    }

    unsafe extern "C" fn record_empty_lock(mutex: *mut Mutex) {
        unsafe { record_empty_call(1, mutex.cast(), EXPECTED_MUTEX.cast()) };
    }

    unsafe extern "C" fn record_list_is_empty(queue: *mut PointerQueue) -> u32 {
        unsafe {
            record_empty_call(2, queue.cast(), EXPECTED_QUEUE.cast());
            EMPTY_RESULT
        }
    }

    unsafe extern "C" fn record_empty_unlock(mutex: *mut Mutex) {
        unsafe { record_empty_call(3, mutex.cast(), EXPECTED_MUTEX.cast()) };
    }

    unsafe fn install_empty_ops(result: u32, queue: *mut PointerQueue) {
        EXPECTED_QUEUE = queue;
        EXPECTED_MUTEX = core::ptr::addr_of_mut!((*queue).mutex);
        EMPTY_CALLS = [0; 3];
        EMPTY_CALL_COUNT = 0;
        EMPTY_RESULT = result;
        core::ptr::addr_of_mut!(POINTER_QUEUE_IS_EMPTY_OPS).write(PointerQueueIsEmptyOps {
            lock: record_empty_lock,
            list_is_empty: record_list_is_empty,
            unlock: record_empty_unlock,
        });
    }

    fn empty_queue() -> PointerQueue {
        PointerQueue {
            vtable: 0,
            pending: ListHead {
                head: null_mut(),
                tail: null_mut(),
            },
            mutex: Mutex {
                sem_cell: null_mut(),
                unused: 0,
            },
            ready: CondVar {
                lock_obj: null_mut(),
                waiters: ListHead {
                    head: null_mut(),
                    tail: null_mut(),
                },
            },
        }
    }

    #[test]
    fn enqueue_allocates_wrapper_and_signals_a_waiter() {
        let _heap = mock_heap();
        let mut storage = NodeStorage([0; 2]);
        let mut queue = empty_queue();
        let mut waiter = WaitNode {
            next: null_mut(),
            object: 0xfeedusize as *mut u32,
        };
        queue.ready.waiters.head = (&mut waiter as *mut WaitNode).cast();
        queue.ready.waiters.tail = (&mut waiter as *mut WaitNode).cast();
        unsafe {
            set_alloc_ret(storage.0.as_mut_ptr().cast());
            let value = 0x1234usize as *mut c_void;
            pointer_queue_enqueue(&mut queue, value);

            let node = storage.0.as_mut_ptr().cast::<PointerQueueNode>();
            assert_eq!(alloc_log(), (1, POINTER_QUEUE_NODE_TARGET_SIZE, 2));
            assert_eq!(queue.pending.head, (&mut (*node).link as *mut ListNode));
            assert_eq!(queue.pending.tail, (&mut (*node).link as *mut ListNode));
            assert_eq!((*node).link.next, null_mut());
            assert_eq!((*node).value, value);
            assert!(queue.ready.waiters.head.is_null());
            assert!(queue.ready.waiters.tail.is_null());
        }
    }

    #[test]
    fn enqueue_preserves_head_and_links_after_existing_tail() {
        let _heap = mock_heap();
        let mut existing = PointerQueueNode {
            link: ListNode { next: null_mut() },
            value: ptr::null_mut(),
        };
        let mut storage = NodeStorage([0; 2]);
        let mut queue = empty_queue();
        queue.pending.head = &mut existing.link as *mut ListNode;
        queue.pending.tail = &mut existing.link as *mut ListNode;

        unsafe {
            set_alloc_ret(storage.0.as_mut_ptr().cast());
            let value = 0x5678usize as *mut c_void;
            pointer_queue_enqueue(&mut queue, value);

            let node = storage.0.as_mut_ptr().cast::<PointerQueueNode>();
            assert_eq!(queue.pending.head, &mut existing.link as *mut ListNode);
            assert_eq!(existing.link.next, &mut (*node).link as *mut ListNode);
            assert_eq!(queue.pending.tail, &mut (*node).link as *mut ListNode);
            assert_eq!((*node).link.next, null_mut());
            assert_eq!((*node).value, value);
        }
    }

    #[test]
    fn is_empty_locks_queries_unlocks_and_returns_empty_result() {
        let _guard = EMPTY_OPS_LOCK.lock();
        let mut queue = empty_queue();
        unsafe {
            install_empty_ops(1, &mut queue);
            assert_eq!(pointer_queue_is_empty(&mut queue), 1);
            assert_eq!(EMPTY_CALLS, [1, 2, 3]);
        }
    }

    #[test]
    fn is_empty_preserves_nonempty_result_after_unlock() {
        let _guard = EMPTY_OPS_LOCK.lock();
        let mut queue = empty_queue();
        unsafe {
            install_empty_ops(0, &mut queue);
            assert_eq!(pointer_queue_is_empty(&mut queue), 0);
            assert_eq!(EMPTY_CALLS, [1, 2, 3]);
        }
    }
}
