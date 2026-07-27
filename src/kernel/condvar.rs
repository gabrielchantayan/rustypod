//! Port of the retailOS condition-variable / wait-queue layer @
//! 0x0807f5cc..0x0807f740 plus its intrusive singly-linked list helpers @
//! 0x080f10b8 (pop front), 0x080f10ec (remove) and 0x080f1158 (push back).
//!
//! The layer is a condvar-style sleep queue built on top of the RTXC
//! Quadros kernel in the S5L8702 mask ROM. A `CondVar` is three words:
//!
//! ```text
//! +0x00  lock_obj  pointer to a 4-byte kernel-object block (created by
//! |                the stock 0x08056724); *lock_obj is the semaphore
//! |                handle released/reacquired around the sleep
//! +0x04  head      intrusive wait-queue head
//! +0x08  tail      intrusive wait-queue tail
//! ```
//!
//! A waiter pushes a stack-resident node {next, object} where `object` is a
//! per-waiter kernel object (stock 0x08056788), unlocks the mutex
//! (semaphore signal on *lock_obj), sleeps on the object with a timeout
//! (stock 0x0805695c, true on RTXC RC 5 = timeout), relocks (semaphore
//! wait), destroys the object and unlinks the node. `condvar_broadcast`
//! pops every waiter and signals its object (stock 0x080567f8 -> ROM
//! 0x220041cc). There is no single-shot "signal" in this range; wakeups
//! always drain the whole queue.
//!
//! The single-shot signal lives elsewhere: `condvar_signal` —
//! `FUN_080744d8` @ 0x080744d8 (32 bytes, next to the mutex layer;
//! 10 bl call sites, among them the queue-node recycler @ 0x080ed958
//! twice). It pops ONE waiter off the queue at condvar+4 and signals its
//! object (`ldr r0, [node, #4]`, tail branch to stock 0x080567f8); an
//! empty queue is a no-op.
//!
//! Also in the range: `mqueue_receive` (0x0807f5f4), a locked message-queue
//! consumer over a different struct (mutex handle @ +0x2c, queue anchor @
//! +0x40) that pops nodes until the external deliver helper (0x080b4a88)
//! accepts one; `condvar_init`/`condvar_destroy` (0x0807f680/0x0807f650);
//! the semaphore-signal veneer `rtxc_semaphore_signal` (0x0807f6a0, the
//! name the heap link contract in heap/wrappers.rs expects); and the two
//! yield wrappers `task_yield`/`task_yield_thunk` (0x0807f670/0x0807f6a8)
//! around stock 0x80568fc, which tail-branches ROM 0x22004260 with r0 = 0.
//!
//! # Hook routing
//!
//! Every kernel/ROM call goes through the `CONDVAR_HOOKS` fn-pointer table
//! (pattern from heap/wrappers.rs): the stock semaphore/object wrappers
//! (0x08056510/0x08056710/0x08056724/0x0805646c/0x08056788/0x0805695c/
//! 0x080564ec/0x080567f8/0x080568fc) and the deliver helper 0x080b4a88 are
//! ported by other modules, so they cannot be imported here. The default
//! stubs model "kernel not present": creates return NULL, the sleep reports
//! success, deliver accepts the first node, everything else is a no-op.
//! Host tests install mocks; the ARM build replaces the table at link time.
//!
//! # Simplifications / deviations
//!
//! - `list_remove` (0x080f10ec) is kept private (not `#[no_mangle]`): the
//!   address sits between the two assigned helper exports and may be ported
//!   separately; `condvar_wait` needs the logic regardless. Faithful quirk
//!   kept: a node that is not found still gets its `next` zeroed.
//! - `waiter_create`'s hook takes no argument; the stock wrapper ignores
//!   the condvar pointer its caller leaves in r0.
//! - The ROM service behind `task_yield` (0x22004260, called with r0 = 0)
//!   is unidentified; it is yield-like (no input, result discarded by
//!   0x0807f670). `task_yield_thunk` (0x0807f6a8) is a naked tail branch in
//!   the original; the Rust version returns void, so the ROM result in r0
//!   is not propagated (the sole caller ignores it).
//! - `condvar_wait`'s double unlink on the timeout path (the node is
//!   removed once unconditionally and again when the sleep timed out) is
//!   deliberate in the original and is preserved.
//! - Struct fields are pointer-width, so byte offsets (+0x2c/+0x40 in
//!   `LockedQueue`, +0x04/+0x08 in `CondVar`) are exact only on the
//!   32-bit target; host tests go through field accesses and are
//!   layout-independent.

use core::ptr::null_mut;

/// Return code: operation completed (signaled / node delivered).
pub const CONDVAR_OK: i32 = 0;
/// `mqueue_receive` return code: queue empty.
pub const CONDVAR_EMPTY: i32 = 2;
/// `condvar_wait` return code: zero timeout or the sleep timed out.
pub const CONDVAR_TIMEOUT: i32 = 3;

/// Intrusive list node: the linkage word is always the FIRST word of the
/// containing node; the rest is the owner's payload.
#[repr(C)]
pub struct ListNode {
    pub next: *mut ListNode,
}

/// Head/tail anchor. `tail` makes push-back O(1); popping or removing the
/// last node clears both words.
#[repr(C)]
pub struct ListHead {
    pub head: *mut ListNode,
    pub tail: *mut ListNode,
}

/// Wait-queue node: linkage word + the per-waiter kernel-object handle
/// (created by the `waiter_create` hook, signalled by `waiter_wake`).
#[repr(C)]
pub struct WaitNode {
    pub next: *mut WaitNode,
    pub object: *mut u32,
}

/// Condition variable (see module header for the layout).
#[repr(C)]
pub struct CondVar {
    /// +0x00: kernel-object block from the `object_create` hook; the word
    /// inside the block is the semaphore handle released around the sleep.
    pub lock_obj: *mut u32,
    /// +0x04/+0x08: wait-queue anchor.
    pub waiters: ListHead,
}

/// Locked message queue consumed by `mqueue_receive` (0x0807f5f4). Only
/// the words the original touches are modelled; the pads stand in for the
/// owner struct's other fields.
#[repr(C)]
pub struct LockedQueue {
    /// +0x00..+0x2c: owner fields, not used here.
    _pad_0x00: [u32; 11],
    /// +0x2c: mutex handle (a semaphore slot pointer), passed by value to
    /// the sem_wait/sem_signal hooks around every pop.
    pub mutex: *mut u32,
    /// +0x30..+0x40: owner fields, not used here.
    _pad_0x30: [u32; 4],
    /// +0x40/+0x44: queue anchor (nodes are `ListNode`-linked; the deliver
    /// hook reads the payload at node+8).
    pub queue: ListHead,
}

/// Kernel/ROM services the layer depends on. See the module header for the
/// default-stub policy; every member cites the stock address it routes to.
#[derive(Copy, Clone)]
pub struct CondvarHooks {
    /// Stock 0x08056724: allocate a 4-byte block and create the kernel
    /// object whose handle is stored inside it. NULL on failure.
    pub object_create: unsafe extern "C" fn() -> *mut u32,
    /// Stock 0x0805646c: delete the kernel object whose handle is `*block`
    /// and free the block.
    pub object_delete: unsafe extern "C" fn(block: *mut u32),
    /// Stock 0x08056788: create a per-waiter kernel object, return its
    /// handle (the stock caller's r0 is ignored by the wrapper).
    pub waiter_create: unsafe extern "C" fn() -> *mut u32,
    /// Stock 0x0805695c: sleep on a waiter object for up to `timeout`
    /// ticks; returns 1 when the kernel reported the timeout return code
    /// (RTXC RC 5), 0 when signalled.
    pub waiter_wait: unsafe extern "C" fn(handle: *mut u32, timeout: u32) -> u32,
    /// Stock 0x080564ec: destroy a per-waiter kernel object.
    pub waiter_delete: unsafe extern "C" fn(handle: *mut u32),
    /// Stock 0x080567f8 (thunk to ROM 0x220041cc): signal a waiter object,
    /// waking its sleeper.
    pub waiter_wake: unsafe extern "C" fn(handle: *mut u32),
    /// Stock 0x08056510: semaphore wait (P). `slot` is the handle word;
    /// the stock wrapper waits on `*slot` when both are nonzero.
    pub sem_wait: unsafe extern "C" fn(slot: *mut u32),
    /// Stock 0x08056710: semaphore signal (V), same slot convention.
    pub sem_signal: unsafe extern "C" fn(slot: *mut u32),
    /// Stock 0x080568fc: ROM service 0x22004260 called with r0 = 0
    /// (yield-like; exact RTXC service unidentified).
    pub task_yield: unsafe extern "C" fn(),
    /// Stock 0x080b4a88: deliver a dequeued queue node. Copies the 8-byte
    /// payload at node+8 to `out_data`, stores the node (or NULL) to
    /// `*out_node`, returns nonzero when the node was accepted.
    pub deliver: unsafe extern "C" fn(
        node: *mut ListNode,
        out_data: *mut u32,
        out_node: *mut *mut ListNode,
    ) -> u32,
}

unsafe extern "C" fn missing_object_create() -> *mut u32 {
    null_mut()
}
unsafe extern "C" fn missing_object_delete(_block: *mut u32) {}
unsafe extern "C" fn missing_waiter_create() -> *mut u32 {
    null_mut()
}
unsafe extern "C" fn missing_waiter_wait(_handle: *mut u32, _timeout: u32) -> u32 {
    0
}
unsafe extern "C" fn missing_waiter_delete(_handle: *mut u32) {}
unsafe extern "C" fn missing_waiter_wake(_handle: *mut u32) {}
unsafe extern "C" fn missing_sem_op(_slot: *mut u32) {}
unsafe extern "C" fn missing_task_yield() {}
unsafe extern "C" fn missing_deliver(
    _node: *mut ListNode,
    _out_data: *mut u32,
    _out_node: *mut *mut ListNode,
) -> u32 {
    1
}

/// Hook table for the kernel/ROM dependencies. Replace before first use on
/// target; host tests install mocks via `core::ptr::addr_of_mut!`.
pub static mut CONDVAR_HOOKS: CondvarHooks = CondvarHooks {
    object_create: missing_object_create,
    object_delete: missing_object_delete,
    waiter_create: missing_waiter_create,
    waiter_wait: missing_waiter_wait,
    waiter_delete: missing_waiter_delete,
    waiter_wake: missing_waiter_wake,
    sem_wait: missing_sem_op,
    sem_signal: missing_sem_op,
    task_yield: missing_task_yield,
    deliver: missing_deliver,
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the loads
/// to the default stubs (see heap/wrappers.rs).
#[inline(always)]
fn hooks() -> CondvarHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDVAR_HOOKS)) }
}

/// list_pop_front — original: `FUN_080f10b8` @ 0x080f10b8 (48 bytes).
///
/// Removes and returns the head node, or NULL when the list is empty.
/// When the popped node was also the tail (single-element list) both
/// anchor words are cleared; the popped node's `next` is always zeroed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_pop_front(list: *mut ListHead) -> *mut ListNode {
    let node = (*list).head;
    if node.is_null() {
        return null_mut();
    }
    (*list).head = (*node).next;
    if (*list).tail == node {
        (*list).head = null_mut();
        (*list).tail = null_mut();
    }
    (*node).next = null_mut();
    node
}

/// list_push_back — original: `FUN_080f1158` @ 0x080f1158 (36 bytes).
///
/// Appends `node` at the tail (or makes it the head of an empty list) and
/// zeroes its `next`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn list_push_back(list: *mut ListHead, node: *mut ListNode) {
    if (*list).head.is_null() {
        (*list).head = node;
    } else {
        (*(*list).tail).next = node;
    }
    (*list).tail = node;
    (*node).next = null_mut();
}

/// list_remove — original: `FUN_080f10ec` @ 0x080f10ec (108 bytes).
///
/// Unlinks `node` from the list, fixing up the tail when needed. A NULL
/// node or an empty list is a no-op; a node that is never found still gets
/// its `next` zeroed (faithful to the original). Private on purpose — see
/// the module header.
unsafe fn list_remove(list: *mut ListHead, node: *mut ListNode) {
    if node.is_null() || (*list).head.is_null() {
        return;
    }
    if (*list).head == node {
        (*list).head = (*node).next;
        if (*list).tail == node {
            (*list).head = null_mut();
            (*list).tail = null_mut();
        }
    } else {
        let mut prev = (*list).head;
        let mut cur = (*prev).next;
        while !cur.is_null() {
            if cur == node {
                (*prev).next = (*node).next;
                if (*list).tail == node {
                    (*list).tail = prev;
                }
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }
    }
    (*node).next = null_mut();
}

/// condvar_broadcast — original: `FUN_0807f5cc` @ 0x0807f5cc (40 bytes).
///
/// Pops every waiter off the queue and signals its kernel object (FIFO
/// wake order). Does not touch the caller's mutex; the original is called
/// with the surrounding lock already held.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_broadcast(condvar: *mut CondVar) {
    let h = hooks();
    loop {
        let node = list_pop_front(&mut (*condvar).waiters);
        if node.is_null() {
            break;
        }
        (h.waiter_wake)((*(node as *mut WaitNode)).object);
    }
}

/// condvar_signal — original: `FUN_080744d8` @ 0x080744d8 (32 bytes;
/// 10 bl call sites).
///
/// Single-shot wake: pops the FIRST waiter (if any) and signals its
/// kernel object; the rest of the queue stays queued. Like the
/// broadcast, the caller holds the surrounding lock.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_signal(condvar: *mut CondVar) {
    let node = list_pop_front(&mut (*condvar).waiters);
    if !node.is_null() {
        (hooks().waiter_wake)((*(node as *mut WaitNode)).object);
    }
}

/// mqueue_receive — original: `FUN_0807f5f4` @ 0x0807f5f4 (92 bytes).
///
/// Locked message-queue consumer: takes the queue's mutex, pops the head
/// node, drops the mutex, and hands the node to the deliver hook. Nodes
/// the deliver hook rejects (return 0) are skipped; the loop retries until
/// a node is accepted (returns `CONDVAR_OK`) or the queue runs dry
/// (returns `CONDVAR_EMPTY`).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mqueue_receive(
    queue: *mut LockedQueue,
    out_data: *mut u32,
    out_node: *mut *mut ListNode,
) -> i32 {
    let h = hooks();
    loop {
        (h.sem_wait)((*queue).mutex);
        let node = list_pop_front(&mut (*queue).queue);
        (h.sem_signal)((*queue).mutex);
        if node.is_null() {
            return CONDVAR_EMPTY;
        }
        if (h.deliver)(node, out_data, out_node) != 0 {
            return CONDVAR_OK;
        }
    }
}

/// condvar_destroy — original: `FUN_0807f650` @ 0x0807f650 (32 bytes).
///
/// Deletes the kernel object block (if any) and clears the pointer.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_destroy(condvar: *mut CondVar) {
    let lock_obj = (*condvar).lock_obj;
    if !lock_obj.is_null() {
        (hooks().object_delete)(lock_obj);
    }
    (*condvar).lock_obj = null_mut();
}

/// task_yield — original: `FUN_0807f670` @ 0x0807f670 (16 bytes).
///
/// Invokes the yield-like ROM service (stock 0x80568fc -> ROM 0x22004260
/// with r0 = 0), discards its result and returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_yield() -> i32 {
    (hooks().task_yield)();
    0
}

/// task_yield_thunk — original: `thunk_FUN_080568fc` @ 0x0807f6a8
/// (4 bytes).
///
/// Naked tail branch to the same ROM service. The Rust version returns
/// void, so the ROM result in r0 is not propagated (see module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_yield_thunk() {
    (hooks().task_yield)();
}

/// condvar_init — original: `FUN_0807f680` @ 0x0807f680 (32 bytes).
///
/// Creates the kernel object block and empties the wait queue.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_init(condvar: *mut CondVar) {
    (*condvar).lock_obj = (hooks().object_create)();
    (*condvar).waiters.head = null_mut();
    (*condvar).waiters.tail = null_mut();
}

/// rtxc_semaphore_signal — original: `FUN_0807f6a0` @ 0x0807f6a0
/// (8 bytes).
///
/// Semaphore-signal veneer: loads the handle from `*slot` and signals it
/// (tail branch to stock 0x08056710). This is the "mutex unlock" the heap
/// lock path tail-calls; the name matches the link contract documented in
/// heap/wrappers.rs.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rtxc_semaphore_signal(slot: *mut u32) {
    (hooks().sem_signal)(slot.read() as *mut u32);
}

/// condvar_wait — original: `FUN_0807f6ac` @ 0x0807f6ac (148 bytes).
///
/// Classic monitor wait: a zero `timeout` is rejected with
/// `CONDVAR_TIMEOUT` up front. Otherwise a stack-resident waiter node is
/// created and enqueued, the mutex semaphore (`*lock_obj`) is released,
/// the task sleeps on the per-waiter object for up to `timeout` ticks, the
/// mutex is reacquired, and the node is unlinked. Returns `CONDVAR_OK`
/// when signalled, `CONDVAR_TIMEOUT` when the sleep expired. The
/// original's redundant second unlink on the timeout path is preserved
/// (the node is already gone; the walk simply finds nothing).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_wait(condvar: *mut CondVar, timeout: u32) -> i32 {
    if timeout == 0 {
        return CONDVAR_TIMEOUT;
    }
    let h = hooks();
    let lock_obj = (*condvar).lock_obj;
    let mut node = WaitNode {
        next: null_mut(),
        object: (h.waiter_create)(),
    };
    list_push_back(&mut (*condvar).waiters, &mut node as *mut WaitNode as *mut ListNode);
    (h.sem_signal)(lock_obj.read() as *mut u32);
    let sleep_rc = (h.waiter_wait)(node.object, timeout);
    let result = if sleep_rc == 1 {
        CONDVAR_TIMEOUT
    } else {
        CONDVAR_OK
    };
    (h.sem_wait)(lock_obj.read() as *mut u32);
    (h.waiter_delete)(node.object);
    node.object = null_mut();
    list_remove(&mut (*condvar).waiters, &mut node as *mut WaitNode as *mut ListNode);
    if result == CONDVAR_TIMEOUT {
        list_remove(&mut (*condvar).waiters, &mut node as *mut WaitNode as *mut ListNode);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::format;
    use std::string::String;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests: the hook table and mock state are global.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Default)]
    struct MockState {
        events: Vec<String>,
        wakes: Vec<usize>,
        deliver_calls: usize,
        deliver_rcs: Vec<u32>,
        wait_rc: u32,
        pop_on_wait: bool,
        wait_condvar: *mut CondVar,
        blocks: Vec<*mut u32>,
    }
    unsafe impl Send for MockState {}

    static MOCK: Mutex<Option<MockState>> = Mutex::new(None);

    fn state() -> std::sync::MutexGuard<'static, Option<MockState>> {
        MOCK.lock().unwrap()
    }

    unsafe extern "C" fn mock_object_create() -> *mut u32 {
        let mut g = state();
        let s = g.as_mut().unwrap();
        let block = Box::into_raw(Box::new(0x9000u32 + s.blocks.len() as u32));
        s.blocks.push(block);
        s.events.push(format!("obj_create->{:x}", block as usize));
        block
    }

    unsafe extern "C" fn mock_object_delete(block: *mut u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("obj_delete:{:x}", block as usize));
    }

    unsafe extern "C" fn mock_waiter_create() -> *mut u32 {
        let mut g = state();
        let s = g.as_mut().unwrap();
        s.events.push("waiter_create".into());
        (0xa000usize + s.events.len()) as *mut u32
    }

    unsafe extern "C" fn mock_waiter_wait(handle: *mut u32, timeout: u32) -> u32 {
        let mut g = state();
        let s = g.as_mut().unwrap();
        s.events.push(format!("sleep:{:x}/{timeout}", handle as usize));
        if s.pop_on_wait && !s.wait_condvar.is_null() {
            // Simulate a concurrent broadcast: the sleeper is woken by
            // popping its node before the sleep returns.
            let node = list_pop_front(&mut (*s.wait_condvar).waiters);
            s.wakes.push(node as usize);
        }
        s.wait_rc
    }

    unsafe extern "C" fn mock_waiter_delete(handle: *mut u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("waiter_delete:{:x}", handle as usize));
    }

    unsafe extern "C" fn mock_waiter_wake(handle: *mut u32) {
        let mut g = state();
        let s = g.as_mut().unwrap();
        s.events.push(format!("wake:{:x}", handle as usize));
        s.wakes.push(handle as usize);
    }

    unsafe extern "C" fn mock_sem_wait(slot: *mut u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("sem_wait:{:x}", slot as usize));
    }

    unsafe extern "C" fn mock_sem_signal(slot: *mut u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("sem_signal:{:x}", slot as usize));
    }

    unsafe extern "C" fn mock_task_yield() {
        state().as_mut().unwrap().events.push("yield".into());
    }

    unsafe extern "C" fn mock_deliver(
        node: *mut ListNode,
        out_data: *mut u32,
        out_node: *mut *mut ListNode,
    ) -> u32 {
        let mut g = state();
        let s = g.as_mut().unwrap();
        s.deliver_calls += 1;
        s.events.push(format!("deliver:{:x}", node as usize));
        out_data.write(0xd00d);
        out_node.write(node);
        if s.deliver_rcs.is_empty() {
            1
        } else {
            s.deliver_rcs.remove(0)
        }
    }

    const MOCK_HOOKS: CondvarHooks = CondvarHooks {
        object_create: mock_object_create,
        object_delete: mock_object_delete,
        waiter_create: mock_waiter_create,
        waiter_wait: mock_waiter_wait,
        waiter_delete: mock_waiter_delete,
        waiter_wake: mock_waiter_wake,
        sem_wait: mock_sem_wait,
        sem_signal: mock_sem_signal,
        task_yield: mock_task_yield,
        deliver: mock_deliver,
    };

    fn install(mock: MockState) -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap();
        unsafe {
            *core::ptr::addr_of_mut!(CONDVAR_HOOKS) = MOCK_HOOKS;
        }
        *state() = Some(mock);
        guard
    }

    fn take_events() -> Vec<String> {
        core::mem::take(&mut state().as_mut().unwrap().events)
    }

    fn make_condvar() -> CondVar {
        CondVar {
            lock_obj: null_mut(),
            waiters: ListHead {
                head: null_mut(),
                tail: null_mut(),
            },
        }
    }

    fn make_queue() -> LockedQueue {
        LockedQueue {
            _pad_0x00: [0; 11],
            mutex: null_mut(),
            _pad_0x30: [0; 4],
            queue: ListHead {
                head: null_mut(),
                tail: null_mut(),
            },
        }
    }

    // ---- list helpers ------------------------------------------------

    #[test]
    fn list_pop_empty_returns_null() {
        let mut list = ListHead {
            head: null_mut(),
            tail: null_mut(),
        };
        unsafe {
            assert!(list_pop_front(&mut list).is_null());
        }
    }

    #[test]
    fn list_push_pop_fifo_order() {
        let mut list = ListHead {
            head: null_mut(),
            tail: null_mut(),
        };
        let mut nodes: Vec<Box<ListNode>> =
            (0..4).map(|_| Box::new(ListNode { next: null_mut() })).collect();
        unsafe {
            for n in nodes.iter_mut() {
                list_push_back(&mut list, &mut **n);
            }
            assert_eq!(list.head, &mut *nodes[0] as *mut ListNode);
            assert_eq!(list.tail, &mut *nodes[3] as *mut ListNode);
            // Pop all: FIFO, each popped node's next is zeroed.
            for i in 0..4 {
                let popped = list_pop_front(&mut list);
                assert_eq!(popped, &mut *nodes[i] as *mut ListNode);
                assert!((*popped).next.is_null());
            }
            assert!(list.head.is_null());
            assert!(list.tail.is_null());
            assert!(list_pop_front(&mut list).is_null());
        }
    }

    #[test]
    fn list_single_element_clears_both_anchors() {
        let mut list = ListHead {
            head: null_mut(),
            tail: null_mut(),
        };
        let mut node = ListNode { next: null_mut() };
        unsafe {
            list_push_back(&mut list, &mut node);
            assert_eq!(list.head, &mut node as *mut ListNode);
            assert_eq!(list.tail, &mut node as *mut ListNode);
            assert_eq!(list_pop_front(&mut list), &mut node as *mut ListNode);
            assert!(list.head.is_null());
            assert!(list.tail.is_null());
            assert!(node.next.is_null());
        }
    }

    #[test]
    fn list_remove_head_middle_tail() {
        for remove_idx in 0..3 {
            let mut list = ListHead {
                head: null_mut(),
                tail: null_mut(),
            };
            let mut nodes: Vec<Box<ListNode>> =
                (0..3).map(|_| Box::new(ListNode { next: null_mut() })).collect();
            unsafe {
                for n in nodes.iter_mut() {
                    list_push_back(&mut list, &mut **n);
                }
                list_remove(&mut list, &mut *nodes[remove_idx]);
                // Remaining order preserved, anchors correct.
                let keep: Vec<usize> = (0..3).filter(|&i| i != remove_idx).collect();
                assert_eq!(list.head, &mut *nodes[keep[0]] as *mut ListNode);
                assert_eq!(list.tail, &mut *nodes[keep[1]] as *mut ListNode);
                assert!((*nodes[remove_idx]).next.is_null());
                assert_eq!(list_pop_front(&mut list), &mut *nodes[keep[0]] as *mut ListNode);
                assert_eq!(list_pop_front(&mut list), &mut *nodes[keep[1]] as *mut ListNode);
                assert!(list_pop_front(&mut list).is_null());
            }
        }
    }

    #[test]
    fn list_remove_only_element_and_absent_node() {
        let mut list = ListHead {
            head: null_mut(),
            tail: null_mut(),
        };
        let mut node = ListNode { next: null_mut() };
        let mut stranger = ListNode { next: null_mut() };
        unsafe {
            // Absent node: list untouched, stranger's next still zeroed
            // (faithful quirk).
            list_remove(&mut list, &mut stranger);
            list_push_back(&mut list, &mut node);
            list_remove(&mut list, &mut stranger);
            assert_eq!(list.head, &mut node as *mut ListNode);
            assert_eq!(list.tail, &mut node as *mut ListNode);
            // NULL node and empty list are no-ops.
            list_remove(&mut list, null_mut());
            // Remove the only element.
            list_remove(&mut list, &mut node);
            assert!(list.head.is_null());
            assert!(list.tail.is_null());
            assert!(node.next.is_null());
            // Empty list: no-op.
            list_remove(&mut list, &mut stranger);
        }
    }

    // ---- init / destroy ----------------------------------------------

    #[test]
    fn condvar_init_creates_object_and_empties_queue() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        unsafe {
            condvar_init(&mut cv);
            assert!(!cv.lock_obj.is_null());
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
        }
        let events = take_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].starts_with("obj_create->"));
    }

    #[test]
    fn condvar_destroy_deletes_once_and_clears() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        unsafe {
            condvar_init(&mut cv);
            let block = cv.lock_obj;
            condvar_destroy(&mut cv);
            assert!(cv.lock_obj.is_null());
            // Second destroy: pointer already NULL, no further delete.
            condvar_destroy(&mut cv);
            let events = take_events();
            assert_eq!(
                events,
                Vec::from([
                    format!("obj_create->{:x}", block as usize),
                    format!("obj_delete:{:x}", block as usize),
                ])
            );
        }
    }

    // ---- wait ----------------------------------------------------------

    #[test]
    fn condvar_wait_zero_timeout_rejected_without_touching_kernel() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        unsafe {
            assert_eq!(condvar_wait(&mut cv, 0), CONDVAR_TIMEOUT);
        }
        assert!(take_events().is_empty());
    }

    #[test]
    fn condvar_wait_signaled_releases_and_reacquires_mutex() {
        let mut mock = MockState::default();
        mock.wait_rc = 0;
        let _guard = install(mock);
        let mut cv = make_condvar();
        unsafe {
            condvar_init(&mut cv);
            take_events();
            let rc = condvar_wait(&mut cv, 100);
            assert_eq!(rc, CONDVAR_OK);
            // Node unlinked after the wait.
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
            let handle = cv.lock_obj.read();
            let events = take_events();
            // waiter_create, unlock, sleep, relock, waiter_delete.
            assert_eq!(events[0], "waiter_create");
            assert_eq!(events[1], format!("sem_signal:{:x}", handle as usize));
            assert!(events[2].starts_with("sleep:"));
            assert!(events[2].ends_with("/100"));
            assert_eq!(events[3], format!("sem_wait:{:x}", handle as usize));
            assert!(events[4].starts_with("waiter_delete:"));
            assert_eq!(events.len(), 5);
        }
    }

    #[test]
    fn condvar_wait_timeout_returns_3_and_unlinks() {
        let mut mock = MockState::default();
        mock.wait_rc = 1; // kernel reported the timeout return code
        let _guard = install(mock);
        let mut cv = make_condvar();
        unsafe {
            condvar_init(&mut cv);
            take_events();
            assert_eq!(condvar_wait(&mut cv, 50), CONDVAR_TIMEOUT);
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
        }
    }

    #[test]
    fn condvar_wait_woken_by_broadcast_stays_consistent() {
        let mut mock = MockState::default();
        mock.wait_rc = 0;
        mock.pop_on_wait = true;
        let _guard = install(mock);
        let mut cv = make_condvar();
        unsafe {
            condvar_init(&mut cv);
            state().as_mut().unwrap().wait_condvar = &mut cv;
            take_events();
            assert_eq!(condvar_wait(&mut cv, 10), CONDVAR_OK);
            // The waker popped the node mid-sleep; the trailing unlink
            // found nothing and the queue stayed consistent.
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
            let popped = state().as_mut().unwrap().wakes.clone();
            assert_eq!(popped.len(), 1);
            assert!(!popped.contains(&0));
        }
    }

    // ---- broadcast -----------------------------------------------------

    #[test]
    fn condvar_broadcast_wakes_all_in_fifo_order() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        let mut nodes: Vec<Box<WaitNode>> = (0..3)
            .map(|i| {
                Box::new(WaitNode {
                    next: null_mut(),
                    object: (0xb000 + i) as *mut u32,
                })
            })
            .collect();
        unsafe {
            for n in nodes.iter_mut() {
                list_push_back(&mut cv.waiters, &mut **n as *mut WaitNode as *mut ListNode);
            }
            condvar_broadcast(&mut cv);
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
            for n in nodes.iter() {
                assert!(n.next.is_null());
            }
        }
        let wakes = state().as_mut().unwrap().wakes.clone();
        assert_eq!(wakes, Vec::from([0xb000usize, 0xb001, 0xb002]));
    }

    #[test]
    fn condvar_signal_wakes_only_the_first_waiter() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        let mut nodes: Vec<Box<WaitNode>> = (0..3)
            .map(|i| {
                Box::new(WaitNode {
                    next: null_mut(),
                    object: (0xc000 + i) as *mut u32,
                })
            })
            .collect();
        unsafe {
            for n in nodes.iter_mut() {
                list_push_back(&mut cv.waiters, &mut **n as *mut WaitNode as *mut ListNode);
            }
            condvar_signal(&mut cv);
            // Only the head was popped and woken; the queue keeps 2.
            assert_eq!(cv.waiters.head, &mut *nodes[1] as *mut WaitNode as *mut ListNode);
            assert_eq!(cv.waiters.tail, &mut *nodes[2] as *mut WaitNode as *mut ListNode);
            assert!(nodes[0].next.is_null());
        }
        let wakes = state().as_mut().unwrap().wakes.clone();
        assert_eq!(wakes, Vec::from([0xc000usize]));
    }

    #[test]
    fn condvar_signal_empty_queue_is_noop() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        unsafe {
            condvar_signal(&mut cv);
        }
        assert!(take_events().is_empty());
    }

    #[test]
    fn condvar_broadcast_empty_queue_is_noop() {
        let _guard = install(MockState::default());
        let mut cv = make_condvar();
        unsafe {
            condvar_broadcast(&mut cv);
        }
        assert!(take_events().is_empty());
    }

    // ---- mqueue_receive -------------------------------------------------

    #[test]
    fn mqueue_receive_empty_returns_2_after_lock_cycle() {
        let _guard = install(MockState::default());
        let mut queue = make_queue();
        queue.mutex = 0x7000usize as *mut u32;
        let mut out_data = 0u32;
        let mut out_node: *mut ListNode = null_mut();
        unsafe {
            let rc = mqueue_receive(&mut queue, &mut out_data, &mut out_node);
            assert_eq!(rc, CONDVAR_EMPTY);
        }
        assert_eq!(
            take_events(),
            Vec::from([
                String::from("sem_wait:7000"),
                String::from("sem_signal:7000"),
            ])
        );
    }

    #[test]
    fn mqueue_receive_retries_until_deliver_accepts() {
        let mut mock = MockState::default();
        mock.deliver_rcs = std::vec![0, 1];
        let _guard = install(mock);
        let mut queue = make_queue();
        queue.mutex = 0x7000usize as *mut u32;
        let mut nodes: Vec<Box<ListNode>> =
            (0..2).map(|_| Box::new(ListNode { next: null_mut() })).collect();
        let mut out_data = 0u32;
        let mut out_node: *mut ListNode = null_mut();
        unsafe {
            for n in nodes.iter_mut() {
                list_push_back(&mut queue.queue, &mut **n);
            }
            let rc = mqueue_receive(&mut queue, &mut out_data, &mut out_node);
            assert_eq!(rc, CONDVAR_OK);
            assert_eq!(out_data, 0xd00d);
            assert_eq!(out_node, &mut *nodes[1] as *mut ListNode);
            assert!(queue.queue.head.is_null());
            assert!(queue.queue.tail.is_null());
            let events = take_events();
            // Two lock/pop/unlock cycles, two deliver calls.
            assert_eq!(state().as_mut().unwrap().deliver_calls, 2);
            assert_eq!(events[0], "sem_wait:7000");
            assert_eq!(events[1], "sem_signal:7000");
            assert!(events[2].starts_with("deliver:"));
            assert_eq!(events[3], "sem_wait:7000");
            assert_eq!(events[4], "sem_signal:7000");
            assert!(events[5].starts_with("deliver:"));
            assert_eq!(events.len(), 6);
        }
    }

    // ---- veneers ---------------------------------------------------------

    #[test]
    fn rtxc_semaphore_signal_forwards_loaded_handle() {
        let _guard = install(MockState::default());
        let mut slot: u32 = 0x5000;
        unsafe {
            rtxc_semaphore_signal(&mut slot);
        }
        assert_eq!(
            take_events(),
            Vec::from([String::from("sem_signal:5000")])
        );
    }

    #[test]
    fn task_yield_variants_call_rom_service() {
        let _guard = install(MockState::default());
        unsafe {
            assert_eq!(task_yield(), 0);
            task_yield_thunk();
        }
        assert_eq!(
            take_events(),
            Vec::from([String::from("yield"), String::from("yield")])
        );
    }
}
