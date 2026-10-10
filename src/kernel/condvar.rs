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
//! Also in the range: `mqueue_receive` (0x0807f5f4), now implemented in
//! kernel/mqueue.rs; `condvar_init`/`condvar_destroy` (0x0807f680/0x0807f650);
//! the semaphore-signal veneer `rtxc_semaphore_signal` (0x0807f6a0, the
//! name the heap link contract in heap/wrappers.rs expects); and the two
//! yield wrappers `task_yield`/`task_yield_thunk` (0x0807f670/0x0807f6a8)
//! around stock 0x80568fc, which tail-branches ROM 0x22004260 with r0 = 0.
//!
//! Out-of-range but of the same family: `condvar_bind` — `FUN_080ed9c8` @
//! 0x080ed9c8 (20 bytes, 21 bl call sites). The no-allocation initializer:
//! stores a caller-provided lock word into `lock_obj` and clears the wait
//! queue (the queue-pool initializer @ 0x0809eab8 calls it twice).
//! `condvar_wait_forever` — `FUN_080ed9dc` @ 0x080ed9dc (76 bytes, 30
//! unconditional `bl` call sites) — is the unbounded counterpart: it
//! creates and enqueues a stack waiter, drops the associated semaphore,
//! waits through the raw csem service, destroys the waiter, then relocks.
//!
//! # Hook routing
//!
//! Every timeout-capable kernel/ROM call goes through the `CONDVAR_HOOKS`
//! fn-pointer table (pattern from heap/wrappers.rs): the stock
//! semaphore/object wrappers (0x08056510/0x08056710/0x08056724/0x0805646c/
//! 0x08056788/0x0805695c/0x080564ec/0x080567f8/0x080568fc) and the deliver
//! helper 0x080b4a88 are ported by other modules, so they cannot be imported
//! here. The default stubs model "kernel not present": creates return NULL,
//! the sleep reports success, deliver accepts the first node, everything else
//! is a no-op. Host tests install mocks; the ARM build replaces the table at
//! link time. `condvar_wait_forever` directly calls its already-ported
//! wrappers instead of duplicating those bindings in a new seam.
//!
//! # Simplifications / deviations
//!
//! - `list_remove` (0x080f10ec) preserves the stock quirk: a node that
//!   is not found in a nonempty list still gets its `next` zeroed.
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
//! - Struct fields are pointer-width, so CondVar's +0x04/+0x08 offsets
//!   are exact only on the 32-bit target; host tests use field accesses.

use crate::kernel::{
    csem::csem_wake,
    kobj::{waiter_create, waiter_delete},
    sync_sem::{sem_signal, sem_wait},
};
use core::ptr::null_mut;

/// Return code: operation completed (signaled / node delivered).
pub const CONDVAR_OK: i32 = 0;
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
};

/// Reads the hook table. Volatile so LLVM cannot constant-fold the loads
/// to the default stubs (see heap/wrappers.rs).
#[inline(always)]
fn hooks() -> CondvarHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CONDVAR_HOOKS)) }
}

/// list_pop_front — original: `FUN_080f10b8` @ 0x080f10b8 (52 bytes;
/// 16 bl call sites, all unconditional).
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

/// list_push_back — original: `FUN_080f1158` @ 0x080f1158 (36 bytes;
/// 15 bl call sites, all unconditional, binary-verified).
///
/// Appends `node` at the tail (or makes it the head of an empty list) and
/// zeroes its `next`. The original ends `mov r0,#0; str r0,[r1]; bx lr` —
/// r0 is a zero SCRATCH for the node->next store, not a return value
/// (every caller discards r0), so the port returns void.
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

/// list_remove — original: `FUN_080f10ec` @ 0x080f10ec.
///
/// Raw A32 extent [0x080f10ec, 0x080f1158): 108 bytes, ending in `bx lr`
/// immediately before list_push_back. Two incoming BL sites: plain BL at
/// 0x0807f724 and BLEQ at 0x0807f734; zero outgoing BLs (plain or predicated).
/// Walks the singly-linked list, unlinks `node`, and repairs the tail.
/// A NULL node or empty list is a no-op; an absent node in a nonempty list
/// still has its next link cleared. Removing the head when it is also the
/// tail clears both anchors, even if its next link was non-NULL.
/// Deliberate deviation: repr(C) native pointers widen on the host; target
/// links and anchor fields remain four-byte words. No algorithm deviation.
///
/// # Safety
/// A non-NULL node must be writable. Unless node is NULL, list must be valid;
/// reachable nodes must be writable and form a finite, acyclic chain.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn list_remove(list: *mut ListHead, node: *mut ListNode) {
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
#[inline(never)]
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
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_signal(condvar: *mut CondVar) {
    let node = list_pop_front(&mut (*condvar).waiters);
    if !node.is_null() {
        (hooks().waiter_wake)((*(node as *mut WaitNode)).object);
    }
}

/// Mode-selecting single-shot signal — `FUN_080c675c` @ 0x080c675c.
///
/// True extent: 12 bytes, ending at the independently called mutex-create
/// veneer @ 0x080c6768. Raw words: e3510001 1afeb75c 0aff6159
/// (`cmp r1,#1; bne 0x080744d8; beq 0x0809ecd0`). Verified inbound
/// calls: two plain BL (0x081af864, 0x081afc94), zero predicated BL;
/// no outbound BL. Mode 1 pops one waiter and schedules its deferred wake;
/// every other mode uses the normal single-shot signal. Empty queues do nothing.
///
/// Deliberate deviations: Rust expands the unported 0x0809ecd0 wrapper
/// using the existing list-pop and ROM-service seams, rather than adding
/// another binding. Ordinary Rust calls replace the original tail branches;
/// queue fields use native-width pointers on hosts (four-byte words on ARM).
///
/// # Safety
/// `condvar` and its linked wait nodes must be valid; the caller holds the
/// surrounding lock and installs the kernel hooks before use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_signal_dispatch(condvar: *mut CondVar, mode: u32) {
    if mode == 1 {
        let node = list_pop_front(&mut (*condvar).waiters);
        if !node.is_null() {
            crate::kernel::task_lock::rom_svc_22001cbc(
                (*(node as *mut WaitNode)).object as usize,
            );
        }
    } else {
        condvar_signal(condvar);
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
#[inline(never)]
pub unsafe extern "C" fn condvar_init(condvar: *mut CondVar) {
    (*condvar).lock_obj = (hooks().object_create)();
    (*condvar).waiters.head = null_mut();
    (*condvar).waiters.tail = null_mut();
}

/// condvar_bind — original: `FUN_080ed9c8` @ 0x080ed9c8 (20 bytes;
/// 21 bl call sites, among them queue_pool_init @ 0x0809eadc/0x0809eb44).
///
/// The other condvar initializer: instead of creating a fresh kernel
/// object (`condvar_init`), it binds the condvar to a caller-provided
/// lock word (`lock_obj` = a pointer to the slot holding the associated
/// semaphore/lock handle) and empties the wait queue. Three plain
/// stores, no calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_bind(condvar: *mut CondVar, lock_obj: *mut u32) {
    (*condvar).lock_obj = lock_obj;
    (*condvar).waiters.head = null_mut();
    (*condvar).waiters.tail = null_mut();
}

/// condvar_construct_with_lock — original: `FUN_082743dc` @ 0x082743dc
/// (40 bytes; 11 verified unconditional `bl` call sites, no predicated
/// forms).
///
/// Initializes a caller-owned condvar around `lock_obj`: clears all three
/// words, then invokes `condvar_bind` (0x080ed9c8) with the original
/// forwarded r1 lock-word argument, and returns `condvar`. The preliminary
/// clears are observably redundant with `condvar_bind`'s stores but are kept
/// to preserve the original operation order. Deliberate deviations: none;
/// the existing direct port is called rather than adding a duplicate seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_construct_with_lock(
    condvar: *mut CondVar,
    lock_obj: *mut u32,
) -> *mut CondVar {
    (*condvar).lock_obj = null_mut();
    (*condvar).waiters.head = null_mut();
    (*condvar).waiters.tail = null_mut();
    condvar_bind(condvar, lock_obj);
    condvar
}

/// condvar_wait_forever — original: `FUN_080ed9dc` @ 0x080ed9dc (76 bytes;
/// 30 verified unconditional `bl` call sites).
///
/// Creates a stack waiter, appends it to `condvar`'s wait queue, releases the
/// associated semaphore, enters the raw csem service, deletes the waiter,
/// clears the stack object's handle, and reacquires the semaphore. The raw
/// csem call must not return until a waker has removed this stack node; the
/// original performs no trailing unlink. Deliberate deviations: none. Calls
/// to the already-ported semaphore, waiter, and csem wrappers are direct so
/// this port introduces no duplicate dispatch seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn condvar_wait_forever(condvar: *mut CondVar) {
    let lock_obj = (*condvar).lock_obj;
    let mut node = WaitNode {
        next: null_mut(),
        object: waiter_create() as *mut u32,
    };
    list_push_back(
        &mut (*condvar).waiters,
        &mut node as *mut WaitNode as *mut ListNode,
    );
    sem_signal(lock_obj.read() as *mut u32);
    csem_wake(node.object as usize as u32);
    waiter_delete(node.object as usize as u32);
    node.object = null_mut();
    sem_wait(lock_obj.read() as *mut u32);
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
    use crate::kernel::kobj::{KobjHooks, KOBJ_HOOKS};
    use crate::kernel::sync_sem::{RomKernel, ROM_KERNEL};
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::boxed::Box;
    use parking_lot::MutexGuard as ParkingMutexGuard;
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
        wait_rc: u32,
        pop_on_wait: bool,
        wait_condvar: *mut CondVar,
        blocks: Vec<*mut u32>,
        idle_owner: *mut crate::app::wait_until_idle::IdleWaitOwner,
        idle_wakes_remaining: usize,
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


    struct DirectKernelGuard {
        kobj: KobjHooks,
        sem: RomKernel,
        dispatch: MessageDispatchVeneerOps,
        _dispatch_lock: ParkingMutexGuard<'static, ()>,
    }

    impl Drop for DirectKernelGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(KOBJ_HOOKS), self.kobj);
                core::ptr::write_volatile(core::ptr::addr_of_mut!(ROM_KERNEL), self.sem);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(MESSAGE_DISPATCH_VENEER_OPS),
                    self.dispatch,
                );
            }
        }
    }

    unsafe extern "C" fn direct_waiter_create(_op: u32, slot: *mut u32) {
        slot.write(0xa001);
        state().as_mut().unwrap().events.push("waiter_create".into());
    }

    unsafe extern "C" fn direct_waiter_delete(_op: u32, slot: *mut u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("waiter_delete:{:x}", slot.read()));
    }

    unsafe extern "C" fn direct_task_lock(id: u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("task_lock:{id:x}"));
    }

    unsafe extern "C" fn direct_task_unlock(id: u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("task_unlock:{id:x}"));
    }

    unsafe extern "C" fn direct_heap_alloc(_size: usize) -> *mut u8 {
        null_mut()
    }

    unsafe extern "C" fn direct_heap_free(_ptr: *mut u8) {}

    unsafe extern "C" fn direct_waiter_wait(_id: u32, _timeout: u32) -> u32 {
        0
    }

    unsafe extern "C" fn direct_waiter_signal(_id: u32) {}

    unsafe extern "C" fn direct_sem_create(_op: u32, _slot: *mut u32) {}

    unsafe extern "C" fn direct_sem_delete(_op: u32, _slot: *mut u32) {}

    unsafe extern "C" fn direct_sem_wait(id: u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("sem_wait:{id:x}"));
    }

    unsafe extern "C" fn direct_sem_signal(id: u32) {
        state()
            .as_mut()
            .unwrap()
            .events
            .push(format!("sem_signal:{id:x}"));
    }

    unsafe extern "C" fn direct_in_isr_context() -> u32 {
        0
    }

    unsafe extern "C" fn direct_sem_alloc(_size: usize) -> *mut u32 {
        null_mut()
    }

    unsafe extern "C" fn direct_sem_free(_ptr: *mut u32) {}

    unsafe extern "C" fn direct_gateway_wake(request: *mut u32) {
        assert_eq!(request.read(), 1, "condvar wake posts selector 1");
        let id = request.add(2).read();
        let condvar = state().as_ref().unwrap().wait_condvar;
        let node = if condvar.is_null() {
            null_mut()
        } else {
            list_pop_front(&mut (*condvar).waiters)
        };
        let mut g = state();
        let s = g.as_mut().unwrap();
        s.events.push(format!("csem_wake:{id:x}"));
        s.wakes.push(node as usize);
        if !s.idle_owner.is_null() {
            s.idle_wakes_remaining -= 1;
            if s.idle_wakes_remaining == 0 {
                core::ptr::addr_of_mut!((*s.idle_owner).busy).write(0);
            }
        }
    }

    unsafe fn install_direct_kernel_mocks() -> DirectKernelGuard {
        let dispatch_lock = DISPATCH_OPS_LOCK.lock();
        let guard = DirectKernelGuard {
            kobj: core::ptr::read_volatile(core::ptr::addr_of!(KOBJ_HOOKS)),
            sem: core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL)),
            dispatch: core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_VENEER_OPS)),
            _dispatch_lock: dispatch_lock,
        };
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(KOBJ_HOOKS),
            KobjHooks {
                op_create: direct_waiter_create,
                op_delete: direct_waiter_delete,
                task_lock: direct_task_lock,
                task_unlock: direct_task_unlock,
                heap_alloc: direct_heap_alloc,
                heap_free: direct_heap_free,
                rom_waiter_wait: direct_waiter_wait,
                rom_waiter_signal: direct_waiter_signal,
            },
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(ROM_KERNEL),
            RomKernel {
                op_create: direct_sem_create,
                op_delete: direct_sem_delete,
                wait: direct_sem_wait,
                signal: direct_sem_signal,
                in_isr_context: direct_in_isr_context,
                heap_alloc: direct_sem_alloc,
                heap_free: direct_sem_free,
            },
        );
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(MESSAGE_DISPATCH_VENEER_OPS),
            MessageDispatchVeneerOps {
                dispatch: direct_gateway_wake,
            },
        );
        guard
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
    fn list_remove_singleton_clears_anchors_even_with_successor() {
        let mut successor = ListNode { next: null_mut() };
        let mut node = ListNode { next: &mut successor };
        let mut list = ListHead { head: &mut node, tail: &mut node };
        unsafe { list_remove(&mut list, &mut node); }
        assert!(list.head.is_null());
        assert!(list.tail.is_null());
        assert!(node.next.is_null());
        assert!(successor.next.is_null());
    }

    #[test]
    fn list_remove_null_and_empty_leave_links_untouched() {
        let mut successor = ListNode { next: null_mut() };
        let mut node = ListNode { next: &mut successor };
        let mut list = ListHead { head: null_mut(), tail: &mut node };
        unsafe {
            list_remove(null_mut(), null_mut());
            list_remove(&mut list, &mut node);
        }
        assert!(list.head.is_null());
        assert_eq!(list.tail, &mut node as *mut ListNode);
        assert_eq!(node.next, &mut successor as *mut ListNode);
        list.head = &mut node;
        unsafe { list_remove(&mut list, null_mut()); }
        assert_eq!(list.head, &mut node as *mut ListNode);
        assert_eq!(list.tail, &mut node as *mut ListNode);
        assert_eq!(node.next, &mut successor as *mut ListNode);
    }

    #[test]
    fn list_remove_absent_clears_only_requested_link_and_can_repeat() {
        let mut tail = ListNode { next: null_mut() };
        let mut head = ListNode { next: &mut tail };
        let mut absent = ListNode { next: &mut head };
        let mut list = ListHead { head: &mut head, tail: &mut tail };
        unsafe {
            list_remove(&mut list, &mut absent);
            list_remove(&mut list, &mut absent);
        }
        assert_eq!(list.head, &mut head as *mut ListNode);
        assert_eq!(list.tail, &mut tail as *mut ListNode);
        assert_eq!(head.next, &mut tail as *mut ListNode);
        assert!(tail.next.is_null());
        assert!(absent.next.is_null());
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
    fn condvar_bind_stores_the_lock_word_and_empties_the_queue() {
        let _guard = install(MockState::default());
        let mut lock_word = 0u32;
        let mut cv = make_condvar();
        // Seed a stale wait queue to prove bind clears it.
        let mut stale = ListNode { next: null_mut() };
        cv.waiters.head = &mut stale;
        cv.waiters.tail = &mut stale;
        unsafe {
            condvar_bind(&mut cv, &mut lock_word);
            assert_eq!(cv.lock_obj, &mut lock_word as *mut u32);
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
        }
        assert!(take_events().is_empty(), "pure stores — no kernel calls");
    }

    #[test]
    fn condvar_construct_with_lock_returns_receiver_and_replaces_stale_state() {
        let _guard = install(MockState::default());
        let mut lock_word = 0u32;
        let mut cv = make_condvar();
        let mut stale_lock = 0u32;
        let mut stale = ListNode { next: null_mut() };
        cv.lock_obj = &mut stale_lock;
        cv.waiters.head = &mut stale;
        cv.waiters.tail = &mut stale;

        unsafe {
            let result = condvar_construct_with_lock(&mut cv, &mut lock_word);
            assert_eq!(result, &mut cv as *mut CondVar);
            assert_eq!(cv.lock_obj, &mut lock_word as *mut u32);
            assert!(cv.waiters.head.is_null());
            assert!(cv.waiters.tail.is_null());
        }
        assert!(take_events().is_empty(), "only stores and condvar_bind");
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

    #[test]
    fn idle_wait_rechecks_busy_after_spurious_wakes_and_preserves_owner() {
        use crate::app::wait_until_idle::{wait_until_idle, IdleWaitOwner};

        for (busy, wakes) in [(0, 0), (1, 1), (0x80, 3), (0xff, 2)] {
            let _condvar_guard = install(MockState::default());
            let _kernel_guard = unsafe { install_direct_kernel_mocks() };
            let mut owner: IdleWaitOwner = unsafe { core::mem::zeroed() };
            owner.opaque.fill(0xa5);
            owner.padding = [0x12, 0x34];
            owner.busy = busy;
            let mut lock_word = 0u32;
            let mut zero_handle = 0u32;
            owner.condvar.lock_obj = &mut lock_word;
            // Exercise both null-cell and zero-handle mutex guards.
            if busy & 1 != 0 {
                owner.mutex.sem_cell = &mut zero_handle;
            }
            {
                let mut mock = state();
                let mock = mock.as_mut().unwrap();
                mock.wait_condvar = &mut owner.condvar;
                mock.idle_owner = &mut owner;
                mock.idle_wakes_remaining = wakes;
            }
            unsafe { wait_until_idle(&mut owner) };
            assert_eq!(owner.busy, 0);
            assert_eq!(state().as_ref().unwrap().wakes.len(), wakes);
            assert_eq!(state().as_ref().unwrap().idle_wakes_remaining, 0);
            assert!(owner.condvar.waiters.head.is_null());
            assert!(owner.condvar.waiters.tail.is_null());
            assert_eq!(owner.opaque, [0xa5; 0x22d]);
            assert_eq!(owner.padding, [0x12, 0x34]);
            assert_eq!(zero_handle, 0);
        }
    }

    #[test]
    fn condvar_wait_forever_cycles_the_waiter_and_lock_after_wake() {
        let Some(slab) = try_map_u32_slab(hints::CONDVAR_WAIT_FOREVER_SIGNALED, 0x1000) else {
            note_missing_u32_fixture("kernel::condvar::condvar_wait_forever_signaled");
            return;
        };
        let semaphore_slot = slab.cast::<u32>();
        unsafe {
            semaphore_slot.write(0x1234);
        }
        let mut lock_obj_word = semaphore_slot as usize as u32;
        let _condvar_guard = install(MockState::default());
        let _kernel_guard = unsafe { install_direct_kernel_mocks() };
        let mut cv = make_condvar();
        cv.lock_obj = &mut lock_obj_word;
        state().as_mut().unwrap().wait_condvar = &mut cv;
        unsafe {
            condvar_wait_forever(&mut cv);
        }
        assert!(cv.waiters.head.is_null(), "the raw csem waker popped the stack node");
        assert!(cv.waiters.tail.is_null());
        assert_eq!(
            take_events(),
            Vec::<String>::from([
                "waiter_create".into(),
                "sem_signal:1234".into(),
                "csem_wake:a001".into(),
                "task_lock:a001".into(),
                "task_unlock:a001".into(),
                "waiter_delete:a001".into(),
                "sem_wait:1234".into(),
            ])
        );
        assert_eq!(state().as_ref().unwrap().wakes.len(), 1);
    }

    #[test]
    fn condvar_wait_forever_skips_null_semaphore_id() {
        let Some(slab) = try_map_u32_slab(hints::CONDVAR_WAIT_FOREVER_EMPTY, 0x1000) else {
            note_missing_u32_fixture("kernel::condvar::condvar_wait_forever_empty");
            return;
        };
        let semaphore_slot = slab.cast::<u32>();
        unsafe {
            semaphore_slot.write(0);
        }
        let mut lock_obj_word = semaphore_slot as usize as u32;
        let _condvar_guard = install(MockState::default());
        let _kernel_guard = unsafe { install_direct_kernel_mocks() };
        let mut cv = make_condvar();
        cv.lock_obj = &mut lock_obj_word;
        state().as_mut().unwrap().wait_condvar = &mut cv;
        unsafe {
            condvar_wait_forever(&mut cv);
        }
        assert!(cv.waiters.head.is_null());
        assert!(cv.waiters.tail.is_null());
        assert_eq!(
            take_events(),
            Vec::<String>::from([
                "waiter_create".into(),
                "csem_wake:a001".into(),
                "task_lock:a001".into(),
                "task_unlock:a001".into(),
                "waiter_delete:a001".into(),
            ])
        );
    }

    // ---- broadcast -----------------------------------------------------
    #[test]
    fn pending_work_publishes_before_waking_and_repeatedly_drains_waiters() {
        use crate::app::work_pending_notify::{work_pending_notify, WorkPendingOwner};
        use crate::kernel::sync_mutex::Mutex as OwnerMutex;

        unsafe extern "C" fn wake_after_publication(pending: *mut u32) {
            assert_eq!((pending as *mut u8).read_volatile(), 1);
            mock_waiter_wake(pending);
        }

        let _guard = install(MockState::default());
        unsafe { (*core::ptr::addr_of_mut!(CONDVAR_HOOKS)).waiter_wake = wake_after_publication };
        for initial in [0, 1, 0x80, 0xff] {
            let mut owner = WorkPendingOwner {
                preserved: [0x1234_5678; 10],
                pending: initial,
                padding: [0xa5; 3],
                mutex: OwnerMutex { sem_cell: null_mut(), unused: 0xdead_beef },
                changed: make_condvar(),
            };
            let pending = core::ptr::addr_of_mut!(owner.pending) as *mut u32;
            let mut nodes = [
                WaitNode { next: null_mut(), object: pending },
                WaitNode { next: null_mut(), object: pending },
            ];
            for count in [0, 2, 1, 0] {
                state().as_mut().unwrap().wakes.clear();
                unsafe {
                    for node in &mut nodes[..count] {
                        list_push_back(&mut owner.changed.waiters, node as *mut WaitNode as *mut ListNode);
                    }
                    work_pending_notify(&mut owner);
                }
                assert_eq!(owner.pending, 1);
                assert!(owner.changed.waiters.head.is_null());
                assert!(owner.changed.waiters.tail.is_null());
                assert_eq!(state().as_ref().unwrap().wakes, std::vec![pending as usize; count]);
                assert_eq!(owner.preserved, [0x1234_5678; 10]);
                assert_eq!(owner.padding, [0xa5; 3]);
                assert_eq!(owner.mutex.unused, 0xdead_beef);
                assert!(owner.mutex.sem_cell.is_null());
                assert!(owner.changed.lock_obj.is_null());
                for node in &nodes {
                    assert!(node.next.is_null());
                }
            }
        }
        unsafe { (*core::ptr::addr_of_mut!(CONDVAR_HOOKS)).waiter_wake = mock_waiter_wake };
    }


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

    unsafe extern "C" fn mock_dispatch_deferred_wake(id: usize) -> usize {
        state().as_mut().unwrap().events.push(format!("deferred:{id:x}"));
        0
    }

    #[test]
    fn signal_dispatch_preserves_fifo_and_selects_only_exact_mode_one() {
        let _guard = install(MockState::default());
        let _rom_guard = crate::kernel::task_lock::tests::OPS_LOCK.lock().unwrap();
        unsafe {
            let slot = core::ptr::addr_of_mut!(
                crate::kernel::task_lock::ROM_KERNEL.rom_svc_22001cbc
            );
            let saved = slot.read();
            slot.write(mock_dispatch_deferred_wake);
            for mode in [0, 1, 2, u32::MAX] {
                let mut cv = make_condvar();
                let mut first = WaitNode { next: null_mut(), object: 0x1234 as *mut u32 };
                let mut second = WaitNode { next: null_mut(), object: 0x5678 as *mut u32 };
                list_push_back(&mut cv.waiters, (&mut first as *mut WaitNode).cast());
                list_push_back(&mut cv.waiters, (&mut second as *mut WaitNode).cast());
                condvar_signal_dispatch(&mut cv, mode);
                assert_eq!(cv.waiters.head, (&mut second as *mut WaitNode).cast());
                assert_eq!(cv.waiters.tail, (&mut second as *mut WaitNode).cast());
                assert!(first.next.is_null());
                condvar_signal_dispatch(&mut cv, mode);
                assert!(cv.waiters.head.is_null());
                assert!(cv.waiters.tail.is_null());
                assert!(second.next.is_null());
                let events = take_events();
                let wakes = core::mem::take(&mut state().as_mut().unwrap().wakes);
                if mode == 1 {
                    assert_eq!(events, Vec::from([
                        String::from("deferred:1234"), String::from("deferred:5678"),
                    ]));
                    assert!(wakes.is_empty());
                } else {
                    assert_eq!(wakes, Vec::from([0x1234usize, 0x5678]));
                }
                condvar_signal_dispatch(&mut cv, mode);
                assert!(take_events().is_empty());
                assert!(state().as_ref().unwrap().wakes.is_empty());
            }
            slot.write(saved);
        }
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
