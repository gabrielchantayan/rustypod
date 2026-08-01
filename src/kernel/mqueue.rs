//! Message-queue node delivery and recycling — the consumer-side accept
//! step of the locked message queues drained by `mqueue_receive`
//! (kernel/condvar.rs), and the pool return path.
//!
//! - `mqueue_deliver` — original: `FUN_080b4a88` @ 0x080b4a88 (84 bytes;
//!   2 call sites: `mqueue_receive` @ 0x0807f63c and the wrapper loop @
//!   0x0807a330). Takes a node popped off a queue and decides what the
//!   consumer sees:
//!
//!   ```text
//!   if !node->valid      { *out_node = 0; recycle(node); return 0 }
//!   out_data[0] = node->data[0]; out_data[1] = node->data[1];
//!   if node->persistent  { *out_node = node }
//!   else                 { *out_node = 0; recycle(node) }
//!   return 1
//!   ```
//!
//! - `mqueue_node_recycle` — original: `FUN_080ed958` @ 0x080ed958
//!   (112 bytes; 2 bl call sites, both in `mqueue_deliver`). Returns a
//!   node to its owner pool; a NULL node is a no-op. Sequence (`pool` is
//!   the owner at node+4):
//!
//!   ```text
//!   if node->persistent { sem_wait(*pool->persist_sem);
//!                         condvar_signal(pool->persist_cv) }
//!   sem_wait(pool->lock)
//!   list_push_back(&pool->free, node)
//!   condvar_signal(&pool->notify)
//!   sem_signal(pool->lock)
//!   if node->persistent { sem_signal(*pool->persist_sem) }
//!   return 0
//!   ```
//!
//!   The stock callees: sem_wait/sem_signal 0x08056510/0x08056710
//!   (ported, kernel/sync_sem.rs), condvar_signal 0x080744d8 (ported,
//!   kernel/condvar.rs), list_push_back 0x080f1158 (ported,
//!   kernel/condvar.rs — called directly, like the original's plain bl).
//!
//! Also here — the pool bring-up:
//!
//! - `queue_pool_init` — original: `FUN_0809eab8` @ 0x0809eab8 (160
//!   bytes; 1 bl call site, `queue_pool_create` @ 0x0807a0bc, which
//!   allocates `capacity * 0x14 + 0x48` bytes and hands the node array
//!   at base+0x48 here). Lays out the full 0x48-byte header — see the
//!   function doc for the exact store sequence.
//!
//! # Layout note
//!
//! The node's linkage word (+0) is the intrusive `ListNode` of
//! kernel/condvar.rs; +4 holds the owner-pool pointer. `QueuePool` models
//! the full 0x48-byte header laid out by `queue_pool_init`: the recycler
//! touches +0x00..+0x28; the delivery side (+0x2c mutex, +0x34 condvar,
//! +0x40 queue anchor — condvar.rs's `LockedQueue` view of the same
//! block) belongs to the receive path. Byte offsets are exact on the
//! 32-bit target only; host tests go through field accesses (same caveat
//! as condvar.rs).
//!
//! # Dispatch design
//!
//! House pattern: the recycler's kernel dependencies route through
//! `MQUEUE_HOOKS`, with every slot defaulting to the REAL ported
//! function (sync_sem's sem_wait/sem_signal, condvar's condvar_signal,
//! and this module's mqueue_node_recycle for the deliver step) — on
//! target no install is needed. The slots exist so host tests can
//! observe the lock/signal ordering without racing the other modules'
//! own mock tables. `read_volatile` prevents LLVM from constant-folding
//! the table (see sync_sem.rs).
//!
//! Wiring note for condvar.rs: `CONDVAR_HOOKS.deliver` (stock
//! 0x080b4a88) is `mqueue_deliver` — install it there when the kernel
//! modules get wired; the hook types the node as `*mut ListNode`, cast
//! at install time.

use crate::kernel::condvar::{
    condvar_bind, condvar_signal, list_push_back, CondVar, ListHead, ListNode,
};
use crate::kernel::sync_mutex::{mutex_create, Mutex};
use crate::kernel::sync_sem::{sem_create, sem_signal, sem_wait, SemHandle};

/// Message-queue node (20-byte pool stride; nodes come from the owner's
/// pool array at pool+0x48).
#[repr(C)]
pub struct QueueNode {
    /// +0x00: intrusive list linkage (condvar.rs `ListNode`).
    pub next: *mut QueueNode,
    /// +0x04: owner pool, consumed by the recycler.
    pub owner: *mut QueuePool,
    /// +0x08: the 8-byte message payload delivered to the consumer.
    pub data: [u32; 2],
    /// +0x10: nonzero when the node carries a message.
    pub valid: u8,
    /// +0x11: nonzero when the node survives delivery (the consumer gets
    /// the node itself and returns it later); zero -> recycled here.
    pub persistent: u8,
}

/// Queue-node pool header (see the module layout note; only the fields
/// the recycler touches are modeled).
#[repr(C)]
pub struct QueuePool {
    /// +0x00: pool lock (semaphore slot) held around the free-list push.
    pub lock: SemHandle,
    /// +0x04: init-zeroed, untouched here.
    pub _x04: u32,
    /// +0x08: consumers' condvar (its lock_obj word at +0x08 is the
    /// initializer's back-reference to the pool).
    pub notify: CondVar,
    /// +0x14: free-node list the recycler pushes onto.
    pub free: ListHead,
    /// +0x1c: node array base (written by the initializer).
    pub nodes: *mut QueueNode,
    /// +0x20: persistent-node block; its word 0 is a semaphore slot the
    /// recycler brackets the persistent return with.
    pub persist_sem: *mut SemHandle,
    /// +0x24: persistent-node condvar, signaled on every persistent
    /// return.
    pub persist_cv: *mut CondVar,
    /// +0x28: init-zeroed, untouched by this module.
    pub _x28: u32,
    /// +0x2c: delivery-side mutex (sync_mutex.rs `Mutex`, 8 bytes on
    /// target). condvar.rs's `LockedQueue.mutex` word at +0x2c is this
    /// mutex's `sem_cell`.
    pub mutex: Mutex,
    /// +0x34: delivery-side condvar, bound to the mutex at +0x2c.
    pub deliver_cv: CondVar,
    /// +0x40: delivered-message queue anchor (`LockedQueue`'s +0x40 view
    /// of the same block).
    pub queue: ListHead,
}

// The original header is exactly 0x48 bytes (queue_pool_create allocates
// `capacity * 0x14 + 0x48` and the node array starts at base + 0x48).
#[cfg(target_pointer_width = "32")]
const _QUEUE_POOL_SIZE_CHECK: [u8; 0x48] = [0; core::mem::size_of::<QueuePool>()];

// Node stride: the original walks the array in 0x14-byte steps.
#[cfg(target_pointer_width = "32")]
const _QUEUE_NODE_SIZE_CHECK: [u8; 0x14] = [0; core::mem::size_of::<QueueNode>()];

/// External services this module depends on. Every slot defaults to the
/// real ported function (see the module header).
#[derive(Clone, Copy)]
pub struct MqueueHooks {
    /// Stock 0x080ed958: return a node to its owner pool (NULL-safe).
    pub node_recycle: unsafe extern "C" fn(node: *mut QueueNode) -> u32,
    /// Stock 0x08056510: semaphore wait (kernel/sync_sem.rs port).
    pub sem_wait: unsafe extern "C" fn(sem: SemHandle),
    /// Stock 0x08056710: semaphore signal (kernel/sync_sem.rs port).
    pub sem_signal: unsafe extern "C" fn(sem: SemHandle),
    /// Stock 0x080744d8: single-shot condvar wake (kernel/condvar.rs
    /// port).
    pub cv_signal: unsafe extern "C" fn(condvar: *mut CondVar),
    /// Stock 0x08056724: semaphore create (kernel/sync_sem.rs port) —
    /// the pool lock the initializer installs at +0x00.
    pub sem_create: unsafe extern "C" fn() -> SemHandle,
    /// Stock 0x080744a4: mutex-cell create (kernel/sync_mutex.rs port) —
    /// the delivery mutex the initializer lays out at +0x2c.
    pub mutex_create: unsafe extern "C" fn(mutex: *mut Mutex),
}

/// Shipped defaults — all real ports; no install needed on target.
pub const DEFAULT_MQUEUE_HOOKS: MqueueHooks = MqueueHooks {
    node_recycle: mqueue_node_recycle,
    sem_wait,
    sem_signal,
    cv_signal: condvar_signal,
    sem_create,
    mutex_create,
};

/// The active hook table. Written once at init on target; host tests
/// serialize access.
pub static mut MQUEUE_HOOKS: MqueueHooks = DEFAULT_MQUEUE_HOOKS;

/// Reads the hook table (volatile — see the module header).
#[inline(always)]
fn hooks() -> MqueueHooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MQUEUE_HOOKS)) }
}

/// mqueue_deliver — original: `FUN_080b4a88` @ 0x080b4a88 (84 bytes).
///
/// Delivers a popped queue node: copies the payload to `out_data`, hands
/// the node itself to the consumer through `*out_node` when it is
/// persistent (recycling it otherwise), and returns 1. An invalid node
/// is recycled without touching `out_data` and returns 0. No NULL check
/// on `node` before the `valid` load (faithful — a NULL node faults
/// exactly like the original would; the recycler guards its own).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mqueue_deliver(
    node: *mut QueueNode,
    out_data: *mut u32,
    out_node: *mut *mut QueueNode,
) -> u32 {
    if (*node).valid == 0 {
        *out_node = core::ptr::null_mut();
        (hooks().node_recycle)(node);
        return 0;
    }
    *out_data = (*node).data[0];
    *out_data.add(1) = (*node).data[1];
    if (*node).persistent != 0 {
        *out_node = node;
    } else {
        *out_node = core::ptr::null_mut();
        (hooks().node_recycle)(node);
    }
    1
}
/// queue_node_clear_data — original: `FUN_08056b10` @ 0x08056b10
/// (16 bytes).
///
/// Clears a [`QueueNode`]'s two-word message payload. The stock leaf stores
/// zero to +0x0c before +0x08; it does not touch the linkage, owning pool, or
/// validity and persistence flags. The raw caller at 0x080393d4 passes its
/// embedded queue node, and the target's +0x08/+0x0c offsets are exactly
/// [`QueueNode::data`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queue_node_clear_data(node: *mut QueueNode) {
    core::ptr::addr_of_mut!((*node).data[1]).write_volatile(0);
    core::ptr::addr_of_mut!((*node).data[0]).write_volatile(0);
}


/// mqueue_node_recycle — original: `FUN_080ed958` @ 0x080ed958
/// (112 bytes; 2 bl call sites, both in `mqueue_deliver`).
///
/// Returns a node to its owner pool's free list under the pool lock and
/// wakes one consumer; a persistent node's return is additionally
/// bracketed by the pool's persistent-block semaphore (wait before, one
/// wake of the persistent condvar, signal after). NULL is a no-op.
/// Always returns 0.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mqueue_node_recycle(node: *mut QueueNode) -> u32 {
    if node.is_null() {
        return 0;
    }
    let h = hooks();
    let persistent = (*node).persistent != 0;
    let pool = (*node).owner;
    if persistent {
        (h.sem_wait)(*(*pool).persist_sem);
        (h.cv_signal)((*pool).persist_cv);
    }
    (h.sem_wait)((*pool).lock);
    list_push_back(
        core::ptr::addr_of_mut!((*pool).free),
        node as *mut ListNode,
    );
    (h.cv_signal)(core::ptr::addr_of_mut!((*pool).notify));
    (h.sem_signal)((*pool).lock);
    if persistent {
        (h.sem_signal)(*(*pool).persist_sem);
    }
    0
}

/// queue_pool_init — original: `FUN_0809eab8` @ 0x0809eab8 (160 bytes;
/// 1 bl call site, queue_pool_create @ 0x0807a0bc).
///
/// Lays out the 0x48-byte pool header over `pool` and threads the
/// `capacity` nodes (0x14-byte stride from `nodes`) onto the free list:
///
/// ```text
/// pool->lock = sem_create(); pool->_x04 = 0
/// condvar_bind(&pool->notify, pool)          // lock word = pool base
/// persist_sem/persist_cv/_x28 = 0; pool->nodes = nodes; free = {0, 0}
/// for each of the capacity nodes:
///     node->owner = pool; node->valid = 1; push_back(&pool->free, node)
/// mutex_create(&pool->mutex)
/// condvar_bind(&pool->deliver_cv, &pool->mutex)
/// pool->queue = {0, 0}
/// return 0
/// ```
///
/// `capacity < 1` skips the threading loop (queue_pool_create then
/// passes NULL nodes — never dereferenced). Store order and the
/// signed compare follow the original; `condvar_bind` and
/// `list_push_back` are plain calls like the original's `bl`s, while
/// the create pair routes through `MQUEUE_HOOKS` (defaults are the real
/// ports).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queue_pool_init(
    capacity: i32,
    nodes: *mut QueueNode,
    pool: *mut QueuePool,
) -> u32 {
    let h = hooks();
    (*pool).lock = (h.sem_create)();
    (*pool)._x04 = 0;
    condvar_bind(core::ptr::addr_of_mut!((*pool).notify), pool as *mut u32);
    (*pool).persist_sem = core::ptr::null_mut();
    (*pool).persist_cv = core::ptr::null_mut();
    (*pool).nodes = nodes;
    (*pool)._x28 = 0;
    (*pool).free.tail = core::ptr::null_mut();
    (*pool).free.head = core::ptr::null_mut();
    let mut node = nodes;
    for _ in 0..capacity {
        (*node).owner = pool;
        (*node).valid = 1;
        list_push_back(
            core::ptr::addr_of_mut!((*pool).free),
            node as *mut ListNode,
        );
        node = node.add(1);
    }
    (h.mutex_create)(core::ptr::addr_of_mut!((*pool).mutex));
    condvar_bind(
        core::ptr::addr_of_mut!((*pool).deliver_cv),
        core::ptr::addr_of_mut!((*pool).mutex) as *mut u32,
    );
    (*pool).queue.tail = core::ptr::null_mut();
    (*pool).queue.head = core::ptr::null_mut();
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::null_mut;
    use std::sync::{Mutex, MutexGuard};
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global hook table.
    static HOOKS_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Recycle(usize),
        SemWait(usize),
        SemSignal(usize),
        CvSignal(usize),
        SemCreate,
        MutexCreate(usize),
    }

    static CALLS: Mutex<Vec<Call>> = Mutex::new(Vec::new());

    unsafe extern "C" fn mock_recycle(node: *mut QueueNode) -> u32 {
        CALLS.lock().unwrap().push(Call::Recycle(node as usize));
        0
    }

    unsafe extern "C" fn mock_sem_wait(sem: SemHandle) {
        CALLS.lock().unwrap().push(Call::SemWait(sem as usize));
    }

    unsafe extern "C" fn mock_sem_signal(sem: SemHandle) {
        CALLS.lock().unwrap().push(Call::SemSignal(sem as usize));
    }

    unsafe extern "C" fn mock_cv_signal(condvar: *mut CondVar) {
        CALLS.lock().unwrap().push(Call::CvSignal(condvar as usize));
    }

    /// Handle the sem_create mock hands out (never dereferenced).
    const MOCK_SEM: usize = 0xC5EA;

    unsafe extern "C" fn mock_sem_create() -> SemHandle {
        CALLS.lock().unwrap().push(Call::SemCreate);
        MOCK_SEM as SemHandle
    }

    /// The kernel mutex type (`Mutex` is shadowed by std's in here).
    use crate::kernel::sync_mutex::Mutex as KernelMutex;

    /// Cell value the mutex_create mock installs (never dereferenced).
    const MOCK_MUTEX_CELL: usize = 0x30C4;

    unsafe extern "C" fn mock_mutex_create(mutex: *mut KernelMutex) {
        CALLS.lock().unwrap().push(Call::MutexCreate(mutex as usize));
        (*mutex).sem_cell = MOCK_MUTEX_CELL as *mut u32;
        (*mutex).unused = 0;
    }

    fn mock_hooks() -> MutexGuard<'static, ()> {
        let guard = HOOKS_LOCK.lock().unwrap();
        unsafe {
            core::ptr::addr_of_mut!(MQUEUE_HOOKS).write(MqueueHooks {
                node_recycle: mock_recycle,
                sem_wait: mock_sem_wait,
                sem_signal: mock_sem_signal,
                cv_signal: mock_cv_signal,
                sem_create: mock_sem_create,
                mutex_create: mock_mutex_create,
            });
        }
        CALLS.lock().unwrap().clear();
        guard
    }

    /// Same, but with the REAL recycler in the slot (deliver -> recycle
    /// integration) while the kernel ops stay mocked.
    fn mock_hooks_real_recycle() -> MutexGuard<'static, ()> {
        let guard = mock_hooks();
        unsafe {
            (*core::ptr::addr_of_mut!(MQUEUE_HOOKS)).node_recycle = mqueue_node_recycle;
        }
        guard
    }

    fn drain() -> Vec<Call> {
        core::mem::take(&mut *CALLS.lock().unwrap())
    }

    fn node(valid: u8, persistent: u8) -> QueueNode {
        QueueNode {
            next: null_mut(),
            owner: null_mut(),
            data: [0x1111_2222, 0x3333_4444],
            valid,
            persistent,
        }
    }

    fn empty_cv() -> CondVar {
        CondVar {
            lock_obj: null_mut(),
            waiters: ListHead {
                head: null_mut(),
                tail: null_mut(),
            },
        }
    }

    /// A pool with distinct, recognizable lock/persist handles.
    struct PoolFixture {
        pool: QueuePool,
        persist_sem_cell: SemHandle,
        persist_cv: CondVar,
    }

    fn empty_pool() -> QueuePool {
        QueuePool {
            lock: 0x7000 as SemHandle,
            _x04: 0,
            notify: empty_cv(),
            free: ListHead {
                head: null_mut(),
                tail: null_mut(),
            },
            nodes: null_mut(),
            persist_sem: null_mut(),
            persist_cv: null_mut(),
            _x28: 0,
            mutex: KernelMutex {
                sem_cell: null_mut(),
                unused: 0,
            },
            deliver_cv: empty_cv(),
            queue: ListHead {
                head: null_mut(),
                tail: null_mut(),
            },
        }
    }

    fn make_pool() -> std::boxed::Box<PoolFixture> {
        let mut f = std::boxed::Box::new(PoolFixture {
            pool: empty_pool(),
            persist_sem_cell: 0x9990 as SemHandle,
            persist_cv: empty_cv(),
        });
        f.pool.persist_sem = &mut f.persist_sem_cell;
        f.pool.persist_cv = &mut f.persist_cv;
        f
    }

    // ---- mqueue_deliver ----------------------------------------------

    #[test]
    fn persistent_node_is_handed_to_the_consumer() {
        let _guard = mock_hooks();
        let mut n = node(1, 1);
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = null_mut();
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 1);
        assert_eq!(data, [0x1111_2222, 0x3333_4444]);
        assert_eq!(out, &mut n as *mut QueueNode, "consumer owns the node");
        assert!(drain().is_empty(), "persistent nodes are not recycled");
    }

    #[test]
    fn transient_node_is_recycled_after_the_copy() {
        let _guard = mock_hooks();
        let mut n = node(1, 0);
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = &mut n;
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 1, "the payload was still delivered");
        assert_eq!(data, [0x1111_2222, 0x3333_4444]);
        assert!(out.is_null(), "consumer does not get a transient node");
        assert_eq!(drain(), vec![Call::Recycle(&mut n as *mut QueueNode as usize)]);
    }

    #[test]
    fn invalid_node_is_recycled_without_touching_the_payload() {
        let _guard = mock_hooks();
        let mut n = node(0, 1);
        let mut data = [0xaaaa_aaaa_u32; 2];
        let mut out: *mut QueueNode = &mut n;
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 0);
        assert_eq!(data, [0xaaaa_aaaa; 2], "out_data untouched on the empty path");
        assert!(out.is_null());
        assert_eq!(drain(), vec![Call::Recycle(&mut n as *mut QueueNode as usize)]);
    }

    #[test]
    fn flag_bytes_are_tested_as_bytes() {
        // Any nonzero byte counts (the original uses ldrb + cmp #0).
        let _guard = mock_hooks();
        let mut n = node(0x80, 0xff);
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = null_mut();
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 1);
        assert_eq!(out, &mut n as *mut QueueNode);
    }

    // ---- queue_node_clear_data ---------------------------------------

    #[test]
    fn clear_data_zeros_only_the_two_payload_words() {
        let mut n = QueueNode {
            next: 0x1111_2222usize as *mut QueueNode,
            owner: 0x3333_4444usize as *mut QueuePool,
            data: [0x5555_6666, 0x7777_8888],
            valid: 0x99,
            persistent: 0xaa,
        };

        unsafe {
            queue_node_clear_data(&mut n);
        }

        assert_eq!(n.data, [0, 0], "the +0x08/+0x0c payload words are cleared");
        assert_eq!(n.next, 0x1111_2222usize as *mut QueueNode, "+0x00 linkage untouched");
        assert_eq!(n.owner, 0x3333_4444usize as *mut QueuePool, "+0x04 owner untouched");
        assert_eq!(n.valid, 0x99, "+0x10 valid flag untouched");
        assert_eq!(n.persistent, 0xaa, "+0x11 persistence flag untouched");
    }

    // ---- mqueue_node_recycle -----------------------------------------

    #[test]
    fn recycle_null_node_is_a_noop() {
        let _guard = mock_hooks();
        unsafe {
            assert_eq!(mqueue_node_recycle(null_mut()), 0);
        }
        assert!(drain().is_empty());
    }

    #[test]
    fn recycle_transient_node_locks_pushes_and_wakes_one() {
        let _guard = mock_hooks();
        let mut f = make_pool();
        let mut n = node(0, 0);
        n.owner = &mut f.pool;
        unsafe {
            assert_eq!(mqueue_node_recycle(&mut n), 0);
        }
        let notify = core::ptr::addr_of!(f.pool.notify) as usize;
        assert_eq!(
            drain(),
            vec![
                Call::SemWait(0x7000),
                Call::CvSignal(notify),
                Call::SemSignal(0x7000),
            ],
            "lock, wake-one, unlock — no persistent bracket"
        );
        assert_eq!(
            f.pool.free.head, &mut n as *mut QueueNode as *mut ListNode,
            "the node landed on the free list (under the lock)"
        );
        assert_eq!(f.pool.free.tail, &mut n as *mut QueueNode as *mut ListNode);
        assert!(n.next.is_null());
    }

    #[test]
    fn recycle_persistent_node_brackets_with_the_persist_semaphore() {
        let _guard = mock_hooks();
        let mut f = make_pool();
        let mut n = node(0, 1);
        n.owner = &mut f.pool;
        unsafe {
            assert_eq!(mqueue_node_recycle(&mut n), 0);
        }
        let notify = core::ptr::addr_of!(f.pool.notify) as usize;
        let persist_cv = f.pool.persist_cv as usize;
        assert_eq!(
            drain(),
            vec![
                Call::SemWait(0x9990),
                Call::CvSignal(persist_cv),
                Call::SemWait(0x7000),
                Call::CvSignal(notify),
                Call::SemSignal(0x7000),
                Call::SemSignal(0x9990),
            ]
        );
        assert_eq!(f.pool.free.head, &mut n as *mut QueueNode as *mut ListNode);
    }

    #[test]
    fn recycle_appends_behind_existing_free_nodes() {
        let _guard = mock_hooks();
        let mut f = make_pool();
        let mut first = node(0, 0);
        let mut second = node(0, 0);
        first.owner = &mut f.pool;
        second.owner = &mut f.pool;
        unsafe {
            mqueue_node_recycle(&mut first);
            mqueue_node_recycle(&mut second);
        }
        assert_eq!(f.pool.free.head, &mut first as *mut QueueNode as *mut ListNode);
        assert_eq!(f.pool.free.tail, &mut second as *mut QueueNode as *mut ListNode);
        assert_eq!(first.next, &mut second as *mut QueueNode);
    }

    #[test]
    fn deliver_routes_the_invalid_node_through_the_real_recycler() {
        let _guard = mock_hooks_real_recycle();
        let mut f = make_pool();
        let mut n = node(0, 0);
        n.owner = &mut f.pool;
        let mut data = [0u32; 2];
        let mut out: *mut QueueNode = &mut n;
        let r = unsafe { mqueue_deliver(&mut n, data.as_mut_ptr(), &mut out) };
        assert_eq!(r, 0);
        assert!(out.is_null());
        assert_eq!(
            f.pool.free.head, &mut n as *mut QueueNode as *mut ListNode,
            "the rejected node went back to the pool"
        );
    }

    // ---- queue_pool_init ---------------------------------------------

    /// A header prefilled with recognizable garbage, so the layout test
    /// proves every field is written by the initializer.
    fn garbage_pool() -> QueuePool {
        let mut p = empty_pool();
        p.lock = 0xdead as SemHandle;
        p._x04 = 0xa5a5_a5a5;
        p.notify.lock_obj = 0xdead as *mut u32;
        p.notify.waiters.head = 0xdead as *mut ListNode;
        p.notify.waiters.tail = 0xdead as *mut ListNode;
        p.free.head = 0xdead as *mut ListNode;
        p.free.tail = 0xdead as *mut ListNode;
        p.nodes = 0xdead as *mut QueueNode;
        p.persist_sem = 0xdead as *mut SemHandle;
        p.persist_cv = 0xdead as *mut CondVar;
        p._x28 = 0xa5a5_a5a5;
        p.deliver_cv.lock_obj = 0xdead as *mut u32;
        p.deliver_cv.waiters.head = 0xdead as *mut ListNode;
        p.deliver_cv.waiters.tail = 0xdead as *mut ListNode;
        p.queue.head = 0xdead as *mut ListNode;
        p.queue.tail = 0xdead as *mut ListNode;
        p
    }

    #[test]
    fn pool_init_lays_out_the_header_and_threads_the_free_list() {
        let _guard = mock_hooks();
        let mut pool = garbage_pool();
        let mut nodes = [node(0xee, 7), node(0xee, 7), node(0xee, 7)];
        let p = &mut pool as *mut QueuePool;
        let r = unsafe { queue_pool_init(3, nodes.as_mut_ptr(), p) };
        assert_eq!(r, 0);
        // Header layout.
        assert_eq!(pool.lock, MOCK_SEM as SemHandle);
        assert_eq!(pool._x04, 0);
        assert_eq!(
            pool.notify.lock_obj, p as *mut u32,
            "consumer condvar bound to the pool base (its +0 lock word)"
        );
        assert!(pool.notify.waiters.head.is_null());
        assert!(pool.notify.waiters.tail.is_null());
        assert_eq!(pool.nodes, nodes.as_mut_ptr());
        assert!(pool.persist_sem.is_null());
        assert!(pool.persist_cv.is_null());
        assert_eq!(pool._x28, 0);
        assert_eq!(
            pool.mutex.sem_cell, MOCK_MUTEX_CELL as *mut u32,
            "mutex_create ran over the +0x2c cell"
        );
        assert_eq!(
            pool.deliver_cv.lock_obj,
            core::ptr::addr_of_mut!(pool.mutex) as *mut u32,
            "delivery condvar bound to the mutex at +0x2c"
        );
        assert!(pool.deliver_cv.waiters.head.is_null());
        assert!(pool.deliver_cv.waiters.tail.is_null());
        assert!(pool.queue.head.is_null());
        assert!(pool.queue.tail.is_null());
        // Free-list threading: all three nodes, in array order.
        let n0 = nodes.as_mut_ptr();
        let (n1, n2) = unsafe { (n0.add(1), n0.add(2)) };
        assert_eq!(pool.free.head, n0 as *mut ListNode);
        assert_eq!(pool.free.tail, n2 as *mut ListNode);
        assert_eq!(nodes[0].next, n1);
        assert_eq!(nodes[1].next, n2);
        assert!(nodes[2].next.is_null());
        for n in &nodes {
            assert_eq!(n.owner, p);
            assert_eq!(n.valid, 1);
            assert_eq!(n.persistent, 7, "only owner/valid are written");
            assert_eq!(n.data, [0x1111_2222, 0x3333_4444], "payload untouched");
        }
        assert_eq!(
            drain(),
            vec![
                Call::SemCreate,
                Call::MutexCreate(core::ptr::addr_of_mut!(pool.mutex) as usize),
            ],
            "exactly one lock and one mutex are created"
        );
    }

    #[test]
    fn pool_init_zero_capacity_skips_the_node_loop() {
        let _guard = mock_hooks();
        let mut pool = garbage_pool();
        let r = unsafe { queue_pool_init(0, null_mut(), &mut pool) };
        assert_eq!(r, 0);
        assert!(pool.free.head.is_null());
        assert!(pool.free.tail.is_null());
        assert!(pool.nodes.is_null(), "NULL node base stored verbatim");
        assert_eq!(drain().len(), 2, "create pair still runs");
    }

    #[test]
    fn pool_init_negative_capacity_behaves_like_zero() {
        let _guard = mock_hooks();
        let mut pool = garbage_pool();
        // The original's `ble` treats any capacity < 1 the same way.
        let r = unsafe { queue_pool_init(-5, null_mut(), &mut pool) };
        assert_eq!(r, 0);
        assert!(pool.free.head.is_null());
        assert!(pool.free.tail.is_null());
    }

    #[test]
    fn pool_init_then_recycle_round_trips_a_node() {
        // The initialized pool is directly consumable by the recycler.
        let _guard = mock_hooks();
        let mut pool = empty_pool();
        let mut nodes = [node(0, 0), node(0, 0)];
        let n0 = nodes.as_mut_ptr();
        unsafe {
            queue_pool_init(2, n0, &mut pool);
            let popped = crate::kernel::condvar::list_pop_front(
                core::ptr::addr_of_mut!(pool.free),
            ) as *mut QueueNode;
            assert_eq!(popped, n0);
            drain();
            mqueue_node_recycle(popped);
        }
        assert_eq!(
            pool.free.tail, n0 as *mut ListNode,
            "the popped node went back to its owner's free list"
        );
        assert_eq!(nodes[1].next, n0);
    }

    #[test]
    fn default_slots_are_the_real_ports() {
        assert_eq!(
            DEFAULT_MQUEUE_HOOKS.node_recycle as usize,
            mqueue_node_recycle as usize
        );
        assert_eq!(
            DEFAULT_MQUEUE_HOOKS.sem_wait as usize,
            crate::kernel::sync_sem::sem_wait as usize
        );
        assert_eq!(
            DEFAULT_MQUEUE_HOOKS.sem_signal as usize,
            crate::kernel::sync_sem::sem_signal as usize
        );
        assert_eq!(
            DEFAULT_MQUEUE_HOOKS.cv_signal as usize,
            crate::kernel::condvar::condvar_signal as usize
        );
        assert_eq!(
            DEFAULT_MQUEUE_HOOKS.sem_create as usize,
            crate::kernel::sync_sem::sem_create as usize
        );
        assert_eq!(
            DEFAULT_MQUEUE_HOOKS.mutex_create as usize,
            crate::kernel::sync_mutex::mutex_create as usize
        );
    }
}
