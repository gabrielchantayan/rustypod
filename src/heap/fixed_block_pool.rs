//! `fixed_block_pool_alloc` — original: `FUN_0826c0d8` @ 0x0826c0d8
//! (92 bytes, 0x0826c0d8..0x0826c134; **70 `bl` + 2 tail `b` call
//! sites**, binary-scanned by decoding every B/BL word in osos.dec).
//!
//! The allocation entry point of retailOS's **fixed-block pool**: a
//! small C++ object that owns one contiguous slab pre-carved into
//! `block_count` blocks of exactly `block_size` bytes, chained through a
//! mutex-protected singly linked free list. It is the backing store of
//! the class-specific `operator new` a couple of dozen framework classes
//! install; the shape of every call site is
//!
//! ```text
//! bl   <pool accessor>      ; r0 = the class's singleton pool
//! mov  r1, #0x1c            ; sizeof(the class)
//! bl   0x0826c0d8
//! ```
//!
//! and the thinnest of them (e.g. 0x08103550, one of the two tail-`b`
//! sites) is literally `void *operator new(size_t n) { return
//! fixed_block_pool_alloc(pool(), n); }`.
//!
//! # Decoded from the raw ARM at 0x0826c0d8
//!
//! ```text
//! push  {r4, r5, r6, lr}
//! mov   r4, r0            ; pool
//! ldr   r0, [r0, #8]      ; pool->block_size
//! mov   r6, r1            ; size
//! cmp   r0, r1
//! beq   0x0826c0fc
//! 0x0826c0f0:             ; fallback
//! mov   r0, r6
//! pop   {r4, r5, r6, lr}
//! b     0x082aadd4        ; tail call operator_new(size)
//! 0x0826c0fc:
//! mov   r0, r4
//! bl    0x0807f5c4        ; mutex_lock(pool)
//! ldr   r5, [r4, #0x18]   ; pool->free_head
//! cmp   r5, #0
//! bne   0x0826c11c
//! mov   r0, r4
//! bl    0x0807f6a0        ; mutex_unlock(pool)
//! b     0x0826c0f0        ; exhausted -> fallback
//! 0x0826c11c:
//! ldr   r0, [r5]          ; block->next
//! str   r0, [r4, #0x18]   ; pool->free_head = block->next
//! mov   r0, r4
//! bl    0x0807f6a0        ; mutex_unlock(pool)
//! mov   r0, r5
//! pop   {r4, r5, r6, pc}  ; return block
//! ```
//!
//! Two properties worth naming, because they are what the port has to
//! preserve: the size check happens **before** the lock is taken and is
//! an exact `==`, not a `<=` — a request of any other size never touches
//! the pool at all; and the exhausted pool is not an error, it silently
//! degrades to the global tag-2 `operator_new` (so blocks handed out by
//! this pool and by the heap are indistinguishable to the caller, which
//! is why the matching `operator delete` has to range-check the slab).
//!
//! # Class layout, recovered from the pool's own constructor/destructor
//!
//! The neighbouring `FUN_0826c134` @ 0x0826c134 (116 bytes) is the
//! constructor and `FUN_0826c1a8` @ 0x0826c1a8 the destructor (Ghidra
//! says 16 bytes; the raw words say 32, 0x0826c1a8..0x0826c1c8, ending
//! in `mov r0,r4; pop {r4,pc}` — the usual dropped tail). Between them
//! they pin every field:
//!
//! ```text
//! ctor(this, block_size, count):
//!   stmia this+8, {block_size, count, 0}   ; +0x08, +0x0c, +0x10
//!   this->storage   = 0                    ; +0x14
//!   this->free_head = 0                    ; +0x18
//!   mutex_create(this)                     ; 0x080744a4 — mutex AT +0
//!   this->total = block_size * count       ; +0x10
//!   this->storage = operator_new(total)    ; 0x082aadd4
//!   for (i = 0; i < count - 1; i++)        ; link the slab into a list
//!       block[i].next = block[i + 1];
//!   block[count - 1].next = NULL;
//!   this->free_head = this->storage;
//!
//! dtor(this):
//!   operator_delete(this->storage);        ; 0x082aad24
//!   mutex_delete(this);                    ; 0x0807f650 — mutex AT +0
//!   return this;
//! ```
//!
//! So the mutex the allocator locks is the object's *first member*
//! (`mutex_lock` is called with `this` unadjusted), the free-list link
//! lives at offset 0 of each free block, and a block is only ever
//! `block_size` bytes — see [`FixedBlockPool`] and [`FreeBlock`].
//!
//! # Deviations
//!
//! - Field widths follow the host/target pointer width instead of the
//!   original's fixed 32-bit words, so the port never spells a literal
//!   byte offset (the house rule): [`FixedBlockPool`] is `#[repr(C)]`
//!   and every access goes through a named field. On target the layout
//!   is exactly the original's +0x00/+0x08/+0x0c/+0x10/+0x14/+0x18.
//! - The three callees ride [`FIXED_BLOCK_POOL_OPS`] (the
//!   heap/pool_client.rs precedent) so host tests can observe the
//!   lock/pop/unlock bracketing and the fallback. **All three defaults
//!   are the real ports** — `mutex_lock`/`mutex_unlock` (kernel/
//!   sync_mutex.rs, no-ops on host through their own NULL-cell guard)
//!   and `operator_new` (heap/veneers.rs) — so with no mocks installed
//!   the original call graph runs end to end.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// A free block, seen through its list link. The original stores the
/// link at offset 0 of the block itself (`ldr r0, [r5]` in the
/// allocator, `str r2, [r0]` in the constructor's link loop), so a
/// pooled class only gets its storage back once it is handed out.
#[repr(C)]
pub struct FreeBlock {
    /// Next free block, NULL at the tail of the list.
    pub next: *mut FreeBlock,
}

/// The fixed-block pool. Offsets in the comments are the original's.
#[repr(C)]
pub struct FixedBlockPool {
    /// +0x00 — the pool's own mutex, constructed by `mutex_create(this)`
    /// and destroyed by `mutex_delete(this)`; it is the first member, so
    /// `this` *is* the mutex address.
    pub lock: Mutex,
    /// +0x08 — bytes per block. Compared for exact equality against the
    /// requested size; anything else goes to the global allocator.
    pub block_size: usize,
    /// +0x0c — number of blocks in the slab.
    pub block_count: usize,
    /// +0x10 — `block_size * block_count`, the slab's byte size.
    pub total_bytes: usize,
    /// +0x14 — the slab, one `operator_new(total_bytes)` allocation.
    pub storage: *mut u8,
    /// +0x18 — head of the free list, NULL when the pool is exhausted.
    pub free_head: *mut FreeBlock,
}

/// Indirect dispatch for the allocator's three callees. Every default is
/// the real port; the slots exist so host tests can observe the
/// lock/pop/unlock order and the fallback without entering the
/// target-only allocation engine (heap/pool_client.rs precedent).
#[derive(Clone, Copy)]
pub struct FixedBlockPoolOps {
    /// Original 0x0807f5c4.
    pub lock: unsafe extern "C" fn(mutex: *mut Mutex),
    /// Original 0x0807f6a0.
    pub unlock: unsafe extern "C" fn(mutex: *mut Mutex),
    /// Original 0x082aadd4, the tag-2 global `operator new` this
    /// allocator degrades to.
    pub fallback_new: unsafe extern "C" fn(size: usize) -> *mut u8,
}

/// The wired defaults: the real `mutex_lock` / `mutex_unlock` /
/// `operator_new` ports.
pub const DEFAULT_FIXED_BLOCK_POOL_OPS: FixedBlockPoolOps = FixedBlockPoolOps {
    lock: mutex_lock,
    unlock: mutex_unlock,
    fallback_new: crate::heap::veneers::operator_new,
};

/// The active callee set. Host tests install recording mocks.
pub static mut FIXED_BLOCK_POOL_OPS: FixedBlockPoolOps = DEFAULT_FIXED_BLOCK_POOL_OPS;

#[inline(always)]
unsafe fn ops() -> FixedBlockPoolOps {
    core::ptr::read_volatile(core::ptr::addr_of!(FIXED_BLOCK_POOL_OPS))
}

/// fixed_block_pool_alloc — original: `FUN_0826c0d8` @ 0x0826c0d8
/// (92 bytes; 70 `bl` + 2 tail `b` call sites, binary-scanned).
///
/// Pops one block off `pool`'s free list, or falls back to the global
/// `operator new` when `size` is not the pool's block size or the pool
/// is exhausted. Never returns NULL unless the global allocator does.
/// No NULL guard on `pool`, matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_block_pool_alloc(
    pool: *mut FixedBlockPool,
    size: usize,
) -> *mut u8 {
    let ops = ops();
    // Read before locking, and compare for exact equality — the
    // original's `ldr r0,[r0,#8]; cmp r0,r1; beq`.
    if (*pool).block_size != size {
        return (ops.fallback_new)(size);
    }

    let mutex = core::ptr::addr_of_mut!((*pool).lock);
    (ops.lock)(mutex);
    let block = (*pool).free_head;
    if block.is_null() {
        (ops.unlock)(mutex);
        return (ops.fallback_new)(size);
    }
    (*pool).free_head = (*block).next;
    (ops.unlock)(mutex);
    block as *mut u8
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex as StdMutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the dispatch slots and their recorders.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    /// What the recording mocks saw, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        /// `mutex_lock(mutex)` — with the free head as the mock observed
        /// it at that instant, which is what proves the pop is inside
        /// the critical section.
        Lock(usize, usize),
        /// `mutex_unlock(mutex)`, same snapshot.
        Unlock(usize, usize),
        /// `operator_new(size)`.
        FallbackNew(usize),
    }

    static mut CALLS: Vec<Call> = Vec::new();
    /// The pool the recorders snapshot the free head from.
    static mut WATCHED: *mut FixedBlockPool = core::ptr::null_mut();
    /// Canned return for the fallback recorder.
    static mut FALLBACK_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe fn record(call: Call) {
        (*core::ptr::addr_of_mut!(CALLS)).push(call);
    }

    unsafe fn watched_free_head() -> usize {
        let pool = core::ptr::read_volatile(core::ptr::addr_of!(WATCHED));
        if pool.is_null() {
            0
        } else {
            (*pool).free_head as usize
        }
    }

    unsafe extern "C" fn recording_lock(mutex: *mut Mutex) {
        record(Call::Lock(mutex as usize, watched_free_head()));
    }

    unsafe extern "C" fn recording_unlock(mutex: *mut Mutex) {
        record(Call::Unlock(mutex as usize, watched_free_head()));
    }

    unsafe extern "C" fn recording_fallback_new(size: usize) -> *mut u8 {
        record(Call::FallbackNew(size));
        core::ptr::read_volatile(core::ptr::addr_of!(FALLBACK_RESULT))
    }

    /// Restores the wired defaults even when a test panics.
    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(FIXED_BLOCK_POOL_OPS)
                    .write_volatile(DEFAULT_FIXED_BLOCK_POOL_OPS);
                core::ptr::addr_of_mut!(WATCHED).write_volatile(core::ptr::null_mut());
            }
        }
    }

    fn pool_bench(watched: *mut FixedBlockPool, fallback: *mut u8) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(WATCHED).write_volatile(watched);
            core::ptr::addr_of_mut!(FALLBACK_RESULT).write_volatile(fallback);
            core::ptr::addr_of_mut!(FIXED_BLOCK_POOL_OPS).write_volatile(FixedBlockPoolOps {
                lock: recording_lock,
                unlock: recording_unlock,
                fallback_new: recording_fallback_new,
            });
        }
        OpsGuard { _lock: lock }
    }

    fn calls() -> Vec<Call> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// A pool whose slab is `count` blocks of `block_size` bytes, linked
    /// exactly the way the original constructor links it. `slab` must
    /// outlive the pool.
    fn build_pool(slab: &mut [u8], block_size: usize, count: usize) -> FixedBlockPool {
        assert!(slab.len() >= block_size * count);
        assert!(block_size >= core::mem::size_of::<*mut FreeBlock>());
        let base = slab.as_mut_ptr();
        unsafe {
            for i in 0..count {
                let block = base.add(i * block_size) as *mut FreeBlock;
                (*block).next = if i + 1 < count {
                    base.add((i + 1) * block_size) as *mut FreeBlock
                } else {
                    core::ptr::null_mut()
                };
            }
        }
        FixedBlockPool {
            // The pool's mutex is never created in these tests; the real
            // ports treat a NULL cell as "no kernel yet" and no-op, and
            // the recorders only look at its address.
            lock: Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            },
            block_size,
            block_count: count,
            total_bytes: block_size * count,
            storage: base,
            free_head: base as *mut FreeBlock,
        }
    }

    const BLOCK: usize = 0x20;

    #[test]
    fn matching_size_pops_the_free_list_head_under_the_lock() {
        let mut slab = [0u8; BLOCK * 3];
        let mut pool = build_pool(&mut slab, BLOCK, 3);
        let pool_ptr = &mut pool as *mut FixedBlockPool;
        let _bench = pool_bench(pool_ptr, core::ptr::null_mut());

        let base = pool.storage;
        let first = unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) };

        assert_eq!(first, base, "the head block comes back verbatim");
        assert_eq!(
            pool.free_head as *mut u8,
            unsafe { base.add(BLOCK) },
            "the head advanced to block[1]"
        );
        let mutex = core::ptr::addr_of_mut!(pool.lock) as usize;
        assert_eq!(mutex, pool_ptr as usize, "the mutex is the object's first member");
        assert_eq!(
            calls(),
            std::vec![
                Call::Lock(mutex, base as usize),
                // The unlock recorder sees the head already advanced:
                // the pop happens inside the critical section.
                Call::Unlock(mutex, unsafe { base.add(BLOCK) } as usize),
            ],
            "lock, pop, unlock — and no fallback"
        );
    }

    #[test]
    fn successive_allocations_walk_the_list_then_the_pool_empties() {
        let mut slab = [0u8; BLOCK * 3];
        let mut pool = build_pool(&mut slab, BLOCK, 3);
        let pool_ptr = &mut pool as *mut FixedBlockPool;
        let fallback = 0x1234_5678usize as *mut u8;
        let _bench = pool_bench(pool_ptr, fallback);

        let base = pool.storage;
        let blocks: Vec<*mut u8> =
            (0..3).map(|_| unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) }).collect();

        assert_eq!(
            blocks,
            std::vec![base, unsafe { base.add(BLOCK) }, unsafe { base.add(2 * BLOCK) }],
            "blocks come out in slab order"
        );
        assert!(pool.free_head.is_null(), "the list is drained");

        // The exhausted pool still takes the lock, finds NULL, unlocks
        // and degrades to the global allocator — it is not an error.
        let overflow = unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) };
        assert_eq!(overflow, fallback);
        let mutex = core::ptr::addr_of_mut!(pool.lock) as usize;
        assert_eq!(
            &calls()[6..],
            &[Call::Lock(mutex, 0), Call::Unlock(mutex, 0), Call::FallbackNew(BLOCK)],
            "exhausted: lock, look, unlock, then operator_new(size)"
        );
        assert!(pool.free_head.is_null(), "the failed pop left the list alone");
    }

    #[test]
    fn a_mismatched_size_never_touches_the_lock_or_the_list() {
        let mut slab = [0u8; BLOCK * 2];
        let mut pool = build_pool(&mut slab, BLOCK, 2);
        let pool_ptr = &mut pool as *mut FixedBlockPool;
        let fallback = 0x0bad_f00dusize as *mut u8;
        let _bench = pool_bench(pool_ptr, fallback);

        let head_before = pool.free_head;
        // The comparison is exact equality, not "fits": one byte under
        // the block size is just as foreign as one byte over, and zero
        // is foreign too.
        for size in [0usize, 1, BLOCK - 1, BLOCK + 1, usize::MAX] {
            assert_eq!(unsafe { fixed_block_pool_alloc(pool_ptr, size) }, fallback);
        }

        assert_eq!(pool.free_head, head_before, "the free list is untouched");
        assert_eq!(
            calls(),
            std::vec![
                Call::FallbackNew(0),
                Call::FallbackNew(1),
                Call::FallbackNew(BLOCK - 1),
                Call::FallbackNew(BLOCK + 1),
                Call::FallbackNew(usize::MAX),
            ],
            "no lock is taken on the mismatch path"
        );
    }

    #[test]
    fn a_failing_global_allocator_propagates_null() {
        let mut slab = [0u8; BLOCK];
        let mut pool = build_pool(&mut slab, BLOCK, 1);
        let pool_ptr = &mut pool as *mut FixedBlockPool;
        let _bench = pool_bench(pool_ptr, core::ptr::null_mut());

        // Drain, then fail: the pool has no NULL-checking of its own.
        assert!(!unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) }.is_null());
        assert!(unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) }.is_null());
        assert!(unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK + 8) }.is_null());
    }

    #[test]
    fn the_wired_defaults_run_the_pool_path_with_no_mocks() {
        // No bench: the real mutex_lock/mutex_unlock ports bracket the
        // pop. Their NULL-cell guard makes them no-ops on host, so the
        // pooled path is fully exercised without a kernel; only the
        // fallback would reach the target-only allocation engine, and
        // this test never takes it.
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(FIXED_BLOCK_POOL_OPS)
                .write_volatile(DEFAULT_FIXED_BLOCK_POOL_OPS);
        }

        let mut slab = [0u8; BLOCK * 2];
        let mut pool = build_pool(&mut slab, BLOCK, 2);
        let pool_ptr = &mut pool as *mut FixedBlockPool;
        let base = pool.storage;

        assert_eq!(unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) }, base);
        assert_eq!(unsafe { fixed_block_pool_alloc(pool_ptr, BLOCK) }, unsafe {
            base.add(BLOCK)
        });
        assert!(pool.free_head.is_null());
    }
}
