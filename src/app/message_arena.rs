//! The queued-message arena's class-specific `operator new`.
//!
//! Port: `message_arena_alloc` — `FUN_08103550` @ 0x08103550
//! (24 bytes, 0x08103550..0x08103568; **48 `bl` call sites, 0 tail
//! branches**, binary-scanned by decoding every B/BL word in osos.dec;
//! no DATA word holds the address, so it is never dispatched
//! virtually).
//!
//! # Decoded from the raw ARM at 0x08103550
//!
//! ```text
//! push  {r4, lr}
//! mov   r4, r0            ; size
//! bl    0x08103400        ; r0 = the message arena's singleton pool
//! mov   r1, r4            ; size
//! pop   {r4, lr}
//! b     0x0826c0d8        ; tail call fixed_block_pool_alloc(pool, size)
//! ```
//!
//! Six instructions, no literal pool — the extent is confirmed by the
//! preceding function's literal word ending at 0x0810354c and by
//! 0x08103568 starting the next one (`cmp r1, #0x8300`).
//!
//! So this is literally
//! `void *operator new(size_t n) { return alloc(pool(), n); }`, the
//! class-specific allocator the queued-message envelope class installs.
//! `fixed_block_pool_alloc` (heap/fixed_block_pool.rs) is already
//! ported and is called directly.
//!
//! # Which arena, and the size that always arrives
//!
//! The accessor `FUN_08103400` @ 0x08103400 (100 bytes,
//! 0x08103400..0x08103464 — the next word is
//! `queued_message_construct`'s push) is a textbook ADS C++
//! function-local static:
//!
//! ```text
//! guard word  0x089ca840 (loaded as 0x089ca7fc + 0x44); bit 0 = built
//! tst guard,#1 -> fast path returns the object
//! __cxa_guard_acquire (0x082ab31c) on 0x089ca840
//! FixedBlockPool ctor (0x0826c134) on 0x08a1b1d4 with
//!     r1 = block_size 12, r2 = block_count 128
//! __cxa_atexit (0x082ab1c8) with (pool, dtor 0x082612d0,
//!     __dso_handle 0x089ca09c)
//! __cxa_guard_release (0x082ab338)
//! return 0x08a1b1d4
//! ```
//!
//! A slab of 128 blocks of 12 bytes: exactly the 12-byte envelope
//! `queued_message_construct` @ 0x08103464 builds (vtable, kind,
//! payload). And every one of the 48 call sites loads the size as
//! `mov r0, #12` — verified by decoding the immediate at all 48, not
//! sampled — so the pool's exact-size test in
//! [`fixed_block_pool_alloc`] always matches and the global
//! `operator new` fallback is unreachable *through this entry point*.
//! The parameter is still a real parameter: it is forwarded verbatim,
//! never folded to a constant, and the port keeps it that way.
//!
//! # Deviations
//!
//! - The accessor is not ported yet, so it rides the
//!   [`MESSAGE_ARENA_POOL`] slot (the app/queued_message.rs precedent):
//!   on target the default calls the firmware address 0x08103400
//!   directly; on host it panics until a test installs a pool. The
//!   allocator itself is the real [`fixed_block_pool_alloc`], called
//!   directly — there is no seam between the two.
//! - The original's tail `b` becomes a plain call; LLVM decides whether
//!   to keep it a tail call.

use crate::heap::fixed_block_pool::{fixed_block_pool_alloc, FixedBlockPool};

/// `mov r1, #12` in the pool constructor call at 0x0810342c, and the
/// `mov r0, #12` every one of this function's 48 call sites uses: the
/// 12-byte queued-message envelope.
pub const MESSAGE_ARENA_BLOCK_SIZE: usize = 12;

/// `mov r2, #0x80` in the same constructor call — 128 envelopes.
pub const MESSAGE_ARENA_BLOCK_COUNT: usize = 128;

/// The pool accessor's type: `FUN_08103400`, a nullary getter for the
/// lazily constructed singleton at 0x08a1b1d4.
pub type MessageArenaPoolFn = unsafe extern "C" fn() -> *mut FixedBlockPool;

/// Target default: call the stock accessor in place.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_message_arena_pool() -> *mut FixedBlockPool {
    let accessor: MessageArenaPoolFn = unsafe { core::mem::transmute(0x0810_3400usize) };
    unsafe { accessor() }
}

/// Host default: there is no firmware to call, and handing back NULL
/// would turn a missing install into a silent wild pointer inside the
/// allocator.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_message_arena_pool() -> *mut FixedBlockPool {
    panic!("message_arena_alloc requires the arena pool accessor 0x08103400")
}

/// The arena's pool accessor. Host tests install a pool here.
#[cfg(target_os = "none")]
pub static mut MESSAGE_ARENA_POOL: MessageArenaPoolFn = firmware_message_arena_pool;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_ARENA_POOL: MessageArenaPoolFn = missing_message_arena_pool;

/// Reads the accessor slot. Volatile so a build in which nothing
/// rewrites the slot cannot constant-fold the default in and delete the
/// dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn arena_pool() -> MessageArenaPoolFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_ARENA_POOL)) }
}

/// message_arena_alloc — original: `FUN_08103550` @ 0x08103550
/// (24 bytes; 48 `bl` call sites, binary-scanned).
///
/// The queued-message class's `operator new`: fetch the arena's
/// singleton fixed-block pool and pop one block of `size` bytes off it.
/// `size` is forwarded unchanged, so a request that is not the pool's
/// block size degrades to the global `operator new` inside
/// [`fixed_block_pool_alloc`] exactly as it does for every other pooled
/// class.
///
/// # Safety
///
/// [`MESSAGE_ARENA_POOL`] must yield a constructed pool. The result is
/// raw, uninitialized storage and is not NULL-checked here — faithful
/// to the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_arena_alloc(size: usize) -> *mut u8 {
    let pool = unsafe { (arena_pool())() };
    unsafe { fixed_block_pool_alloc(pool, size) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::fixed_block_pool::FreeBlock;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes swaps of [`MESSAGE_ARENA_POOL`].
    static POOL_LOCK: Mutex<()> = Mutex::new(());

    /// Pools the mock accessor hands out, one per call, then repeating
    /// the last — so a test can prove the accessor runs on every call.
    static mut POOLS: Vec<*mut FixedBlockPool> = Vec::new();
    static mut POOL_CALLS: usize = 0;

    unsafe extern "C" fn mock_arena_pool() -> *mut FixedBlockPool {
        unsafe {
            let pools = &*core::ptr::addr_of!(POOLS);
            let n = *core::ptr::addr_of!(POOL_CALLS);
            *core::ptr::addr_of_mut!(POOL_CALLS) = n + 1;
            pools[n.min(pools.len() - 1)]
        }
    }

    /// Restores the shipped default even when a test panics.
    struct PoolGuard(#[allow(dead_code)] MutexGuard<'static, ()>);

    impl Drop for PoolGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(MESSAGE_ARENA_POOL).write(missing_message_arena_pool);
                (*core::ptr::addr_of_mut!(POOLS)).clear();
            }
        }
    }

    fn install(pools: &[*mut FixedBlockPool]) -> PoolGuard {
        let guard = POOL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let slot = &mut *core::ptr::addr_of_mut!(POOLS);
            slot.clear();
            slot.extend_from_slice(pools);
            *core::ptr::addr_of_mut!(POOL_CALLS) = 0;
            core::ptr::addr_of_mut!(MESSAGE_ARENA_POOL).write(mock_arena_pool);
        }
        PoolGuard(guard)
    }

    fn pool_calls() -> usize {
        unsafe { *core::ptr::addr_of!(POOL_CALLS) }
    }

    /// A pool over a leaked slab, linked the way the original
    /// constructor links it (`block[i].next = block[i + 1]`, NULL tail).
    /// Leaked because the pool hands its blocks out as raw pointers.
    ///
    /// The declared `block_size` is the original's — it is what the
    /// allocator compares the request against — but the blocks are laid
    /// out at a stride rounded up to the host pointer alignment, since
    /// `FreeBlock.next` is 8 bytes here and 4 on target. The allocator
    /// only ever follows `next`, never a stride, so the widened spacing
    /// is invisible to it.
    fn build_pool(block_size: usize, count: usize) -> Box<FixedBlockPool> {
        let stride = block_size.next_multiple_of(core::mem::align_of::<*mut FreeBlock>());
        let links = count * (stride / core::mem::size_of::<*mut FreeBlock>());
        let slab: &'static mut [*mut FreeBlock] =
            Box::leak(std::vec![core::ptr::null_mut::<FreeBlock>(); links].into_boxed_slice());
        let base = slab.as_mut_ptr() as *mut u8;
        unsafe {
            for i in 0..count {
                let block = base.add(i * stride) as *mut FreeBlock;
                (*block).next = if i + 1 == count {
                    core::ptr::null_mut()
                } else {
                    base.add((i + 1) * stride) as *mut FreeBlock
                };
            }
        }
        Box::new(FixedBlockPool {
            lock: crate::kernel::sync_mutex::Mutex {
                sem_cell: core::ptr::null_mut(),
                unused: 0,
            },
            block_size,
            block_count: count,
            total_bytes: block_size * count,
            storage: base,
            free_head: base as *mut FreeBlock,
        })
    }

    #[test]
    fn pops_the_arenas_head_block_for_the_stock_twelve_byte_request() {
        let mut pool = build_pool(MESSAGE_ARENA_BLOCK_SIZE, MESSAGE_ARENA_BLOCK_COUNT);
        let head = pool.free_head;
        let second = unsafe { (*head).next };
        let _guard = install(&[&mut *pool as *mut FixedBlockPool]);

        let block = unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) };

        assert_eq!(block as *mut FreeBlock, head, "returns the free-list head");
        assert_eq!(pool.free_head, second, "and relinks the head past it");
        assert_eq!(pool_calls(), 1, "one accessor call per allocation");
    }

    #[test]
    fn forwards_the_size_verbatim_rather_than_assuming_twelve() {
        // Every stock call site passes 12, but the argument is a real
        // parameter: a pool of a different block size still matches.
        let mut pool = build_pool(20, 4);
        let head = pool.free_head;
        let _guard = install(&[&mut *pool as *mut FixedBlockPool]);

        let block = unsafe { message_arena_alloc(20) };

        assert_eq!(block as *mut FreeBlock, head, "20 reached the pool's size test");
    }

    #[test]
    fn re_reads_the_accessor_on_every_call_instead_of_caching_a_pool() {
        let mut first = build_pool(MESSAGE_ARENA_BLOCK_SIZE, 2);
        let mut second = build_pool(MESSAGE_ARENA_BLOCK_SIZE, 2);
        let first_head = first.free_head;
        let second_head = second.free_head;
        let _guard = install(&[
            &mut *first as *mut FixedBlockPool,
            &mut *second as *mut FixedBlockPool,
        ]);

        let a = unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) };
        let b = unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) };

        assert_eq!(a as *mut FreeBlock, first_head, "first call takes the first pool");
        assert_eq!(b as *mut FreeBlock, second_head, "second call re-fetches");
        assert_eq!(pool_calls(), 2);
    }

    #[test]
    fn drains_the_arena_block_by_block_in_free_list_order() {
        let mut pool = build_pool(MESSAGE_ARENA_BLOCK_SIZE, 3);
        let expected: Vec<*mut FreeBlock> = unsafe {
            let a = pool.free_head;
            let b = (*a).next;
            std::vec![a, b, (*b).next]
        };
        let _guard = install(&[&mut *pool as *mut FixedBlockPool]);

        let got: Vec<*mut FreeBlock> = (0..3)
            .map(|_| unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) as *mut FreeBlock })
            .collect();

        assert_eq!(got, expected, "LIFO over the constructor's initial links");
        assert!(pool.free_head.is_null(), "the arena is now exhausted");
    }
}
