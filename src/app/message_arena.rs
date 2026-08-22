//! The queued-message arena: the singleton pool's accessor and the
//! class-specific `operator new` that pops blocks off it.
//!
//! Ports:
//!
//! - [`message_arena_pool`] — `FUN_08103400` @ 0x08103400 (100 bytes,
//!   0x08103400..0x08103464: 80 of code plus a 5-word literal pool; the
//!   next word is `queued_message_construct`'s `push`; **43 `bl` call
//!   sites, 0 predicated, 0 tail branches**, binary-scanned by decoding
//!   every B/BL word in osos.dec; no DATA word holds the address, so
//!   it is never dispatched virtually).
//! - [`message_arena_alloc`] — `FUN_08103550` @ 0x08103550 (24 bytes,
//!   0x08103550..0x08103568; **48 `bl` call sites, 0 tail branches**,
//!   binary-scanned; no DATA word holds the address either).
//!
//! # The accessor: a textbook ADS function-local static
//!
//! Decoded from the raw ARM at 0x08103400:
//!
//! ```text
//! ldr  r0, =0x089ca7fc     ; pool @ 0x08103450
//! ldr  r0, [r0, #0x44]     ; the guard word @ 0x089ca840
//! tst  r0, #1
//! bne  done                ; inlined fast path: bit 0 = built
//! ldr  r0, =0x089ca840     ; pool @ 0x08103454: the guard, again
//! bl   cxa_guard_acquire   ; 0x082ab31c (ported)
//! cmp  r0, #0; beq done
//! ldr  r0, =0x08a1b1d4     ; pool @ 0x08103458: the object
//! mov  r1, #12             ; block_size
//! mov  r2, #128            ; block_count
//! bl   0x0826c134          ; FixedBlockPool::FixedBlockPool
//! ldr  r2, =0x089ca09c     ; pool @ 0x0810345c: __dso_handle
//! ldr  r1, =0x082612d0     ; pool @ 0x08103460: the "destructor"
//! bl   cxa_atexit          ; 0x082ab1c8 (ported)
//! ldr  r0, =0x089ca840
//! bl   cxa_guard_release   ; 0x082ab338 (ported)
//! done:
//! ldr  r0, =0x08a1b1d4     ; reloaded — NOT the ctor's return
//! pop  {r4, pc}
//! ```
//!
//! (The fast path's `ldr r0, [r0, #0x44]` and the slow path's
//! `ldr r0, =0x089ca840` name the same word: 0x089ca7fc + 0x44 =
//! 0x089ca840.) Ghidra's 80-byte extent is the code only; the five
//! pool words @ 0x08103450..0x08103460 belong to the function and the
//! next function opens at 0x08103464 (`push {r4-r8, lr}`,
//! `queued_message_construct`), so the true extent is 100 bytes.
//!
//! A slab of 128 blocks of 12 bytes: exactly the 12-byte envelope
//! `queued_message_construct` @ 0x08103464 builds (vtable, kind,
//! payload).
//!
//! The guard pair and `cxa_atexit` are ported and called directly. The
//! FixedBlockPool constructor @ 0x0826c134 is not, so it rides the
//! [`MESSAGE_ARENA_CTOR`] seam (the `bl` @ 0x08103430): on target the
//! default calls the stock constructor in place; on host it panics
//! until a test installs one. The registered "destructor" 0x082612d0
//! is not a function entry — see [`message_arena_destructor`].
//!
//! # The allocator
//!
//! `message_arena_alloc` is the queued-message class's
//! class-specific `operator new`:
//!
//! ```text
//! push  {r4, lr}
//! mov   r4, r0            ; size
//! bl    0x08103400        ; message_arena_pool (ported above)
//! mov   r1, r4            ; size
//! pop   {r4, lr}
//! b     0x0826c0d8        ; tail call fixed_block_pool_alloc(pool, size)
//! ```
//!
//! Six instructions, no literal pool — the extent is confirmed by the
//! preceding function's literal word ending at 0x0810354c and by
//! 0x08103568 starting the next one (`cmp r1, #0x8300`). So this is
//! literally `void *operator new(size_t n) { return alloc(pool(), n); }`.
//! [`fixed_block_pool_alloc`] (heap/fixed_block_pool.rs) is ported and
//! is called directly.
//!
//! Every one of the 48 call sites loads the size as `mov r0, #12` —
//! verified by decoding the immediate at all 48, not sampled — so the
//! pool's exact-size test in [`fixed_block_pool_alloc`] always matches
//! and the global `operator new` fallback is unreachable *through this
//! entry point*. The parameter is still a real parameter: it is
//! forwarded verbatim, never folded to a constant.
//!
//! # Deviations
//!
//! - The guard word and the pool object are crate statics rather than
//!   the .bss words @ 0x089ca840 / 0x08a1b1d4 (the block_mgr.rs
//!   deviation: the 0x089cxxxx RW pages are runtime-initialized and
//!   the image's contents there are stale). Both zero-init, the exact
//!   pre-init state. On target `FixedBlockPool` is exactly the
//!   original's 0x1c bytes (+0x00 lock .. +0x18 free_head).
//! - `message_arena_alloc` calls the ported accessor directly (the
//!   `MESSAGE_ARENA_POOL` seam it used while the accessor was unported
//!   is gone); its tail `b` becomes a plain call and LLVM decides
//!   whether to keep it a tail call.

use core::ffi::c_void;

use crate::heap::fixed_block_pool::{fixed_block_pool_alloc, FixedBlockPool};
use crate::kernel::sync_mutex::Mutex;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// `mov r1, #12` in the pool constructor call at 0x0810342c, and the
/// `mov r0, #12` every one of the allocator's 48 call sites uses: the
/// 12-byte queued-message envelope.
pub const MESSAGE_ARENA_BLOCK_SIZE: usize = 12;

/// `mov r2, #0x80` in the same constructor call — 128 envelopes.
pub const MESSAGE_ARENA_BLOCK_COUNT: usize = 128;

/// `__dso_handle` — the pool word @ 0x0810345c (0x089ca09c), the key
/// every ADS static's `cxa_atexit` registration carries. See
/// runtime/shutdown_chain.rs.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The one-time-initialization guard (original: the .bss word @
/// 0x089ca840 — read on the fast path as `[0x089ca7fc + 0x44]`, pool
/// word @ 0x08103450, and loaded from the pool word @ 0x08103454 on
/// the slow path). A crate static rather than the .bss word, per the
/// module header's deviation. Zero is the exact pre-init state.
static mut MESSAGE_ARENA_GUARD: u32 = 0;

/// The pool object itself (original: the fixed .bss object @
/// 0x08a1b1d4, the pool word @ 0x08103458). Same crate-static
/// deviation as the guard; all-zero is the pre-construction state.
static mut MESSAGE_ARENA: FixedBlockPool = FixedBlockPool {
    lock: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
    block_size: 0,
    block_count: 0,
    total_bytes: 0,
    storage: core::ptr::null_mut(),
    free_head: core::ptr::null_mut(),
};

/// The FixedBlockPool constructor's type — original `FUN_0826c134` @
/// 0x0826c134 (116 bytes): `FixedBlockPool::FixedBlockPool(this,
/// block_size, block_count)`, returns `this`.
pub type MessageArenaCtorFn = unsafe extern "C" fn(
    this: *mut FixedBlockPool,
    block_size: usize,
    block_count: usize,
) -> *mut FixedBlockPool;

/// Target default: call the stock constructor in place.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_message_arena_ctor(
    this: *mut FixedBlockPool,
    block_size: usize,
    block_count: usize,
) -> *mut FixedBlockPool {
    let ctor: MessageArenaCtorFn = unsafe { core::mem::transmute(0x0826_c134usize) };
    unsafe { ctor(this, block_size, block_count) }
}

/// Host default: there is no firmware to call, and silently
/// "constructing" nothing would hand the allocator a zeroed pool whose
/// every allocation degrades to the global heap.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_message_arena_ctor(
    _this: *mut FixedBlockPool,
    _block_size: usize,
    _block_count: usize,
) -> *mut FixedBlockPool {
    panic!("message_arena_pool requires the FixedBlockPool constructor 0x0826c134")
}

/// The active constructor — the dispatch seam for `FUN_0826c134` (the
/// `bl` @ 0x08103430). Host tests install a recording mock; the real
/// port replaces the default when it lands in heap/fixed_block_pool.rs.
#[cfg(target_os = "none")]
pub static mut MESSAGE_ARENA_CTOR: MessageArenaCtorFn = firmware_message_arena_ctor;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_ARENA_CTOR: MessageArenaCtorFn = missing_message_arena_ctor;

/// Reads the constructor slot. Volatile so a build in which nothing
/// rewrites the slot cannot constant-fold the default in and delete the
/// dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn arena_ctor() -> MessageArenaCtorFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_ARENA_CTOR)) }
}

/// The destructor registered with `cxa_atexit` — original: the pool
/// word @ 0x08103460, 0x082612d0.
///
/// That address is **not a function entry**: it sits 0x140 bytes
/// inside `FUN_08261190` (0x08261190, 880 bytes per
/// decomp/functions.csv), on a `ldr r0, [r6, r0, lsl #2]` — an
/// interior load through its caller's r6/r0. Run as a shutdown handler
/// it would index a garbage pointer, so the registration could never
/// actually fire; retailOS never runs `exit`'s chain anyway
/// (runtime/shutdown_chain.rs: the sole runner caller is
/// `exit_stdio_cleanup`). The same situation as `node_list_get`'s
/// 0x0810516c and `media_command_facade_get`'s 0x0817f190. A no-op
/// matches every observable path.
unsafe extern "C" fn message_arena_destructor(_object: *mut c_void) {}

/// message_arena_pool — original: `FUN_08103400` @ 0x08103400
/// (100 bytes: 80 of code plus a 5-word literal pool; 43 `bl` call
/// sites, binary-scanned).
///
/// Returns the queued-message arena's singleton fixed-block pool,
/// running its one-time construction (128 blocks of 12 bytes) on the
/// first call. See the module header for the stock instruction
/// sequence.
///
/// Faithful details:
/// - The return value is always the fixed object's address, reloaded
///   after the init block (the original's second
///   `ldr r0, =0x08a1b1d4` @ 0x08103448) — never the constructor's
///   return. The registration with `cxa_atexit` carries the
///   *constructor's* return; they coincide here, and the distinction
///   is preserved.
/// - The inlined fast path tests bit 0 only (`tst r0, #1`) while
///   [`cxa_guard_acquire`] tests the whole word, so a nonzero guard
///   with bit 0 clear (never produced by this pair) takes the slow
///   path and is still turned away. Reproduced.
/// - A refused acquire (a re-entrant initializer) skips construction
///   and still hands out the object half-built — the guard is spent
///   either way. Inherited from the ported guard pair.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_arena_pool() -> *mut FixedBlockPool {
    let guard = core::ptr::addr_of_mut!(MESSAGE_ARENA_GUARD);
    let object = core::ptr::addr_of_mut!(MESSAGE_ARENA);
    if (core::ptr::read_volatile(guard) & 1) == 0 {
        if unsafe { cxa_guard_acquire(guard) } != 0 {
            let this = unsafe {
                (arena_ctor())(object, MESSAGE_ARENA_BLOCK_SIZE, MESSAGE_ARENA_BLOCK_COUNT)
            };
            unsafe {
                cxa_atexit(this as *mut c_void, message_arena_destructor, DSO_HANDLE);
                cxa_guard_release(guard);
            }
        }
    }
    object
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
/// The arena must have been constructed — on target the accessor's
/// one-time init guarantees it; host tests must drive the same path or
/// pre-build the pool. The result is raw, uninitialized storage and is
/// not NULL-checked here — faithful to the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_arena_alloc(size: usize) -> *mut u8 {
    unsafe { fixed_block_pool_alloc(message_arena_pool(), size) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::fixed_block_pool::FreeBlock;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use std::boxed::Box;
    use std::sync::{Mutex as StdMutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test below: the guard, the object, the ctor
    /// slot and the shutdown chain are all process-wide.
    static ARENA_LOCK: StdMutex<()> = StdMutex::new(());

    /// What the recording constructor saw, in order.
    static mut CTOR_CALLS: Vec<(*mut FixedBlockPool, usize, usize)> = Vec::new();

    /// What the recording constructor returns.
    static mut CTOR_RESULT: *mut FixedBlockPool = core::ptr::null_mut();

    /// Owns the slab backing the pool under test. The pool hands its
    /// blocks out as raw pointers, so the slab must stay put for the
    /// whole test; it lives here (never `Box::leak`) and is freed by
    /// the next `reset`/`restore` once no raw pointer can reach it.
    static mut SLAB: Option<Box<[*mut FreeBlock]>> = None;

    unsafe extern "C" fn recording_ctor(
        this: *mut FixedBlockPool,
        block_size: usize,
        block_count: usize,
    ) -> *mut FixedBlockPool {
        unsafe {
            (*core::ptr::addr_of_mut!(CTOR_CALLS)).push((this, block_size, block_count));
            core::ptr::read_volatile(core::ptr::addr_of!(CTOR_RESULT))
        }
    }

    /// Box-backed node allocator pair for the shutdown chain (the
    /// shipped defaults are the firmware malloc/free, wrong for host
    /// memory — the node_list.rs test pattern).
    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: core::ptr::null_mut(),
            arg: core::ptr::null_mut(),
            handler: message_arena_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(unsafe { Box::from_raw(block as *mut ShutdownNode) });
    }

    fn storage() -> *mut FixedBlockPool {
        core::ptr::addr_of_mut!(MESSAGE_ARENA)
    }

    /// Resets the guard, the object and the chain to their pre-init
    /// state and installs the Box allocator pair and the recording
    /// constructor.
    fn reset() -> MutexGuard<'static, ()> {
        let guard = ARENA_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MESSAGE_ARENA_GUARD = 0;
            (storage() as *mut u8)
                .write_bytes(0xa5, core::mem::size_of::<FixedBlockPool>());
            MESSAGE_ARENA_CTOR = recording_ctor;
            (*core::ptr::addr_of_mut!(CTOR_CALLS)).clear();
            CTOR_RESULT = storage();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = core::ptr::null_mut();
            *core::ptr::addr_of_mut!(SLAB) = None;
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held.
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            // Drain leftover registrations BEFORE restoring the
            // firmware allocator pair, so the nodes are freed by the
            // allocator that made them.
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            MESSAGE_ARENA_CTOR = missing_message_arena_ctor;
            MESSAGE_ARENA_GUARD = 0;
            (storage() as *mut u8).write_bytes(0, core::mem::size_of::<FixedBlockPool>());
            *core::ptr::addr_of_mut!(SLAB) = None;
        }
        drop(guard);
    }

    /// Builds a pool over a fresh slab into the singleton object,
    /// linked the way the original constructor links it
    /// (`block[i].next = block[i + 1]`, NULL tail), and publishes the
    /// guard so the accessor's fast path hands it out. The slab is
    /// owned by [`SLAB`] for the rest of the test.
    ///
    /// The declared `block_size` is the original's — it is what the
    /// allocator compares the request against — but the blocks are laid
    /// out at a stride rounded up to the host pointer alignment, since
    /// `FreeBlock.next` is 8 bytes here and 4 on target. The allocator
    /// only ever follows `next`, never a stride, so the widened spacing
    /// is invisible to it.
    fn install_pool(block_size: usize, count: usize) -> MutexGuard<'static, ()> {
        let guard = reset();
        let stride = block_size.next_multiple_of(core::mem::align_of::<*mut FreeBlock>());
        let links = count * (stride / core::mem::size_of::<*mut FreeBlock>());
        let slab = std::vec![core::ptr::null_mut::<FreeBlock>(); links].into_boxed_slice();
        let base = slab.as_ptr() as *mut u8;
        unsafe { *core::ptr::addr_of_mut!(SLAB) = Some(slab) };
        unsafe {
            for i in 0..count {
                let block = base.add(i * stride) as *mut FreeBlock;
                (*block).next = if i + 1 == count {
                    core::ptr::null_mut()
                } else {
                    base.add((i + 1) * stride) as *mut FreeBlock
                };
            }
            let pool = &mut *storage();
            pool.lock = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            pool.block_size = block_size;
            pool.block_count = count;
            pool.total_bytes = block_size * count;
            pool.storage = base;
            pool.free_head = base as *mut FreeBlock;
            MESSAGE_ARENA_GUARD = 1;
        }
        guard
    }

    #[test]
    fn the_first_call_constructs_registers_and_publishes_the_guard() {
        let guard = reset();
        unsafe {
            assert_eq!(message_arena_pool(), storage());
            assert_eq!(
                *core::ptr::addr_of!(CTOR_CALLS),
                std::vec![(storage(), MESSAGE_ARENA_BLOCK_SIZE, MESSAGE_ARENA_BLOCK_COUNT)],
                "constructed in place, 128 blocks of 12 bytes"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_ARENA_GUARD)),
                1,
                "acquire published the flag"
            );

            let head = *shutdown_chain_head();
            assert!(!head.is_null(), "registered with cxa_atexit");
            assert_eq!((*head).arg as *mut FixedBlockPool, storage(), "the ctor's return");
            assert_eq!((*head).handler as usize, message_arena_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE, "__dso_handle @ 0x089ca09c");
            assert!((*head).next.is_null(), "registered exactly once");
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_takes_the_bit0_fast_path() {
        let guard = reset();
        unsafe {
            message_arena_pool();
            // A post-construction mutation must survive: the 43 call
            // sites after boot must not reconstruct the pool.
            (*storage()).block_size = 0x5a;
            assert_eq!(message_arena_pool(), storage());
            assert_eq!(message_arena_pool(), storage());
            assert_eq!(
                (*core::ptr::addr_of!(CTOR_CALLS)).len(),
                1,
                "constructed exactly once"
            );
            assert_eq!((*storage()).block_size, 0x5a, "no reconstruction");
            assert!((*(*shutdown_chain_head())).next.is_null(), "no second registration");
        }
        restore(guard);
    }

    #[test]
    fn a_guard_with_bit0_set_short_circuits_everything() {
        let guard = reset();
        unsafe {
            MESSAGE_ARENA_GUARD = 3; // bit 0 set -> `tst r0, #1`, bne done
            assert_eq!(message_arena_pool(), storage());
            assert!((*core::ptr::addr_of!(CTOR_CALLS)).is_empty(), "no construction");
            assert!(shutdown_chain_head().read().is_null(), "no registration");
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_ARENA_GUARD)),
                3,
                "untouched"
            );
            assert_eq!((storage() as *mut u8).read(), 0xa5, "the object is handed out untouched");
        }
        restore(guard);
    }

    #[test]
    fn a_nonzero_guard_with_bit0_clear_is_still_turned_away_by_acquire() {
        // The fast path tests bit 0, cxa_guard_acquire the whole word.
        // This pair never produces the state, but the original's
        // two-level test defines its behavior.
        let guard = reset();
        unsafe {
            MESSAGE_ARENA_GUARD = 2;
            assert_eq!(message_arena_pool(), storage());
            assert!(
                (*core::ptr::addr_of!(CTOR_CALLS)).is_empty(),
                "acquire refused: no construction"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_ARENA_GUARD)),
                2,
                "a refused acquire never writes"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_object_literal_is_returned_not_the_constructors_value() {
        // The original reloads the pool word 0x08103458 @ 0x08103448;
        // only the REGISTRATION sees the constructor's return.
        let guard = reset();
        unsafe {
            let sentinel = storage().add(1); // deliberately different
            CTOR_RESULT = sentinel;
            assert_eq!(message_arena_pool(), storage(), "the reloaded literal wins");
            assert_eq!((*(*shutdown_chain_head())).arg as *mut FixedBlockPool, sentinel);
        }
        restore(guard);
    }

    #[test]
    fn the_registration_is_real_and_the_chain_runs_the_noop_destructor() {
        let guard = reset();
        unsafe {
            message_arena_pool();
            (*storage()).block_size = 0xa5;
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "the node ran and was freed");
            assert_eq!((*storage()).block_size, 0xa5, "the no-op destructor touched nothing");
        }
        restore(guard);
    }

    #[test]
    fn pops_the_arenas_head_block_for_the_stock_twelve_byte_request() {
        let guard = install_pool(MESSAGE_ARENA_BLOCK_SIZE, MESSAGE_ARENA_BLOCK_COUNT);
        let head = unsafe { (*storage()).free_head };
        let second = unsafe { (*head).next };

        let block = unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) };

        assert_eq!(block as *mut FreeBlock, head, "returns the free-list head");
        assert_eq!(unsafe { (*storage()).free_head }, second, "and relinks the head past it");
        restore(guard);
    }

    #[test]
    fn forwards_the_size_verbatim_rather_than_assuming_twelve() {
        // Every stock call site passes 12, but the argument is a real
        // parameter: a pool of a different block size still matches.
        let guard = install_pool(20, 4);
        let head = unsafe { (*storage()).free_head };

        let block = unsafe { message_arena_alloc(20) };

        assert_eq!(block as *mut FreeBlock, head, "20 reached the pool's size test");
        restore(guard);
    }

    #[test]
    fn successive_allocations_walk_the_same_singletons_free_list() {
        // The allocator re-fetches the pool on every call; both blocks
        // come off the one fixed object, in free-list order.
        let guard = install_pool(MESSAGE_ARENA_BLOCK_SIZE, 2);
        let (head, next) = unsafe {
            let head = (*storage()).free_head;
            (head, (*head).next)
        };

        let a = unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) };
        let b = unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) };

        assert_eq!(a as *mut FreeBlock, head, "first call takes the head");
        assert_eq!(b as *mut FreeBlock, next, "second call takes the relinked head");
        restore(guard);
    }

    #[test]
    fn drains_the_arena_block_by_block_in_free_list_order() {
        let guard = install_pool(MESSAGE_ARENA_BLOCK_SIZE, 3);
        let expected: Vec<*mut FreeBlock> = unsafe {
            let a = (*storage()).free_head;
            let b = (*a).next;
            std::vec![a, b, (*b).next]
        };

        let got: Vec<*mut FreeBlock> = (0..3)
            .map(|_| unsafe { message_arena_alloc(MESSAGE_ARENA_BLOCK_SIZE) as *mut FreeBlock })
            .collect();

        assert_eq!(got, expected, "LIFO over the constructor's initial links");
        assert!(unsafe { (*storage()).free_head }.is_null(), "the arena is now exhausted");
        restore(guard);
    }

    #[test]
    fn the_pool_geometry_and_dso_key_are_the_stock_literals() {
        // `mov r1, #12` @ 0x0810342c, `mov r2, #0x80` @ 0x08103428,
        // pool word 0x089ca09c @ 0x0810345c.
        assert_eq!(MESSAGE_ARENA_BLOCK_SIZE, 12);
        assert_eq!(MESSAGE_ARENA_BLOCK_COUNT, 128);
        assert_eq!(DSO_HANDLE, 0x089ca09c);
    }
}
