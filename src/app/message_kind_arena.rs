//! The MessageKind arena: the singleton fixed-block pool's accessor.
//!
//! Port:
//!
//! - [`message_kind_arena_pool`] — `FUN_082669e4` @ 0x082669e4
//!   (100 bytes, 0x082669e4..0x08266a48: 80 of code plus a 5-word
//!   literal pool; the next word is `message_kind_construct`'s
//!   `push {r4, lr}` @ 0x08266a48; **37 `bl` call sites, 0 predicated,
//!   0 tail branches**, binary-scanned by decoding every B/BL word in
//!   osos.dec; no DATA word holds the address, so it is never
//!   dispatched virtually).
//!
//! # A textbook ADS function-local static
//!
//! Decoded from the raw ARM at 0x082669e4 (Ghidra's C in
//! decomp/c/025/082669e4_FUN_082669e4.c matches instruction for
//! instruction):
//!
//! ```text
//! ldr  r0, =0x089ca7fc     ; pool @ 0x08266a34
//! ldr  r0, [r0, #0x38]     ; the guard word @ 0x089ca834
//! tst  r0, #1
//! bne  done                ; inlined fast path: bit 0 = built
//! ldr  r0, =0x089ca834     ; pool @ 0x08266a38: the guard, again
//! bl   cxa_guard_acquire   ; 0x082ab31c (ported)
//! cmp  r0, #0; beq done
//! ldr  r0, =0x08a1b180     ; pool @ 0x08266a3c: the object
//! mov  r1, #8              ; block_size
//! mov  r2, #0x100          ; block_count = 256
//! bl   0x0826c134          ; FixedBlockPool::FixedBlockPool
//! ldr  r2, =0x089ca09c     ; pool @ 0x08266a40: __dso_handle
//! ldr  r1, =0x082612d0     ; pool @ 0x08266a44: the "destructor"
//! bl   cxa_atexit          ; 0x082ab1c8 (ported)
//! ldr  r0, =0x089ca834
//! bl   cxa_guard_release   ; 0x082ab338 (ported)
//! done:
//! ldr  r0, =0x08a1b180     ; reloaded — NOT the ctor's return
//! pop  {r4, pc}
//! ```
//!
//! (The fast path's `ldr r0, [r0, #0x38]` and the slow path's
//! `ldr r0, =0x089ca834` name the same word: 0x089ca7fc + 0x38 =
//! 0x089ca834.) Ghidra's 80-byte extent is the code only; the five
//! pool words @ 0x08266a34..0x08266a48 belong to the function, so the
//! true extent is 100 bytes — the message_arena.rs sibling @
//! 0x08103400 is the identical shape.
//!
//! A slab of 256 blocks of 8 bytes: exactly the 8-byte object
//! `message_kind_construct` @ 0x08266a48 (ported, app/message_kind.rs)
//! builds — a vtable word plus the +0x04 kind tag. The class's own
//! `operator new` / `operator delete` pair sits immediately after that
//! ctor: 0x08266aa4 (`bl 0x082669e4; mov r1, r4; b
//! fixed_block_pool_alloc`) and 0x08266a84 (`bl 0x082669e4; ...; b
//! 0x0826c074`), neither yet ported.
//!
//! Who calls it: all 37 sites feed the result straight to
//! `fixed_block_pool_alloc` @ 0x0826c0d8 (ported) or its free
//! counterpart. Decoding the `mov r1, #imm` at every site: exactly 8
//! sites request 8 bytes and can hit the pool; the rest request
//! 12/16/20/24/28/32 or pass a variable size and always take the
//! allocator's exact-equality fallback to the global `operator new`
//! (the `cmp r0, r1; beq` @ 0x0826c0e8, binary-verified). The pool is
//! in practice the MessageKind class arena; the other sites are
//! sibling message classes sharing the accessor, where the mismatch
//! costs only a redundant pool fetch.
//!
//! The guard pair and `cxa_atexit` are ported and called directly. The
//! FixedBlockPool constructor @ 0x0826c134 is not, so it rides the
//! [`MESSAGE_KIND_ARENA_CTOR`] seam (the `bl` @ 0x08266a14): on
//! target the default calls the stock constructor in place; on host
//! it panics until a test installs one. The registered "destructor"
//! 0x082612d0 is not a function entry — see
//! [`message_kind_arena_destructor`].
//!
//! # Deviations
//!
//! - The guard word and the pool object are crate statics rather than
//!   the .bss words @ 0x089ca834 / 0x08a1b180 (the block_mgr.rs
//!   deviation: the 0x089cxxxx RW pages are runtime-initialized and
//!   the image's contents there are stale). Both zero-init, the exact
//!   pre-init state. On target `FixedBlockPool` is exactly the
//!   original's 0x1c bytes (+0x00 lock .. +0x18 free_head).

use core::ffi::c_void;

use crate::heap::fixed_block_pool::FixedBlockPool;
use crate::kernel::sync_mutex::Mutex;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// `mov r1, #8` in the pool constructor call at 0x08266a10, and the
/// `mov r1, #8` 8 of the 37 call sites pass to
/// `fixed_block_pool_alloc`: the 8-byte MessageKind object (vtable
/// word + kind tag).
pub const MESSAGE_KIND_ARENA_BLOCK_SIZE: usize = 8;

/// `mov r2, #0x100` in the same constructor call — 256 objects.
pub const MESSAGE_KIND_ARENA_BLOCK_COUNT: usize = 256;

/// `__dso_handle` — the pool word @ 0x08266a40 (0x089ca09c), the key
/// every ADS static's `cxa_atexit` registration carries. See
/// runtime/shutdown_chain.rs.
const DSO_HANDLE: i32 = 0x089ca09c;

/// The one-time-initialization guard (original: the .bss word @
/// 0x089ca834 — read on the fast path as `[0x089ca7fc + 0x38]`, pool
/// word @ 0x08266a34, and loaded from the pool word @ 0x08266a38 on
/// the slow path). A crate static rather than the .bss word, per the
/// module header's deviation. Zero is the exact pre-init state.
static mut MESSAGE_KIND_ARENA_GUARD: u32 = 0;

/// The pool object itself (original: the fixed .bss object @
/// 0x08a1b180, the pool word @ 0x08266a3c). Same crate-static
/// deviation as the guard; all-zero is the pre-construction state.
static mut MESSAGE_KIND_ARENA: FixedBlockPool = FixedBlockPool {
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
pub type MessageKindArenaCtorFn = unsafe extern "C" fn(
    this: *mut FixedBlockPool,
    block_size: usize,
    block_count: usize,
) -> *mut FixedBlockPool;

/// Target default: call the stock constructor in place.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_message_kind_arena_ctor(
    this: *mut FixedBlockPool,
    block_size: usize,
    block_count: usize,
) -> *mut FixedBlockPool {
    let ctor: MessageKindArenaCtorFn = unsafe { core::mem::transmute(0x0826_c134usize) };
    unsafe { ctor(this, block_size, block_count) }
}

/// Host default: there is no firmware to call, and silently
/// "constructing" nothing would hand callers a zeroed pool whose
/// every allocation degrades to the global heap.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_message_kind_arena_ctor(
    _this: *mut FixedBlockPool,
    _block_size: usize,
    _block_count: usize,
) -> *mut FixedBlockPool {
    panic!("message_kind_arena_pool requires the FixedBlockPool constructor 0x0826c134")
}

/// The active constructor — the dispatch seam for `FUN_0826c134` (the
/// `bl` @ 0x08266a14). Host tests install a recording mock; the real
/// port replaces the default when it lands in heap/fixed_block_pool.rs.
#[cfg(target_os = "none")]
pub static mut MESSAGE_KIND_ARENA_CTOR: MessageKindArenaCtorFn =
    firmware_message_kind_arena_ctor;

/// See the target definition.
#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_KIND_ARENA_CTOR: MessageKindArenaCtorFn = missing_message_kind_arena_ctor;

/// Reads the constructor slot. Volatile so a build in which nothing
/// rewrites the slot cannot constant-fold the default in and delete the
/// dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn arena_ctor() -> MessageKindArenaCtorFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_KIND_ARENA_CTOR)) }
}

/// The destructor registered with `cxa_atexit` — original: the pool
/// word @ 0x08266a44, 0x082612d0.
///
/// That address is **not a function entry**: it sits 0x140 bytes
/// inside `FUN_08261190` (0x08261190, 880 bytes per
/// decomp/functions.csv), on a `ldr r0, [r6, r0, lsl #2]` — an
/// interior load through its caller's r6/r0. Run as a shutdown handler
/// it would index a garbage pointer, so the registration could never
/// actually fire; retailOS never runs `exit`'s chain anyway
/// (runtime/shutdown_chain.rs: the sole runner caller is
/// `exit_stdio_cleanup`). The same registration every FixedBlockPool
/// static carries — see app/message_arena.rs. A no-op matches every
/// observable path.
unsafe extern "C" fn message_kind_arena_destructor(_object: *mut c_void) {}

/// message_kind_arena_pool — original: `FUN_082669e4` @ 0x082669e4
/// (100 bytes: 80 of code plus a 5-word literal pool; 37 `bl` call
/// sites, binary-scanned).
///
/// Returns the MessageKind arena's singleton fixed-block pool, running
/// its one-time construction (256 blocks of 8 bytes) on the first
/// call. See the module header for the stock instruction sequence.
///
/// Faithful details:
/// - The return value is always the fixed object's address, reloaded
///   after the init block (the original's second
///   `ldr r0, =0x08a1b180` @ 0x08266a2c) — never the constructor's
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
pub unsafe extern "C" fn message_kind_arena_pool() -> *mut FixedBlockPool {
    let guard = core::ptr::addr_of_mut!(MESSAGE_KIND_ARENA_GUARD);
    let object = core::ptr::addr_of_mut!(MESSAGE_KIND_ARENA);
    if (core::ptr::read_volatile(guard) & 1) == 0 {
        if unsafe { cxa_guard_acquire(guard) } != 0 {
            let this = unsafe {
                (arena_ctor())(
                    object,
                    MESSAGE_KIND_ARENA_BLOCK_SIZE,
                    MESSAGE_KIND_ARENA_BLOCK_COUNT,
                )
            };
            unsafe {
                cxa_atexit(this as *mut c_void, message_kind_arena_destructor, DSO_HANDLE);
                cxa_guard_release(guard);
            }
        }
    }
    object
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
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
            handler: message_kind_arena_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(unsafe { Box::from_raw(block as *mut ShutdownNode) });
    }

    fn storage() -> *mut FixedBlockPool {
        core::ptr::addr_of_mut!(MESSAGE_KIND_ARENA)
    }

    /// Resets the guard, the object and the chain to their pre-init
    /// state and installs the Box allocator pair and the recording
    /// constructor.
    fn reset() -> MutexGuard<'static, ()> {
        let guard = ARENA_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MESSAGE_KIND_ARENA_GUARD = 0;
            (storage() as *mut u8)
                .write_bytes(0xa5, core::mem::size_of::<FixedBlockPool>());
            MESSAGE_KIND_ARENA_CTOR = recording_ctor;
            (*core::ptr::addr_of_mut!(CTOR_CALLS)).clear();
            CTOR_RESULT = storage();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = core::ptr::null_mut();
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
            MESSAGE_KIND_ARENA_CTOR = missing_message_kind_arena_ctor;
            MESSAGE_KIND_ARENA_GUARD = 0;
            (storage() as *mut u8).write_bytes(0, core::mem::size_of::<FixedBlockPool>());
        }
        drop(guard);
    }

    #[test]
    fn the_first_call_constructs_registers_and_publishes_the_guard() {
        let guard = reset();
        unsafe {
            assert_eq!(message_kind_arena_pool(), storage());
            assert_eq!(
                *core::ptr::addr_of!(CTOR_CALLS),
                std::vec![(
                    storage(),
                    MESSAGE_KIND_ARENA_BLOCK_SIZE,
                    MESSAGE_KIND_ARENA_BLOCK_COUNT
                )],
                "constructed in place, 256 blocks of 8 bytes"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_KIND_ARENA_GUARD)),
                1,
                "acquire published the flag"
            );

            let head = *shutdown_chain_head();
            assert!(!head.is_null(), "registered with cxa_atexit");
            assert_eq!((*head).arg as *mut FixedBlockPool, storage(), "the ctor's return");
            assert_eq!((*head).handler as usize, message_kind_arena_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE, "__dso_handle @ 0x089ca09c");
            assert!((*head).next.is_null(), "registered exactly once");
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_takes_the_bit0_fast_path() {
        let guard = reset();
        unsafe {
            message_kind_arena_pool();
            // A post-construction mutation must survive: the 37 call
            // sites after boot must not reconstruct the pool.
            (*storage()).block_size = 0x5a;
            assert_eq!(message_kind_arena_pool(), storage());
            assert_eq!(message_kind_arena_pool(), storage());
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
            MESSAGE_KIND_ARENA_GUARD = 3; // bit 0 set -> `tst r0, #1`, bne done
            assert_eq!(message_kind_arena_pool(), storage());
            assert!((*core::ptr::addr_of!(CTOR_CALLS)).is_empty(), "no construction");
            assert!(shutdown_chain_head().read().is_null(), "no registration");
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_KIND_ARENA_GUARD)),
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
            MESSAGE_KIND_ARENA_GUARD = 2;
            assert_eq!(message_kind_arena_pool(), storage());
            assert!(
                (*core::ptr::addr_of!(CTOR_CALLS)).is_empty(),
                "acquire refused: no construction"
            );
            assert_eq!(
                core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_KIND_ARENA_GUARD)),
                2,
                "a refused acquire never writes"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_object_literal_is_returned_not_the_constructors_value() {
        // The original reloads the pool word 0x08266a3c @ 0x08266a2c;
        // only the REGISTRATION sees the constructor's return.
        let guard = reset();
        unsafe {
            let sentinel = storage().add(1); // deliberately different
            CTOR_RESULT = sentinel;
            assert_eq!(message_kind_arena_pool(), storage(), "the reloaded literal wins");
            assert_eq!((*(*shutdown_chain_head())).arg as *mut FixedBlockPool, sentinel);
        }
        restore(guard);
    }

    #[test]
    fn the_registration_is_real_and_the_chain_runs_the_noop_destructor() {
        let guard = reset();
        unsafe {
            message_kind_arena_pool();
            (*storage()).block_size = 0xa5;
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null(), "the node ran and was freed");
            assert_eq!((*storage()).block_size, 0xa5, "the no-op destructor touched nothing");
        }
        restore(guard);
    }

    #[test]
    fn the_pool_geometry_and_dso_key_are_the_stock_literals() {
        // `mov r1, #8` @ 0x08266a10, `mov r2, #0x100` @ 0x08266a0c,
        // pool word 0x089ca09c @ 0x08266a40.
        assert_eq!(MESSAGE_KIND_ARENA_BLOCK_SIZE, 8);
        assert_eq!(MESSAGE_KIND_ARENA_BLOCK_COUNT, 256);
        assert_eq!(DSO_HANDLE, 0x089ca09c);
    }
}
