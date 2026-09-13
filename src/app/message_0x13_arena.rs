//! Fixed-block arena for message code `0x13`.
//!
//! Port: [`message_0x13_arena_pool`] — `FUN_081cd754` @ `0x081cd754`
//! (100 bytes: 80 bytes of instructions plus its 20-byte literal pool; the
//! next separately linked function begins at `0x081cd7b8`). Raw ARM decoding
//! found **7 direct `bl` callers, all
//! unconditional; 0 predicated and 0 tail `b` callers**: `0x0813322c`,
//! `0x08133610`, `0x08133bbc`, `0x08143918`, `0x081cd820`, `0x08212a38`, and
//! `0x08272310`.
//!
//! Algorithm: test bit 0 of the static guard at `0x089ca83c`; if clear and
//! [`cxa_guard_acquire`] succeeds, construct the fixed pool at `0x08a1b1b8`
//! with 16-byte blocks and 16 blocks, register the constructor return with
//! `cxa_atexit`, release the guard, and return the fixed pool address. The
//! sibling constructor `FUN_081cd7b8` stamps every allocation with message
//! code `0x13`, which identifies this arena.
//!
//! Deliberate deviations: the runtime-initialized `.bss` guard and pool are
//! crate statics, initialized to their stock all-zero pre-init state. The
//! unported `FixedBlockPool` constructor is a unique volatile dispatch seam:
//! target builds call `0x0826c134`; host builds require an installed test
//! constructor. The registered `0x082612d0` address is an interior instruction,
//! not a function entry, so its host shutdown callback is a no-op.

use core::ffi::c_void;

use crate::heap::fixed_block_pool::FixedBlockPool;
use crate::kernel::sync_mutex::Mutex;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// `mov r1, #16` at `0x081cd780`: one message-code-0x13 object per block.
pub const MESSAGE_0X13_ARENA_BLOCK_SIZE: usize = 16;
/// `mov r2, #16` at `0x081cd77c`: sixteen fixed blocks.
pub const MESSAGE_0X13_ARENA_BLOCK_COUNT: usize = 16;
const DSO_HANDLE: i32 = 0x089ca09c;

/// Original `.bss` word `0x089ca83c`, loaded through literal `0x081cd7a8`.
static mut MESSAGE_0X13_ARENA_GUARD: u32 = 0;

/// Original fixed pool object `0x08a1b1b8`, loaded through `0x081cd7ac`.
static mut MESSAGE_0X13_ARENA: FixedBlockPool = FixedBlockPool {
    lock: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
    block_size: 0,
    block_count: 0,
    total_bytes: 0,
    storage: core::ptr::null_mut(),
    free_head: core::ptr::null_mut(),
};

/// `FUN_0826c134`: `FixedBlockPool::FixedBlockPool(this, block_size, count)`.
pub type Message0x13ArenaCtorFn = unsafe extern "C" fn(
    this: *mut FixedBlockPool,
    block_size: usize,
    block_count: usize,
) -> *mut FixedBlockPool;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_message_0x13_arena_ctor(
    this: *mut FixedBlockPool,
    block_size: usize,
    block_count: usize,
) -> *mut FixedBlockPool {
    let ctor: Message0x13ArenaCtorFn = unsafe { core::mem::transmute(0x0826_c134usize) };
    unsafe { ctor(this, block_size, block_count) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_message_0x13_arena_ctor(
    _this: *mut FixedBlockPool,
    _block_size: usize,
    _block_count: usize,
) -> *mut FixedBlockPool {
    panic!("message_0x13_arena_pool requires the FixedBlockPool constructor 0x0826c134")
}

/// Volatile seam for the unported fixed-block-pool constructor. This is unique
/// to `FUN_081cd754`; it is not a duplicate of another arena's seam.
#[cfg(target_os = "none")]
pub static mut MESSAGE_0X13_ARENA_CTOR: Message0x13ArenaCtorFn = firmware_message_0x13_arena_ctor;
#[cfg(not(target_os = "none"))]
pub static mut MESSAGE_0X13_ARENA_CTOR: Message0x13ArenaCtorFn = missing_message_0x13_arena_ctor;

#[inline(always)]
unsafe fn arena_ctor() -> Message0x13ArenaCtorFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_0X13_ARENA_CTOR)) }
}

/// `0x082612d0` is inside `FUN_08261190`, rather than a callable entry point.
unsafe extern "C" fn message_0x13_arena_destructor(_object: *mut c_void) {}

/// message_0x13_arena_pool — `FUN_081cd754` @ `0x081cd754` (100 bytes).
///
/// Returns the singleton pool backing 16-byte message-code-`0x13` objects.
/// The returned pointer is always the fixed object; only `cxa_atexit` receives
/// the constructor's return value. A guard with bit 0 set bypasses every call;
/// a nonzero guard with bit 0 clear reaches and is refused by `cxa_guard_acquire`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_0x13_arena_pool() -> *mut FixedBlockPool {
    let guard = core::ptr::addr_of_mut!(MESSAGE_0X13_ARENA_GUARD);
    let object = core::ptr::addr_of_mut!(MESSAGE_0X13_ARENA);
    if (core::ptr::read_volatile(guard) & 1) == 0 {
        if unsafe { cxa_guard_acquire(guard) } != 0 {
            let this = unsafe {
                (arena_ctor())(object, MESSAGE_0X13_ARENA_BLOCK_SIZE, MESSAGE_0X13_ARENA_BLOCK_COUNT)
            };
            unsafe {
                cxa_atexit(this as *mut c_void, message_0x13_arena_destructor, DSO_HANDLE);
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

    static ARENA_LOCK: StdMutex<()> = StdMutex::new(());
    static mut CTOR_CALLS: Vec<(*mut FixedBlockPool, usize, usize)> = Vec::new();
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

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: core::ptr::null_mut(),
            arg: core::ptr::null_mut(),
            handler: message_0x13_arena_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(unsafe { Box::from_raw(block as *mut ShutdownNode) });
    }

    fn storage() -> *mut FixedBlockPool {
        core::ptr::addr_of_mut!(MESSAGE_0X13_ARENA)
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = ARENA_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MESSAGE_0X13_ARENA_GUARD = 0;
            (storage() as *mut u8).write_bytes(0xa5, core::mem::size_of::<FixedBlockPool>());
            MESSAGE_0X13_ARENA_CTOR = recording_ctor;
            (*core::ptr::addr_of_mut!(CTOR_CALLS)).clear();
            CTOR_RESULT = storage();
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = core::ptr::null_mut();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            MESSAGE_0X13_ARENA_CTOR = missing_message_0x13_arena_ctor;
            MESSAGE_0X13_ARENA_GUARD = 0;
            (storage() as *mut u8).write_bytes(0, core::mem::size_of::<FixedBlockPool>());
        }
        drop(guard);
    }

    #[test]
    fn first_call_constructs_registers_and_publishes() {
        let guard = reset();
        unsafe {
            assert_eq!(message_0x13_arena_pool(), storage());
            assert_eq!(
                *core::ptr::addr_of!(CTOR_CALLS),
                std::vec![(storage(), MESSAGE_0X13_ARENA_BLOCK_SIZE, MESSAGE_0X13_ARENA_BLOCK_COUNT)]
            );
            assert_eq!(MESSAGE_0X13_ARENA_GUARD, 1);
            let head = *shutdown_chain_head();
            assert!(!head.is_null());
            assert_eq!((*head).arg as *mut FixedBlockPool, storage());
            assert_eq!((*head).handler as usize, message_0x13_arena_destructor as usize);
            assert_eq!((*head).key, DSO_HANDLE);
            assert!((*head).next.is_null());
        }
        restore(guard);
    }

    #[test]
    fn bit0_fast_path_preserves_the_constructed_pool() {
        let guard = reset();
        unsafe {
            message_0x13_arena_pool();
            (*storage()).block_size = 0x5a;
            assert_eq!(message_0x13_arena_pool(), storage());
            assert_eq!((*core::ptr::addr_of!(CTOR_CALLS)).len(), 1);
            assert_eq!((*storage()).block_size, 0x5a);
            assert!((*(*shutdown_chain_head())).next.is_null());
        }
        restore(guard);
    }

    #[test]
    fn bit0_set_guard_skips_construction_and_registration() {
        let guard = reset();
        unsafe {
            MESSAGE_0X13_ARENA_GUARD = 3;
            assert_eq!(message_0x13_arena_pool(), storage());
            assert!((*core::ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!(MESSAGE_0X13_ARENA_GUARD, 3);
            assert_eq!((storage() as *mut u8).read(), 0xa5);
        }
        restore(guard);
    }

    #[test]
    fn nonzero_bit0_clear_guard_is_refused_by_acquire() {
        let guard = reset();
        unsafe {
            MESSAGE_0X13_ARENA_GUARD = 2;
            assert_eq!(message_0x13_arena_pool(), storage());
            assert!((*core::ptr::addr_of!(CTOR_CALLS)).is_empty());
            assert_eq!(MESSAGE_0X13_ARENA_GUARD, 2);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(guard);
    }

    #[test]
    fn fixed_pool_address_wins_over_constructor_return() {
        let guard = reset();
        unsafe {
            let sentinel = storage().add(1);
            CTOR_RESULT = sentinel;
            assert_eq!(message_0x13_arena_pool(), storage());
            assert_eq!((*(*shutdown_chain_head())).arg as *mut FixedBlockPool, sentinel);
        }
        restore(guard);
    }

    #[test]
    fn registration_runs_the_noop_in_the_real_shutdown_chain() {
        let guard = reset();
        unsafe {
            message_0x13_arena_pool();
            (*storage()).block_size = 0xa5;
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null());
            assert_eq!((*storage()).block_size, 0xa5);
        }
        restore(guard);
    }

    #[test]
    fn stock_pool_geometry_and_dso_key_are_fixed() {
        assert_eq!(MESSAGE_0X13_ARENA_BLOCK_SIZE, 16);
        assert_eq!(MESSAGE_0X13_ARENA_BLOCK_COUNT, 16);
        assert_eq!(DSO_HANDLE, 0x089ca09c);
    }
}
