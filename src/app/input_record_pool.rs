//! Singleton pool for the 24-byte records created by `FUN_08292b54`.
//!
//! Original `FUN_08292af0` @ 0x08292af0: true size 100 bytes (80 code,
//! 20 literals), next function @ 0x08292b54. Raw ARM decoding finds two
//! inbound plain BL calls (0x08110808, 0x08292b98), four outbound plain
//! BL calls, and zero predicated BL calls in either direction.
//!
//! Test guard bit zero, acquire if clear, construct eight 24-byte blocks,
//! register the constructor return for shutdown, release, and always return
//! the fixed pool. Registration failure does not undo initialization.
//!
//! Deliberate deviations: native-pointer context enables isolated host tests;
//! production retains the firmware guard and object addresses. The existing
//! constructor and guard/registration ports are reused. LLVM may eliminate
//! the empty guard release and inline registration. The opaque handler word
//! 0x082612d0 is preserved exactly: it is an interior instruction of
//! FUN_08261190, not a verified destructor entry. No inert replacement is used.

use core::ffi::c_void;
use crate::heap::fixed_block_pool::{fixed_block_pool_init, FixedBlockPool};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

#[inline(always)]
unsafe fn pool_get_at(
    guard: *mut u32,
    pool: *mut FixedBlockPool,
    construct: impl FnOnce(*mut FixedBlockPool) -> *mut FixedBlockPool,
    register: impl FnOnce(*mut FixedBlockPool),
) -> *mut FixedBlockPool {
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        let initialized = construct(pool);
        register(initialized);
        cxa_guard_release(guard);
    }
    pool
}

/// Firmware singleton accessor; the fixed addresses must be mapped and valid.
/// See the module header for extent, call counts, algorithm and deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn input_record_pool_get() -> *mut FixedBlockPool {
    pool_get_at(0x089c_a844 as *mut u32, 0x08a1_b1f0 as *mut FixedBlockPool,
        |pool| fixed_block_pool_init(pool, 24, 8),
        |initialized| {
            let handler: ShutdownHandlerFn = core::mem::transmute(0x0826_12d0usize);
            cxa_atexit(initialized.cast::<c_void>(), handler, 0x089c_a09c);
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn nonzero_guards_never_construct_even_when_bit_zero_is_clear() {
        for mut guard in [1u32, 2, 4, 0x8000_0000, u32::MAX] {
            let before = guard;
            let pool = core::ptr::NonNull::<FixedBlockPool>::dangling().as_ptr();
            let result = unsafe { pool_get_at(&mut guard, pool,
                |_| panic!("nonzero guard must refuse construction"),
                |_| panic!("refused construction must not register")) };
            assert_eq!(result, pool);
            assert_eq!(guard, before);
        }
    }

    #[test]
    fn acquire_publishes_before_reentry_and_return_is_not_constructor_result() {
        let mut guard = 0u32;
        let guard_ptr = &mut guard as *mut u32;
        let pool = core::ptr::NonNull::<FixedBlockPool>::dangling().as_ptr();
        let registered = Cell::new(false);
        unsafe {
            let result = pool_get_at(guard_ptr, pool, |_| {
                assert_eq!(guard_ptr.read(), 1);
                assert_eq!(pool_get_at(guard_ptr, pool,
                    |_| panic!("reentry must not reconstruct"),
                    |_| panic!("reentry must not register")), pool);
                core::ptr::null_mut()
            }, |initialized| {
                assert!(initialized.is_null());
                registered.set(true);
                // A failed registration is ignored by the firmware accessor.
            });
            assert_eq!(result, pool);
            assert!(registered.get());
            assert_eq!(guard, 1);
            assert_eq!(pool_get_at(guard_ptr, pool,
                |_| panic!("spent guard must not retry"),
                |_| panic!("spent guard must not register again")), pool);
        }
    }
}
