//! The four-slot buffer-pool local-static accessor.
//!
//! Port:
//! - [`four_slot_buffer_pool_get`] — original: `FUN_08149648` @ `0x08149648`
//!   (**112-byte raw extent**: 84 bytes of code plus the five-word literal
//!   pool at `0x081496a4..0x081496b4`; **7 direct unconditional `bl` call
//!   sites, zero predicated forms and no tail branches**, verified by decoding
//!   every ARM B/BL word in `osos.dec`).
//!
//! ## Algorithm
//!
//! The function is an ADS function-local-static accessor. It tests bit zero
//! of the guard at `0x089ca324`; when clear and `cxa_guard_acquire` succeeds,
//! it calls the existing four-argument `cpp_array_construct` adapter with
//! fixed storage at `0x08a10728`, four 36-byte elements, and the raw
//! initializer word `0x0813ead0`. It clears the trailing accounting word at
//! result + `0x90`, registers the helper result with `cxa_atexit`, releases
//! the guard, then returns the fixed storage address on every path.
//!
//! The initializer word is deliberately not named or dispatched as a Rust
//! callee: raw ARM shows `0x0813ead0` is an interior instruction of the body
//! beginning at `0x0813eac0`, not a standalone entry. The teardown word
//! `0x0813e6f8` is likewise an interior `pop {..., pc}`. Target builds retain
//! that exact callback word for `cxa_atexit`; host builds use an inert handler.
//!
//! ## Deliberate deviations
//!
//! Firmware RAM is represented by statics on the host. Initialization routes
//! through the existing `cpp_array_construct` / `PAIR_HEADER_ELEMENT_ARRAY_OPS`
//! seam because its final eleven-word helper remains unported; no new seam is
//! invented for either anomalous literal.

use core::ffi::c_void;

use crate::runtime::cpp_array_construct::cpp_array_construct;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

const SLOT_COUNT: u32 = 4;
const SLOT_SIZE: u32 = 0x24;
const SLOT_INITIALIZER_WORD: u32 = 0x0813_ead0;
const DSO_HANDLE: i32 = 0x089c_a09c;
const SLOT_DESTRUCTOR_ADDRESS: usize = 0x0813_e6f8;
const POOL_WORDS: usize = ((SLOT_COUNT * SLOT_SIZE) as usize + 3) / 4 + 1;

type CxaAtexit = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// The ADS one-time-initialization guard at `0x089ca324`.
pub static mut FOUR_SLOT_BUFFER_POOL_GUARD: u32 = 0;
/// Four 36-byte slot records followed by the accounting word at +0x90.
pub static mut FOUR_SLOT_BUFFER_POOL: [u32; POOL_WORDS] = [0; POOL_WORDS];

/// Volatile bindings preserve the retail registration and release call boundaries.
static mut FOUR_SLOT_BUFFER_POOL_CXA_ATEXIT: CxaAtexit = cxa_atexit;
static mut FOUR_SLOT_BUFFER_POOL_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn slot_destructor() -> ShutdownHandlerFn {
    core::mem::transmute(SLOT_DESTRUCTOR_ADDRESS)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_slot_destructor(_object: *mut c_void) {}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn slot_destructor() -> ShutdownHandlerFn {
    host_slot_destructor
}

#[inline(always)]
unsafe fn slot_pool_cxa_atexit() -> CxaAtexit {
    core::ptr::read_volatile(core::ptr::addr_of!(FOUR_SLOT_BUFFER_POOL_CXA_ATEXIT))
}

#[inline(always)]
unsafe fn slot_pool_cxa_guard_release() -> CxaGuardRelease {
    core::ptr::read_volatile(core::ptr::addr_of!(FOUR_SLOT_BUFFER_POOL_CXA_GUARD_RELEASE))
}

/// four_slot_buffer_pool_get — original: `FUN_08149648` @ `0x08149648`
/// (112 bytes: 84 code bytes plus the five-word literal pool).
///
/// Initializes the four 36-byte records once and always returns the fixed
/// pool. The raw helper result, rather than the reloaded fixed base, receives
/// the `+0x90` clear and shutdown registration exactly as in ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.four_slot_buffer_pool_get")]
pub unsafe extern "C" fn four_slot_buffer_pool_get() -> *mut u32 {
    let guard = core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL_GUARD);
    let pool = core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL).cast::<u32>();

    if (core::ptr::read_volatile(guard) & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        let initialized = cpp_array_construct(pool, SLOT_INITIALIZER_WORD, SLOT_SIZE, SLOT_COUNT);
        core::ptr::write_volatile(initialized.add((SLOT_COUNT * SLOT_SIZE / 4) as usize), 0);
        slot_pool_cxa_atexit()(initialized.cast::<c_void>(), slot_destructor(), DSO_HANDLE);
        slot_pool_cxa_guard_release()(guard);
    }

    pool
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;
    use crate::cxx::pair_header::{PairHeaderElementArrayOps, PAIR_HEADER_ELEMENT_ARRAY_OPS};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut HELPER_CALLS: u32 = 0;
    static mut HELPER_ARGUMENTS: [usize; 3] = [0; 3];
    static mut REGISTRATION: [usize; 3] = [0; 3];

    unsafe extern "C" fn record_array_reset(
        this: *mut u32,
        field_count: u32,
        field_size: u32,
        _allocation_header_bytes: u32,
        _initializer_argument: u32,
        element_initializer: u32,
        _initializer_context: u32,
        _allocator_callback: u32,
        _allocator_context: u32,
        _allocation_flags: u32,
        _zero_initialize: u32,
    ) -> *mut u32 {
        let calls = core::ptr::addr_of_mut!(HELPER_CALLS);
        calls.write_volatile(calls.read_volatile() + 1);
        core::ptr::addr_of_mut!(HELPER_ARGUMENTS).write_volatile([
            field_count as usize,
            field_size as usize,
            element_initializer as usize,
        ]);
        this
    }

    unsafe extern "C" fn record_atexit(
        object: *mut c_void,
        destructor: ShutdownHandlerFn,
        dso_handle: i32,
    ) -> i32 {
        core::ptr::addr_of_mut!(REGISTRATION).write_volatile([
            object as usize,
            destructor as usize,
            dso_handle as usize,
        ]);
        1
    }

    struct TestStateGuard {
        previous_reset: unsafe extern "C" fn(
            *mut u32, u32, u32, u32, u32, u32, u32, u32, u32, u32, u32,
        ) -> *mut u32,
        previous_atexit: CxaAtexit,
    }

    impl TestStateGuard {
        unsafe fn install() -> Self {
            let previous_reset = core::ptr::addr_of!(PAIR_HEADER_ELEMENT_ARRAY_OPS.reset).read_volatile();
            let previous_atexit = core::ptr::addr_of!(FOUR_SLOT_BUFFER_POOL_CXA_ATEXIT).read_volatile();
            core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                PairHeaderElementArrayOps { reset: record_array_reset },
            );
            core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL_CXA_ATEXIT).write_volatile(record_atexit);
            core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL_GUARD).write_volatile(0);
            core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL).write_volatile([0; POOL_WORDS]);
            core::ptr::addr_of_mut!(HELPER_CALLS).write_volatile(0);
            core::ptr::addr_of_mut!(HELPER_ARGUMENTS).write_volatile([0; 3]);
            core::ptr::addr_of_mut!(REGISTRATION).write_volatile([0; 3]);
            Self { previous_reset, previous_atexit }
        }
    }

    impl Drop for TestStateGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PAIR_HEADER_ELEMENT_ARRAY_OPS).write_volatile(
                    PairHeaderElementArrayOps { reset: self.previous_reset },
                );
                core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL_CXA_ATEXIT).write_volatile(self.previous_atexit);
                core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL_GUARD).write_volatile(0);
                core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL).write_volatile([0; POOL_WORDS]);
            }
        }
    }

    #[test]
    fn initializes_slots_clears_accounting_and_registers_raw_result() {
        let _array_lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock();
        let _test_lock = TEST_LOCK.lock();
        unsafe {
            let _state = TestStateGuard::install();
            let pool = four_slot_buffer_pool_get();

            assert_eq!(pool, core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL).cast::<u32>());
            assert_eq!(core::ptr::addr_of!(HELPER_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(HELPER_ARGUMENTS).read_volatile(),
                [SLOT_COUNT as usize, SLOT_SIZE as usize, SLOT_INITIALIZER_WORD as usize],
            );
            assert_eq!((*pool.add(POOL_WORDS - 1)), 0);
            assert_eq!(
                core::ptr::addr_of!(REGISTRATION).read_volatile(),
                [pool as usize, slot_destructor() as usize, DSO_HANDLE as usize],
            );
        }
    }

    #[test]
    fn nonzero_guard_without_bit_zero_skips_initialization() {
        let _array_lock = crate::testing::CPP_ARRAY_OPS_TEST_LOCK.lock();
        let _test_lock = TEST_LOCK.lock();
        unsafe {
            let _state = TestStateGuard::install();
            let pool = core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL).cast::<u32>();
            core::ptr::addr_of_mut!(FOUR_SLOT_BUFFER_POOL_GUARD).write_volatile(2);
            pool.add(POOL_WORDS - 1).write_volatile(0xfeed_beef);

            assert_eq!(four_slot_buffer_pool_get(), pool);
            assert_eq!(core::ptr::addr_of!(HELPER_CALLS).read_volatile(), 0);
            assert_eq!(core::ptr::addr_of!(REGISTRATION).read_volatile(), [0; 3]);
            assert_eq!(pool.add(POOL_WORDS - 1).read_volatile(), 0xfeed_beef);
        }
    }
}
