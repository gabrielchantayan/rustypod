//! OpenSSL's `BIO_new` factory.
//!
//! Port: `bio_new` — `FUN_0803d558` @ `0x0803d558` (**104 bytes**,
//! `0x0803d558..0x0803d5c0`; the separately linked successor begins at
//! `0x0803d5c0`). Raw decoding of every ARM B/BL word in `osos.dec` found
//! **9 call sites**, all unconditional `bl`: `0x0803d634`, `0x0805ffdc`,
//! `0x0806006c`, `0x080602d0`, `0x0806030c`, `0x082728e8`, `0x082728f8`,
//! `0x082d44b8`, and `0x082d45b0`. There are no predicated calls or direct
//! tail branches.
//!
//! # Algorithm
//!
//! Allocate the 64-byte OpenSSL `BIO`, then delegate initialization to the
//! internal `BIO_set` body at `0x0803d8c0`. Allocation failure records
//! `ERR_LIB_BIO` `(0x20, 0x6c, 0x41, 0, 0)` and returns NULL. An initializer
//! result of zero frees the exact allocation and also returns NULL; every
//! nonzero result returns the allocation, not the initializer's value.
//!
//! # Deliberate deviations
//!
//! `BIO_set` is not yet ported. Target builds invoke its verified original
//! entry directly; host builds expose [`BIO_SET`] so tests can model its
//! result. The allocator and diagnostic recorder are already ported and are
//! called directly.

use core::ptr;

use crate::crypto::bio_ctrl::{Bio, BioMethod};
use crate::drivers::ata_cmd::{traced_alloc, traced_free};
use crate::kernel::diag_ring_record::diag_ring_record;

/// The `BIO_set(BIO *, BIO_METHOD *)` internal initialization ABI.
pub type BioSetFn = unsafe extern "C" fn(bio: *mut Bio, method: *mut BioMethod) -> i32;

/// Original `BIO_set` body entered after the allocation succeeds.
const BIO_SET_ADDRESS: usize = 0x0803_d8c0;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_set(_bio: *mut Bio, _method: *mut BioMethod) -> i32 {
    0
}

/// Host execution model for the unported `BIO_set` call boundary.
///
/// Firmware builds call [`BIO_SET_ADDRESS`] directly instead.
#[cfg(not(target_os = "none"))]
pub static mut BIO_SET: BioSetFn = missing_bio_set;

#[inline(always)]
unsafe fn bio_set(bio: *mut Bio, method: *mut BioMethod) -> i32 {
    #[cfg(target_os = "none")]
    {
        let set: BioSetFn = unsafe { core::mem::transmute(BIO_SET_ADDRESS) };
        unsafe { set(bio, method) }
    }

    #[cfg(not(target_os = "none"))]
    {
        let set = unsafe { ptr::read_volatile(ptr::addr_of!(BIO_SET)) };
        unsafe { set(bio, method) }
    }
}

/// bio_new — original: `FUN_0803d558` @ 0x0803d558 (104 bytes; 9 direct,
/// unconditional `bl` call sites, binary-verified from `osos.dec`).
///
/// Allocates a 64-byte OpenSSL BIO, initializes it through `BIO_set`, and
/// returns it only when initialization succeeds. Allocation failure records
/// `(0x20, 0x6c, 0x41, 0, 0)`; initialization failure releases the allocation.
///
/// # Safety
///
/// `method` must be a valid `BIO_METHOD *` for the unported initializer when
/// non-NULL. A non-NULL result is a 64-byte allocation owned by the caller's
/// corresponding BIO destruction path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_new(method: *mut BioMethod) -> *mut Bio {
    let bio = unsafe { traced_alloc(0x40, 0, 0) }.cast::<Bio>();
    if bio.is_null() {
        unsafe { diag_ring_record(0x20, 0x6c, 0x41, 0, 0) };
        return ptr::null_mut();
    }

    if unsafe { bio_set(bio, method) } == 0 {
        unsafe { traced_free(bio.cast()) };
        return ptr::null_mut();
    }

    bio
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
        TRACED_FREE_TEST_LOCK,
    };
    use crate::kernel::diag_ring_record::{
        DiagEventRing, DIAG_RING_BLOCK_GETTER,
    };
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use parking_lot::{Mutex, MutexGuard};

    static BIO_NEW_TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Calls> = Mutex::new(Calls::new());
    static mut ALLOCATION: [u32; 16] = [0; 16];
    static mut DIAGNOSTICS: DiagEventRing = DiagEventRing {
        owner: 0,
        tags: [0; 16],
        pointers: [0; 16],
        flags: [0; 16],
        data0: [0; 16],
        data1: [0; 16],
        head: 0,
        tail: 0,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Calls {
        allocation: Option<(i32, u32, u32)>,
        initialized: Option<(usize, usize)>,
        freed: Option<usize>,
        initializer_result: i32,
    }

    impl Calls {
        const fn new() -> Self {
            Self {
                allocation: None,
                initialized: None,
                freed: None,
                initializer_result: 1,
            }
        }
    }

    unsafe extern "C" fn allocating(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        CALLS.lock().allocation = Some((size, tag1, tag2));
        ptr::addr_of_mut!(ALLOCATION).cast()
    }

    unsafe extern "C" fn failing_alloc(_size: i32, _tag1: u32, _tag2: u32) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn recording_set(bio: *mut Bio, method: *mut BioMethod) -> i32 {
        let mut calls = CALLS.lock();
        calls.initialized = Some((bio as usize, method as usize));
        calls.initializer_result
    }

    unsafe extern "C" fn recording_free(block: *mut u8) {
        CALLS.lock().freed = Some(block as usize);
    }

    unsafe extern "C" fn diagnostic_ring() -> *mut DiagEventRing {
        ptr::addr_of_mut!(DIAGNOSTICS)
    }

    struct HooksGuard {
        allocation: TracedAllocHooks,
        free: TracedFreeHooks,
        initializer: BioSetFn,
        diagnostic_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
    }

    impl HooksGuard {
        unsafe fn install(allocator: unsafe extern "C" fn(i32, u32, u32) -> *mut u8) -> Self {
            let guard = Self {
                allocation: unsafe { ptr::read_volatile(ptr::addr_of!(TRACED_ALLOC_HOOKS)) },
                free: unsafe { ptr::read_volatile(ptr::addr_of!(TRACED_FREE_HOOKS)) },
                initializer: unsafe { ptr::read_volatile(ptr::addr_of!(BIO_SET)) },
                diagnostic_getter: unsafe { ptr::read_volatile(ptr::addr_of!(DIAG_RING_BLOCK_GETTER)) },
            };
            unsafe {
                TRACED_ALLOC_HOOKS = TracedAllocHooks { alloc: allocator, trace: None };
                TRACED_FREE_HOOKS = TracedFreeHooks { free: recording_free, trace: None };
                BIO_SET = recording_set;
                DIAG_RING_BLOCK_GETTER = None;
                ALLOCATION = [0xa5a5_a5a5; 16];
                DIAGNOSTICS = DiagEventRing {
                    owner: 0,
                    tags: [0; 16],
                    pointers: [0; 16],
                    flags: [0; 16],
                    data0: [0; 16],
                    data1: [0; 16],
                    head: 0,
                    tail: 0,
                };
            }
            *CALLS.lock() = Calls::new();
            guard
        }
    }

    impl Drop for HooksGuard {
        fn drop(&mut self) {
            unsafe {
                TRACED_ALLOC_HOOKS = self.allocation;
                TRACED_FREE_HOOKS = self.free;
                BIO_SET = self.initializer;
                DIAG_RING_BLOCK_GETTER = self.diagnostic_getter;
            }
        }
    }

    fn lock() -> MutexGuard<'static, ()> {
        BIO_NEW_TEST_LOCK.lock()
    }

    #[test]
    fn returns_the_allocation_after_successful_initialization() {
        let _test_guard = lock();
        let _allocation_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _diagnostic_guard = DIAG_RING_TEST_LOCK.lock().unwrap();
        let _hooks = unsafe { HooksGuard::install(allocating) };
        let mut method = BioMethod { _reserved: [0; 6], ctrl: 0 };

        let result = unsafe { bio_new(&mut method) };

        assert_eq!(result.cast::<u8>(), ptr::addr_of_mut!(ALLOCATION).cast());
        let calls = *CALLS.lock();
        assert_eq!(calls.allocation, Some((0x40, 0, 0)));
        assert_eq!(calls.initialized, Some((result as usize, ptr::addr_of_mut!(method) as usize)));
        assert_eq!(calls.freed, None);
    }

    #[test]
    fn frees_the_exact_allocation_when_initialization_fails() {
        let _test_guard = lock();
        let _allocation_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _diagnostic_guard = DIAG_RING_TEST_LOCK.lock().unwrap();
        let _hooks = unsafe { HooksGuard::install(allocating) };
        CALLS.lock().initializer_result = 0;

        let result = unsafe { bio_new(ptr::null_mut()) };

        assert!(result.is_null());
        let calls = *CALLS.lock();
        assert_eq!(calls.initialized, Some((ptr::addr_of_mut!(ALLOCATION) as usize, 0)));
        assert_eq!(calls.freed, Some(ptr::addr_of_mut!(ALLOCATION) as usize));
    }

    #[test]
    fn records_bio_allocation_failure_without_calling_the_initializer() {
        let _test_guard = lock();
        let _allocation_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let _free_guard = TRACED_FREE_TEST_LOCK.lock();
        let _diagnostic_guard = DIAG_RING_TEST_LOCK.lock().unwrap();
        let _hooks = unsafe { HooksGuard::install(failing_alloc) };
        unsafe { DIAG_RING_BLOCK_GETTER = Some(diagnostic_ring) };

        let result = unsafe { bio_new(ptr::null_mut()) };

        assert!(result.is_null());
        let calls = *CALLS.lock();
        assert_eq!(calls.initialized, None);
        assert_eq!(calls.freed, None);
        let ring = unsafe { &*ptr::addr_of!(DIAGNOSTICS) };
        assert_eq!(ring.head, 1);
        assert_eq!(ring.tags[1], 0x20_06c_041);
        assert_eq!((ring.data0[1], ring.data1[1]), (0, 0));
    }
}
