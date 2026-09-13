//! `handler_context_get` — original: `FUN_081e8ca0` @ **0x081e8ca0**
//! (**48 bytes**: eleven code words through `pop {r4, pc}` @ 0x081e8cc8,
//! plus cache-word literal 0x089cfe38 @ 0x081e8ccc; the next independent
//! function starts @ 0x081e8cd0; **7 `bl` call sites**, all unconditional,
//! no predicated forms or plain-`b` tail calls, verified by decoding every
//! ARM B/BL word in `work/firmware/osos.dec`: 0x0813472c, 0x08134738,
//! 0x081e87f8, 0x0821ed4c, 0x0821ed58, 0x0821ed64, 0x08289d68.)
//!
//! # Algorithm
//!
//! Lazy getter for the 0x34-byte handler-context object. It loads the cache
//! word at 0x089cfe38. A non-NULL value is returned directly. Otherwise it
//! calls `operator_new(0x34)` and then unconditionally calls the unported
//! context constructor `FUN_081e8ee8` with that result, stores the
//! constructor's return in the cache, and reloads the cache for its result.
//! The constructor call is deliberately not guarded against an allocation
//! failure: a NULL allocation still reaches the constructor, and a NULL
//! constructor result leaves the cache NULL so a later call retries.
//!
//! # Deliberate deviations
//!
//! The firmware cache word lives in a runtime-initialized RAM page. This port
//! uses [`HANDLER_CONTEXT_INSTANCE`] instead; its device constructor default
//! still calls stock `FUN_081e8ee8` until that constructor is ported. Host
//! defaults panic, so tests explicitly install a constructor.

#[cfg(test)]
extern crate std;
use crate::heap::veneers::operator_new;

/// The allocation extent passed to `operator_new` (`mov r0, #0x34`).
pub const HANDLER_CONTEXT_SIZE: usize = 0x34;

/// Constructor ABI for `FUN_081e8ee8`: receives the raw allocation and
/// returns the handler-context pointer cached by the getter.
pub type HandlerContextConstructor = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// Unported dependencies of [`handler_context_get`].
#[derive(Clone, Copy)]
pub struct HandlerContextOps {
    /// `FUN_081e8ee8` @ 0x081e8ee8 — constructs a handler context in the
    /// supplied `operator_new(0x34)` storage.
    pub construct: HandlerContextConstructor,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_handler_context_construct(storage: *mut u8) -> *mut u8 {
    let construct: HandlerContextConstructor = unsafe { core::mem::transmute(0x081e_8ee8usize) };
    unsafe { construct(storage) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_handler_context_construct(_storage: *mut u8) -> *mut u8 {
    panic!("handler_context_get requires constructor 0x081e8ee8")
}

/// Device-wired constructor dependency. The constructor remains stock until
/// its own port replaces this seam.
#[cfg(target_os = "none")]
pub const DEFAULT_HANDLER_CONTEXT_OPS: HandlerContextOps = HandlerContextOps {
    construct: firmware_handler_context_construct,
};

/// Host default: construction must be made explicit by a test.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_HANDLER_CONTEXT_OPS: HandlerContextOps = HandlerContextOps {
    construct: missing_handler_context_construct,
};

/// Active constructor dependency. Read volatile on the cold path so a device
/// integrator can replace it without recompiling callers.
pub static mut HANDLER_CONTEXT_OPS: HandlerContextOps = DEFAULT_HANDLER_CONTEXT_OPS;

/// Replacement for the firmware cache word @ 0x089cfe38.
pub static mut HANDLER_CONTEXT_INSTANCE: *mut u8 = core::ptr::null_mut();

/// Returns the lazily constructed handler-context singleton.
///
/// # Safety
///
/// The active constructor must accept the `operator_new(0x34)` result,
/// including NULL, and return a pointer suitable for all handler-context
/// consumers. This is the original's unguarded constructor contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn handler_context_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(HANDLER_CONTEXT_INSTANCE);
    if core::ptr::read_volatile(cache).is_null() {
        let storage = operator_new(HANDLER_CONTEXT_SIZE);
        let construct = core::ptr::read_volatile(core::ptr::addr_of!(HANDLER_CONTEXT_OPS.construct));
        let context = construct(storage);
        core::ptr::write_volatile(cache, context);
    }
    core::ptr::read_volatile(cache)
}

#[cfg(test)]
pub static HANDLER_CONTEXT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use std::sync::MutexGuard;

    static mut CONSTRUCT_CALLS: usize = 0;
    static mut CONSTRUCT_STORAGE: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_construct(storage: *mut u8) -> *mut u8 {
        CONSTRUCT_CALLS += 1;
        CONSTRUCT_STORAGE = storage;
        CONSTRUCT_RESULT
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let context = HANDLER_CONTEXT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap = mock_heap();
        unsafe {
            HANDLER_CONTEXT_OPS = HandlerContextOps { construct: recording_construct };
            HANDLER_CONTEXT_INSTANCE = core::ptr::null_mut();
            CONSTRUCT_CALLS = 0;
            CONSTRUCT_STORAGE = core::ptr::null_mut();
            CONSTRUCT_RESULT = core::ptr::null_mut();
        }
        (context, heap)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            HANDLER_CONTEXT_OPS = DEFAULT_HANDLER_CONTEXT_OPS;
            HANDLER_CONTEXT_INSTANCE = core::ptr::null_mut();
        }
        drop(guards);
    }

    #[test]
    fn allocates_constructs_and_caches_the_constructor_result() {
        let guards = install();
        let mut storage = [0u8; HANDLER_CONTEXT_SIZE];
        let context = 0x2bad_0000usize as *mut u8;

        unsafe {
            set_alloc_ret(storage.as_mut_ptr());
            CONSTRUCT_RESULT = context;

            assert_eq!(handler_context_get(), context);
            assert_eq!(handler_context_get(), context, "a populated cache bypasses allocation and construction");
            assert_eq!(alloc_log(), (1, HANDLER_CONTEXT_SIZE, 2), "one tag-2 operator_new(0x34)");
            assert_eq!(CONSTRUCT_CALLS, 1);
            assert_eq!(CONSTRUCT_STORAGE, storage.as_mut_ptr());
            assert_eq!(HANDLER_CONTEXT_INSTANCE, context, "the constructor result, not raw storage, is cached");
        }

        restore(guards);
    }

    #[test]
    fn null_allocation_still_calls_constructor_and_retries_when_it_returns_null() {
        let guards = install();

        unsafe {
            set_alloc_ret(core::ptr::null_mut());

            assert!(handler_context_get().is_null());
            assert!(handler_context_get().is_null());
            assert_eq!(alloc_log(), (2, HANDLER_CONTEXT_SIZE, 2), "a NULL cache retries allocation on every call");
            assert_eq!(CONSTRUCT_CALLS, 2, "the raw ARM has no allocation NULL guard");
            assert!(CONSTRUCT_STORAGE.is_null());
        }

        restore(guards);
    }
}
