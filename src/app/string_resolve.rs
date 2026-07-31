//! `app_string_resolve` — original: `FUN_0811ca48` @ 0x0811ca48 (16 bytes).
//!
//! This is an ABI-adaptation wrapper around the unported resolver at
//! `FUN_0811ca58`: it preserves its three incoming arguments, supplies a
//! one-word stack output slot as the fourth argument, and returns the callee's
//! `r0` unchanged. The resolved value is consumed as a C string by the known
//! callers, but the resolver's object formats remain unported.
//!
//! The original reserves the output word with `stmdb sp!, {r3, lr}` without
//! initializing it, then passes `sp` in `r3`. Rust represents that slot with
//! `MaybeUninit`; it is never read by this wrapper. The unported operation is
//! an explicit replaceable seam rather than a claim to port `FUN_0811ca58`.
//! Sources: `ipod-decomp/decomp/c/010/0811ca48_FUN_0811ca48.c`,
//! `ipod-decomp/decomp/c/010/0811ca58_FUN_0811ca58.c`, callers at
//! `0x0829a124` / `0x0829a4dc`, and the instruction sequence at `0x0811ca48`
//! in `ipod-decomp/decomp/osos.asm`.

use core::mem::MaybeUninit;

/// ABI of the unported resolver at `FUN_0811ca58`.
///
/// The three input pointers occupy `r0` through `r2`; `output_slot` is the
/// wrapper-created word passed in `r3`. Its result remains in `r0`.
pub type AppStringResolveOperation = unsafe extern "C" fn(
    resolver: *mut u8,
    context: *mut u8,
    value: *mut u8,
    output_slot: *mut *mut u8,
) -> *mut u8;

/// Replaceable dependency used by [`app_string_resolve`].
#[derive(Clone, Copy)]
pub struct AppStringResolveOps {
    pub resolve: AppStringResolveOperation,
}

// The wrapped resolver owns the object-format dispatch and has not yet been
// ported. Target integration must install it before this wrapper is hooked.
unsafe extern "C" fn missing_app_string_resolve(
    _resolver: *mut u8,
    _context: *mut u8,
    _value: *mut u8,
    _output_slot: *mut *mut u8,
) -> *mut u8 {
    panic!("app_string_resolve requires resolver 0x0811ca58")
}

/// Active resolver operation. Focused host tests install a recorder; a target
/// integration replaces this before routing retailOS through the wrapper.
pub static mut APP_STRING_RESOLVE_OPS: AppStringResolveOps = AppStringResolveOps {
    resolve: missing_app_string_resolve,
};

#[inline(always)]
unsafe fn app_string_resolve_ops() -> AppStringResolveOps {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_STRING_RESOLVE_OPS))
}

/// app_string_resolve — original: `FUN_0811ca48` @ 0x0811ca48 (16 bytes).
///
/// Forwards `resolver`, `context`, and `value` in that order to the unported
/// resolver, with an uninitialized local output word as its fourth argument.
/// The resolver's return value is propagated unchanged; this wrapper does not
/// inspect its output word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_string_resolve(
    resolver: *mut u8,
    context: *mut u8,
    value: *mut u8,
) -> *mut u8 {
    let mut output_slot = MaybeUninit::<*mut u8>::uninit();
    (app_string_resolve_ops().resolve)(resolver, context, value, output_slot.as_mut_ptr())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECORDED_RESOLVER: usize = 0;
    static mut RECORDED_CONTEXT: usize = 0;
    static mut RECORDED_VALUE: usize = 0;
    static mut RECORDED_OUTPUT_SLOT: usize = 0;
    static mut CALLEE_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_resolve(
        resolver: *mut u8,
        context: *mut u8,
        value: *mut u8,
        output_slot: *mut *mut u8,
    ) -> *mut u8 {
        CALLS += 1;
        RECORDED_RESOLVER = resolver as usize;
        RECORDED_CONTEXT = context as usize;
        RECORDED_VALUE = value as usize;
        RECORDED_OUTPUT_SLOT = output_slot as usize;
        output_slot.write(0x1234_5678usize as *mut u8);
        CALLEE_RESULT
    }

    struct RestoreOps;

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe {
                APP_STRING_RESOLVE_OPS = AppStringResolveOps {
                    resolve: missing_app_string_resolve,
                };
            }
        }
    }

    fn mock_resolve() -> (MutexGuard<'static, ()>, RestoreOps) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = 0;
            RECORDED_RESOLVER = 0;
            RECORDED_CONTEXT = 0;
            RECORDED_VALUE = 0;
            RECORDED_OUTPUT_SLOT = 0;
            CALLEE_RESULT = core::ptr::null_mut();
            APP_STRING_RESOLVE_OPS = AppStringResolveOps {
                resolve: recording_resolve,
            };
        }
        (lock, RestoreOps)
    }

    #[test]
    fn forwards_once_with_a_distinct_stack_output_slot_and_preserves_the_return() {
        let (_lock, _restore) = mock_resolve();
        let resolver = 0x0102_0304usize as *mut u8;
        let context = 0x1112_1314usize as *mut u8;
        let value = 0x2122_2324usize as *mut u8;
        let expected_result = 0x3132_3334usize as *mut u8;

        unsafe {
            CALLEE_RESULT = expected_result;
            assert_eq!(app_string_resolve(resolver, context, value), expected_result);
            assert_eq!(CALLS, 1);
            assert_eq!(RECORDED_RESOLVER, resolver as usize);
            assert_eq!(RECORDED_CONTEXT, context as usize);
            assert_eq!(RECORDED_VALUE, value as usize);
            assert_ne!(RECORDED_OUTPUT_SLOT, 0);
            assert_ne!(RECORDED_OUTPUT_SLOT, resolver as usize);
            assert_ne!(RECORDED_OUTPUT_SLOT, context as usize);
            assert_ne!(RECORDED_OUTPUT_SLOT, value as usize);
        }
    }
}
