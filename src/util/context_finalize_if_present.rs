//! `context_finalize_if_present` — original: `FUN_080b3ec0` @ `0x080b3ec0`
//! (20 bytes; four verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM words establish the exact extent `0x080b3ec0..0x080b3ed4`:
//! `push {r4,lr}; cmp r0,#0; blne 0x080489fc; mov r0,#0; pop {r4,pc}`.
//! The next separately entered function begins at `0x080b3ed4` with
//! `push {r4-r11,lr}`. The body has zero plain outbound `bl` instructions
//! and one predicated outbound `blne`; a whole-image A32 decode finds four
//! inbound plain `bl` sites (`0x0806175c`, `0x080635b0`, `0x080636a0`, and
//! `0x08065ce4`) and no predicated inbound calls.
//!
//! It invokes the unrecovered retailOS routine at `0x080489fc` only when the
//! context pointer is non-null, then returns zero regardless of that call's
//! return value. Deliberate deviation: the unresolved callee remains a raw
//! address seam on target and a replaceable recording seam in host tests;
//! its semantic identity is not claimed here.

use core::ptr;

type RetailContextFinalizer = unsafe extern "C" fn(*mut u8);

unsafe extern "C" fn firmware_context_finalizer(context: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let finalizer: RetailContextFinalizer = core::mem::transmute(0x0804_89fcusize);
        finalizer(context);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = context;
    }
}

static mut CONTEXT_FINALIZER: RetailContextFinalizer = firmware_context_finalizer;

#[inline(always)]
unsafe fn context_finalizer() -> RetailContextFinalizer {
    ptr::read_volatile(ptr::addr_of!(CONTEXT_FINALIZER))
}

/// Finalizes a present context through retailOS and always returns zero.
///
/// # Safety
///
/// When `context` is non-null it must satisfy the unrecovered retailOS
/// routine at `0x080489fc`; this function preserves that routine's unchecked
/// pointer contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_finalize_if_present(context: *mut u8) -> u32 {
    if !context.is_null() {
        context_finalizer()(context);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{context_finalize_if_present, firmware_context_finalizer, CONTEXT_FINALIZER};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static FINALIZER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: usize = 0;
    static mut CONTEXT: usize = 0;

    unsafe extern "C" fn record_finalizer(context: *mut u8) {
        unsafe {
            CALL_COUNT += 1;
            CONTEXT = context as usize;
        }
    }

    struct Fixture {
        _lock: MutexGuard<'static, ()>,
    }

    fn fixture() -> Fixture {
        let lock = FINALIZER_LOCK.lock();
        unsafe {
            CALL_COUNT = 0;
            CONTEXT = 0;
            ptr::addr_of_mut!(CONTEXT_FINALIZER).write(record_finalizer);
        }
        Fixture { _lock: lock }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(CONTEXT_FINALIZER).write(firmware_context_finalizer) };
        }
    }

    #[test]
    fn null_context_skips_the_predicated_call_and_returns_zero() {
        let _fixture = fixture();

        assert_eq!(unsafe { context_finalize_if_present(ptr::null_mut()) }, 0);
        assert_eq!(unsafe { CALL_COUNT }, 0);
    }

    #[test]
    fn present_context_is_finalized_once_and_result_is_discarded() {
        let _fixture = fixture();
        let mut context = [0u8; 1];

        assert_eq!(unsafe { context_finalize_if_present(context.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { CALL_COUNT }, 1);
        assert_eq!(unsafe { CONTEXT }, context.as_mut_ptr() as usize);
    }
}
