//! `context_submit_u32` — original: `FUN_08261d88` @ **0x08261d88**
//! (**20 bytes**, `0x08261d88..0x08261d9b`; the next separately entered
//! function is the tail-branch veneer at `0x08261d9c`).
//!
//! Full-image A32 decoding finds **3 incoming plain `bl` calls** and **0
//! predicated incoming `bl` calls**. The body makes one unconditional `bl`,
//! to the unported `FUN_082e7cb0` at `0x082e7cb0`.
//!
//! Algorithm: materialize the supplied 32-bit scalar in the caller's stack
//! frame and pass its address to the opaque context-value submitter together
//! with the context. The submitter's r0 result is preserved by the retail
//! epilogue even though all known callers discard it; this port exposes that
//! observable ABI result rather than Ghidra's `void` prototype. The callee
//! has no recovered identity, so target builds call its verified fixed address
//! and host builds use a replaceable seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_CONTEXT_VALUE_SUBMIT: usize = 0x082e_7cb0;

/// Observed ABI of the unported `FUN_082e7cb0` context-value submitter.
pub type ContextValueSubmit = unsafe extern "C" fn(*mut u8, *mut u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn submit_context_value(context: *mut u8, value_slot: *mut u32) -> u32 {
    let submit: ContextValueSubmit = core::mem::transmute(RETAIL_CONTEXT_VALUE_SUBMIT);
    submit(context, value_slot)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_value_submit(_context: *mut u8, _value_slot: *mut u32) -> u32 {
    0
}

/// Host seam for the unported context-value submitter at `0x082e7cb0`.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_VALUE_SUBMIT: ContextValueSubmit = missing_context_value_submit;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn submit_context_value(context: *mut u8, value_slot: *mut u32) -> u32 {
    let submit = core::ptr::read_volatile(addr_of!(CONTEXT_VALUE_SUBMIT));
    submit(context, value_slot)
}

/// Submits `value` to the opaque retailOS context-value handler.
///
/// # Safety
///
/// `context` and the retail submitter selected for the current build must meet
/// the unported `FUN_082e7cb0` contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_submit_u32(context: *mut u8, value: u32) -> u32 {
    let mut value_slot = value;
    submit_context_value(context, &mut value_slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::{Mutex, MutexGuard};

    static SUBMIT_LOCK: Mutex<()> = Mutex::new(());
    static mut OBSERVED_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut OBSERVED_VALUE: u32 = 0;

    unsafe extern "C" fn record_submit(context: *mut u8, value_slot: *mut u32) -> u32 {
        OBSERVED_CONTEXT = context;
        OBSERVED_VALUE = value_slot.read();
        0x1a
    }

    unsafe fn install_recording_submit() -> (MutexGuard<'static, ()>, ContextValueSubmit) {
        let lock = SUBMIT_LOCK.lock();
        let previous = core::ptr::read_volatile(addr_of!(CONTEXT_VALUE_SUBMIT));
        core::ptr::write_volatile(addr_of_mut!(CONTEXT_VALUE_SUBMIT), record_submit);
        (lock, previous)
    }

    unsafe fn restore_submit(previous: ContextValueSubmit) {
        core::ptr::write_volatile(addr_of_mut!(CONTEXT_VALUE_SUBMIT), previous);
    }

    #[test]
    fn submits_zero_scalar_through_stack_slot() {
        unsafe {
            let (_lock, previous) = install_recording_submit();
            let context = 0x1234usize as *mut u8;
            assert_eq!(context_submit_u32(context, 0), 0x1a);
            assert_eq!(OBSERVED_CONTEXT, context);
            assert_eq!(OBSERVED_VALUE, 0);
            restore_submit(previous);
        }
    }

    #[test]
    fn submits_full_width_scalar_without_truncation() {
        unsafe {
            let (_lock, previous) = install_recording_submit();
            assert_eq!(context_submit_u32(core::ptr::null_mut(), u32::MAX), 0x1a);
            assert!(OBSERVED_CONTEXT.is_null());
            assert_eq!(OBSERVED_VALUE, u32::MAX);
            restore_submit(previous);
        }
    }
}
