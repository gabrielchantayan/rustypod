//! Default-context retail operation wrapper.
//!
//! Port: [`default_context_operation`] — original: `FUN_08093d64` @
//! **0x08093d64** (8 bytes exactly, `0x08093d64..0x08093d6b`); the literal
//! pool word at `0x08093d6c` is not code, and `0x08093d70` starts a sibling.
//! Raw decoding is `ldr r1, [pc, #0]` / `b 0x080bd7f8`: no body `bl`
//! instructions, predicated or otherwise. There are exactly three direct,
//! unconditional `bl` callers (0x0805ca54, 0x080aafe0, and 0x08113808) and no
//! predicated caller.
//!
//! # Algorithm
//!
//! Preserve r0, load r1 with the literal-pool word `0x083e8bc8`, then tail
//! branch to the unported retail helper at `0x080bd7f8`, returning its r0.
//!
//! # Deliberate deviations
//!
//! The target preserves the retail helper's verified address; host builds use
//! a volatile replaceable seam. The helper's semantic identity is not
//! established; this port claims only the verified two-word ABI.

pub type DefaultContextOperation = unsafe extern "C" fn(*mut u8, *const u8) -> i32;

const RETAIL_DEFAULT_CONTEXT_OPERATION: usize = 0x080b_d7f8;
const DEFAULT_CONTEXT_WORD: usize = 0x083e_8bc8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_default_context_operation(
    argument: *mut u8,
    context: *const u8,
) -> i32 {
    unsafe {
        core::mem::transmute::<usize, DefaultContextOperation>(RETAIL_DEFAULT_CONTEXT_OPERATION)(argument, context)
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_default_context_operation(_: *mut u8, _: *const u8) -> i32 {
    panic!("default_context_operation requires retail helper 0x080bd7f8")
}

#[cfg(not(target_os = "none"))]
pub static mut DEFAULT_CONTEXT_OPERATION: DefaultContextOperation = missing_default_context_operation;

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn default_context_operation_helper() -> DefaultContextOperation {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DEFAULT_CONTEXT_OPERATION)) }
}

/// Forwards `argument` and the fixed retail context word to the helper.
///
/// # Safety
///
/// `argument` must satisfy the unported helper's unchecked ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn default_context_operation(argument: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    unsafe {
        retail_default_context_operation(argument, DEFAULT_CONTEXT_WORD as *const u8)
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        default_context_operation_helper()(argument, DEFAULT_CONTEXT_WORD as *const u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static ARGUMENT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static CONTEXT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_default_context_operation(argument: *mut u8, context: *const u8) -> i32 {
        ARGUMENT.store(argument as usize, Ordering::SeqCst);
        CONTEXT.store(context as usize, Ordering::SeqCst);
        if argument.is_null() { 0 } else { -50 }
    }

    #[test]
    fn forwards_null_and_nonnull_arguments_with_the_fixed_context_word() {
        let _lock = TEST_LOCK.lock();
        unsafe { DEFAULT_CONTEXT_OPERATION = record_default_context_operation; }

        let mut argument = 0u8;
        assert_eq!(unsafe { default_context_operation(core::ptr::null_mut()) }, 0);
        assert_eq!(ARGUMENT.load(Ordering::SeqCst), 0);
        assert_eq!(CONTEXT.load(Ordering::SeqCst), DEFAULT_CONTEXT_WORD);

        assert_eq!(unsafe { default_context_operation(&mut argument) }, -50);
        assert_eq!(ARGUMENT.load(Ordering::SeqCst), core::ptr::addr_of_mut!(argument) as usize);
        assert_eq!(CONTEXT.load(Ordering::SeqCst), DEFAULT_CONTEXT_WORD);
    }
}
