//! Current-task callback queue lookup.
//!
//! The callback predicate at `0x08140208` remains retail code. This port
//! reaches the untouched helper at `0x080a6c0c`, rather than assigning either
//! a stronger identity than the raw call sequence establishes.

use crate::kernel::task::{current_task_ctx_block, TaskCtx};

/// Callback predicate literal loaded from `0x0814b45c` by the instruction at `0x0814b44c`.
const CALLBACK_PREDICATE: usize = 0x0814_0208;
/// Generic locked-queue callback scan at `0x080a6c0c`.
const LOCKED_QUEUE_CALLBACK_FIND: usize = 0x080a_6c0c;

type CallbackQueueFind = unsafe extern "C" fn(*mut u8, usize, *mut u8) -> u32;

/// task_queue_callback_find — original: `FUN_0814b430` @ **0x0814b430**
/// (44 bytes; 3 direct plain `bl` call sites, no predicated `bl` calls).
///
/// Raw ARM spans `0x0814b430..0x0814b45c`: it calls
/// [`current_task_ctx_block`], loads its `queue_pool` at +0x1c, returns zero
/// when that pointer is NULL, and otherwise tail-branches to the generic
/// locked-queue callback scan with the fixed predicate at `0x08140208` and
/// the original argument. The next independent function begins at
/// `0x0814b460`; `0x0814b45c` is the callback literal, not code.
///
/// Deliberate deviation: Rust cannot express the ARM conditional tail branch,
/// so this performs an indirect call to the still-retail helper at
/// `0x080a6c0c`. Its address and argument order come directly from the raw
/// `ldrne r1,[pc,#8]; bne` sequence; no identity is invented for either
/// unported target.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_queue_callback_find(argument: *mut u8) -> u32 {
    task_queue_callback_find_with(
        current_task_ctx_block,
        core::mem::transmute::<usize, CallbackQueueFind>(LOCKED_QUEUE_CALLBACK_FIND),
        argument,
    )
}

unsafe fn task_queue_callback_find_with(
    current_task_context: unsafe extern "C" fn() -> *mut TaskCtx,
    callback_find: CallbackQueueFind,
    argument: *mut u8,
) -> u32 {
    let queue_pool = (*current_task_context()).queue_pool;
    if queue_pool.is_null() {
        0
    } else {
        callback_find(queue_pool, CALLBACK_PREDICATE, argument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONTEXT: TaskCtx = TaskCtx::ZERO;
    static mut CALLS: u32 = 0;
    static mut OBSERVED_QUEUE: *mut u8 = ptr::null_mut();
    static mut OBSERVED_PREDICATE: usize = 0;
    static mut OBSERVED_ARGUMENT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn current_context() -> *mut TaskCtx {
        ptr::addr_of_mut!(CONTEXT)
    }

    unsafe extern "C" fn record_callback_find(queue: *mut u8, predicate: usize, argument: *mut u8) -> u32 {
        CALLS += 1;
        OBSERVED_QUEUE = queue;
        OBSERVED_PREDICATE = predicate;
        OBSERVED_ARGUMENT = argument;
        1
    }
    #[test]
    fn null_current_queue_returns_zero_without_scanning() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CONTEXT = TaskCtx::ZERO;
            CALLS = 0;
            assert_eq!(task_queue_callback_find_with(current_context, record_callback_find, 0x1234usize as *mut u8), 0);
            assert_eq!(CALLS, 0);
        }
    }

    #[test]
    fn queue_scan_receives_raw_predicate_and_original_argument() {
        let _guard = TEST_LOCK.lock();
        let mut queue = [0u8; 0x48];
        let argument = 0x5678usize as *mut u8;
        unsafe {
            CONTEXT = TaskCtx::ZERO;
            CONTEXT.queue_pool = queue.as_mut_ptr();
            CALLS = 0;
            OBSERVED_QUEUE = ptr::null_mut();
            OBSERVED_PREDICATE = 0;
            OBSERVED_ARGUMENT = ptr::null_mut();

            assert_eq!(task_queue_callback_find_with(current_context, record_callback_find, argument), 1);
            assert_eq!(CALLS, 1);
            assert_eq!(OBSERVED_QUEUE, queue.as_mut_ptr());
            assert_eq!(OBSERVED_PREDICATE, CALLBACK_PREDICATE);
            assert_eq!(OBSERVED_ARGUMENT, argument);
        }
    }
}
