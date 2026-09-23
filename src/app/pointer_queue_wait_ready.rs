//! `pointer_queue_wait_ready` — original: `FUN_081ded44` @ **0x081ded44**
//! (**48 bytes**, 0x081ded44..0x081ded74; the next distinct function starts
//! with `push {r1-r5, lr}` at 0x081ded74). **3 plain `bl` call sites**
//! (0x08179d98, 0x0817af5c, and 0x0817c91c), **0 predicated `bl` call sites**,
//! and two unconditional tail branches (0x0817a7fc and 0x0817a908), verified
//! by decoding every ARM B/BL immediate in osos.dec.
//!
//! Polls the unported 0x0839e640 queue-status helper and the byte at
//! `context + 0x26`. It sleeps for 100 ticks after every unsuccessful poll,
//! including the initial attempt, and returns only when both conditions are
//! nonzero. Deliberate deviation: the target calls the stock queue-status
//! helper directly; host tests install an equivalent call seam because that
//! helper is not yet ported.

use core::ptr;

use crate::kernel::task::task_sleep_thunk;

const READY_FLAG_OFFSET: usize = 0x26;
const RETAIL_POINTER_QUEUE_POLL_STATUS: usize = 0x0839_e640;
type QueuePollStatus = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_queue_poll_status(_context: *mut u8) -> u32 {
    panic!("pointer_queue_wait_ready queue-status seam was not installed")
}

#[cfg(not(target_os = "none"))]
static mut QUEUE_POLL_STATUS: QueuePollStatus = missing_queue_poll_status;

#[inline(always)]
unsafe fn queue_poll_status(context: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let poll: QueuePollStatus = core::mem::transmute(RETAIL_POINTER_QUEUE_POLL_STATUS);
        poll(context)
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(QUEUE_POLL_STATUS))(context)
    }
}

/// Waits until the queue-status helper and the context's ready flag both pass.
///
/// Original: `FUN_081ded44` @ 0x081ded44 (48 bytes; 3 plain direct `bl`
/// callers and no predicated direct `bl` callers, binary-verified above).
///
/// # Safety
///
/// `context` must remain valid through offset 0x26 and satisfy the stock
/// queue-status helper's requirements for the duration of this polling loop.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pointer_queue_wait_ready(context: *mut u8) {
    loop {
        if queue_poll_status(context) != 0 && ptr::read_volatile(context.add(READY_FLAG_OFFSET)) != 0 {
            return;
        }
        task_sleep_thunk(100);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut POLL_RESULTS: [u32; 4] = [0; 4];
    static mut POLL_COUNT: usize = 0;
    static mut SLEEP_TICKS: [u32; 4] = [0; 4];
    static mut SLEEP_COUNT: usize = 0;
    static mut CONTEXT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn poll_status(_context: *mut u8) -> u32 {
        let result = POLL_RESULTS[POLL_COUNT];
        POLL_COUNT += 1;
        result
    }

    unsafe extern "C" fn sleep_after_first_poll(_task: usize, ticks: usize) -> usize {
        SLEEP_TICKS[SLEEP_COUNT] = ticks as u32;
        SLEEP_COUNT += 1;
        if SLEEP_COUNT == 1 {
            *CONTEXT.add(READY_FLAG_OFFSET) = 1;
        }
        0
    }

    unsafe fn install(polls: [u32; 4], context: *mut u8) {
        POLL_RESULTS = polls;
        POLL_COUNT = 0;
        SLEEP_TICKS = [0; 4];
        SLEEP_COUNT = 0;
        CONTEXT = context;
        QUEUE_POLL_STATUS = poll_status;
        let mut hooks = crate::kernel::task::DEFAULT_TASK_HOOKS;
        hooks.rom_timed_delay = sleep_after_first_poll;
        crate::kernel::task::TASK_HOOKS = hooks;
    }

    unsafe fn restore() {
        crate::kernel::task::TASK_HOOKS = crate::kernel::task::DEFAULT_TASK_HOOKS;
    }

    #[test]
    fn sleeps_after_an_initial_zero_status_then_accepts_ready_flag() {
        let _guard = TEST_LOCK.lock();
        let _task_guard = crate::testing::TASK_HOOKS_TEST_LOCK.lock();
        let mut context = [0u8; READY_FLAG_OFFSET + 1];
        unsafe {
            install([0, 1, 0, 0], context.as_mut_ptr());
            pointer_queue_wait_ready(context.as_mut_ptr());
            assert_eq!(POLL_COUNT, 2);
            assert_eq!(SLEEP_COUNT, 1);
            assert_eq!(SLEEP_TICKS[0], 100);
            restore();
        }
    }

    #[test]
    fn nonzero_status_still_sleeps_until_the_ready_flag_is_set() {
        let _guard = TEST_LOCK.lock();
        let _task_guard = crate::testing::TASK_HOOKS_TEST_LOCK.lock();
        let mut context = [0u8; READY_FLAG_OFFSET + 1];
        unsafe {
            install([1, 1, 0, 0], context.as_mut_ptr());
            pointer_queue_wait_ready(context.as_mut_ptr());
            assert_eq!(POLL_COUNT, 2);
            assert_eq!(SLEEP_COUNT, 1);
            assert_eq!(SLEEP_TICKS[0], 100);
            restore();
        }
    }
}
