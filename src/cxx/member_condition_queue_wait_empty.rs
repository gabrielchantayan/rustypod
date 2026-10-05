//! Waits for an object's embedded condition queue to empty.
//!
//! `FUN_0819bef8` @ 0x0819bef8, 40 bytes (0x0819bef8..0x0819bf20).
//! Raw A32 decoding verifies two inbound plain BL calls (0x081b5778,
//! 0x081b6038), two outbound plain BL calls, and zero predicated BL calls
//! in either direction. The next function starts with push {r4,lr}.
//!
//! Algorithm: check the queue at object+0x28 before sleeping; while its
//! locked empty predicate returns zero, sleep 100 ticks and check again.
//! Any nonzero predicate result terminates the wait; there is no timeout.
//!
//! Deliberate deviation: target calls the existing Rust predicate and sleep
//! thunk directly rather than the stock addresses. Host-only operations are
//! injectable to model a queue changing while this thread sleeps.

#[cfg(not(target_os = "none"))]
pub struct MemberConditionQueueWaitEmptyOps {
    pub is_empty: unsafe extern "C" fn(*mut u8) -> u32,
    pub sleep: unsafe extern "C" fn(u32) -> usize,
}

#[cfg(not(target_os = "none"))]
pub static mut MEMBER_CONDITION_QUEUE_WAIT_EMPTY_OPS: MemberConditionQueueWaitEmptyOps = MemberConditionQueueWaitEmptyOps {
    is_empty: crate::cxx::condition_queue_is_empty::condition_queue_is_empty,
    sleep: crate::kernel::task::task_sleep_thunk,
};

#[inline(always)]
unsafe fn is_empty(queue: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    unsafe { crate::cxx::condition_queue_is_empty::condition_queue_is_empty(queue) }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MEMBER_CONDITION_QUEUE_WAIT_EMPTY_OPS.is_empty))(queue) }
}

#[inline(always)]
unsafe fn sleep() {
    #[cfg(target_os = "none")]
    unsafe { crate::kernel::task::task_sleep_thunk(100) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MEMBER_CONDITION_QUEUE_WAIT_EMPTY_OPS.sleep))(100) };
}

/// # Safety
/// `object` must contain a valid condition queue at target byte offset +0x28
/// and remain alive for the entire wait. The queue predicate synchronizes
/// access; this function does not own or modify the object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn member_condition_queue_wait_empty(object: *mut u8) {
    let queue = unsafe { object.add(10 * core::mem::size_of::<u32>()) };
    while unsafe { is_empty(queue) } == 0 {
        unsafe { sleep() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut QUEUE: *mut u8 = core::ptr::null_mut();
    static mut REMAINING: u32 = 0;
    static mut CHECKS: u32 = 0;
    static mut SLEEPS: u32 = 0;
    static mut EMPTY_RESULT: u32 = 1;

    unsafe extern "C" fn check(queue: *mut u8) -> u32 {
        unsafe {
            let expected = QUEUE;
            assert_eq!(queue, expected);
            CHECKS += 1;
            if REMAINING == 0 { EMPTY_RESULT } else { 0 }
        }
    }

    unsafe extern "C" fn advance(ticks: u32) -> usize {
        unsafe {
            assert_eq!(ticks, 100);
            assert!(REMAINING > 0, "must not sleep after observing empty");
            REMAINING -= 1;
            SLEEPS += 1;
        }
        usize::MAX // Sleep's return value must not affect the loop.
    }

    #[test]
    fn empty_and_delayed_transitions() {
        let _guard = LOCK.lock();
        let mut object = [0u32; 32];
        unsafe {
            let saved = core::ptr::read(core::ptr::addr_of!(MEMBER_CONDITION_QUEUE_WAIT_EMPTY_OPS));
            MEMBER_CONDITION_QUEUE_WAIT_EMPTY_OPS = MemberConditionQueueWaitEmptyOps {
                is_empty: check, sleep: advance,
            };
            QUEUE = object.as_mut_ptr().cast::<u8>().add(0x28);
            for remaining in [0, 1, 7] {
                for result in [1, 2, u32::MAX] {
                    REMAINING = remaining;
                    EMPTY_RESULT = result;
                    CHECKS = 0;
                    SLEEPS = 0;
                    member_condition_queue_wait_empty(object.as_mut_ptr().cast());
                    let sleeps = SLEEPS;
                    let checks = CHECKS;
                    assert_eq!(sleeps, remaining);
                    assert_eq!(checks, remaining + 1);
                    assert_eq!(object, [0u32; 32]);
                }
            }
            MEMBER_CONDITION_QUEUE_WAIT_EMPTY_OPS = saved;
        }
    }
}
