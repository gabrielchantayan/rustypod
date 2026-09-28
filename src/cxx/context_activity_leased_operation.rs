//! `context_activity_leased_operation` — original: `FUN_0837ec88` @
//! `0x0837ec88` (32 bytes; two direct plain-`bl` calls, no predicated
//! `bl` calls).
//!
//! Raw ARM body, decoded from `osos.dec`:
//!
//! ```text
//! push {r4, lr}
//! mov  r4, r0
//! bl   0x082dd3d8           @ context_activity_enter(context)
//! mov  r0, r4
//! bl   0x082dd71c           @ still-unported context operation
//! ldr  r1, [r4, #0xe0]
//! sub  r1, r1, #1
//! str  r1, [r4, #0xe0]
//! pop  {r4, pc}
//! ```
//!
//! The next separately linked function starts at `0x0837eca8` with `push
//! {r4, r5, r6, lr}`; Ghidra's 36-byte extent includes that prologue. The
//! operation acquires the context activity lease, invokes the still-unported
//! `FUN_082dd71c`, unconditionally releases the lease, and returns the
//! operation's status. Deliberate deviation: only the activity-enter half is
//! ported; target builds call the unidentified operation at its retailOS load
//! address, while host builds use a recording boundary for tests.

const CONTEXT_ACTIVITY: usize = 0xe0;

type ContextOperation = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn run_context_operation(context: *mut u8) -> u32 {
    let operation: ContextOperation = core::mem::transmute(0x082d_d71cusize);
    operation(context)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct OperationHostOps {
    operation: ContextOperation,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_context_operation(_context: *mut u8) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
const DEFAULT_OPERATION_HOST_OPS: OperationHostOps = OperationHostOps {
    operation: unavailable_context_operation,
};

#[cfg(not(target_os = "none"))]
static mut OPERATION_HOST_OPS: OperationHostOps = DEFAULT_OPERATION_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn run_context_operation(context: *mut u8) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(OPERATION_HOST_OPS));
    (ops.operation)(context)
}

/// Acquires `context`'s activity lease, runs retailOS operation `0x082dd71c`,
/// releases the lease, and returns its status. No NULL guard exists in ARM.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_activity_leased_operation")]
#[inline(never)]
pub unsafe extern "C" fn context_activity_leased_operation(context: *mut u8) -> u32 {
    crate::cxx::context_activity::context_activity_enter(context);
    let status = run_context_operation(context);
    let activity = context.add(CONTEXT_ACTIVITY) as *mut u32;
    activity.write_volatile(activity.read_volatile().wrapping_sub(1));
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut LAST_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn recording_operation(context: *mut u8) -> u32 {
        LAST_CONTEXT = context;
        STATUS
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench(status: u32) -> Bench {
        let lock = lock_ops();
        unsafe {
            LAST_CONTEXT = core::ptr::null_mut();
            STATUS = status;
            core::ptr::addr_of_mut!(OPERATION_HOST_OPS).write_volatile(OperationHostOps {
                operation: recording_operation,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(OPERATION_HOST_OPS)
                    .write_volatile(DEFAULT_OPERATION_HOST_OPS);
            }
        }
    }

    #[repr(align(8))]
    struct ContextFixture {
        bytes: [u8; 0x100],
    }

    impl ContextFixture {
        fn new(marked: u32, activity: u32) -> Self {
            let mut fixture = Self { bytes: [0xa5; 0x100] };
            unsafe {
                (fixture.bytes.as_mut_ptr().add(0xdc) as *mut u32).write(marked);
                (fixture.bytes.as_mut_ptr().add(CONTEXT_ACTIVITY) as *mut u32).write(activity);
            }
            fixture
        }

        fn activity(&self) -> u32 {
            unsafe { (self.bytes.as_ptr().add(CONTEXT_ACTIVITY) as *const u32).read() }
        }

        fn assert_untouched_except_activity(&self, before: &Self) {
            for offset in (0..self.bytes.len()).step_by(4) {
                if offset == CONTEXT_ACTIVITY {
                    continue;
                }
                unsafe {
                    assert_eq!(
                        (self.bytes.as_ptr().add(offset) as *const u32).read(),
                        (before.bytes.as_ptr().add(offset) as *const u32).read(),
                        "word at +{offset:#x} changed"
                    );
                }
            }
        }
    }

    #[test]
    fn forwards_context_returns_status_and_balances_lease() {
        let _bench = bench(0xfeed_beef);
        let mut context = ContextFixture::new(0, 7);
        let before = ContextFixture { bytes: context.bytes };

        assert_eq!(unsafe { context_activity_leased_operation(context.bytes.as_mut_ptr()) }, 0xfeed_beef);
        assert_eq!(unsafe { LAST_CONTEXT }, context.bytes.as_mut_ptr());
        assert_eq!(context.activity(), 7);
        context.assert_untouched_except_activity(&before);
    }

    #[test]
    fn marked_context_and_wrapping_count_are_released() {
        let _bench = bench(3);
        let mut context = ContextFixture::new(1, u32::MAX);
        let before = ContextFixture { bytes: context.bytes };

        assert_eq!(unsafe { context_activity_leased_operation(context.bytes.as_mut_ptr()) }, 3);
        assert_eq!(context.activity(), u32::MAX);
        context.assert_untouched_except_activity(&before);
    }
}
