//! Tail-call veneer for the queue completion routine.
//!
//! `tail_call_retail_queue_complete` — original: `thunk_FUN_0822b5e0` @
//! **0x08220534** (4 bytes, `0x08220534..0x08220538`; the next separately
//! linked function begins at `0x08220538`). Raw osos.dec contains the single
//! A32 word `0xea002c29`, an unconditional branch to `0x0822b5e0`. Direct
//! A32 decoding finds **three** inbound calls, all plain unconditional `bl`
//! instructions at `0x08142b90`, `0x0817a98c`, and `0x0817a9c8`; there are no
//! predicated direct `bl` calls.
//!
//! Algorithm: tail-transfer the observed r0 state-pointer ABI and return r0
//! from queue completion. Deliberate deviation: the relocated ARM payload uses
//! an absolute literal veneer rather than the original PC-relative branch; its
//! assembly preserves r0-r3, while the host seam verifies r0 forwarding and
//! return propagation.

/// Host/target seam for the retail queue completion target at `0x0822b5e0`.
pub type RetailQueueComplete = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_queue_complete(_state: *mut u8) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_QUEUE_COMPLETE: RetailQueueComplete = missing_retail_queue_complete;

/// Tail-calls the retail queue completion routine at `0x0822b5e0`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_call_retail_queue_complete(state: *mut u8) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_QUEUE_COMPLETE))(state) }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0-r3, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_call_retail_queue_complete
    .type tail_call_retail_queue_complete, %function
tail_call_retail_queue_complete:
    ldr     pc, 1f
1:  .word   0x0822b5e0
    .size tail_call_retail_queue_complete, . - tail_call_retail_queue_complete
"#
);

#[cfg(test)]
mod tests {
    use super::{RETAIL_QUEUE_COMPLETE, RetailQueueComplete, tail_call_retail_queue_complete};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut STATE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_target(state: *mut u8) -> u32 {
        unsafe {
            CALLS += 1;
            STATE = state;
        }
        0xa55a_0001
    }

    struct TargetRestore(RetailQueueComplete);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_QUEUE_COMPLETE = self.0 };
        }
    }

    #[test]
    fn forwards_state_pointer_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = [0u8; 4];
        let _restore = unsafe {
            let previous = RETAIL_QUEUE_COMPLETE;
            RETAIL_QUEUE_COMPLETE = recording_target;
            CALLS = 0;
            STATE = core::ptr::null_mut();
            TargetRestore(previous)
        };

        let result = unsafe { tail_call_retail_queue_complete(state.as_mut_ptr()) };

        assert_eq!(result, 0xa55a_0001);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { STATE }, state.as_mut_ptr());
    }
}
