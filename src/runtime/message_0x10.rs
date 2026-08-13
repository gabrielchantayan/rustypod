//! RTXC timer-allocation gateway — `FUN_08003b8c` @ `0x08003b8c` (36 bytes).
//!
//! The ARM entry reserves seven stack words, writes service selector `0x10` at
//! the second word, calls the `0x08003660` literal veneer (ROM dispatcher
//! `0x0802dca8`), then reloads the final word at `sp + 0x18`.  The RTXC
//! service catalogue and the adjacent timer-free gateway identify selector
//! `0x10` as `KS_alloc_timer`. The untouched words are intentionally
//! uninitialized in firmware; this wrapper only requires the selector and the
//! callback-owned final word. The shared dispatch seam is defined by the
//! already-ported selector-`0x17` wrapper and defaults to the direct ROM call;
//! host tests install a recording callback.

use core::mem::MaybeUninit;

use crate::runtime::message_0x17::{MessageDispatchOps, MESSAGE_DISPATCH_OPS};

/// RTXC service selector for `KS_alloc_timer`.
const TIMER_ALLOC_SERVICE: u32 = 0x10;
/// The firmware's seven-word frame is dispatched beginning at its second word.
const TIMER_ALLOC_REQUEST_WORDS: usize = 6;
/// Callback-populated final word at `sp + 0x18`, or word five from the request.
const TIMER_ALLOC_RESULT_WORD: usize = 5;

/// Reads the shared dispatcher slot without folding its ROM default into this
/// wrapper. The `0x08003660` veneer is the same target as message selector 0x17.
#[inline(always)]
unsafe fn message_dispatch_ops() -> MessageDispatchOps {
    core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_OPS))
}

/// ks_alloc_timer — original: `FUN_08003b8c` @ `0x08003b8c` (36 bytes).
///
/// Builds the six-word request beginning at the selector's stack address,
/// `{ 0x10, uninitialized, uninitialized, uninitialized, uninitialized,
/// callback_result }`, sends it through the `0x08003660` dispatcher veneer,
/// and returns the callback-populated final word. The original never reads or
/// initializes the intervening request words; `MaybeUninit` preserves that
/// target behavior without materializing an invalid Rust value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ks_alloc_timer() -> u32 {
    let mut request = [MaybeUninit::<u32>::uninit(); TIMER_ALLOC_REQUEST_WORDS];
    let request_words = request.as_mut_ptr().cast::<u32>();
    request_words.write(TIMER_ALLOC_SERVICE);
    (message_dispatch_ops().dispatch)(request_words);
    request_words.add(TIMER_ALLOC_RESULT_WORD).read()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: usize = 0;
    static mut OBSERVED_SELECTOR: u32 = 0;
    static mut OBSERVED_ADDRESS: *mut u32 = core::ptr::null_mut();

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: MessageDispatchOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { MESSAGE_DISPATCH_OPS = self.saved };
        }
    }

    fn install_recording_dispatcher() -> TestOps {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(MESSAGE_DISPATCH_OPS));
            MESSAGE_DISPATCH_OPS = MessageDispatchOps {
                dispatch: record_dispatch,
            };
            core::ptr::addr_of_mut!(CALL_COUNT).write(0);
            core::ptr::addr_of_mut!(OBSERVED_SELECTOR).write(0);
            core::ptr::addr_of_mut!(OBSERVED_ADDRESS).write(core::ptr::null_mut());
            TestOps { _lock: lock, saved }
        }
    }

    unsafe extern "C" fn record_dispatch(request: *mut u32) {
        core::ptr::addr_of_mut!(CALL_COUNT).write(core::ptr::addr_of!(CALL_COUNT).read() + 1);
        core::ptr::addr_of_mut!(OBSERVED_ADDRESS).write(request);
        core::ptr::addr_of_mut!(OBSERVED_SELECTOR).write(request.read());
        // The ARM epilogue reloads sp + 0x18: word five from the dispatched
        // request pointer, after the dispatcher has filled it in.
        request.add(TIMER_ALLOC_RESULT_WORD).write(0xa5a5_5a5a);
    }

    #[test]
    fn dispatches_timer_allocation_selector_and_returns_callback_result() {
        let _ops = install_recording_dispatcher();

        let returned = unsafe { ks_alloc_timer() };

        unsafe {
            assert_eq!(CALL_COUNT, 1, "the dispatcher is called exactly once");
            assert!(
                !OBSERVED_ADDRESS.is_null(),
                "the callback receives the stack request pointer"
            );
            assert_eq!(
                OBSERVED_SELECTOR, TIMER_ALLOC_SERVICE,
                "selector 0x10 is the first dispatched request word"
            );
        }
        assert_eq!(
            returned, 0xa5a5_5a5a,
            "returns the callback-populated final record word"
        );
    }
}
