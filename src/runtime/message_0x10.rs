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

/// iram_ks_alloc_timer_veneer — original: `thunk_EXT_FUN_22003b8c` @
/// `0x08037f18` (8 bytes: `ldr pc,[pc,#-4]` / `0xe51ff004`, followed by the
/// `0x22003b8c` target literal at `0x08037f1c`; Ghidra's 4-byte extent
/// excludes that word).
///
/// Raw `osos.dec` decoding proves the following veneer begins at `0x08037f20`.
/// The relocator at `0x080046e0` copies `0xaed8` bytes from `0x08000000` to
/// `0x22000000`, so the target is the IRAM mirror of [`ks_alloc_timer`] @
/// `0x08003b8c`. Decoding every ARM B/BL word finds exactly five direct
/// calls, all unconditional `bl` at `0x08084bf8`, `0x080c9b8c`, `0x08393640`,
/// `0x08393670`, and `0x08393810` (matching Ghidra's call-site count); there
/// are no predicated calls or tail branches. No raw aligned word holds the
/// thunk address, and the only `0x22003b8c` word is the target literal at
/// `0x08037f1c`, so the veneer has no observed indirect dispatch.
///
/// The original tail-loads PC, passing the returned timer handle through
/// unchanged. This port volatile-loads the already ported body and calls it
/// instead; that extra call/return is the deliberate code-generation
/// deviation needed to keep this exported veneer as a distinct target.
///
/// # Safety
/// Same as [`ks_alloc_timer`]: allocates an RTXC timer through the ROM
/// dispatcher and returns the handle/result word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.iram_ks_alloc_timer_veneer")]
#[inline(never)]
pub unsafe extern "C" fn iram_ks_alloc_timer_veneer() -> u32 {
    let body = core::ptr::read_volatile(&(ks_alloc_timer as unsafe extern "C" fn() -> u32));
    body()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::MutexGuard;
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
        let lock = crate::testing::MESSAGE_DISPATCH_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    #[test]
    fn veneer_delegates_to_alloc_body_once_and_passes_result_through() {
        let _ops = install_recording_dispatcher();

        let returned = unsafe { iram_ks_alloc_timer_veneer() };

        unsafe {
            assert_eq!(CALL_COUNT, 1, "the veneer dispatches exactly once");
            assert_eq!(
                OBSERVED_SELECTOR, TIMER_ALLOC_SERVICE,
                "the veneer reaches the same selector-0x10 request"
            );
        }
        assert_eq!(
            returned, 0xa5a5_5a5a,
            "the veneer returns the body's result word unchanged"
        );
    }
}
