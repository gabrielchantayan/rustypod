//! Transfer submission with the default control word.
//!
//! `queue_transfer_with_default_mode` — original: `FUN_08008648` @
//! `0x08008648` (36 bytes). Reference:
//! `/home/gabe/Programming/ipod-decomp/decomp/c/000/08008648_FUN_08008648.c`;
//! raw ARM is `0x08008648..0x0800866c`.
//!
//! The ARM wrapper shuffles its five input words into the six-word ABI of
//! `FUN_08004a20`: it passes the first three unchanged, supplies literal zero
//! for the callee's fourth control word, then forwards the final two words.
//! Its caller at `FUN_080084dc` uses it to submit each chunk of a transfer.

/// ABI of the unported transfer-submission routine at `0x08004a20`.
pub type TransferSubmitFn = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32) -> u32;

/// Calls outside this one-function port.
///
/// The target default calls the retailOS transfer-submission routine. Host
/// tests replace it with a recorder to verify the wrapper's ABI forwarding.
#[derive(Clone, Copy)]
pub struct TransferDefaultModeOps {
    pub submit_transfer: TransferSubmitFn,
}

unsafe extern "C" fn firmware_submit_transfer(
    first: u32,
    second: u32,
    length: u32,
    control: u32,
    transfer_type: u32,
    transfer_slot: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        let submit_transfer: TransferSubmitFn = core::mem::transmute(0x0800_4a20usize);
        return submit_transfer(first, second, length, control, transfer_type, transfer_slot);
    }

    #[cfg(not(target_os = "none"))]
    {
        let _ = (first, second, length, control, transfer_type, transfer_slot);
        0
    }
}

/// Unwired target/host ROM-dispatch boundary.
pub const DEFAULT_TRANSFER_DEFAULT_MODE_OPS: TransferDefaultModeOps = TransferDefaultModeOps {
    submit_transfer: firmware_submit_transfer,
};

/// Active transfer-submission boundary. Target builds call retailOS; host
/// tests install a recorder to prove the exact six-word ABI.
pub static mut TRANSFER_DEFAULT_MODE_OPS: TransferDefaultModeOps = DEFAULT_TRANSFER_DEFAULT_MODE_OPS;

#[inline(always)]
fn transfer_default_mode_ops() -> TransferDefaultModeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TRANSFER_DEFAULT_MODE_OPS)) }
}

/// queue_transfer_with_default_mode — original: `FUN_08008648` @ `0x08008648`
/// (36 bytes).
///
/// Submits the five caller-provided transfer words through `FUN_08004a20`,
/// inserting literal zero as its fourth control word. The callee's result is
/// deliberately discarded, matching the ARM wrapper's `void` return.
///
/// # Deviations
///
/// `FUN_08004a20` remains retailOS code. [`TRANSFER_DEFAULT_MODE_OPS`] calls
/// its original load address on target and supplies a recording seam on hosts;
/// it does not alter the six argument words or observe the callee result.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn queue_transfer_with_default_mode(
    first: u32,
    second: u32,
    length: u32,
    transfer_type: u32,
    transfer_slot: u32,
) {
    let ops = transfer_default_mode_ops();
    unsafe {
        (ops.submit_transfer)(first, second, length, 0, transfer_type, transfer_slot);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RECORDED_ARGUMENTS: Mutex<[u32; 6]> = Mutex::new([0; 6]);
    static CALL_COUNT: Mutex<u32> = Mutex::new(0);

    unsafe extern "C" fn record_submit_transfer(
        first: u32,
        second: u32,
        length: u32,
        control: u32,
        transfer_type: u32,
        transfer_slot: u32,
    ) -> u32 {
        *RECORDED_ARGUMENTS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) =
            [first, second, length, control, transfer_type, transfer_slot];
        let mut call_count = CALL_COUNT.lock().unwrap_or_else(|error| error.into_inner());
        *call_count += 1;
        0xdead_beef
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous: TransferDefaultModeOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { TRANSFER_DEFAULT_MODE_OPS = self.previous };
        }
    }

    fn bench() -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { TRANSFER_DEFAULT_MODE_OPS };
        *RECORDED_ARGUMENTS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = [0; 6];
        *CALL_COUNT.lock().unwrap_or_else(|error| error.into_inner()) = 0;
        unsafe {
            TRANSFER_DEFAULT_MODE_OPS = TransferDefaultModeOps {
                submit_transfer: record_submit_transfer,
            };
        }
        Bench {
            _lock: lock,
            previous,
        }
    }

    #[test]
    fn forwards_five_words_and_inserts_literal_zero_control() {
        let _bench = bench();

        unsafe {
            queue_transfer_with_default_mode(
                0x1111_1111,
                0x2222_2222,
                0x3333_3333,
                0x4444_4444,
                0x5555_5555,
            );
        }

        assert_eq!(
            *RECORDED_ARGUMENTS
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            [
                0x1111_1111,
                0x2222_2222,
                0x3333_3333,
                0,
                0x4444_4444,
                0x5555_5555,
            ],
            "the wrapper preserves input order and inserts the literal control zero"
        );
        assert_eq!(
            *CALL_COUNT.lock().unwrap_or_else(|error| error.into_inner()),
            1,
            "the callee is invoked exactly once"
        );
    }
}
