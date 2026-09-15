//! Reject a comma-marked parser input and signal the shared parser state.
//!
//! `comma_input_guard` — original: `FUN_08116d8c` @ **0x08116d8c**,
//! 32 bytes (`0x08116d8c..0x08116dac`). The next real function begins with
//! `push {r4, lr}` at 0x08116dac. Raw ARM decoding finds five direct,
//! unconditional `bl` callers and no predicated direct calls; this body has one
//! unconditional `bl` to the unrecovered `FUN_081b9134` at 0x081b9134.
//!
//! # Algorithm
//!
//! Reads byte `input + 0x8c9`. A comma calls `FUN_081b9134`, then returns one;
//! every other byte returns zero. The callee's concrete identity is unrecovered,
//! so its target address is retained rather than assigning it a semantic name.
//!
//! # Deliberate deviation
//!
//! The target build calls the verified firmware address directly. Host builds
//! use a replaceable no-op callback solely to observe that call in tests.

const DELIMITER_OFFSET: usize = 0x8c9;
const COMMA: u8 = b',';
const COMMA_SIGNAL_ADDRESS: usize = 0x081b_9134;

type CommaSignal = unsafe extern "C" fn();

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn signal_comma() {
    let signal: CommaSignal = core::mem::transmute(COMMA_SIGNAL_ADDRESS);
    signal();
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_comma_signal() {}

#[cfg(not(target_os = "none"))]
static mut HOST_COMMA_SIGNAL: CommaSignal = no_comma_signal;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn signal_comma() {
    HOST_COMMA_SIGNAL();
}

#[cfg(test)]
unsafe fn replace_host_comma_signal(signal: CommaSignal) -> CommaSignal {
    let previous = HOST_COMMA_SIGNAL;
    HOST_COMMA_SIGNAL = signal;
    previous
}

/// Returns whether `input` contains a comma at the parser's delimiter offset.
///
/// # Safety
///
/// `input` must point to at least `0x8ca` readable bytes. The retail body has
/// no NULL or bounds guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn comma_input_guard(input: *const u8) -> u32 {
    if input.add(DELIMITER_OFFSET).read() == COMMA {
        signal_comma();
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static SIGNAL_LOCK: Mutex<()> = Mutex::new(());
    static SIGNAL_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_comma_signal() {
        SIGNAL_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    struct SignalRestore(CommaSignal);

    impl Drop for SignalRestore {
        fn drop(&mut self) {
            unsafe { replace_host_comma_signal(self.0) };
        }
    }

    fn install_recorder() -> SignalRestore {
        let previous = unsafe { replace_host_comma_signal(record_comma_signal) };
        SignalRestore(previous)
    }

    #[test]
    fn only_a_comma_at_the_delimiter_offset_signals() {
        let _lock = SIGNAL_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _restore = install_recorder();
        let mut input = std::vec![0_u8; DELIMITER_OFFSET + 2];

        input[DELIMITER_OFFSET - 1] = COMMA;
        input[DELIMITER_OFFSET + 1] = COMMA;
        SIGNAL_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { comma_input_guard(input.as_ptr()) }, 0);
        assert_eq!(SIGNAL_CALLS.load(Ordering::SeqCst), 0);

        input[DELIMITER_OFFSET] = COMMA;
        assert_eq!(unsafe { comma_input_guard(input.as_ptr()) }, 1);
        assert_eq!(SIGNAL_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn nul_at_the_delimiter_is_not_a_comma() {
        let _lock = SIGNAL_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _restore = install_recorder();
        let input = std::vec![0_u8; DELIMITER_OFFSET + 1];

        SIGNAL_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { comma_input_guard(input.as_ptr()) }, 0);
        assert_eq!(SIGNAL_CALLS.load(Ordering::SeqCst), 0);
    }
}
