//! Blocking wait for a retailOS state word @ 0x08055e8c.
//!
//! Original: `FUN_08055e8c` at load address 0x08055e8c (40 bytes),
//! `decomp/c/003/08055e8c_FUN_08055e8c.c`; the corresponding instructions are
//! `decomp/osos.asm:79524-79533`. Its literal pool word at 0x08055eb4 is
//! 0x089ca8bc. The routine loads that state-word pointer once, repeatedly reads
//! the word, and while it is zero calls 0x080e9eb0 with argument 2. That
//! four-byte veneer dispatches to 0x080568e8, whose nonzero-argument path calls
//! its runtime wait/yield dispatcher with `(0, argument)`; this port deliberately
//! preserves that unported device behavior through [`STATE_WAIT_OPS`].

/// Literal-pool target at 0x08055eb4: the state word polled by the original.
const STATE_WORD_ADDRESS: usize = 0x089c_a8bc;

/// Direct-call target used by the original's `bl 0x080e9eb0`.
const ROM_WAIT_OR_YIELD: usize = 0x080e_9eb0;

/// ABI of the unported wait/yield veneer.
pub type StateWaitFn = unsafe extern "C" fn(argument: u32);

/// Runtime integration seam for the literal state word and the wait/yield call.
#[derive(Clone, Copy)]
pub struct StateWaitOps {
    pub state_word: *const i32,
    pub wait_or_yield: StateWaitFn,
}

unsafe extern "C" fn rom_wait_or_yield(argument: u32) {
    let callee: StateWaitFn = core::mem::transmute(ROM_WAIT_OR_YIELD);
    callee(argument);
}

/// Direct-ROM defaults; host tests replace this slot before calling the port.
pub static mut STATE_WAIT_OPS: StateWaitOps = StateWaitOps {
    state_word: STATE_WORD_ADDRESS as *const i32,
    wait_or_yield: rom_wait_or_yield,
};

#[inline(always)]
unsafe fn state_wait_ops() -> StateWaitOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STATE_WAIT_OPS))
}

/// wait_for_nonzero_state — original: `FUN_08055e8c` @ 0x08055e8c (40 bytes).
///
/// Return the nonzero value of the state word at 0x089ca8bc. If it is zero,
/// invoke retailOS's wait/yield veneer with exactly argument 2 and retry. The
/// state pointer is captured once, like the original's `ldr r4,[literal]`; each
/// later read is volatile because the unported wait/yield dispatcher may change
/// the state asynchronously.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn wait_for_nonzero_state() -> i32 {
    let ops = state_wait_ops();
    loop {
        let state = core::ptr::read_volatile(ops.state_word);
        if state != 0 {
            return state;
        }
        (ops.wait_or_yield)(2);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut TEST_STATE: i32 = 0;
    static mut CALLS: usize = 0;
    static mut ARGUMENTS: [u32; 4] = [0; 4];

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        saved_ops: StateWaitOps,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { STATE_WAIT_OPS = self.saved_ops };
        }
    }

    fn bench(wait_or_yield: StateWaitFn) -> Bench {
        let lock = match OPS_LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        unsafe {
            let saved_ops = core::ptr::read_volatile(core::ptr::addr_of!(STATE_WAIT_OPS));
            STATE_WAIT_OPS = StateWaitOps {
                state_word: core::ptr::addr_of!(TEST_STATE),
                wait_or_yield,
            };
            core::ptr::addr_of_mut!(TEST_STATE).write(0);
            core::ptr::addr_of_mut!(CALLS).write(0);
            core::ptr::addr_of_mut!(ARGUMENTS).write([0; 4]);
            Bench {
                _lock: lock,
                saved_ops,
            }
        }
    }

    unsafe extern "C" fn record_yield(argument: u32) {
        let calls = core::ptr::addr_of!(CALLS).read();
        core::ptr::addr_of_mut!(ARGUMENTS).cast::<u32>().add(calls).write(argument);
        core::ptr::addr_of_mut!(CALLS).write(calls + 1);
    }

    unsafe extern "C" fn yield_until_state_is_ready(argument: u32) {
        record_yield(argument);
        if core::ptr::addr_of!(CALLS).read() == 3 {
            core::ptr::addr_of_mut!(TEST_STATE).write(-0x1234_567);
        }
    }

    #[test]
    fn returns_ready_state_without_waiting() {
        let _bench = bench(record_yield);
        unsafe {
            core::ptr::addr_of_mut!(TEST_STATE).write(0x2468);
            assert_eq!(wait_for_nonzero_state(), 0x2468);
            assert_eq!(core::ptr::addr_of!(CALLS).read(), 0);
        }
    }

    #[test]
    fn retries_with_argument_two_until_wait_makes_state_nonzero() {
        let _bench = bench(yield_until_state_is_ready);
        unsafe {
            assert_eq!(wait_for_nonzero_state(), -0x1234_567);
            assert_eq!(core::ptr::addr_of!(CALLS).read(), 3);
            assert_eq!(
                core::ptr::addr_of!(ARGUMENTS).cast::<u32>().read(),
                2,
                "first zero-state retry"
            );
            assert_eq!(
                core::ptr::addr_of!(ARGUMENTS).cast::<u32>().add(1).read(),
                2,
                "second zero-state retry"
            );
            assert_eq!(
                core::ptr::addr_of!(ARGUMENTS).cast::<u32>().add(2).read(),
                2,
                "third zero-state retry"
            );
        }
    }
}
