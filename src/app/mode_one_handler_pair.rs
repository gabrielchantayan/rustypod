//! `mode_one_handler_pair` — original: `FUN_082e5a4c` @ **0x082e5a4c**
//! (**36 bytes**, `0x082e5a4c..0x082e5a70`; the next separately linked function
//! starts with `push {r3,lr}` at `0x082e5a70`).
//!
//! Whole-image raw A32 decoding finds **2 incoming plain `bl` call sites**
//! (`0x08369b08` and `0x08369b24`) and **0 predicated `bl` forms**. The body
//! has two unconditional direct `bl` instructions and no predicated calls.
//!
//! Algorithm: for mode 1 only, call the two retail handlers at `0x082e595c`
//! and `0x082e5a20`, in that order, with zero; always return zero. The
//! handlers' identities are not recovered, so target builds call their
//! verified retail addresses and host tests inject them. Deliberate deviation:
//! Rust performs normal calls rather than preserving the stock register save.

type ModeHandler = unsafe extern "C" fn(u32);

const FIRST_MODE_ONE_HANDLER_ADDRESS: usize = 0x082e_595c;
const SECOND_MODE_ONE_HANDLER_ADDRESS: usize = 0x082e_5a20;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn call_retail_mode_handler(address: usize, mode: u32) {
    let handler: ModeHandler = core::mem::transmute(address);
    handler(mode);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_op_mode_handler(_: u32) {}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ModeOneHandlerPairOps {
    pub first: ModeHandler,
    pub second: ModeHandler,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MODE_ONE_HANDLER_PAIR_OPS: ModeOneHandlerPairOps = ModeOneHandlerPairOps {
    first: no_op_mode_handler,
    second: no_op_mode_handler,
};

#[cfg(not(target_os = "none"))]
pub static mut MODE_ONE_HANDLER_PAIR_OPS: ModeOneHandlerPairOps = DEFAULT_MODE_ONE_HANDLER_PAIR_OPS;

/// Runs the two opaque retail handlers selected by mode 1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mode_one_handler_pair(mode: u32) -> u32 {
    if mode == 1 {
        #[cfg(target_os = "none")]
        {
            call_retail_mode_handler(FIRST_MODE_ONE_HANDLER_ADDRESS, 0);
            call_retail_mode_handler(SECOND_MODE_ONE_HANDLER_ADDRESS, 0);
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = MODE_ONE_HANDLER_PAIR_OPS;
            (ops.first)(0);
            (ops.second)(0);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicU32, Ordering};
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    static FIRST_CALLS: AtomicU32 = AtomicU32::new(0);
    static SECOND_CALLS: AtomicU32 = AtomicU32::new(0);
    static FIRST_ARGUMENT: AtomicU32 = AtomicU32::new(u32::MAX);
    static SECOND_ARGUMENT: AtomicU32 = AtomicU32::new(u32::MAX);
    static ORDER: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn first(mode: u32) {
        FIRST_ARGUMENT.store(mode, Ordering::SeqCst);
        FIRST_CALLS.fetch_add(1, Ordering::SeqCst);
        ORDER.store(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn second(mode: u32) {
        SECOND_ARGUMENT.store(mode, Ordering::SeqCst);
        SECOND_CALLS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(ORDER.load(Ordering::SeqCst), 1);
        ORDER.store(2, Ordering::SeqCst);
    }

    fn reset() {
        FIRST_CALLS.store(0, Ordering::SeqCst);
        SECOND_CALLS.store(0, Ordering::SeqCst);
        FIRST_ARGUMENT.store(u32::MAX, Ordering::SeqCst);
        SECOND_ARGUMENT.store(u32::MAX, Ordering::SeqCst);
        ORDER.store(0, Ordering::SeqCst);
        unsafe { MODE_ONE_HANDLER_PAIR_OPS = ModeOneHandlerPairOps { first, second }; }
    }

    #[test]
    fn mode_one_calls_both_handlers_with_zero_in_order() {
        let _lock = LOCK.lock();
        reset();
        assert_eq!(unsafe { mode_one_handler_pair(1) }, 0);
        assert_eq!(FIRST_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(SECOND_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FIRST_ARGUMENT.load(Ordering::SeqCst), 0);
        assert_eq!(SECOND_ARGUMENT.load(Ordering::SeqCst), 0);
        assert_eq!(ORDER.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn other_modes_return_zero_without_calling_handlers() {
        let _lock = LOCK.lock();
        reset();
        for mode in [0, 2, 4, u32::MAX] {
            assert_eq!(unsafe { mode_one_handler_pair(mode) }, 0);
        }
        assert_eq!(FIRST_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(SECOND_CALLS.load(Ordering::SeqCst), 0);
    }
}
