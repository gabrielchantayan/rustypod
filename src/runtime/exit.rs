//! Ports of the ARM ADS 1.0.1 exit family from osos:
//!
//! - `exit` — original: `FUN_08030f2c` @ 0x08030f2c (48 bytes, including the
//!   fallback-terminate entry at 0x08030f44). Saves the code in r4, executes
//!   one dead `nop` (where stock ADS builds call `__rt_exit`; the retailOS
//!   link has it patched out), then tail-branches to `__rt_sys_exit`.
//! - `__rt_sys_exit` — original: `FUN_08032084` @ 0x08032084 (36 bytes).
//!   Calls the no-op weak hook @ 0x080358ac (`mov pc, lr`), runs the stdio
//!   cleanup `FUN_08035878` @ 0x08035878 (which calls 0x082ab2b0, the
//!   flush-all `FUN_08030624` @ 0x08030624, and 0x0802ecc0), then passes the
//!   preserved code to retailOS terminate @ 0x082b20a0. (0x08032098 is an
//!   alternate `code = -1` entry into terminate, skipped by the main path.)
//! - `abort` — original: `FUN_08032058` @ 0x08032058 (44 bytes). Runs a
//!   report sequence (context snapshot @ 0x0803568c, arg load @ 0x08035894,
//!   message print wrapper `FUN_08035788` @ 0x08035788, no-op @ 0x080358a0,
//!   retailOS log call @ 0x082d8fe8) and tail-branches into `exit` with the
//!   log call's return value as the exit code.
//! - `__rt_exit` — original: `FUN_08033720` @ 0x08033720 (56 bytes). Fetches
//!   the shutdown block via `FUN_080358b4` @ 0x080358b4 (32-byte block at
//!   libspace+0x3c: +0x08 finalizer thunk, +0x10 atexit chain-head thunk).
//!   If the chain thunk is set it is cleared, then called (runs the
//!   registered handlers, LIFO); otherwise the finalizer @ 0x080358b0 runs.
//!   Both paths end in the fallback-terminate `FUN_08030f44` @ 0x08030f44:
//!   default signal-handler check `FUN_080320a8(1, 0)` @ 0x080320a8, stdio
//!   cleanup, terminate(1). NOTE: the original ignores its `code` argument
//!   and always terminates with 1.
//!
//! Deviations / simplifications:
//! - retailOS terminate @ 0x082b20a0 is an OS trap (does not return; Ghidra
//!   models it as svc + infinite loop). Ported as `terminate()`, a
//!   documented park-forever loop stub; host tests can install a mock hook
//!   via the `TERMINATE_HOOK` function-pointer static.
//! - The stdio cleanup/flush and the abort report sequence are
//!   semihost/console-backed dead code under retailOS; ported as documented
//!   no-op stubs with the original addresses noted.
//! - abort's exit code is the return value of the retailOS log call
//!   @ 0x082d8fe8 (not recoverable statically); stubbed as
//!   `ABORT_STUB_EXIT_CODE`.
//! - The atexit handler chain is a SELF-CONTAINED representation: a
//!   fixed-capacity LIFO array in this module instead of the original's
//!   heap-allocated thunk nodes hanging off libspace+0x3c. Unification with
//!   the atexit agent's module (src/atexit.rs) and the libspace model
//!   (src/errno.rs, `Libspace::atexit_table`) is PENDING — this module
//!   deliberately imports nothing from them.
//! - Dispatch mirrors the original's clear-before-call: the chain head is
//!   detached before any handler runs, so handlers registered *during* exit
//!   start a fresh chain and are NOT run by the in-progress `__rt_exit`
//!   (matching the original, which has already cleared the head thunk).

/// Stubbed exit code for `abort`: the original tails into `exit` with the
/// return value of the retailOS log call @ 0x082d8fe8 (see module docs).
const ABORT_STUB_EXIT_CODE: i32 = 0;

/// Capacity of the self-contained atexit handler chain. The original
/// heap-allocates one thunk node per registration; retailOS registers only
/// a handful of handlers, so 32 is ample.
const ATEXIT_CAPACITY: usize = 32;

/// Registered exit handlers, LIFO stack. Self-contained stand-in for the
/// original thunk chain (see module docs; unification pending).
static mut ATEXIT_HANDLERS: [Option<unsafe extern "C" fn()>; ATEXIT_CAPACITY] =
    [None; ATEXIT_CAPACITY];
/// Number of live entries in `ATEXIT_HANDLERS`.
static mut ATEXIT_COUNT: usize = 0;

/// Registers an exit handler (called LIFO from `__rt_exit`).
///
/// Self-contained registration entry point standing in for the atexit
/// agent's module — unification pending, do not use from outside the exit
/// family yet. Returns `false` when the chain is full (the original grows
/// its thunk chain on the heap and has no fixed limit).
///
/// `no_mangle` also serves the firmware build: staticlib roots are only the
/// exported symbols, and without an exported writer the optimizer folds the
/// (private) chain statics to their initializers and deletes the
/// `__rt_exit` handler walk.
#[doc(hidden)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __exit_push_handler(handler: unsafe extern "C" fn()) -> bool {
    let count = *core::ptr::addr_of!(ATEXIT_COUNT);
    if count >= ATEXIT_CAPACITY {
        return false;
    }
    // Guarded above: count < ATEXIT_CAPACITY. Unchecked indexing keeps
    // panic_bounds_check out of the firmware build.
    *(*core::ptr::addr_of_mut!(ATEXIT_HANDLERS)).get_unchecked_mut(count) = Some(handler);
    *core::ptr::addr_of_mut!(ATEXIT_COUNT) = count + 1;
    true
}

/// Runs the registered exit handlers, last-registered-first.
///
/// Mirrors the original __rt_exit dispatch: the chain head is detached
/// before the first handler runs, so a handler that registers another
/// handler during exit does not extend the in-progress walk.
unsafe fn run_exit_handlers() {
    // Dispatch last-registered-first, taking (clearing) each slot before
    // the call. The count is left in place during the walk, so a handler
    // that registers another handler during exit appends above the walked
    // region and is NOT run by this exit — matching the original, which
    // clears the head thunk before calling it and never revisits the chain.
    let handlers = &mut *core::ptr::addr_of_mut!(ATEXIT_HANDLERS);
    let count = *core::ptr::addr_of!(ATEXIT_COUNT);
    // Chain invariant: ATEXIT_COUNT only grows via __exit_push_handler,
    // which caps it at ATEXIT_CAPACITY, so every index below is in bounds;
    // unchecked access keeps panic_bounds_check out of the firmware build.
    let mut i = count;
    while i > 0 {
        i -= 1;
        if let Some(handler) = handlers.get_unchecked_mut(i).take() {
            handler();
        }
    }
    // Compact handlers registered during the walk down to the chain base.
    let leftover = *core::ptr::addr_of!(ATEXIT_COUNT) - count;
    for j in 0..leftover {
        *handlers.get_unchecked_mut(j) = handlers.get_unchecked_mut(count + j).take();
    }
    *core::ptr::addr_of_mut!(ATEXIT_COUNT) = leftover;
}

/// stdio cleanup — original: `FUN_08035878` @ 0x08035878.
///
/// The original calls 0x082ab2b0, the flush-all `FUN_08030624` @ 0x08030624
/// (drains the stdio FILE list) and 0x0802ecc0. All semihost/console-backed
/// dead code under retailOS; stubbed as a no-op.
#[inline]
fn stdio_cleanup() {}

/// Default signal-handler check — original: `FUN_080320a8(1, 0)` @
/// 0x080320a8. If `FUN_08035634` @ 0x08035634 reports a live handler it
/// tail-branches to terminate; otherwise it returns. Stubbed as a no-op
/// (retailOS installs no signal handlers on this path).
#[inline]
fn default_signal_check() {}

/// abort report sequence — original calls, in order: 0x08035890 (no-op),
/// `FUN_0803568c` @ 0x0803568c (current-context snapshot), 0x08035894
/// (loads r0=-1, r1=-3), the message print wrapper `FUN_08035788` @
/// 0x08035788, 0x080358a0 -> 0x08036d08 (no-op), and the retailOS log call
/// @ 0x082d8fe8. Console/semihost-backed; stubbed as a no-op returning the
/// stubbed log result used as abort's exit code.
#[inline]
fn abort_report() -> i32 {
    ABORT_STUB_EXIT_CODE
}

/// retailOS terminate — original @ 0x082b20a0 (moves sp into r0, r1=8,
/// branches to the retailOS trap @ 0x080441e4; does not return).
///
/// Stubbed: parks forever. In host test builds an installed `TERMINATE_HOOK`
/// runs first and the stub then panics so tests can observe the dispatch
/// with `catch_unwind` instead of hanging.
fn terminate(code: i32) -> ! {
    #[cfg(test)]
    {
        unsafe {
            if let Some(hook) = *core::ptr::addr_of!(TERMINATE_HOOK) {
                hook(code);
            }
        }
        panic!("terminate stub reached (code {code})");
    }
    #[cfg(not(test))]
    {
        let _ = code;
        loop {
            // Opaque side effect: without it LLVM treats the side-effect-free
            // infinite loop as UB (mustprogress) and deletes the code paths
            // leading here.
            unsafe { core::arch::asm!("", options(nomem, nostack, preserves_flags)) }
        }
    }
}

/// Body of `__rt_sys_exit`/`exit`, factored out of the diverging extern
/// wrapper so host tests can check the terminate code pass-through.
/// Returns the code that the original hands to retailOS terminate.
#[inline]
unsafe fn sys_exit_body(code: i32) -> i32 {
    // Original also calls the weak hook @ 0x080358ac, a `mov pc, lr` no-op.
    stdio_cleanup();
    code
}

/// Body of `abort`; returns the code the original tails into `exit` with.
#[inline]
unsafe fn abort_body() -> i32 {
    abort_report()
}

/// Body of `__rt_exit`; returns the code handed to terminate. The original
/// ignores its argument and always terminates with 1 via the
/// fallback-terminate `FUN_08030f44` @ 0x08030f44.
#[inline]
unsafe fn rt_exit_body(code: i32) -> i32 {
    let _ = code;
    run_exit_handlers();
    // Fallback-terminate FUN_08030f44 @ 0x08030f44:
    default_signal_check();
    stdio_cleanup();
    1
}

/// exit — original: `FUN_08030f2c` @ 0x08030f2c.
///
/// The stock-ADS `__rt_exit` call is patched out (nop @ 0x08030f34), so
/// this is a pure tail-branch into `__rt_sys_exit`.
///
/// `no_mangle` is gated to the firmware target: in host builds an
/// exported `exit` would interpose libc's `exit(3)` and send the test
/// harness's own process teardown into the terminate stub.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn exit(code: i32) -> ! {
    // The original executes a dead `nop` @ 0x08030f34 (patched-out
    // __rt_exit call) between saving and restoring the code.
    core::arch::asm!("nop", options(nomem, nostack, preserves_flags));
    __rt_sys_exit(code)
}

/// __rt_sys_exit — original: `FUN_08032084` @ 0x08032084.
///
/// stdio cleanup, then retailOS terminate with the caller's code.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_sys_exit(code: i32) -> ! {
    terminate(sys_exit_body(code))
}

/// abort — original: `FUN_08032058` @ 0x08032058.
///
/// Prints the abort report (stubbed), then tails into `exit` with the
/// report's (stubbed) result code.
///
/// `no_mangle` restricted like `exit` above — an exported `abort` would
/// interpose libc's `abort(3)` in host test builds.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn abort() -> ! {
    exit(abort_body())
}

/// __rt_exit — original: `FUN_08033720` @ 0x08033720.
///
/// Runs the registered atexit handler chain (LIFO), then the
/// fallback-terminate path. The original ignores `code` and terminates
/// with 1.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn __rt_exit(code: i32) -> ! {
    terminate(rt_exit_body(code))
}

/// Host-test hook replacing the terminate loop-stub's dispatch. Set by
/// tests to observe the code handed to retailOS terminate.
#[cfg(test)]
static mut TERMINATE_HOOK: Option<fn(i32)> = None;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests: the chain/hook statics are process-global.
    static LOCK: Mutex<()> = Mutex::new(());
    /// Order in which exit handlers ran (handler tags).
    static mut CALL_ORDER: Vec<i32> = Vec::new();
    /// Codes observed by the mock terminate hook.
    static mut TERMINATE_CODES: Vec<i32> = Vec::new();

    fn log(tag: i32) {
        unsafe { (*core::ptr::addr_of_mut!(CALL_ORDER)).push(tag) };
    }

    unsafe extern "C" fn handler_a() {
        log(1);
    }
    unsafe extern "C" fn handler_b() {
        log(2);
    }
    unsafe extern "C" fn handler_c() {
        log(3);
    }
    /// Registers another handler while the exit walk is in progress.
    unsafe extern "C" fn handler_registers_during_exit() {
        log(4);
        assert!(__exit_push_handler(handler_a));
    }

    fn mock_terminate(code: i32) {
        unsafe { (*core::ptr::addr_of_mut!(TERMINATE_CODES)).push(code) };
    }

    unsafe fn reset() {
        *core::ptr::addr_of_mut!(ATEXIT_COUNT) = 0;
        for slot in (*core::ptr::addr_of_mut!(ATEXIT_HANDLERS)).iter_mut() {
            *slot = None;
        }
        (*core::ptr::addr_of_mut!(CALL_ORDER)).clear();
        (*core::ptr::addr_of_mut!(TERMINATE_CODES)).clear();
        *core::ptr::addr_of_mut!(TERMINATE_HOOK) = None;
    }

    #[test]
    fn rt_exit_runs_handlers_lifo_then_terminates_with_1() {
        // Poison-tolerant: the terminate-dispatch test panics deliberately.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            reset();
            assert!(__exit_push_handler(handler_a));
            assert!(__exit_push_handler(handler_b));
            assert!(__exit_push_handler(handler_c));
            // The original ignores its argument and terminates with 1.
            let code = rt_exit_body(42);
            assert_eq!(code, 1);
            assert_eq!(*core::ptr::addr_of!(CALL_ORDER), vec![3, 2, 1]);
            // Chain fully consumed (every slot cleared before its call).
            assert_eq!(*core::ptr::addr_of!(ATEXIT_COUNT), 0);
            assert!((*core::ptr::addr_of!(ATEXIT_HANDLERS))
                .iter()
                .all(|slot| slot.is_none()));
        }
    }

    #[test]
    fn rt_exit_empty_chain_still_terminates_with_1() {
        // Poison-tolerant: the terminate-dispatch test panics deliberately.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            reset();
            assert_eq!(rt_exit_body(-7), 1);
            assert!((*core::ptr::addr_of!(CALL_ORDER)).is_empty());
        }
    }

    #[test]
    fn handlers_registered_during_exit_wait_for_next_exit() {
        // Poison-tolerant: the terminate-dispatch test panics deliberately.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            reset();
            assert!(__exit_push_handler(handler_a));
            assert!(__exit_push_handler(handler_registers_during_exit));
            // Original semantics: the head thunk is cleared before dispatch,
            // so the handler pushed mid-walk is not run by this __rt_exit.
            assert_eq!(rt_exit_body(0), 1);
            assert_eq!(*core::ptr::addr_of!(CALL_ORDER), vec![4, 1]);
            assert_eq!(*core::ptr::addr_of!(ATEXIT_COUNT), 1);
            // A second exit runs the leftover handler.
            assert_eq!(rt_exit_body(0), 1);
            assert_eq!(*core::ptr::addr_of!(CALL_ORDER), vec![4, 1, 1]);
            assert_eq!(*core::ptr::addr_of!(ATEXIT_COUNT), 0);
        }
    }

    #[test]
    fn exit_and_sys_exit_pass_code_through() {
        // Poison-tolerant: the terminate-dispatch test panics deliberately.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            reset();
            for code in [0, 1, 7, -1, -3, i32::MIN, i32::MAX] {
                assert_eq!(sys_exit_body(code), code);
            }
            assert_eq!(abort_body(), ABORT_STUB_EXIT_CODE);
        }
    }

    #[test]
    fn terminate_dispatches_mock_hook_with_code() {
        // Poison-tolerant: the terminate-dispatch test panics deliberately.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            reset();
            *core::ptr::addr_of_mut!(TERMINATE_HOOK) = Some(mock_terminate);
            // terminate is a plain Rust fn, so its stub panic unwinds
            // safely (no extern "C" frame is crossed here).
            let result = std::panic::catch_unwind(|| terminate(9));
            assert!(result.is_err());
            assert_eq!(*core::ptr::addr_of!(TERMINATE_CODES), vec![9]);
            reset();
        }
    }

    #[test]
    fn push_handler_reports_full_chain() {
        // Poison-tolerant: the terminate-dispatch test panics deliberately.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            reset();
            for _ in 0..ATEXIT_CAPACITY {
                assert!(__exit_push_handler(handler_a));
            }
            assert!(!__exit_push_handler(handler_a));
            assert_eq!(*core::ptr::addr_of!(ATEXIT_COUNT), ATEXIT_CAPACITY);
            reset();
        }
    }
}
