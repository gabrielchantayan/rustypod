//! retailOS timer/alarm object services.
//!
//! - `timer_stop` — original: `FUN_0812c6b0` @ 0x0812c6b0 (76 bytes;
//!   144 call sites: 129 `bl` + 15 tail `b`, binary-scanned — the busiest
//!   function in 0x08110000..0x0812ffff). Runs the trace/assert helper
//!   @ 0x08076954 (itself a locked call to 0x0809e620) on the timer,
//!   takes the timer-class global mutex @ 0x089cb294 (the ported
//!   `mutex_lock` @ 0x0807f5c4), and if the object's state word at +0x20
//!   equals the FourCC `TIMER_STATE_EXPIRED` ('expi') cancels the pending
//!   callback through the cancel helper @ 0x080a6c0c with the triple
//!   (object[+0x28], `TIMER_EXPIRY_CALLBACK`, object). It then writes the
//!   FourCC `TIMER_STATE_STOPPED` ('stop') to +0x20 and tail-branches to
//!   `mutex_unlock` @ 0x0807f6a0 on the same global mutex.
//!
//! - `timer_set_delay` — original: `FUN_080744c0` @ 0x080744c0 (24
//!   bytes). Runs the trace/assert helper @ 0x08076954 on the timer
//!   (the same `TimerOps::trace_assert` dispatch `timer_stop` uses),
//!   then stores the delay into the period word at +0x4 — the value the
//!   arm helper @ 0x0807a228 multiplies by 1000 to compute the deadline.
//!   `timer_start_after` tail-branches here.
//!
//! - `timer_restart` — original: `FUN_0812bf4c` @ 0x0812bf4c (32 bytes;
//!   119 call sites: 72 `bl` + 47 tail `b`, binary-scanned). Calls
//!   `timer_stop` on the timer, writes the FourCC `TIMER_STATE_RUNNING`
//!   ('run ') to the state word at +0x20, then tail-branches to the arm
//!   helper @ 0x0807a228 with the timer still in r0, which re-queues it
//!   onto the pending list sorted by deadline. The arm helper is not yet
//!   ported, so it dispatches through `TimerOps::arm_timer`.
//!
//! The FourCC state words are what identify the class as a timer/alarm:
//! `timer_restart` calls `timer_stop` and then writes 'run '
//! (0x72756e20) to +0x20, and `timer_start_after` @ 0x0812c63c stops the
//! timer before re-arming it with a delay.
//!
//! Timer object layout (only the words this function touches):
//!
//! ```text
//! +0x04 u32  period/delay in milliseconds (deadline = tick() + this * 1000)
//! +0x20 u32  state FourCC: 'expi' expired / 'stop' stopped / 'run ' running
//! +0x28 u32  callback queue handle, handed to the cancel helper
//! ```
//!
//! Offsets are literal byte offsets into a `*mut u8` (the
//! `drivers/display_layer.rs` precedent): callers pass interior pointers
//! into larger objects (e.g. `param_1 + 0x26c`), so no `repr(C)` struct
//! is imposed, and nothing here shifts on a 64-bit test host.
//!
//! Dispatch design (deviation, by necessity — mirrors the `ROM_KERNEL`
//! pattern in kernel/sync_mutex.rs): the trace/assert helper @ 0x08076954,
//! the cancel helper @ 0x080a6c0c and the arm helper @ 0x0807a228 are not
//! yet ported, so they dispatch indirectly through the `TIMER_OPS`
//! fn-pointer table instead of undefined `extern "C"` symbols that would
//! break the freestanding ARM link. Default stubs are harmless no-ops; on
//! real hardware the table must be installed before `timer_stop` or
//! `timer_restart` is hooked. The mutex pair is ported, so the global @
//! 0x089cb294 is modeled directly as the static `TIMER_CLASS_MUTEX`.
//!
//! Simplifications:
//! - The original stores the cancel helper's return value into a dead
//!   stack slot (`str r0, [sp]`, never read — the slot exists only
//!   because `stmdb sp!, {r3, ...}` keeps the stack 8-byte aligned).
//!   The dead store is dropped; the call itself is preserved.
//! - `TIMER_EXPIRY_CALLBACK` reaches the original as a link-time literal
//!   (0x081216b4, the expiry callback whose pending instance is
//!   cancelled); it is modeled as a static so the value is observable/
//!   overridable, per the `KERNEL_NOTIFY_CALLBACK` precedent.
//! - `TIMER_CLASS_MUTEX` is read out with a volatile load and the
//!   lock/unlock run on the read-out value; without this LLVM folds the
//!   null-initialized cell and deletes the entire mutex pair (see the
//!   comment in `timer_stop`). The mutex ops only read through the
//!   object, so this is behaviorally identical.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// +0x4: period/delay in milliseconds — the arm helper @ 0x0807a228
/// computes the deadline as tick() + period * 1000 from this word.
const PERIOD: usize = 0x4;
/// +0x20: state word — one of the FourCCs below.
const STATE: usize = 0x20;
/// +0x28: callback queue handle (a 32-bit firmware pointer), first
/// argument to the cancel helper.
const CALLBACK_HANDLE: usize = 0x28;

/// State FourCC @ +0x20: 'expi' — the timer fired and its callback is
/// pending; `timer_stop` cancels it.
pub const TIMER_STATE_EXPIRED: u32 = 0x6578_7069;
/// State FourCC @ +0x20: 'stop' — written by `timer_stop` on every path.
pub const TIMER_STATE_STOPPED: u32 = 0x7374_6f70;
/// State FourCC @ +0x20: 'run ' — written by `timer_restart` after it
/// calls `timer_stop`, before the timer is re-armed.
pub const TIMER_STATE_RUNNING: u32 = 0x7275_6e20;

/// Original: global timer-class mutex object @ 0x089cb294, taken around
/// the state-word update by `timer_stop` (and by its siblings).
pub static mut TIMER_CLASS_MUTEX: Mutex = Mutex {
    sem_cell: core::ptr::null_mut(),
    unused: 0,
};

/// Original: code pointer 0x081216b4 — the expiry callback identity the
/// cancel helper matches against. In osos it reaches `timer_stop` as a
/// link-time constant (literal pool), not as a loaded global; modeled as
/// a static so the value is observable/overridable (the
/// `KERNEL_NOTIFY_CALLBACK` precedent in kernel/sync_mutex.rs).
pub static mut TIMER_EXPIRY_CALLBACK: usize = 0x0812_16b4;

/// Indirect dispatch table for the not-yet-ported callees (see the
/// module header for the design and the default-stub behavior).
#[derive(Clone, Copy)]
pub struct TimerOps {
    /// Trace/assert helper @ 0x08076954: locks its own global and calls
    /// 0x0809e620 on the timer (a validation/trace walk over the
    /// object's words at +0x18/+0x1c). Argument is the timer.
    pub trace_assert: unsafe extern "C" fn(timer: *mut u8),
    /// Cancel helper @ 0x080a6c0c(handle, callback_id, timer) -> u32:
    /// walks the callback queue `handle`, and for a pending entry whose
    /// identity matches `callback_id` invokes it with `timer` and removes
    /// it. Returns nonzero when an entry was cancelled; `timer_stop`
    /// discards the result (see module header).
    pub cancel_callback: unsafe extern "C" fn(
        handle: usize,
        callback_id: usize,
        timer: *mut u8,
    ) -> u32,
    /// Arm/schedule helper @ 0x0807a228(timer): no-op when the armed flag
    /// at +0x1c is nonzero; otherwise, under the class mutex, traces the
    /// timer, computes the deadline (+0x8 = tick() + period(+0x4) * 1000),
    /// inserts the timer into the pending queue sorted by deadline, and
    /// sets the armed flag. `timer_restart` tail-branches to it.
    pub arm_timer: unsafe extern "C" fn(timer: *mut u8),
}

// Default stubs: without the trace/cancel/arm layer these operations have
// no meaning. On real hardware TIMER_OPS must be installed before any
// timer is stopped or restarted through this port.
unsafe extern "C" fn missing_trace_assert(_timer: *mut u8) {}
unsafe extern "C" fn missing_cancel_callback(
    _handle: usize,
    _callback_id: usize,
    _timer: *mut u8,
) -> u32 {
    0
}
unsafe extern "C" fn missing_arm_timer(_timer: *mut u8) {}

/// The active timer-service dispatch table. Defaults to the documented
/// stubs above; replaced by host tests (mocks) and eventually by the
/// ported trace/cancel/arm layer. Written once at init on target; tests
/// serialize access.
pub static mut TIMER_OPS: TimerOps = TimerOps {
    trace_assert: missing_trace_assert,
    cancel_callback: missing_cancel_callback,
    arm_timer: missing_arm_timer,
};

/// Reads the ops table. The read is volatile: the table is meant to be
/// swapped at runtime, and in a build where nothing writes it yet LLVM
/// would otherwise constant-fold the loads to the default stubs
/// (observed in malloc_rt: indirect calls collapsed to the stubs).
#[inline(always)]
fn timer_ops() -> TimerOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TIMER_OPS)) }
}

#[inline(always)]
unsafe fn word(timer: *mut u8, offset: usize) -> u32 {
    timer.add(offset).cast::<u32>().read_volatile()
}

#[inline(always)]
unsafe fn set_word(timer: *mut u8, offset: usize, value: u32) {
    timer.add(offset).cast::<u32>().write_volatile(value);
}

/// timer_stop — original: `FUN_0812c6b0` @ 0x0812c6b0 (76 bytes).
///
/// Stops `timer`: traces/asserts it, then under the timer-class mutex
/// cancels the pending expiry callback when the state word is
/// `TIMER_STATE_EXPIRED`, and unconditionally leaves
/// `TIMER_STATE_STOPPED` in the state word. The `timer` argument is not
/// NULL-checked, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_stop(timer: *mut u8) {
    (timer_ops().trace_assert)(timer);
    // Volatile: nothing in this crate installs the class mutex's cell
    // yet, and LLVM would otherwise fold the `sem_cell` load to the null
    // initializer and eliminate the lock/unlock pair entirely (observed
    // in the ARM build: the whole mutex pair optimized out). The mutex
    // ops only ever read through the object (cell pointer, then *cell),
    // so operating on the read-out value is behaviorally identical.
    let mut class_mutex = core::ptr::addr_of!(TIMER_CLASS_MUTEX).read_volatile();
    mutex_lock(&mut class_mutex);
    if word(timer, STATE) == TIMER_STATE_EXPIRED {
        // The original stores the result into a dead stack slot
        // (`str r0, [sp]`); the store is dropped, the call is not.
        (timer_ops().cancel_callback)(
            word(timer, CALLBACK_HANDLE) as usize,
            core::ptr::addr_of!(TIMER_EXPIRY_CALLBACK).read_volatile(),
            timer,
        );
    }
    set_word(timer, STATE, TIMER_STATE_STOPPED);
    mutex_unlock(&mut class_mutex);
}

/// timer_restart — original: `FUN_0812bf4c` @ 0x0812bf4c (32 bytes).
///
/// Restarts `timer`: stops it (the ported `timer_stop` @ 0x0812c6b0,
/// which runs unlocked before this store), writes the
/// `TIMER_STATE_RUNNING` ('run ') FourCC to the state word at +0x20, and
/// tail-branches to the arm helper @ 0x0807a228 with the timer as its
/// only argument, re-queuing it onto the pending list. The Ghidra
/// signature is `void`: the tail call's r0 (the arm helper's leftover —
/// the armed flag or the mutex pointer) is garbage to the caller, not
/// the timer, so the scouted `u8 *` return is corrected to `void`. The
/// 'run ' store is deliberately outside the class mutex, exactly as in
/// the original (the `str` sits between the `bl timer_stop` and the
/// tail branch).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_restart(timer: *mut u8) {
    timer_stop(timer);
    set_word(timer, STATE, TIMER_STATE_RUNNING);
    (timer_ops().arm_timer)(timer);
}

/// timer_set_delay — original: `FUN_080744c0` @ 0x080744c0 (24 bytes).
///
/// Traces/asserts `timer` (the helper @ 0x08076954, dispatched through
/// `TimerOps::trace_assert` as in `timer_stop`), then stores `delay`
/// into the period word at +0x4 — the value the arm helper @ 0x0807a228
/// multiplies by 1000 to compute the deadline. `timer_start_after`
/// tail-branches here with the timer in r0 and the delay in r1. The
/// `timer` argument is not NULL-checked, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_set_delay(timer: *mut u8, delay: u32) {
    (timer_ops().trace_assert)(timer);
    set_word(timer, PERIOD, delay);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
    use std::sync::Mutex as StdMutex;
    use std::vec;
    use std::vec::Vec;

    /// Serializes tests that swap the global ops tables / mock state.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Trace(usize),
        Wait(u32),
        Signal(u32),
        Cancel(usize, usize, usize),
        Arm(usize),
    }

    static CALLS: StdMutex<Vec<Call>> = StdMutex::new(Vec::new());

    fn record(call: Call) {
        CALLS.lock().unwrap().push(call);
    }

    fn calls() -> Vec<Call> {
        CALLS.lock().unwrap().clone()
    }

    /// Handle the mock sema ops see. Tests install the class-mutex cell
    /// directly; the ROM define never runs.
    const MOCK_HANDLE: u32 = 0x71e0_0001;

    unsafe extern "C" fn mock_trace(timer: *mut u8) {
        record(Call::Trace(timer as usize));
    }
    unsafe extern "C" fn mock_cancel(handle: usize, id: usize, timer: *mut u8) -> u32 {
        record(Call::Cancel(handle, id, timer as usize));
        1
    }
    unsafe extern "C" fn mock_arm(timer: *mut u8) {
        record(Call::Arm(timer as usize));
    }
    unsafe extern "C" fn mock_sema_wait(handle: u32) {
        record(Call::Wait(handle));
    }
    unsafe extern "C" fn mock_sema_signal(handle: u32) {
        record(Call::Signal(handle));
    }

    const MOCK_TIMER_OPS: TimerOps = TimerOps {
        trace_assert: mock_trace,
        cancel_callback: mock_cancel,
        arm_timer: mock_arm,
    };

    /// A 0x30-byte timer object: state word at +0x20, handle at +0x28.
    struct MockTimer {
        bytes: [u8; 0x30],
    }

    impl MockTimer {
        fn new(state: u32, handle: u32) -> Self {
            let mut timer = MockTimer { bytes: [0; 0x30] };
            timer.set_state(state);
            timer.set_handle(handle);
            timer
        }
        fn ptr(&mut self) -> *mut u8 {
            self.bytes.as_mut_ptr()
        }
        fn state(&self) -> u32 {
            u32::from_le_bytes(self.bytes[STATE..STATE + 4].try_into().unwrap())
        }
        fn set_state(&mut self, value: u32) {
            self.bytes[STATE..STATE + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn set_handle(&mut self, value: u32) {
            self.bytes[CALLBACK_HANDLE..CALLBACK_HANDLE + 4]
                .copy_from_slice(&value.to_le_bytes());
        }
        fn period(&self) -> u32 {
            u32::from_le_bytes(self.bytes[PERIOD..PERIOD + 4].try_into().unwrap())
        }
    }

    /// Resets the mock state, installs the mock tables and a live class
    /// mutex, returns the lock guard that serializes table-swapping tests.
    fn mock_env() -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap();
        CALLS.lock().unwrap().clear();
        unsafe {
            let mut rom = core::ptr::addr_of!(ROM_KERNEL).read_volatile();
            rom.sema_wait = mock_sema_wait;
            rom.sema_signal = mock_sema_signal;
            *core::ptr::addr_of_mut!(ROM_KERNEL) = rom;
            *core::ptr::addr_of_mut!(TIMER_OPS) = MOCK_TIMER_OPS;
            core::ptr::addr_of_mut!(TIMER_EXPIRY_CALLBACK).write_volatile(0x0812_16b4);
            core::ptr::addr_of_mut!(TIMER_CLASS_MUTEX).write_volatile(Mutex {
                sem_cell: core::ptr::addr_of_mut!(CLASS_MUTEX_CELL),
                unused: 0,
            });
            CLASS_MUTEX_CELL = MOCK_HANDLE;
        }
        guard
    }

    static mut CLASS_MUTEX_CELL: u32 = 0;

    /// State 'expi': the pending callback is cancelled with the exact
    /// (handle, callback identity, timer) triple, under the mutex, and
    /// the state word ends up 'stop'.
    #[test]
    fn expired_timer_cancels_then_stops() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_EXPIRED, 0x08A0_1234);
        let timer_ptr = timer.ptr();
        unsafe { timer_stop(timer_ptr) };
        assert_eq!(
            calls(),
            vec![
                Call::Trace(timer_ptr as usize),
                Call::Wait(MOCK_HANDLE),
                Call::Cancel(0x08A0_1234, 0x0812_16b4, timer_ptr as usize),
                Call::Signal(MOCK_HANDLE),
            ]
        );
        assert_eq!(timer.state(), TIMER_STATE_STOPPED);
    }

    /// Any non-'expi' state skips the cancel but still ends 'stop'.
    #[test]
    fn running_timer_stops_without_cancelling() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0x08A0_1234);
        let timer_ptr = timer.ptr();
        unsafe { timer_stop(timer_ptr) };
        assert_eq!(
            calls(),
            vec![
                Call::Trace(timer_ptr as usize),
                Call::Wait(MOCK_HANDLE),
                Call::Signal(MOCK_HANDLE),
            ],
            "no cancel when the state word is not 'expi'"
        );
        assert_eq!(timer.state(), TIMER_STATE_STOPPED);
    }

    /// Already stopped: idempotent, still no cancel.
    #[test]
    fn stopped_timer_is_idempotent() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_STOPPED, 0);
        unsafe { timer_stop(timer.ptr()) };
        assert_eq!(timer.state(), TIMER_STATE_STOPPED);
        assert!(
            calls().iter().all(|c| !matches!(c, Call::Cancel(..))),
            "already-stopped timer must not cancel"
        );
    }

    /// The trace runs before the mutex is taken — the original's first
    /// `bl` precedes the lock, and the helper takes its own internal
    /// lock, so the order is observable.
    #[test]
    fn trace_precedes_the_lock() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0);
        unsafe { timer_stop(timer.ptr()) };
        let seen = calls();
        assert!(matches!(seen.first(), Some(Call::Trace(_))));
        assert!(matches!(seen.get(1), Some(Call::Wait(_))));
    }

    /// The 'stop' store lands before the unlock — the original stores
    /// +0x20 and *then* tail-branches to mutex_unlock.
    #[test]
    fn state_store_precedes_unlock() {
        let _lock = mock_env();
        static mut PROBED_TIMER: *const MockTimer = core::ptr::null();
        static mut STATE_AT_SIGNAL: u32 = 0;
        unsafe extern "C" fn probing_signal(handle: u32) {
            record(Call::Signal(handle));
            unsafe { STATE_AT_SIGNAL = (*PROBED_TIMER).state() };
        }
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0);
        unsafe {
            PROBED_TIMER = &timer;
            let mut rom = core::ptr::addr_of!(ROM_KERNEL).read_volatile();
            rom.sema_signal = probing_signal;
            *core::ptr::addr_of_mut!(ROM_KERNEL) = rom;
            timer_stop(timer.ptr());
            assert_eq!(STATE_AT_SIGNAL, TIMER_STATE_STOPPED);
        }
    }

    /// The cancel helper's return value is discarded (the original's
    /// `str r0, [sp]` is a dead store): stopping an expired timer returns
    /// nothing and leaves only the state word changed.
    #[test]
    fn cancel_result_is_discarded() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_EXPIRED, 0x08A0_9999);
        let before = timer.bytes;
        unsafe { timer_stop(timer.ptr()) };
        let mut after_cancel = before;
        after_cancel[STATE..STATE + 4].copy_from_slice(&TIMER_STATE_STOPPED.to_le_bytes());
        assert_eq!(timer.bytes, after_cancel, "only the state word changes");
    }

    /// Expired timer: restart runs the full stop sequence (trace, lock,
    /// cancel, unlock), then writes 'run ' and arms the timer — in that
    /// order, matching the original's stop; str +0x20; tail-branch.
    #[test]
    fn restart_expired_timer_stops_marks_running_then_arms() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_EXPIRED, 0x08A0_1234);
        let timer_ptr = timer.ptr();
        unsafe { timer_restart(timer_ptr) };
        assert_eq!(
            calls(),
            vec![
                Call::Trace(timer_ptr as usize),
                Call::Wait(MOCK_HANDLE),
                Call::Cancel(0x08A0_1234, 0x0812_16b4, timer_ptr as usize),
                Call::Signal(MOCK_HANDLE),
                Call::Arm(timer_ptr as usize),
            ]
        );
        assert_eq!(timer.state(), TIMER_STATE_RUNNING);
    }

    /// The 'run ' store lands between the stop's unlock and the arm call:
    /// the original's `str` sits after `timer_stop` returns (no lock is
    /// held) and before the tail branch.
    #[test]
    fn restart_marks_running_before_arming() {
        let _lock = mock_env();
        static mut PROBED_TIMER: *const MockTimer = core::ptr::null();
        static mut STATE_AT_ARM: u32 = 0;
        unsafe extern "C" fn probing_arm(timer: *mut u8) {
            record(Call::Arm(timer as usize));
            unsafe { STATE_AT_ARM = (*PROBED_TIMER).state() };
        }
        let mut timer = MockTimer::new(TIMER_STATE_STOPPED, 0);
        unsafe {
            PROBED_TIMER = &timer;
            let mut ops = core::ptr::addr_of!(TIMER_OPS).read_volatile();
            ops.arm_timer = probing_arm;
            *core::ptr::addr_of_mut!(TIMER_OPS) = ops;
            timer_restart(timer.ptr());
            assert_eq!(STATE_AT_ARM, TIMER_STATE_RUNNING);
        }
    }

    /// The trace runs before the delay store — the original's `bl
    /// 0x08076954` precedes the `str r5, [r4, #0x4]`, and the helper
    /// takes its own internal lock, so the order is observable.
    #[test]
    fn set_delay_traces_then_stores() {
        let _lock = mock_env();
        static mut PROBED_TIMER: *const MockTimer = core::ptr::null();
        static mut PERIOD_AT_TRACE: u32 = 0xdead_beef;
        unsafe extern "C" fn probing_trace(timer: *mut u8) {
            record(Call::Trace(timer as usize));
            unsafe { PERIOD_AT_TRACE = (*PROBED_TIMER).period() };
        }
        let mut timer = MockTimer::new(TIMER_STATE_STOPPED, 0);
        let timer_ptr = timer.ptr();
        unsafe {
            PROBED_TIMER = &timer;
            let mut ops = core::ptr::addr_of!(TIMER_OPS).read_volatile();
            ops.trace_assert = probing_trace;
            *core::ptr::addr_of_mut!(TIMER_OPS) = ops;
            timer_set_delay(timer_ptr, 1000);
            assert_eq!(PERIOD_AT_TRACE, 0, "period not yet written at trace time");
            assert_eq!(calls(), vec![Call::Trace(timer_ptr as usize)]);
        }
        assert_eq!(timer.period(), 1000);
    }

    /// Only the period word changes: the trace is the whole prologue,
    /// and every other byte (state word, handle) is untouched.
    #[test]
    fn set_delay_touches_only_the_period_word() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0x08A0_5555);
        let before = timer.bytes;
        unsafe { timer_set_delay(timer.ptr(), 0x7d) };
        let mut expected = before;
        expected[PERIOD..PERIOD + 4].copy_from_slice(&0x7du32.to_le_bytes());
        assert_eq!(timer.bytes, expected, "only the period word changes");
    }

    /// Restart leaves every word but the state word untouched and always
    /// hands the same pointer to the arm helper (the original keeps the
    /// timer in r4 across the stop and moves it back to r0 for the tail
    /// branch).
    #[test]
    fn restart_touches_only_the_state_word() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0x08A0_7777);
        let before = timer.bytes;
        let timer_ptr = timer.ptr();
        unsafe { timer_restart(timer_ptr) };
        let mut expected = before;
        expected[STATE..STATE + 4].copy_from_slice(&TIMER_STATE_RUNNING.to_le_bytes());
        assert_eq!(timer.bytes, expected, "only the state word changes");
        assert!(
            matches!(calls().last(), Some(Call::Arm(t)) if *t == timer_ptr as usize),
            "arm helper receives the same timer pointer"
        );
    }
}
