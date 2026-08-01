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
//! - `timer_start_after` — original: `FUN_0812c63c` @ 0x0812c63c (32
//!   bytes; 100 call sites: 98 `bl` + 2 tail `b`, binary-scanned).
//!   Stops the timer (the ported `timer_stop`), then tail-branches to
//!   the ported `timer_set_delay` @ 0x080744c0 with (timer, delay) —
//!   the delay survives the stop in r5, which is what marks it as the
//!   delay/deadline.
//!
//! - `timer_restart` — original: `FUN_0812bf4c` @ 0x0812bf4c (32 bytes;
//!   119 call sites: 72 `bl` + 47 tail `b`, binary-scanned). Calls
//!   `timer_stop` on the timer, writes the FourCC `TIMER_STATE_RUNNING`
//!   ('run ') to the state word at +0x20, then tail-branches to the arm
//!   helper @ 0x0807a228 with the timer still in r0, which re-queues it
//!   onto the pending list sorted by deadline. The arm helper is ported
//!   as `timer_arm` below; the `TimerOps::arm_timer` slot remains as the
//!   dispatch indirection (its wired default is the port).
//!
//! - `timer_arm` — original: `FUN_0807a228` @ 0x0807a228 (176 bytes;
//!   7 call sites: 5 `bl` + 2 tail `b`, binary-scanned — including the
//!   `timer_restart` tail branch). No-op when the armed flag at +0x1c
//!   is set; otherwise, under the pending-list mutex @ 0x089ca318 (NOT
//!   the 0x089cb294 mutex `timer_stop` takes), validates the timer,
//!   computes the deadline (+0x8 = tick() + period(+0x4) * 1000), stamps
//!   'run ' into the queued-state word at +0x18, splices the timer into
//!   the pending queue (head cell @ 0x089ca300, link at +0x0) sorted by
//!   deadline, sets the armed flag, and kicks the notify helper @
//!   0x0808e2a8 on the cell @ 0x089ca310 before unlocking.
//!
//! - `timer_schedule_shim` — original: `FUN_0811108c` @ 0x0811108c (20
//!   bytes; 64 `bl` call sites). Pure argument plumbing: rotates its
//!   arguments (r0 -> r2, r1 -> r0, r2 -> r1, r3 untouched) and
//!   tail-branches to the timer constructor @ 0x0812c65c, which runs the
//!   object-init helper @ 0x08076924, writes an initial state word to
//!   +0x20, stores the first argument to +0x24, and records the
//!   callback-queue handle (r3, or the current task's queue when r3 is
//!   0) at +0x28. The constructor is not yet ported, so it dispatches
//!   through `TimerOps::construct_timer`.
//!
//! The FourCC state words are what identify the class as a timer/alarm:
//! `timer_restart` calls `timer_stop` and then writes 'run '
//! (0x72756e20) to +0x20, and `timer_start_after` @ 0x0812c63c stops the
//! timer before re-arming it with a delay.
//!
//! Timer object layout (only the words this function touches):
//!
//! ```text
//! +0x00 u32  pending-list link (next timer; 0 = list end)
//! +0x04 u32  period/delay in milliseconds (deadline = tick() + this * 1000)
//! +0x08 u32  deadline in tick units, written by `timer_arm`
//! +0x18 u32  queued-state FourCC: 'run ' once linked into the pending queue
//! +0x1c u32  armed flag: nonzero = already queued; `timer_arm` is a no-op
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
//! the cancel helper @ 0x080a6c0c and the timer constructor @ 0x0812c65c
//! are not yet ported, so they dispatch indirectly through the `TIMER_OPS`
//! fn-pointer table instead of undefined `extern "C"` symbols that would
//! break the freestanding ARM link. Default stubs are harmless no-ops; on
//! real hardware the table must be installed before `timer_stop` is
//! hooked. The arm helper @ 0x0807a228 IS ported (`timer_arm`) and is the
//! wired default of the `arm_timer` slot; its own four callees — the
//! trace/validate walk @ 0x0809e620, the tick getter @ 0x08056658, the
//! deadline comparator @ 0x082a243c and the notify helper @ 0x0808e2a8 —
//! are not, so they are slots of their own with documented default stubs.
//! The mutex pair is ported, so the globals @ 0x089cb294 and @ 0x089ca318
//! are modeled directly as the statics `TIMER_CLASS_MUTEX` /
//! `TIMER_PENDING_MUTEX`.
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
//!   object, so this is behaviorally identical. `TIMER_PENDING_MUTEX`
//!   follows the same pattern.
//! - Pending-list link words (+0x0 in each timer, and the head cell @
//!   0x089ca300) are 32-bit absolute pointers on the ARM target; 64-bit
//!   host test builds store u32 offsets from a per-test arena base
//!   (`TEST_LINK_BASE`, the `heap/alloc_core.rs` precedent). 0 is the
//!   NULL list end in both worlds; only the link-word<->pointer cast
//!   changes, so the ARM build is the original algorithm.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// S5L8702 timer-controller base. The firmware's literal global
/// `DAT_080023d0` at 0x080023d0 contains this physical address.
const TIMER_REGISTER_BASE: usize = 0x3c70_0000;
/// Timer E's live 32-bit counter (`TECNT`) within the timer controller.
const TIMER_E_COUNTER_OFFSET: usize = 0xb4;
/// Physical address of the `TECNT` word read by [`usec_timer_read`].
const TIMER_E_COUNTER: *const u32 =
    (TIMER_REGISTER_BASE + TIMER_E_COUNTER_OFFSET) as *const u32;

#[cfg(not(target_os = "none"))]
use core::sync::atomic::{AtomicU32, Ordering};

/// Deterministic driver-local replacement for Timer E's counter on hosts,
/// where 0x3c70_00b4 is not mapped.
#[cfg(not(target_os = "none"))]
static HOST_USEC_TIMER_COUNT: AtomicU32 = AtomicU32::new(0);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn read_usec_timer_counter() -> u32 {
    core::ptr::read_volatile(TIMER_E_COUNTER)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn read_usec_timer_counter() -> u32 {
    HOST_USEC_TIMER_COUNT.load(Ordering::Relaxed)
}

/// usec_timer_read — original: `FUN_08001edc` @ 0x08001edc (12 bytes).
/// Reference: `ipod-decomp/decomp/c/000/08001edc_FUN_08001edc.c` and
/// `ipod-decomp/decomp/osos.asm` @ 0x08001edc..0x08001ee4.
///
/// Returns the raw `u32` counter word from Timer E's `TECNT` register. The
/// three-instruction firmware body loads the timer-controller address from
/// its literal global at 0x080023d0 (0x3c70_0000), reads exactly `+0xb4`,
/// and returns that word in `r0`; callers use wrapping subtraction for
/// microsecond timeout polling. Deviation: the target path performs that
/// volatile MMIO read; host builds read the deterministic driver-local seam
/// above because the physical register is unavailable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usec_timer_read() -> u32 {
    #[cfg(target_os = "none")]
    {
        return read_usec_timer_counter();
    }

    #[cfg(not(target_os = "none"))]
    {
        read_usec_timer_counter()
    }
}
/// usec_timer_elapsed — original: `FUN_08001ee8` @ 0x08001ee8 (28 bytes).
/// Reference: `ipod-decomp/decomp/c/000/08001ee8_FUN_08001ee8.c` and
/// `ipod-decomp/decomp/osos.asm` @ 0x08001ee8..0x08001efc.
///
/// Reads Timer E's microsecond counter through [`usec_timer_read`], subtracts
/// `start` with the firmware's unsigned 32-bit wrapping semantics, and
/// returns whether that elapsed duration is at least `interval`. This keeps
/// timeout polling correct across a counter wrap. Deviation: none; the
/// shared read function supplies the existing host timer seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usec_timer_elapsed(start: u32, interval: u32) -> bool {
    unsafe { usec_timer_read() }.wrapping_sub(start) >= interval
}
/// usec_timer_elapsed_millis — original: `FUN_08001f04` @ 0x08001f04
/// (52 bytes).
/// Reference: `ipod-decomp/decomp/c/000/08001f04_FUN_08001f04.c` and
/// `ipod-decomp/decomp/osos.asm` @ 0x08001f04..0x08001f38.
///
/// Reads Timer E before validating `milliseconds` against the firmware's
/// `0x0041_8937` maximum (`floor(u32::MAX / 1000)`). An over-limit duration
/// returns `u32::MAX`; otherwise it subtracts `start` from the counter with
/// `u32` wrapping, compares the elapsed microseconds with the firmware's
/// wrapping `milliseconds * 1000`, and returns 0 or 1. Deviation: none; the
/// existing [`usec_timer_read`] seam supplies the counter on both targets.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn usec_timer_elapsed_millis(start: u32, milliseconds: u32) -> u32 {
    const MAX_MILLISECONDS: u32 = 0x0041_8937;

    // The firmware reads the hardware counter before checking the interval.
    let elapsed = unsafe { usec_timer_read() }.wrapping_sub(start);
    if milliseconds > MAX_MILLISECONDS {
        u32::MAX
    } else {
        (elapsed >= milliseconds.wrapping_mul(1_000)) as u32
    }
}



#[cfg(test)]
mod usec_timer_tests {
    use super::*;

    #[test]
    fn returns_the_raw_timer_e_counter_word_at_exact_b4_offset() {

        assert_eq!(TIMER_E_COUNTER as usize, 0x3c70_00b4);
        assert_eq!(
            TIMER_E_COUNTER as usize - TIMER_REGISTER_BASE,
            TIMER_E_COUNTER_OFFSET
        );

        for count in [0, 1, 0x1234_5678, u32::MAX] {
            HOST_USEC_TIMER_COUNT.store(count, Ordering::Relaxed);
            assert_eq!(unsafe { usec_timer_read() }, count);
        }
    }

    #[test]
    fn elapsed_predicate_honors_normal_and_wrapped_boundaries() {
        const INTERVAL: u32 = 10;

        for start in [1_000, u32::MAX - 4] {
            for (elapsed, expected) in [
                (INTERVAL - 1, false),
                (INTERVAL, true),
                (INTERVAL + 1, true),
            ] {
                HOST_USEC_TIMER_COUNT.store(start.wrapping_add(elapsed), Ordering::Relaxed);
                assert_eq!(
                    unsafe { usec_timer_elapsed(start, INTERVAL) },
                    expected,
                    "start={start:#010x}, elapsed={elapsed}"
                );
            }
        }
    }

    #[test]
    fn elapsed_millis_matches_boundary_wrapping_and_limit_conventions() {
        const MAX_MILLISECONDS: u32 = 0x0041_8937;

        HOST_USEC_TIMER_COUNT.store(10_999, Ordering::Relaxed);
        assert_eq!(unsafe { usec_timer_elapsed_millis(1_000, 10) }, 0);
        HOST_USEC_TIMER_COUNT.store(11_000, Ordering::Relaxed);
        assert_eq!(unsafe { usec_timer_elapsed_millis(1_000, 10) }, 1);

        let wrapped_start = u32::MAX - 499;
        HOST_USEC_TIMER_COUNT.store(500, Ordering::Relaxed);
        assert_eq!(
            unsafe { usec_timer_elapsed_millis(wrapped_start, 1) },
            1
        );

        let max_usecs = MAX_MILLISECONDS.wrapping_mul(1_000);
        HOST_USEC_TIMER_COUNT.store(max_usecs, Ordering::Relaxed);
        assert_eq!(
            unsafe { usec_timer_elapsed_millis(0, MAX_MILLISECONDS) },
            1
        );

        HOST_USEC_TIMER_COUNT.store(0, Ordering::Relaxed);
        assert_eq!(
            unsafe { usec_timer_elapsed_millis(0, MAX_MILLISECONDS + 1) },
            u32::MAX
        );
    }
}

/// +0x0: pending-list link — the next timer in the deadline-sorted
/// queue; 0 is the list end.
const NEXT: usize = 0x0;
/// +0x4: period/delay in milliseconds — the arm helper @ 0x0807a228
/// computes the deadline as tick() + period * 1000 from this word.
const PERIOD: usize = 0x4;
/// +0x8: deadline in tick units, written by `timer_arm` when the timer
/// is queued.
const DEADLINE: usize = 0x8;
/// +0x18: queued-state word — `timer_arm` stamps `TIMER_STATE_RUNNING`
/// ('run ') here when it links the timer into the pending queue.
const QUEUED_STATE: usize = 0x18;
/// +0x1c: armed flag — nonzero means the timer is already queued and
/// `timer_arm` returns immediately.
const ARMED: usize = 0x1c;
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

/// Original: global pending-list mutex object @ 0x089ca318, taken by
/// `timer_arm` around the validate/deadline/queue-insert sequence (a
/// different global from `TIMER_CLASS_MUTEX` — the arm helper never
/// touches 0x089cb294).
pub static mut TIMER_PENDING_MUTEX: Mutex = Mutex {
    sem_cell: core::ptr::null_mut(),
    unused: 0,
};

/// Original: pending-queue head cell @ 0x089ca300 — the link word of
/// the first queued timer, 0 when the queue is empty. `timer_arm`
/// rewrites it only when the new timer sorts ahead of every queued
/// entry.
pub static mut TIMER_PENDING_HEAD: u32 = 0;

/// Original: notify-handle cell @ 0x089ca310, handed to the notify
/// helper @ 0x0808e2a8 (which loads the handle from it). The handle is
/// installed at runtime by the not-yet-ported timer-service init;
/// modeled as a static so the value is observable/overridable (the
/// `TIMER_EXPIRY_CALLBACK` precedent).
pub static mut TIMER_NOTIFY_CELL: u32 = 0;

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
    /// at +0x1c is nonzero; otherwise, under the pending-list mutex,
    /// validates the timer, computes the deadline (+0x8 = tick() +
    /// period(+0x4) * 1000), inserts the timer into the pending queue
    /// sorted by deadline, and sets the armed flag. `timer_restart`
    /// tail-branches to it. Ported as `timer_arm`; that port is the
    /// wired default of this slot.
    pub arm_timer: unsafe extern "C" fn(timer: *mut u8),
    /// Trace/validate walk @ 0x0809e620(timer): the unlocked core of the
    /// trace/assert helper @ 0x08076954 (a walk over the object's words
    /// at +0x18/+0x1c). `timer_arm` calls it directly — the pending-list
    /// mutex is already held.
    pub trace_validate: unsafe extern "C" fn(timer: *mut u8),
    /// System tick getter @ 0x08056658 — a 4-byte thunk to 0x0836af80,
    /// which reads the free-running counter register @ 0x3C7000B4 in the
    /// S5L8702 timer block. Microsecond units: the deadline math is
    /// tick() + period_ms * 1000.
    pub tick: unsafe extern "C" fn() -> u32,
    /// Deadline comparator @ 0x082a243c(a, b) -> u32: returns 1 when the
    /// signed difference *a - *b is greater than 0, else 0. `timer_arm`
    /// calls it as (entry + 0x8, timer + 0x8), so a nonzero result
    /// breaks the queue walk and inserts the timer ahead of `entry`;
    /// equal deadlines keep FIFO order.
    pub compare_deadlines: unsafe extern "C" fn(a: *const u32, b: *const u32) -> u32,
    /// Notify helper @ 0x0808e2a8(cell): loads the handle from `cell`
    /// (@ 0x089ca310, modeled as `TIMER_NOTIFY_CELL`) and tail-branches
    /// to 0x080567a8, which posts through 0x08056328(1, handle) — kicks
    /// the queue owner so it re-evaluates the new head deadline. Runs on
    /// every locked path of `timer_arm`, queued or not.
    pub notify_pending: unsafe extern "C" fn(cell: *const u32),
    /// Timer constructor @ 0x0812c65c(timer, init_arg, config_word,
    /// callback_handle): runs the object-init helper @ 0x08076924 with
    /// (timer, class-descriptor word, init_arg, 0), writes an initial
    /// state word to +0x20, stores `config_word` at +0x24, and records
    /// `callback_handle` at +0x28 — substituting the current task's
    /// queue handle (0x080cb828()+0x1c) when `callback_handle` is 0.
    /// `timer_schedule_shim` tail-branches to it with its arguments
    /// rotated.
    pub construct_timer: unsafe extern "C" fn(
        timer: *mut u8,
        init_arg: u32,
        config_word: u32,
        callback_handle: usize,
    ),
}

// Default stubs: without the trace/cancel/construct layer these
// operations have no meaning. On real hardware TIMER_OPS must be
// installed before any timer is stopped through this port. The four
// `timer_arm` callees likewise default to stubs: trace/notify drop the
// call, `tick` reads 0, and the comparator never breaks the walk — so
// the stock-default `timer_arm` appends to the queue tail with deadline
// period * 1000; documented, harmless, and replaced by the ported
// helpers as they land.
unsafe extern "C" fn missing_trace_assert(_timer: *mut u8) {}
unsafe extern "C" fn missing_cancel_callback(
    _handle: usize,
    _callback_id: usize,
    _timer: *mut u8,
) -> u32 {
    0
}
unsafe extern "C" fn missing_construct_timer(
    _timer: *mut u8,
    _init_arg: u32,
    _config_word: u32,
    _callback_handle: usize,
) {
}
unsafe extern "C" fn missing_trace_validate(_timer: *mut u8) {}
unsafe extern "C" fn missing_tick() -> u32 {
    0
}
unsafe extern "C" fn missing_compare_deadlines(_a: *const u32, _b: *const u32) -> u32 {
    0
}
unsafe extern "C" fn missing_notify_pending(_cell: *const u32) {}

/// The wired defaults: the arm slot is the ported `timer_arm` below;
/// the not-yet-ported callees are the documented stubs above.
const DEFAULT_TIMER_OPS: TimerOps = TimerOps {
    trace_assert: missing_trace_assert,
    cancel_callback: missing_cancel_callback,
    arm_timer: timer_arm,
    construct_timer: missing_construct_timer,
    trace_validate: missing_trace_validate,
    tick: missing_tick,
    compare_deadlines: missing_compare_deadlines,
    notify_pending: missing_notify_pending,
};

/// The active timer-service dispatch table. Defaults to
/// `DEFAULT_TIMER_OPS`; replaced by host tests (mocks) and eventually by
/// the ported trace/cancel/construct layer. Written once at init on
/// target; tests serialize access.
pub static mut TIMER_OPS: TimerOps = DEFAULT_TIMER_OPS;

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

/// Link word -> timer pointer. On the ARM target a link word *is* the
/// absolute 32-bit pointer the original stored. In 64-bit host test
/// builds links are u32 offsets from `TEST_LINK_BASE` (see the module
/// header); 0 is the NULL list end in both worlds.
#[cfg(not(test))]
#[inline(always)]
fn link_to_ptr(link: u32) -> *mut u8 {
    link as *mut u8
}

#[cfg(test)]
static mut TEST_LINK_BASE: *mut u8 = core::ptr::null_mut();

#[cfg(test)]
#[inline(always)]
fn link_to_ptr(link: u32) -> *mut u8 {
    unsafe {
        if link == 0 {
            core::ptr::null_mut()
        } else {
            TEST_LINK_BASE.add(link as usize)
        }
    }
}

/// Timer pointer -> link word, the inverse of [`link_to_ptr`].
#[cfg(not(test))]
#[inline(always)]
fn ptr_to_link(timer: *mut u8) -> u32 {
    timer as u32
}

#[cfg(test)]
#[inline(always)]
fn ptr_to_link(timer: *mut u8) -> u32 {
    unsafe {
        if timer.is_null() {
            0
        } else {
            timer.offset_from(TEST_LINK_BASE) as u32
        }
    }
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

/// timer_arm — original: `FUN_0807a228` @ 0x0807a228 (176 bytes).
///
/// Arms `timer` onto the deadline-sorted pending queue. When the armed
/// flag at +0x1c is nonzero the original returns immediately
/// (`ldmiane`) — no lock, no notify — and so does this port. Otherwise,
/// under the pending-list mutex @ 0x089ca318: runs the trace/validate
/// walk @ 0x0809e620, and when the period word at +0x4 is nonzero
/// computes the deadline +0x8 = tick() + period * 1000 (the original
/// multiplies by 125 and shifts left 3 — identical mod 2^32), stamps
/// `TIMER_STATE_RUNNING` ('run ') into the queued-state word at +0x18,
/// and splices the timer into the singly-linked pending queue (head
/// cell @ 0x089ca300, link at +0x0) ahead of the first entry whose
/// deadline compares strictly greater (signed compare @ 0x082a243c on
/// the +0x8 words — equal deadlines keep FIFO order), then sets the
/// armed flag. The notify helper @ 0x0808e2a8 on the cell @ 0x089ca310
/// runs on BOTH the queued and the zero-period path (the original's
/// shared epilogue), and the unlock @ 0x0807f6a0 is the original's tail
/// branch. The `timer` argument is not NULL-checked, as in the
/// original. The four unported callees dispatch through `TimerOps` (see
/// the module header); the link-word representation is the
/// `heap/alloc_core.rs` offset-link precedent on host test builds.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_arm(timer: *mut u8) {
    if word(timer, ARMED) != 0 {
        return;
    }
    // Volatile, same rationale as TIMER_CLASS_MUTEX in timer_stop: the
    // cell is null-initialized and LLVM would otherwise fold the load
    // and delete the whole mutex pair.
    let mut pending_mutex = core::ptr::addr_of!(TIMER_PENDING_MUTEX).read_volatile();
    mutex_lock(&mut pending_mutex);
    let ops = timer_ops();
    (ops.trace_validate)(timer);
    let period = word(timer, PERIOD);
    if period != 0 {
        let deadline = (ops.tick)().wrapping_add(period.wrapping_mul(1000));
        set_word(timer, DEADLINE, deadline);
        set_word(timer, QUEUED_STATE, TIMER_STATE_RUNNING);
        let mut prev: *mut u8 = core::ptr::null_mut();
        let mut entry =
            link_to_ptr(core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).read_volatile());
        while !entry.is_null() {
            if (ops.compare_deadlines)(
                entry.add(DEADLINE).cast::<u32>(),
                timer.add(DEADLINE).cast::<u32>(),
            ) != 0
            {
                break;
            }
            prev = entry;
            entry = link_to_ptr(word(entry, NEXT));
        }
        // Store order as in the original: predecessor/head link first,
        // then the armed flag, then the timer's own link.
        if prev.is_null() {
            core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(ptr_to_link(timer));
        } else {
            set_word(prev, NEXT, ptr_to_link(timer));
        }
        set_word(timer, ARMED, 1);
        set_word(timer, NEXT, ptr_to_link(entry));
    }
    (ops.notify_pending)(core::ptr::addr_of_mut!(TIMER_NOTIFY_CELL));
    mutex_unlock(&mut pending_mutex);
}
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

/// timer_start_after — original: `FUN_0812c63c` @ 0x0812c63c (32 bytes).
///
/// Stops `timer` (the ported `timer_stop` @ 0x0812c6b0), then
/// tail-branches to `timer_set_delay` @ 0x080744c0 with the timer and
/// `delay` — the delay is preserved in r5 across the stop, which is
/// what marks it as the delay/deadline. Unlike `timer_restart` this
/// does NOT write the 'run ' state word or arm the timer; it only
/// stops and reprograms the period. The Ghidra signature is `void`:
/// the tail call's r0 is `timer_set_delay`'s leftover, not the timer,
/// so the scouted `u8 *` return is corrected to `void` (the
/// `timer_restart` precedent).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_start_after(timer: *mut u8, delay: u32) {
    timer_stop(timer);
    timer_set_delay(timer, delay);
}

/// timer_schedule_shim — original: `FUN_0811108c` @ 0x0811108c (20
/// bytes).
///
/// Pure argument plumbing in front of the timer constructor @
/// 0x0812c65c: rotates the register arguments (r0 -> r2, r1 -> r0,
/// r2 -> r1) and tail-branches, so the constructor sees
/// (timer, init_arg, config_word, callback_handle). The fourth argument
/// rides through in r3 untouched — every one of the 64 `bl` call sites
/// sets r3 (to 0) immediately before the branch, and the constructor
/// consumes it as the callback-queue handle — so the scouted
/// three-argument signature is corrected to four. The return type is
/// corrected from the scouted `u32` to `void`: the tail call's r0 is
/// the constructor's leftover, not a result (the `timer_restart`
/// precedent). The exact semantics of `config_word` (stored verbatim at
/// +0x24) and `init_arg` (forwarded verbatim to the object-init helper
/// @ 0x08076924) are not yet identified; the names reflect the data
/// flow, nothing more.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timer_schedule_shim(
    config_word: u32,
    timer: *mut u8,
    init_arg: u32,
    callback_handle: usize,
) {
    // Reads the fn-pointer field directly rather than going through
    // `timer_ops()`: with the whole-table volatile read, LLVM's ARM
    // sibling-call lowering drops the argument rotation and the call
    // target entirely (observed: the port tail-branched to r1 — the
    // `timer` argument). The single-field read sidesteps the ldrd
    // pair-load that triggers it.
    let construct_timer =
        core::ptr::addr_of!(TIMER_OPS.construct_timer).read_volatile();
    construct_timer(timer, init_arg, config_word, callback_handle);
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
        Construct(usize, u32, u32, usize),
        Validate(usize),
        Tick,
        Compare(u32, u32),
        Notify(usize),
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
    /// Same for the pending-list mutex `timer_arm` takes.
    const PENDING_MOCK_HANDLE: u32 = 0x71e0_0002;

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
    unsafe extern "C" fn mock_construct(
        timer: *mut u8,
        init_arg: u32,
        config_word: u32,
        callback_handle: usize,
    ) {
        record(Call::Construct(
            timer as usize,
            init_arg,
            config_word,
            callback_handle,
        ));
    }
    unsafe extern "C" fn mock_sema_wait(handle: u32) {
        record(Call::Wait(handle));
    }
    unsafe extern "C" fn mock_sema_signal(handle: u32) {
        record(Call::Signal(handle));
    }
    unsafe extern "C" fn mock_validate(timer: *mut u8) {
        record(Call::Validate(timer as usize));
    }
    unsafe extern "C" fn mock_tick() -> u32 {
        record(Call::Tick);
        unsafe { MOCK_TICK }
    }
    /// The mock comparator implements the original @ 0x082a243c exactly:
    /// 1 when the signed difference *a - *b is > 0, else 0.
    unsafe extern "C" fn mock_compare(a: *const u32, b: *const u32) -> u32 {
        let (a, b) = unsafe { (*a, *b) };
        record(Call::Compare(a, b));
        (a.wrapping_sub(b) as i32 > 0) as u32
    }
    unsafe extern "C" fn mock_notify(cell: *const u32) {
        record(Call::Notify(cell as usize));
    }

    static mut MOCK_TICK: u32 = 0;

    const MOCK_TIMER_OPS: TimerOps = TimerOps {
        trace_assert: mock_trace,
        cancel_callback: mock_cancel,
        arm_timer: mock_arm,
        construct_timer: mock_construct,
        trace_validate: mock_validate,
        tick: mock_tick,
        compare_deadlines: mock_compare,
        notify_pending: mock_notify,
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
            core::ptr::addr_of_mut!(TIMER_PENDING_MUTEX).write_volatile(Mutex {
                sem_cell: core::ptr::addr_of_mut!(PENDING_MUTEX_CELL),
                unused: 0,
            });
            PENDING_MUTEX_CELL = PENDING_MOCK_HANDLE;
            core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(0);
            core::ptr::addr_of_mut!(TIMER_NOTIFY_CELL).write_volatile(0);
            MOCK_TICK = 0;
            // Zero the arena and rebase the offset links at it.
            TEST_LINK_BASE = core::ptr::addr_of_mut!(ARENA) as *mut u8;
            TEST_LINK_BASE.write_bytes(0, ARENA_SIZE);
        }
        guard
    }

    static mut CLASS_MUTEX_CELL: u32 = 0;
    static mut PENDING_MUTEX_CELL: u32 = 0;

    /// Link arena for the pending-queue tests: host builds store list
    /// links as u32 offsets from `TEST_LINK_BASE` (see the module
    /// header), so every timer handed to `timer_arm` lives here.
    const ARENA_SIZE: usize = 0x200;

    #[repr(align(4))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);

    /// Arena timer at byte `offset` with the given period word; every
    /// other word starts zeroed (mock_env just cleared the arena).
    /// `offset` must be nonzero: in the offset-link representation 0 is
    /// the NULL list end, so a linkable timer cannot live at offset 0.
    unsafe fn arena_timer(offset: usize, period: u32) -> *mut u8 {
        let timer = unsafe { TEST_LINK_BASE.add(offset) };
        unsafe { set_word(timer, PERIOD, period) };
        timer
    }

    /// Pre-queued arena timer: deadline and armed flag set, link word
    /// `next` (a link, not a pointer).
    unsafe fn queued_timer(offset: usize, deadline: u32, next: u32) -> *mut u8 {
        let timer = arena_timer(offset, 0);
        unsafe {
            set_word(timer, DEADLINE, deadline);
            set_word(timer, ARMED, 1);
            set_word(timer, NEXT, next);
        }
        timer
    }

    fn pending_head() -> *mut u8 {
        link_to_ptr(unsafe { core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).read_volatile() })
    }

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

    /// Expired timer: start_after runs the full stop sequence (trace,
    /// lock, cancel, unlock), then the set_delay tail (trace again,
    /// store the delay) — in that order, matching the original's
    /// `bl timer_stop` followed by the tail branch.
    #[test]
    fn start_after_expired_timer_stops_then_sets_delay() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_EXPIRED, 0x08A0_1234);
        let timer_ptr = timer.ptr();
        unsafe { timer_start_after(timer_ptr, 500) };
        assert_eq!(
            calls(),
            vec![
                Call::Trace(timer_ptr as usize),
                Call::Wait(MOCK_HANDLE),
                Call::Cancel(0x08A0_1234, 0x0812_16b4, timer_ptr as usize),
                Call::Signal(MOCK_HANDLE),
                Call::Trace(timer_ptr as usize),
            ]
        );
        assert_eq!(timer.state(), TIMER_STATE_STOPPED);
        assert_eq!(timer.period(), 500);
    }

    /// The delay survives the stop untouched (the original parks it in
    /// r5 across `bl timer_stop`): a stopped timer gets exactly the
    /// requested delay, and the store happens after the stop's unlock.
    #[test]
    fn start_after_preserves_the_delay_across_the_stop() {
        let _lock = mock_env();
        static mut PROBED_TIMER: *const MockTimer = core::ptr::null();
        static mut PERIOD_AT_SIGNAL: u32 = 0xdead_beef;
        unsafe extern "C" fn probing_signal(handle: u32) {
            record(Call::Signal(handle));
            unsafe { PERIOD_AT_SIGNAL = (*PROBED_TIMER).period() };
        }
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0);
        unsafe {
            PROBED_TIMER = &timer;
            let mut rom = core::ptr::addr_of!(ROM_KERNEL).read_volatile();
            rom.sema_signal = probing_signal;
            *core::ptr::addr_of_mut!(ROM_KERNEL) = rom;
            timer_start_after(timer.ptr(), 0x1f4);
            assert_eq!(PERIOD_AT_SIGNAL, 0, "delay stored only after the stop");
        }
        assert_eq!(timer.period(), 0x1f4);
    }

    /// Unlike timer_restart, start_after never writes 'run ' and never
    /// arms: only the state word (stop's 'stop') and the period word
    /// change, and the arm helper is not called.
    #[test]
    fn start_after_touches_only_state_and_period() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_RUNNING, 0x08A0_7777);
        let before = timer.bytes;
        unsafe { timer_start_after(timer.ptr(), 0x7d) };
        let mut expected = before;
        expected[STATE..STATE + 4].copy_from_slice(&TIMER_STATE_STOPPED.to_le_bytes());
        expected[PERIOD..PERIOD + 4].copy_from_slice(&0x7du32.to_le_bytes());
        assert_eq!(timer.bytes, expected, "only state and period change");
        assert!(
            calls().iter().all(|c| !matches!(c, Call::Arm(_))),
            "start_after must not arm the timer"
        );
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
    fn restart_touches_only_the_state_word() {        let _lock = mock_env();
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

    /// The whole function is the rotation: the constructor receives
    /// exactly (timer, init_arg, config_word, callback_handle) — the
    /// original's r0 -> r2, r1 -> r0, r2 -> r1 with r3 untouched.
    #[test]
    fn shim_rotates_arguments_into_the_constructor() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_STOPPED, 0);
        let timer_ptr = timer.ptr();
        unsafe { timer_schedule_shim(0xc0ff_ee11, timer_ptr, 0x0b1e_f00d, 0x08a0_4242) };
        assert_eq!(
            calls(),
            vec![Call::Construct(
                timer_ptr as usize,
                0x0b1e_f00d,
                0xc0ff_ee11,
                0x08a0_4242,
            )]
        );
    }

    /// r3 rides through untouched: the call sites' zero handle reaches
    /// the constructor as zero (where the original substitutes the
    /// current task's queue), and a nonzero handle is passed as-is.
    #[test]
    fn shim_forwards_the_callback_handle_verbatim() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_STOPPED, 0);
        let timer_ptr = timer.ptr();
        unsafe { timer_schedule_shim(7, timer_ptr, 9, 0) };
        unsafe { timer_schedule_shim(8, timer_ptr, 10, 0x080c_b828) };
        assert_eq!(
            calls(),
            vec![
                Call::Construct(timer_ptr as usize, 9, 7, 0),
                Call::Construct(timer_ptr as usize, 10, 8, 0x080c_b828),
            ]
        );
    }

    /// The shim itself touches nothing: no trace, no mutex, no word of
    /// the timer object — it is plumbing and nothing else.
    #[test]
    fn shim_has_no_side_effects_of_its_own() {
        let _lock = mock_env();
        let mut timer = MockTimer::new(TIMER_STATE_EXPIRED, 0x08A0_1234);
        let before = timer.bytes;
        unsafe { timer_schedule_shim(1, timer.ptr(), 2, 3) };
        assert_eq!(timer.bytes, before, "the shim must not touch the object");
        assert_eq!(
            calls().iter().filter(|c| !matches!(c, Call::Construct(..))).count(),
            0,
            "no trace/lock/cancel/arm around the construct call"
        );
    }

    /// The arm slot's wired default is the ported timer_arm itself —
    /// the stub is gone.
    #[test]
    fn arm_slot_defaults_to_the_port() {
        let _lock = mock_env();
        assert_eq!(
            DEFAULT_TIMER_OPS.arm_timer as usize,
            timer_arm as usize,
            "the arm dispatch slot must default to the ported timer_arm"
        );
    }

    /// Armed flag set: the whole function is the early return — no
    /// lock, no validate, no notify, and not a word of the timer or the
    /// queue head changes.
    #[test]
    fn armed_timer_is_a_no_op() {
        let _lock = mock_env();
        let timer = unsafe { arena_timer(0x100, 100) };
        unsafe { set_word(timer, ARMED, 1) };
        unsafe { timer_arm(timer) };
        assert_eq!(calls(), vec![], "an armed timer must not touch anything");
        assert_eq!(pending_head(), core::ptr::null_mut());
        unsafe {
            assert_eq!(word(timer, DEADLINE), 0);
            assert_eq!(word(timer, NEXT), 0);
        }
    }

    /// Empty queue: deadline = tick + period * 1000 lands at +0x8, the
    /// queued-state word gets 'run ', the armed flag is set, the timer
    /// becomes the head with a NULL link — validate/tick/notify and the
    /// pending-mutex pair run in the original's order.
    #[test]
    fn arm_computes_the_deadline_and_takes_the_head() {
        let _lock = mock_env();
        unsafe { MOCK_TICK = 65_536 };
        let timer = unsafe { arena_timer(0x100, 500) };
        unsafe { timer_arm(timer) };
        unsafe {
            assert_eq!(word(timer, DEADLINE), 65_536 + 500 * 1000);
            assert_eq!(word(timer, QUEUED_STATE), TIMER_STATE_RUNNING);
            assert_eq!(word(timer, ARMED), 1);
            assert_eq!(word(timer, NEXT), 0, "sole entry ends the list");
        }
        assert_eq!(pending_head(), timer);
        assert_eq!(
            calls(),
            vec![
                Call::Wait(PENDING_MOCK_HANDLE),
                Call::Validate(timer as usize),
                Call::Tick,
                Call::Notify(core::ptr::addr_of_mut!(TIMER_NOTIFY_CELL) as usize),
                Call::Signal(PENDING_MOCK_HANDLE),
            ]
        );
    }

    /// Sorted insertion: a timer whose deadline falls between two queued
    /// entries is spliced between them; the comparator sees
    /// (entry.deadline, timer.deadline) pairs in walk order.
    #[test]
    fn arm_inserts_sorted_by_deadline() {
        let _lock = mock_env();
        let b = unsafe { queued_timer(0x80, 3000, 0) };
        let a = unsafe { queued_timer(0x40, 1000, ptr_to_link(b)) };
        unsafe { core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(ptr_to_link(a)) };
        let timer = unsafe { arena_timer(0x100, 2) }; // deadline 2000
        unsafe { timer_arm(timer) };
        assert_eq!(pending_head(), a, "head unchanged");
        unsafe {
            assert_eq!(link_to_ptr(word(a, NEXT)), timer);
            assert_eq!(link_to_ptr(word(timer, NEXT)), b);
            assert_eq!(word(b, NEXT), 0);
            assert_eq!(word(timer, DEADLINE), 2000);
        }
        let compares: Vec<_> = calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Compare(a, b) => Some((a, b)),
                _ => None,
            })
            .collect();
        assert_eq!(compares, vec![(1000, 2000), (3000, 2000)]);
    }

    /// A deadline ahead of every queued entry rewrites the head cell and
    /// links the old head behind the new timer.
    #[test]
    fn arm_inserts_ahead_of_the_head() {
        let _lock = mock_env();
        let a = unsafe { queued_timer(0x40, 2000, 0) };
        unsafe { core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(ptr_to_link(a)) };
        let timer = unsafe { arena_timer(0x100, 1) }; // deadline 1000
        unsafe { timer_arm(timer) };
        assert_eq!(pending_head(), timer);
        unsafe {
            assert_eq!(link_to_ptr(word(timer, NEXT)), a);
            assert_eq!(word(a, NEXT), 0);
        }
    }

    /// Equal deadline: the compare is strictly-greater, so the new timer
    /// sorts behind the existing entry — FIFO for ties.
    #[test]
    fn arm_appends_after_an_equal_deadline() {
        let _lock = mock_env();
        let a = unsafe { queued_timer(0x40, 2000, 0) };
        unsafe { core::ptr::addr_of_mut!(TIMER_PENDING_HEAD).write_volatile(ptr_to_link(a)) };
        let timer = unsafe { arena_timer(0x100, 2) }; // deadline 2000
        unsafe { timer_arm(timer) };
        assert_eq!(pending_head(), a);
        unsafe {
            assert_eq!(link_to_ptr(word(a, NEXT)), timer);
            assert_eq!(word(timer, NEXT), 0);
        }
    }

    /// Period zero: validate and notify still run and the mutex pair
    /// brackets them (the original's shared epilogue), but no tick is
    /// read, no deadline/queued-state/armed word is written, and the
    /// queue is untouched.
    #[test]
    fn zero_period_skips_the_queue_but_still_notifies() {
        let _lock = mock_env();
        let timer = unsafe { arena_timer(0x100, 0) };
        unsafe { timer_arm(timer) };
        assert_eq!(
            calls(),
            vec![
                Call::Wait(PENDING_MOCK_HANDLE),
                Call::Validate(timer as usize),
                Call::Notify(core::ptr::addr_of_mut!(TIMER_NOTIFY_CELL) as usize),
                Call::Signal(PENDING_MOCK_HANDLE),
            ]
        );
        assert_eq!(pending_head(), core::ptr::null_mut());
        unsafe {
            assert_eq!(word(timer, DEADLINE), 0);
            assert_eq!(word(timer, QUEUED_STATE), 0);
            assert_eq!(word(timer, ARMED), 0);
        }
    }

    /// The deadline wraps mod 2^32 exactly like the original's
    /// 32-bit mul/shift/add.
    #[test]
    fn deadline_arithmetic_wraps() {
        let _lock = mock_env();
        unsafe { MOCK_TICK = 0xffff_ff00 };
        let timer = unsafe { arena_timer(0x100, 4) }; // +4000 wraps
        unsafe { timer_arm(timer) };
        unsafe {
            assert_eq!(
                word(timer, DEADLINE),
                0xffff_ff00u32.wrapping_add(4000)
            );
        }
    }
}
