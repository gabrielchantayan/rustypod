//! Startup status-clear polling routines @ 0x080003b8 and 0x080004ec.
//!
//! The status word, timer pair, IRQ-state predicate, and RTXC yield gateway
//! are outside this port. Their target defaults retain the stock addresses;
//! host tests replace them through [`STARTUP_WAIT_OPS`].

/// Status word address loaded through the literal at 0x08000500, plus its
/// +0x04 status/control register offset.
const STARTUP_STATUS_WORD: *const u32 = 0x3c60_0004 as *const u32;
/// Status bit which keeps the stock poller active (`tst r0, #0x20`).
pub const STARTUP_STATUS_PENDING: u32 = 0x20;
/// Stock verdict when the final status read remains pending.
pub const STARTUP_STATUS_WAIT_TIMEOUT: u32 = 0x15;

/// Load addresses of the unported timing, IRQ-state, and scheduler helpers.
const ROM_TIMER_READ: usize = 0x0800_1edc;
const ROM_TIMER_ELAPSED: usize = 0x0800_1ee8;
const ROM_IRQ_ENABLED: usize = 0x0800_1e98;
const ROM_TASK_YIELD: usize = 0x0800_3d44;

/// The fixed timeout literal loaded by the wrapper at 0x080004ec.
pub const STARTUP_STATUS_WAIT_TICKS: u32 = 100_000;

/// Reads the pending-status word.
pub type StartupStatusReadFn = unsafe extern "C" fn() -> u32;
/// Reads the free-running timer used to establish the deadline.
pub type StartupTimerReadFn = unsafe extern "C" fn() -> u32;
/// Returns nonzero when `now - start` has reached `timeout_ticks`.
pub type StartupTimerElapsedFn = unsafe extern "C" fn(start: u32, timeout_ticks: u32) -> u32;
/// Returns nonzero only while IRQ delivery is enabled.
pub type StartupIrqEnabledFn = unsafe extern "C" fn() -> u32;
/// Gives the RTXC scheduler one tick (`task_delay(0, 1)`).
pub type StartupYieldFn = unsafe extern "C" fn(unused: u32, ticks: u32);

/// Runtime integration seams for `startup_wait_status_clear`.
#[derive(Clone, Copy)]
pub struct StartupWaitOps {
    pub status_read: StartupStatusReadFn,
    pub timer_read: StartupTimerReadFn,
    pub timer_elapsed: StartupTimerElapsedFn,
    pub irq_enabled: StartupIrqEnabledFn,
    pub task_yield: StartupYieldFn,
}

unsafe extern "C" fn rom_status_read() -> u32 {
    core::ptr::read_volatile(STARTUP_STATUS_WORD)
}

unsafe extern "C" fn rom_timer_read() -> u32 {
    let callee: StartupTimerReadFn = core::mem::transmute(ROM_TIMER_READ);
    callee()
}

unsafe extern "C" fn rom_timer_elapsed(start: u32, timeout_ticks: u32) -> u32 {
    let callee: StartupTimerElapsedFn = core::mem::transmute(ROM_TIMER_ELAPSED);
    callee(start, timeout_ticks)
}

unsafe extern "C" fn rom_irq_enabled() -> u32 {
    let callee: StartupIrqEnabledFn = core::mem::transmute(ROM_IRQ_ENABLED);
    callee()
}

unsafe extern "C" fn rom_task_yield(unused: u32, ticks: u32) {
    let callee: StartupYieldFn = core::mem::transmute(ROM_TASK_YIELD);
    callee(unused, ticks)
}

/// Direct-ROM defaults used on device; host tests replace this slot before use.
pub static mut STARTUP_WAIT_OPS: StartupWaitOps = StartupWaitOps {
    status_read: rom_status_read,
    timer_read: rom_timer_read,
    timer_elapsed: rom_timer_elapsed,
    irq_enabled: rom_irq_enabled,
    task_yield: rom_task_yield,
};

#[inline(always)]
unsafe fn startup_wait_ops() -> StartupWaitOps {
    core::ptr::read_volatile(core::ptr::addr_of!(STARTUP_WAIT_OPS))
}

/// startup_wait_status_clear — original: `FUN_080003b8` @ 0x080003b8
/// (112 bytes). Reference: `decomp/c/000/080003b8_FUN_080003b8.c` and
/// `decomp/osos.asm` @ 0x080003b8..0x08000424.
///
/// If [`STARTUP_STATUS_PENDING`] is already clear, returns zero without
/// reading the timer. Otherwise snapshots the timer, then repeatedly checks
/// the status before testing the deadline. Before each next poll it calls
/// `task_delay(0, 1)` only when IRQs are enabled. A final status read decides
/// the result, so a status clear concurrent with deadline expiry succeeds;
/// a still-pending status returns [`STARTUP_STATUS_WAIT_TIMEOUT`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn startup_wait_status_clear(timeout_ticks: u32) -> u32 {
    let ops = startup_wait_ops();
    if ((ops.status_read)() & STARTUP_STATUS_PENDING) == 0 {
        return 0;
    }

    let start = (ops.timer_read)();
    loop {
        if ((ops.status_read)() & STARTUP_STATUS_PENDING) == 0
            || (ops.timer_elapsed)(start, timeout_ticks) != 0
        {
            break;
        }
        if (ops.irq_enabled)() != 0 {
            (ops.task_yield)(0, 1);
        }
    }

    if ((ops.status_read)() & STARTUP_STATUS_PENDING) != 0 {
        STARTUP_STATUS_WAIT_TIMEOUT
    } else {
        0
    }
}

/// startup_wait_for_status_clear — original: `FUN_080004ec` @ 0x080004ec
/// (20 bytes). Reference: `decomp/c/000/080004ec_FUN_080004ec.c`.
///
/// Calls [`startup_wait_status_clear`] with 100,000 ticks, discards its return
/// value, then returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn startup_wait_for_status_clear() -> i32 {
    startup_wait_status_clear(STARTUP_STATUS_WAIT_TICKS);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut STATUS_VALUES: [u32; 4] = [0; 4];
    static mut STATUS_LEN: usize = 0;
    static mut STATUS_INDEX: usize = 0;
    static mut ELAPSED_VALUES: [u32; 2] = [0; 2];
    static mut ELAPSED_LEN: usize = 0;
    static mut ELAPSED_INDEX: usize = 0;
    static mut EVENTS: [u8; 12] = [0; 12];
    static mut EVENT_LEN: usize = 0;

    const STATUS_READ: u8 = 1;
    const TIMER_READ: u8 = 2;
    const TIMER_ELAPSED: u8 = 3;
    const IRQ_ENABLED: u8 = 4;
    const TASK_YIELD: u8 = 5;

    unsafe fn record(event: u8) {
        EVENTS[EVENT_LEN] = event;
        EVENT_LEN += 1;
    }

    unsafe extern "C" fn scripted_status_read() -> u32 {
        record(STATUS_READ);
        let index = STATUS_INDEX;
        STATUS_INDEX += 1;
        STATUS_VALUES[if index < STATUS_LEN { index } else { STATUS_LEN - 1 }]
    }

    unsafe extern "C" fn scripted_timer_read() -> u32 {
        record(TIMER_READ);
        0xfeed_beef
    }

    unsafe extern "C" fn scripted_timer_elapsed(_start: u32, _timeout_ticks: u32) -> u32 {
        record(TIMER_ELAPSED);
        let index = ELAPSED_INDEX;
        ELAPSED_INDEX += 1;
        ELAPSED_VALUES[if index < ELAPSED_LEN { index } else { ELAPSED_LEN - 1 }]
    }

    unsafe extern "C" fn irq_enabled() -> u32 {
        record(IRQ_ENABLED);
        1
    }

    unsafe extern "C" fn task_yield(_unused: u32, _ticks: u32) {
        record(TASK_YIELD);
    }

    unsafe fn install(status_values: &[u32], elapsed_values: &[u32]) -> StartupWaitOps {
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(STARTUP_WAIT_OPS));
        STATUS_VALUES = [0; 4];
        STATUS_VALUES[..status_values.len()].copy_from_slice(status_values);
        STATUS_LEN = status_values.len();
        STATUS_INDEX = 0;
        ELAPSED_VALUES = [0; 2];
        ELAPSED_VALUES[..elapsed_values.len()].copy_from_slice(elapsed_values);
        ELAPSED_LEN = elapsed_values.len();
        ELAPSED_INDEX = 0;
        EVENTS = [0; 12];
        EVENT_LEN = 0;
        STARTUP_WAIT_OPS = StartupWaitOps {
            status_read: scripted_status_read,
            timer_read: scripted_timer_read,
            timer_elapsed: scripted_timer_elapsed,
            irq_enabled,
            task_yield,
        };
        saved
    }

    unsafe fn events() -> &'static [u8] {
        &EVENTS[..EVENT_LEN]
    }

    #[test]
    fn already_clear_status_skips_the_timer_and_returns_zero() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install(&[0], &[1]);
            let result = startup_wait_status_clear(9);
            let log = events().to_vec();
            STARTUP_WAIT_OPS = saved;

            assert_eq!(result, 0);
            assert_eq!(log, [STATUS_READ]);
        }
    }

    #[test]
    fn yields_between_pending_polls_until_status_clears() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install(
                &[STARTUP_STATUS_PENDING, STARTUP_STATUS_PENDING, 0, 0],
                &[0],
            );
            let result = startup_wait_status_clear(9);
            let log = events().to_vec();
            STARTUP_WAIT_OPS = saved;

            assert_eq!(result, 0);
            assert_eq!(
                log,
                [
                    STATUS_READ,
                    TIMER_READ,
                    STATUS_READ,
                    TIMER_ELAPSED,
                    IRQ_ENABLED,
                    TASK_YIELD,
                    STATUS_READ,
                    STATUS_READ,
                ]
            );
        }
    }

    #[test]
    fn deadline_with_pending_status_returns_stock_timeout() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install(
                &[STARTUP_STATUS_PENDING, STARTUP_STATUS_PENDING, STARTUP_STATUS_PENDING],
                &[1],
            );
            let result = startup_wait_status_clear(9);
            let log = events().to_vec();
            STARTUP_WAIT_OPS = saved;

            assert_eq!(result, STARTUP_STATUS_WAIT_TIMEOUT);
            assert_eq!(
                log,
                [STATUS_READ, TIMER_READ, STATUS_READ, TIMER_ELAPSED, STATUS_READ]
            );
        }
    }

    #[test]
    fn final_status_read_wins_a_deadline_race() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install(&[STARTUP_STATUS_PENDING, STARTUP_STATUS_PENDING, 0], &[1]);
            let result = startup_wait_status_clear(9);
            STARTUP_WAIT_OPS = saved;

            assert_eq!(result, 0);
        }
    }

    #[test]
    fn wrapper_passes_its_fixed_timeout_and_discards_status() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = install(&[0], &[1]);
            let result = startup_wait_for_status_clear();
            let log = events().to_vec();
            STARTUP_WAIT_OPS = saved;

            assert_eq!(result, 0);
            assert_eq!(log, [STATUS_READ]);
        }
    }
}
