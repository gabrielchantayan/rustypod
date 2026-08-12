//! I2C0 bus-idle wait @ 0x080003b8 — the status-clear wait behind
//! `startup_wait_for_status_clear` (runtime/startup_wait.rs).
//!
//! The polled register is the S5L8702 I2C bus-0 controller at physical
//! 0x3c60_0000 (Rockbox `s5l87xx.h`: `IIC_BASE`; the block sits between
//! SYSCON @ 0x3c50_0000 and TIMER @ 0x3c70_0000). Offset +0x04 is the
//! Samsung `IICSTAT` control/status word; bit 5 (`IICSTAT[5]`) is the
//! bus-busy status the original tests. The sibling routine @ 0x08000428
//! polls the same `IICSTAT` bit together with `IICSTA2` (+0x20) bit 8 —
//! the s5l8702 byte-transferred interrupt flag — corroborating the I2C
//! identification. Timeout units are microseconds: the deadline helpers
//! are the ported Timer E microsecond counter pair
//! (`usec_timer_read`/`usec_timer_elapsed`, drivers/timer.rs), and the
//! only caller passes 100,000 (100 ms).

use crate::drivers::interrupts::cpsr_irq_enabled;
use crate::drivers::timer::{usec_timer_elapsed, usec_timer_read};

/// S5L8702 I2C bus-0 controller base (the firmware literal at 0x08000500).
const I2C0_REGISTER_BASE: usize = 0x3c60_0000;
/// `IICSTAT` control/status offset within the controller.
const I2C0_STAT_OFFSET: usize = 0x04;
/// Physical address of the I2C0 `IICSTAT` word.
const I2C0_STAT: *const u32 = (I2C0_REGISTER_BASE + I2C0_STAT_OFFSET) as *const u32;
/// `IICSTAT[5]`: bus-busy status (original: `tst r0, #0x20`).
pub const I2C0_STAT_BUSY: u32 = 0x20;
/// The status returned when the bus is still busy after the timeout
/// (original: `movne r5, #0x15`) — the I2C family's timeout code; the
/// struct-tm time getter FUN_0806418c maps this same 0x15 apart from
/// other read errors.
pub const I2C0_IDLE_TIMEOUT: u32 = 0x15;

/// Load address of the unported RTXC task-delay gateway (selector 0x14)
/// the original calls as `task_delay(0, 1)` when IRQs are enabled.
#[cfg(target_os = "none")]
const ROM_TASK_DELAY: usize = 0x0800_3d44;

/// The callee boundary of the original routine.
#[derive(Clone, Copy)]
pub struct I2c0IdleOps {
    /// I2C0 `IICSTAT` read (default: volatile MMIO on target, the
    /// driver-local host seam otherwise).
    pub stat_read: unsafe extern "C" fn() -> u32,
    /// Microsecond counter read (default: the ported `usec_timer_read`).
    pub timer_read: unsafe extern "C" fn() -> u32,
    /// Elapsed predicate, 0/1 (default: the ported `usec_timer_elapsed`).
    pub timer_elapsed: unsafe extern "C" fn(start: u32, timeout_usec: u32) -> u32,
    /// CPSR IRQ-enabled predicate (default: the ported `cpsr_irq_enabled`).
    pub irq_enabled: unsafe extern "C" fn() -> u32,
    /// RTXC task-delay gateway (default: the ROM routine on target, a
    /// no-op stub on hosts).
    pub task_delay: unsafe extern "C" fn(unused: u32, ticks: u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_stat_read() -> u32 {
    core::ptr::read_volatile(I2C0_STAT)
}

/// Deterministic driver-local replacement for `IICSTAT` on hosts, where
/// 0x3c60_0004 is not mapped. Reset value 0: bus idle.
#[cfg(not(target_os = "none"))]
static HOST_I2C0_STAT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_stat_read() -> u32 {
    HOST_I2C0_STAT.load(core::sync::atomic::Ordering::Relaxed)
}

/// 0/1 adapter over the ported boolean elapsed predicate.
unsafe extern "C" fn default_timer_elapsed(start: u32, timeout_usec: u32) -> u32 {
    u32::from(unsafe { usec_timer_elapsed(start, timeout_usec) })
}

/// On target the default reaches the original ROM gateway, exactly like
/// the stock routine's `bl 0x08003d44`.
#[cfg(target_os = "none")]
unsafe extern "C" fn default_task_delay(unused: u32, ticks: u32) {
    let gateway: unsafe extern "C" fn(u32, u32) = core::mem::transmute(ROM_TASK_DELAY);
    gateway(unused, ticks);
}

/// Hosts have no RTXC gateway; the delay is a scheduler hint that does
/// not affect the wait's result, so the host default is a no-op.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_task_delay(_unused: u32, _ticks: u32) {}

/// Runtime integration seam for the original callees. Shipped defaults
/// are the ported helpers (and the ROM gateway on target); host tests
/// install recorders.
pub static mut I2C0_IDLE_OPS: I2c0IdleOps = I2c0IdleOps {
    stat_read: default_stat_read,
    timer_read: usec_timer_read,
    timer_elapsed: default_timer_elapsed,
    irq_enabled: cpsr_irq_enabled,
    task_delay: default_task_delay,
};

/// Reads the dispatch table (volatile — same rationale as every dispatch
/// table: a build in which nothing swaps it must not constant-fold the
/// defaults in).
#[inline(always)]
fn i2c0_idle_ops() -> I2c0IdleOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2C0_IDLE_OPS)) }
}

/// i2c0_wait_bus_idle — original: `FUN_080003b8` @ 0x080003b8 (112
/// bytes). Reference: `ipod-decomp/decomp/c/000/080003b8_FUN_080003b8.c`
/// and `ipod-decomp/decomp/osos.asm` @ 0x080003b8..0x08000424.
///
/// Waits for the I2C0 bus-busy bit (`IICSTAT[5]`) to clear. If the bus is
/// already idle the routine returns 0 without touching the timer (the
/// `beq 0x08000420` fast path). Otherwise it snapshots the microsecond
/// counter once, then polls: re-read `IICSTAT`, stop with success when
/// busy cleared; stop when `usec_timer_elapsed(start, timeout_usec)`
/// reports the deadline passed; between polls, when IRQs are enabled,
/// yield through the RTXC task-delay gateway as `task_delay(0, 1)` (the
/// `blne 0x08003d44`). After the loop a final `IICSTAT` re-read decides
/// the result: still busy returns [`I2C0_IDLE_TIMEOUT`] (0x15), clear
/// returns 0 — so a bus that clears exactly at the deadline still
/// reports success.
///
/// # Deviation
///
/// The four callees and the `IICSTAT` read dispatch through the
/// [`I2C0_IDLE_OPS`] slot (the house ops-slot pattern): the shipped
/// defaults are the ported `usec_timer_read`, `usec_timer_elapsed` and
/// `cpsr_irq_enabled`, plus the ROM task-delay gateway on target (a
/// no-op stub on hosts, where the gateway is unreachable). Target builds
/// perform the original volatile MMIO read of 0x3c60_0004; host builds
/// read the deterministic driver-local seam (the drivers/pwrcon
/// precedent), because the physical register is unmapped. The algorithm
/// — poll order, delay placement, final re-read, result codes — is the
/// original's.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2c0_wait_bus_idle(timeout_usec: u32) -> u32 {
    let ops = i2c0_idle_ops();
    let mut status = 0;
    if (ops.stat_read)() & I2C0_STAT_BUSY != 0 {
        let start = (ops.timer_read)();
        loop {
            if (ops.stat_read)() & I2C0_STAT_BUSY == 0 {
                break;
            }
            if (ops.timer_elapsed)(start, timeout_usec) != 0 {
                break;
            }
            if (ops.irq_enabled)() != 0 {
                (ops.task_delay)(0, 1);
            }
        }
        if (ops.stat_read)() & I2C0_STAT_BUSY != 0 {
            status = I2C0_IDLE_TIMEOUT;
        }
    }
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that reprogram the global dispatch table.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    static mut STAT_WORD: u32 = 0;
    /// Stat-read count after which the busy bit clears (u32::MAX: never).
    static mut STAT_CLEAR_AFTER: u32 = 0;
    static mut STAT_READS: u32 = 0;
    static mut TIMER_READS: u32 = 0;
    static mut ELAPSED_CALLS: u32 = 0;
    /// Elapsed-call count at which the deadline reports passed.
    static mut ELAPSED_PASS_AT: u32 = 0;
    static mut IRQ_WORD: u32 = 0;
    static mut DELAY_CALLS: u32 = 0;
    static mut DELAY_ARGS: (u32, u32) = (u32::MAX, u32::MAX);

    unsafe extern "C" fn mock_stat_read() -> u32 {
        STAT_READS += 1;
        if STAT_READS > STAT_CLEAR_AFTER {
            STAT_WORD &= !I2C0_STAT_BUSY;
        }
        STAT_WORD
    }

    unsafe extern "C" fn mock_timer_read() -> u32 {
        TIMER_READS += 1;
        0
    }

    unsafe extern "C" fn mock_timer_elapsed(_start: u32, _timeout_usec: u32) -> u32 {
        ELAPSED_CALLS += 1;
        (ELAPSED_CALLS >= ELAPSED_PASS_AT) as u32
    }

    unsafe extern "C" fn mock_irq_enabled() -> u32 {
        IRQ_WORD
    }

    unsafe extern "C" fn mock_task_delay(unused: u32, ticks: u32) {
        DELAY_CALLS += 1;
        DELAY_ARGS = (unused, ticks);
    }

    /// Installs the recording mocks with the given script and returns the
    /// lock guard; the guard's drop restores the shipped defaults.
    fn install_mocks(
        stat_word: u32,
        stat_clear_after: u32,
        elapsed_pass_at: u32,
        irq_word: u32,
    ) -> OpsGuard {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STAT_WORD = stat_word;
            STAT_CLEAR_AFTER = stat_clear_after;
            STAT_READS = 0;
            TIMER_READS = 0;
            ELAPSED_CALLS = 0;
            ELAPSED_PASS_AT = elapsed_pass_at;
            IRQ_WORD = irq_word;
            DELAY_CALLS = 0;
            DELAY_ARGS = (u32::MAX, u32::MAX);
            I2C0_IDLE_OPS = I2c0IdleOps {
                stat_read: mock_stat_read,
                timer_read: mock_timer_read,
                timer_elapsed: mock_timer_elapsed,
                irq_enabled: mock_irq_enabled,
                task_delay: mock_task_delay,
            };
        }
        OpsGuard { _lock: guard }
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                I2C0_IDLE_OPS = I2c0IdleOps {
                    stat_read: default_stat_read,
                    timer_read: usec_timer_read,
                    timer_elapsed: default_timer_elapsed,
                    irq_enabled: cpsr_irq_enabled,
                    task_delay: default_task_delay,
                };
            }
        }
    }

    /// A plain-data snapshot of the recording counters, so assertions
    /// never hold references to the mutable statics.
    #[derive(Debug)]
    struct Counts {
        stat_reads: u32,
        timer_reads: u32,
        elapsed_calls: u32,
        delay_calls: u32,
        delay_args: (u32, u32),
    }

    fn counts() -> Counts {
        unsafe {
            Counts {
                stat_reads: STAT_READS,
                timer_reads: TIMER_READS,
                elapsed_calls: ELAPSED_CALLS,
                delay_calls: DELAY_CALLS,
                delay_args: DELAY_ARGS,
            }
        }
    }

    #[test]
    fn already_idle_returns_zero_without_polling() {
        let _guard = install_mocks(0, u32::MAX, u32::MAX, 1);

        let result = unsafe { i2c0_wait_bus_idle(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.stat_reads, 1, "only the entry probe reads IICSTAT");
        assert_eq!(c.timer_reads, 0, "no timer snapshot when already idle");
        assert_eq!(c.elapsed_calls, 0);
        assert_eq!(c.delay_calls, 0);
    }

    #[test]
    fn busy_then_clear_returns_zero_and_delays_each_poll() {
        // Busy on stat reads 1..=3, clear from read 4; deadline never passes.
        let _guard = install_mocks(I2C0_STAT_BUSY, 3, u32::MAX, 1);

        let result = unsafe { i2c0_wait_bus_idle(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        // Entry probe, three in-loop busy reads (reads 2, 3 then the
        // cleared read 4), and the final confirming re-read.
        assert_eq!(c.stat_reads, 5);
        assert_eq!(c.timer_reads, 1, "the deadline is snapshotted once");
        assert_eq!(c.elapsed_calls, 2, "elapsed runs only while busy");
        assert_eq!(c.delay_calls, 2, "one yield per still-busy poll");
        assert_eq!(c.delay_args, (0, 1), "the stock task_delay(0, 1)");
    }

    #[test]
    fn busy_past_deadline_returns_timeout_status() {
        // Bus never clears; the deadline passes on the third elapsed call.
        let _guard = install_mocks(I2C0_STAT_BUSY, u32::MAX, 3, 1);

        let result = unsafe { i2c0_wait_bus_idle(100_000) };
        let c = counts();

        assert_eq!(result, I2C0_IDLE_TIMEOUT);
        // Entry probe, three in-loop busy reads, final re-read.
        assert_eq!(c.stat_reads, 5);
        assert_eq!(c.elapsed_calls, 3);
        assert_eq!(c.delay_calls, 2, "no yield once the deadline passed");
    }

    #[test]
    fn irqs_disabled_polls_without_yielding() {
        // Busy on reads 1..=2, clear from read 3; IRQs disabled.
        let _guard = install_mocks(I2C0_STAT_BUSY, 2, u32::MAX, 0);

        let result = unsafe { i2c0_wait_bus_idle(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.stat_reads, 4);
        assert_eq!(c.elapsed_calls, 1);
        assert_eq!(c.delay_calls, 0, "no yield while IRQs are disabled");
    }

    #[test]
    fn immediate_deadline_still_confirms_busy_before_timeout_status() {
        // Deadline already passed at the first elapsed call (e.g. a zero
        // timeout): one in-loop busy read, then the final re-read.
        let _guard = install_mocks(I2C0_STAT_BUSY, u32::MAX, 1, 1);

        let result = unsafe { i2c0_wait_bus_idle(0) };
        let c = counts();

        assert_eq!(result, I2C0_IDLE_TIMEOUT);
        assert_eq!(c.stat_reads, 3);
        assert_eq!(c.timer_reads, 1);
        assert_eq!(c.elapsed_calls, 1);
        assert_eq!(c.delay_calls, 0);
    }

    #[test]
    fn clearing_at_the_deadline_reports_success() {
        // Deadline passes on the first elapsed call, but the bus clears
        // before the final confirming re-read (read 3).
        let _guard = install_mocks(I2C0_STAT_BUSY, 2, 1, 1);

        let result = unsafe { i2c0_wait_bus_idle(100_000) };
        let c = counts();

        assert_eq!(result, 0, "the final re-read decides the result");
        assert_eq!(c.stat_reads, 3);
        assert_eq!(c.elapsed_calls, 1);
        assert_eq!(c.delay_calls, 0);
    }

    #[test]
    fn stat_constant_names_iicstat_at_i2c0_base_plus_4() {
        assert_eq!(I2C0_STAT as usize, 0x3c60_0004);
        assert_eq!(I2C0_STAT as usize - I2C0_REGISTER_BASE, I2C0_STAT_OFFSET);
    }

    #[test]
    fn shipped_defaults_read_the_host_stat_seam() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        HOST_I2C0_STAT.store(0, core::sync::atomic::Ordering::Relaxed);

        // Shipped defaults: host seam idle -> the entry fast path returns 0
        // without consulting the (frozen) host timer seam.
        let result = unsafe { i2c0_wait_bus_idle(100_000) };
        assert_eq!(result, 0);

        HOST_I2C0_STAT.store(I2C0_STAT_BUSY, core::sync::atomic::Ordering::Relaxed);
        let ops = i2c0_idle_ops();
        assert_eq!(
            unsafe { (ops.stat_read)() } & I2C0_STAT_BUSY,
            I2C0_STAT_BUSY,
            "the default stat reader observes the driver-local seam"
        );
        HOST_I2C0_STAT.store(0, core::sync::atomic::Ordering::Relaxed);
    }
}
