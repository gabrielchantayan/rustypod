//! I2C0 transfer-completion wait @ 0x08000428 — the timeout-and-flag
//! sibling of `i2c0_wait_bus_idle` (runtime/i2c0_idle.rs, original @
//! 0x080003b8).
//!
//! Both routines poll the S5L8702 I2C bus-0 controller at physical
//! 0x3c60_0000 (Rockbox `s5l87xx.h`: `IIC_BASE`). This one waits on two
//! status words: `IICSTAT` (+0x04) bit 5, the Samsung bus-busy status the
//! sibling tests, and `IICSTA2` (+0x20) bit 8, the s5l8702
//! byte-transferred interrupt flag. Where the sibling only waits, this
//! routine also finishes the transaction: it drains `IICCON` (+0x10) by
//! reading until the word reads zero, then sets the `IICSTA2` bit-8 flag
//! with a read-modify-write — the Samsung acknowledge-a-pending-interrupt
//! idiom. Timeout units are microseconds against the same ported Timer E
//! microsecond pair (`usec_timer_read`/`usec_timer_elapsed`,
//! drivers/timer.rs) the sibling uses.

use crate::drivers::interrupts::cpsr_irq_enabled;
use crate::drivers::timer::{usec_timer_elapsed, usec_timer_read};
use crate::runtime::i2c0_idle::{I2C0_IDLE_TIMEOUT, I2C0_REGISTER_BASE, I2C0_STAT_BUSY};

/// `IICSTAT` control/status offset within the controller (shared with
/// the sibling i2c0_wait_bus_idle, which owns the bit definitions).
const I2C0_STAT_OFFSET: usize = 0x04;
/// Physical address of the I2C0 `IICSTAT` word.
const I2C0_STAT: *const u32 = (I2C0_REGISTER_BASE + I2C0_STAT_OFFSET) as *const u32;
/// `IICCON` control-register offset within the controller.
const I2C0_CON_OFFSET: usize = 0x10;
/// Physical address of the I2C0 `IICCON` word.
const I2C0_CON: *const u32 = (I2C0_REGISTER_BASE + I2C0_CON_OFFSET) as *const u32;
/// `IICSTA2` second status-register offset within the controller.
const I2C0_STA2_OFFSET: usize = 0x20;
/// Physical address of the I2C0 `IICSTA2` word.
const I2C0_STA2: *const u32 = (I2C0_REGISTER_BASE + I2C0_STA2_OFFSET) as *const u32;
/// `IICSTA2[8]`: byte-transferred interrupt flag (original:
/// `tst r0, #0x100`; the epilogue's `orr r0, r0, #0x100`).
pub const I2C0_STA2_BYTE_DONE: u32 = 0x100;
/// The status returned when the confirming elapsed re-check after the
/// poll loop reports the deadline passed (original: `movne r4, #0x1f`)
/// — this routine's own timeout code, distinct from the I2C family's
/// [`I2C0_IDLE_TIMEOUT`] (0x15) it reuses for the still-busy race below.
pub const I2C0_TRANSFER_TIMEOUT: u32 = 0x1f;

/// Load address of the unported RTXC task-delay gateway (selector 0x14)
/// the original calls as `task_delay(0, 1)` when IRQs are enabled.
#[cfg(target_os = "none")]
const ROM_TASK_DELAY: usize = 0x0800_3d44;

/// The callee boundary of the original routine.
#[derive(Clone, Copy)]
pub struct I2c0TransferOps {
    /// I2C0 `IICSTAT` read (default: volatile MMIO on target, the
    /// driver-local host seam otherwise).
    pub stat_read: unsafe extern "C" fn() -> u32,
    /// I2C0 `IICSTA2` read (default: volatile MMIO on target, the
    /// driver-local host seam otherwise).
    pub sta2_read: unsafe extern "C" fn() -> u32,
    /// I2C0 `IICSTA2` write (default: volatile MMIO on target, the
    /// driver-local host seam otherwise).
    pub sta2_write: unsafe extern "C" fn(value: u32),
    /// I2C0 `IICCON` read (default: volatile MMIO on target, the
    /// driver-local host seam otherwise).
    pub con_read: unsafe extern "C" fn() -> u32,
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

/// Deterministic driver-local replacements for the I2C0 registers on
/// hosts, where 0x3c60_0000 is not mapped. Reset values 0: bus idle,
/// no byte-done flag, `IICCON` already drained.
#[cfg(not(target_os = "none"))]
static HOST_I2C0_STAT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_I2C0_STA2: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(not(target_os = "none"))]
static HOST_I2C0_CON: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_stat_read() -> u32 {
    HOST_I2C0_STAT.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_sta2_read() -> u32 {
    core::ptr::read_volatile(I2C0_STA2)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_sta2_read() -> u32 {
    HOST_I2C0_STA2.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_sta2_write(value: u32) {
    core::ptr::write_volatile(I2C0_STA2 as *mut u32, value);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_sta2_write(value: u32) {
    HOST_I2C0_STA2.store(value, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn default_con_read() -> u32 {
    core::ptr::read_volatile(I2C0_CON)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_con_read() -> u32 {
    HOST_I2C0_CON.load(core::sync::atomic::Ordering::Relaxed)
}

/// 0/1 adapter over the ported boolean elapsed predicate.
unsafe extern "C" fn default_timer_elapsed(start: u32, timeout_usec: u32) -> u32 {
    u32::from(unsafe { usec_timer_elapsed(start, timeout_usec) })
}

/// On target the default reaches the original ROM gateway, exactly like
/// the stock routine's `blne 0x08003d44`.
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
pub static mut I2C0_TRANSFER_OPS: I2c0TransferOps = I2c0TransferOps {
    stat_read: default_stat_read,
    sta2_read: default_sta2_read,
    sta2_write: default_sta2_write,
    con_read: default_con_read,
    timer_read: usec_timer_read,
    timer_elapsed: default_timer_elapsed,
    irq_enabled: cpsr_irq_enabled,
    task_delay: default_task_delay,
};

/// Reads the dispatch table (volatile — same rationale as every dispatch
/// table: a build in which nothing swaps it must not constant-fold the
/// defaults in).
#[inline(always)]
fn i2c0_transfer_ops() -> I2c0TransferOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2C0_TRANSFER_OPS)) }
}

/// i2c0_wait_transfer_done — original: `FUN_08000428` @ 0x08000428 (196
/// bytes). Reference: `ipod-decomp/decomp/c/000/08000428_FUN_08000428.c`
/// and `ipod-decomp/decomp/osos.asm` @ 0x08000428..0x080004e8.
///
/// Waits for the in-flight I2C0 transfer to complete: while the bus-busy
/// bit (`IICSTAT[5]`) is set AND the byte-transferred flag
/// (`IICSTA2[8]`) is clear, poll until either changes or the microsecond
/// deadline passes. If the bus is already idle — or the flag is already
/// set — the entry fast path (`beq`/`bne 0x080004cc`) skips the wait
/// entirely without snapshotting the timer. Otherwise the routine
/// snapshots the counter once, then polls `IICSTAT`, `IICSTA2` and the
/// elapsed predicate in that order, yielding through the RTXC task-delay
/// gateway as `task_delay(0, 1)` between polls whenever IRQs are enabled
/// (the `blne 0x08003d44`). After the loop a second elapsed call decides
/// the status: deadline passed returns [`I2C0_TRANSFER_TIMEOUT`] (0x1f);
/// otherwise a confirming re-read of both status words returns
/// [`I2C0_IDLE_TIMEOUT`] (0x15, the I2C family timeout code) when the
/// bus is still busy with the flag still clear — the race where the
/// in-loop elapsed call fired but the confirming call did not — and 0
/// when either completion condition now holds. On every path the routine
/// then drains `IICCON` (+0x10) by reading until the word reads zero,
/// and finally sets `IICSTA2[8]` with a read-modify-write before
/// returning the status.
///
/// # Deviation
///
/// The four callees and the three register accesses dispatch through the
/// [`I2C0_TRANSFER_OPS`] slot (the house ops-slot pattern): the shipped
/// defaults are the ported `usec_timer_read`, `usec_timer_elapsed` and
/// `cpsr_irq_enabled`, plus the ROM task-delay gateway on target (a
/// no-op stub on hosts, where the gateway is unreachable). Target builds
/// perform the original volatile MMIO reads/writes at 0x3c60_0004/10/20;
/// host builds use deterministic driver-local seams (the drivers/pwrcon
/// precedent), because the physical registers are unmapped. The
/// algorithm — entry short-circuit order, poll order, delay placement,
/// the double elapsed check, status codes, drain loop, flag set — is the
/// original's.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2c0_wait_transfer_done(timeout_usec: u32) -> u32 {
    let ops = i2c0_transfer_ops();
    let mut status = 0;
    if (ops.stat_read)() & I2C0_STAT_BUSY != 0 && (ops.sta2_read)() & I2C0_STA2_BYTE_DONE == 0 {
        let start = (ops.timer_read)();
        loop {
            if (ops.stat_read)() & I2C0_STAT_BUSY == 0 {
                break;
            }
            if (ops.sta2_read)() & I2C0_STA2_BYTE_DONE != 0 {
                break;
            }
            if (ops.timer_elapsed)(start, timeout_usec) != 0 {
                break;
            }
            if (ops.irq_enabled)() != 0 {
                (ops.task_delay)(0, 1);
            }
        }
        if (ops.timer_elapsed)(start, timeout_usec) != 0 {
            status = I2C0_TRANSFER_TIMEOUT;
        } else if (ops.stat_read)() & I2C0_STAT_BUSY != 0
            && (ops.sta2_read)() & I2C0_STA2_BYTE_DONE == 0
        {
            status = I2C0_IDLE_TIMEOUT;
        }
    }
    while (ops.con_read)() != 0 {}
    let sta2 = (ops.sta2_read)();
    (ops.sta2_write)(sta2 | I2C0_STA2_BYTE_DONE);
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
    static mut STA2_WORD: u32 = 0;
    /// Sta2-read count after which the byte-done flag sets (u32::MAX:
    /// never). The epilogue's read-modify-write observes it too.
    static mut STA2_SET_AFTER: u32 = 0;
    /// Con-read count after which IICCON drains to zero (0: already
    /// drained).
    static mut CON_DRAIN_AFTER: u32 = 0;
    /// Bit (elapsed-call count - 1) of this mask is the call's 0/1
    /// result, so scripts can make the confirming re-check disagree with
    /// the in-loop call (the 0x15 race path).
    static mut ELAPSED_MASK: u64 = 0;
    static mut IRQ_WORD: u32 = 0;

    static mut STAT_READS: u32 = 0;
    static mut STA2_READS: u32 = 0;
    static mut STA2_WRITES: u32 = 0;
    static mut STA2_WRITTEN: u32 = 0;
    static mut CON_READS: u32 = 0;
    static mut TIMER_READS: u32 = 0;
    static mut ELAPSED_CALLS: u32 = 0;
    static mut DELAY_CALLS: u32 = 0;
    static mut DELAY_ARGS: (u32, u32) = (u32::MAX, u32::MAX);

    /// Monotonic event counter proving epilogue order: the drain
    /// completes before the flag write.
    static mut EVENT: u32 = 0;
    static mut CON_ZERO_EVENT: u32 = 0;
    static mut STA2_WRITE_EVENT: u32 = 0;

    unsafe extern "C" fn mock_stat_read() -> u32 {
        STAT_READS += 1;
        if STAT_READS > STAT_CLEAR_AFTER {
            STAT_WORD &= !I2C0_STAT_BUSY;
        }
        STAT_WORD
    }

    unsafe extern "C" fn mock_sta2_read() -> u32 {
        STA2_READS += 1;
        if STA2_READS > STA2_SET_AFTER {
            STA2_WORD |= I2C0_STA2_BYTE_DONE;
        }
        STA2_WORD
    }

    unsafe extern "C" fn mock_sta2_write(value: u32) {
        STA2_WRITES += 1;
        STA2_WRITTEN = value;
        STA2_WORD = value;
        EVENT += 1;
        STA2_WRITE_EVENT = EVENT;
    }

    unsafe extern "C" fn mock_con_read() -> u32 {
        CON_READS += 1;
        if CON_READS <= CON_DRAIN_AFTER {
            1
        } else {
            if CON_ZERO_EVENT == 0 {
                EVENT += 1;
                CON_ZERO_EVENT = EVENT;
            }
            0
        }
    }

    unsafe extern "C" fn mock_timer_read() -> u32 {
        TIMER_READS += 1;
        0
    }

    unsafe extern "C" fn mock_timer_elapsed(_start: u32, _timeout_usec: u32) -> u32 {
        ELAPSED_CALLS += 1;
        ((ELAPSED_MASK >> (ELAPSED_CALLS - 1)) & 1) as u32
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
        sta2_word: u32,
        sta2_set_after: u32,
        con_drain_after: u32,
        elapsed_mask: u64,
        irq_word: u32,
    ) -> OpsGuard {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            STAT_WORD = stat_word;
            STAT_CLEAR_AFTER = stat_clear_after;
            STA2_WORD = sta2_word;
            STA2_SET_AFTER = sta2_set_after;
            CON_DRAIN_AFTER = con_drain_after;
            ELAPSED_MASK = elapsed_mask;
            IRQ_WORD = irq_word;
            STAT_READS = 0;
            STA2_READS = 0;
            STA2_WRITES = 0;
            STA2_WRITTEN = u32::MAX;
            CON_READS = 0;
            TIMER_READS = 0;
            ELAPSED_CALLS = 0;
            DELAY_CALLS = 0;
            DELAY_ARGS = (u32::MAX, u32::MAX);
            EVENT = 0;
            CON_ZERO_EVENT = 0;
            STA2_WRITE_EVENT = 0;
            I2C0_TRANSFER_OPS = I2c0TransferOps {
                stat_read: mock_stat_read,
                sta2_read: mock_sta2_read,
                sta2_write: mock_sta2_write,
                con_read: mock_con_read,
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
                I2C0_TRANSFER_OPS = I2c0TransferOps {
                    stat_read: default_stat_read,
                    sta2_read: default_sta2_read,
                    sta2_write: default_sta2_write,
                    con_read: default_con_read,
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
        sta2_reads: u32,
        sta2_writes: u32,
        sta2_written: u32,
        con_reads: u32,
        timer_reads: u32,
        elapsed_calls: u32,
        delay_calls: u32,
        delay_args: (u32, u32),
        con_zero_event: u32,
        sta2_write_event: u32,
    }

    fn counts() -> Counts {
        unsafe {
            Counts {
                stat_reads: STAT_READS,
                sta2_reads: STA2_READS,
                sta2_writes: STA2_WRITES,
                sta2_written: STA2_WRITTEN,
                con_reads: CON_READS,
                timer_reads: TIMER_READS,
                elapsed_calls: ELAPSED_CALLS,
                delay_calls: DELAY_CALLS,
                delay_args: DELAY_ARGS,
                con_zero_event: CON_ZERO_EVENT,
                sta2_write_event: STA2_WRITE_EVENT,
            }
        }
    }

    #[test]
    fn already_idle_fast_path_drains_and_sets_flag() {
        let _guard = install_mocks(0, u32::MAX, 0, u32::MAX, 0, 0, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.stat_reads, 1, "only the entry probe reads IICSTAT");
        assert_eq!(c.timer_reads, 0, "no timer snapshot when already idle");
        assert_eq!(c.elapsed_calls, 0);
        assert_eq!(c.delay_calls, 0);
        assert_eq!(c.con_reads, 1, "the drain still runs on the fast path");
        assert_eq!(c.sta2_writes, 1);
        assert_eq!(c.sta2_written, I2C0_STA2_BYTE_DONE, "the epilogue sets the flag");
    }

    #[test]
    fn busy_then_flag_clear_at_entry_skips_wait() {
        // Bus busy but the byte-done flag is already set at entry: the
        // wait is skipped exactly like the already-idle fast path.
        let _guard = install_mocks(I2C0_STAT_BUSY, u32::MAX, I2C0_STA2_BYTE_DONE, u32::MAX, 0, 0, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.stat_reads, 1, "the busy bit does not force a wait on its own");
        assert_eq!(c.timer_reads, 0);
        assert_eq!(c.elapsed_calls, 0);
        assert_eq!(c.sta2_written, I2C0_STA2_BYTE_DONE);
    }

    #[test]
    fn busy_then_clear_returns_zero_and_delays_each_poll() {
        // Busy on stat reads 1..=3, clear from read 4; flag never sets;
        // deadline never passes.
        let _guard = install_mocks(I2C0_STAT_BUSY, 3, 0, u32::MAX, 0, 0, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        // Entry probe, three in-loop busy reads, one confirming re-read.
        assert_eq!(c.stat_reads, 5);
        assert_eq!(c.timer_reads, 1, "the deadline is snapshotted once");
        // Two in-loop calls plus the confirming re-check after the loop.
        assert_eq!(c.elapsed_calls, 3);
        assert_eq!(c.delay_calls, 2, "one yield per still-pending poll");
        assert_eq!(c.delay_args, (0, 1), "the stock task_delay(0, 1)");
        assert_eq!(c.sta2_writes, 1);
    }

    #[test]
    fn flag_set_during_wait_returns_zero_despite_busy_bus() {
        // Bus never clears, but the byte-done flag sets on the second
        // sta2 read: completion via the interrupt flag, not bus idle.
        let _guard = install_mocks(I2C0_STAT_BUSY, u32::MAX, 0, 1, 0, 0, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.timer_reads, 1);
        // One confirming elapsed re-check after the loop, never passing.
        assert_eq!(c.elapsed_calls, 1);
        assert_eq!(c.delay_calls, 0, "no poll iteration ran to the delay");
    }

    #[test]
    fn confirmed_deadline_returns_transfer_timeout() {
        // Bus never clears, flag never sets; the in-loop elapsed call and
        // the confirming re-check both report the deadline passed.
        let _guard = install_mocks(I2C0_STAT_BUSY, u32::MAX, 0, u32::MAX, 0, u64::MAX, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, I2C0_TRANSFER_TIMEOUT);
        assert_eq!(c.elapsed_calls, 2, "in-loop call plus the confirming re-check");
        assert_eq!(c.delay_calls, 0, "no yield once the deadline passed");
        assert_eq!(c.sta2_writes, 1, "the epilogue runs even on timeout");
        assert_eq!(c.sta2_written, I2C0_STA2_BYTE_DONE);
    }

    #[test]
    fn elapsed_race_with_bus_still_busy_returns_idle_timeout() {
        // The in-loop elapsed call reports the deadline passed but the
        // confirming re-check does not, and both status words still show
        // the transfer pending: the 0x15 race path.
        let _guard = install_mocks(I2C0_STAT_BUSY, u32::MAX, 0, u32::MAX, 0, 0b01, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, I2C0_IDLE_TIMEOUT);
        assert_eq!(c.elapsed_calls, 2);
        // Entry probe, one in-loop busy read, one confirming re-read.
        assert_eq!(c.stat_reads, 3);
        // Entry read, one in-loop read, one confirming re-read, one
        // epilogue read-modify-write read.
        assert_eq!(c.sta2_reads, 4);
    }

    #[test]
    fn drain_loops_until_iiccon_reads_zero() {
        // Already-idle fast path with IICCON nonzero for two reads.
        let _guard = install_mocks(0, u32::MAX, 0, u32::MAX, 2, 0, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.con_reads, 3, "two nonzero reads then the draining zero");
    }

    #[test]
    fn epilogue_sets_flag_after_the_drain_completes() {
        // Preserve the unrelated high bits and set bit 8, after IICCON
        // has drained: the original's read-modify-write order.
        let _guard = install_mocks(0, u32::MAX, 0x5a00, u32::MAX, 1, 0, 1);

        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        let c = counts();

        assert_eq!(result, 0);
        assert_eq!(c.sta2_writes, 1);
        assert_eq!(c.sta2_written, 0x5a00 | I2C0_STA2_BYTE_DONE);
        assert!(c.con_zero_event > 0, "the drain observed a zero");
        assert!(
            c.con_zero_event < c.sta2_write_event,
            "IICCON drains before the IICSTA2 flag write"
        );
    }

    #[test]
    fn register_constants_name_iiccon_and_iicsta2_at_i2c0_base() {
        assert_eq!(I2C0_STAT as usize, 0x3c60_0004);
        assert_eq!(I2C0_STAT as usize - I2C0_REGISTER_BASE, I2C0_STAT_OFFSET);
        assert_eq!(I2C0_CON as usize, 0x3c60_0010);
        assert_eq!(I2C0_CON as usize - I2C0_REGISTER_BASE, I2C0_CON_OFFSET);
        assert_eq!(I2C0_STA2 as usize, 0x3c60_0020);
        assert_eq!(I2C0_STA2 as usize - I2C0_REGISTER_BASE, I2C0_STA2_OFFSET);
    }

    #[test]
    fn shipped_defaults_read_the_host_register_seams() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        HOST_I2C0_STAT.store(0, core::sync::atomic::Ordering::Relaxed);
        HOST_I2C0_STA2.store(0, core::sync::atomic::Ordering::Relaxed);
        HOST_I2C0_CON.store(0, core::sync::atomic::Ordering::Relaxed);

        // Shipped defaults: host seams idle -> the entry fast path returns
        // 0 without consulting the (frozen) host timer seam, and the
        // epilogue sets the host seam's byte-done flag.
        let result = unsafe { i2c0_wait_transfer_done(100_000) };
        assert_eq!(result, 0);
        assert_eq!(
            HOST_I2C0_STA2.load(core::sync::atomic::Ordering::Relaxed),
            I2C0_STA2_BYTE_DONE,
            "the default sta2 writer observes the driver-local seam"
        );

        HOST_I2C0_STAT.store(I2C0_STAT_BUSY, core::sync::atomic::Ordering::Relaxed);
        let ops = i2c0_transfer_ops();
        assert_eq!(
            unsafe { (ops.stat_read)() } & I2C0_STAT_BUSY,
            I2C0_STAT_BUSY,
            "the default stat reader observes the driver-local seam"
        );
        HOST_I2C0_STAT.store(0, core::sync::atomic::Ordering::Relaxed);
        HOST_I2C0_STA2.store(0, core::sync::atomic::Ordering::Relaxed);
    }
}
