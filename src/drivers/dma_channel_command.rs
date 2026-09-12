//! `dma_channel_command_and_wait` — original: `FUN_080f49b8` @
//! **0x080f49b8** (80 bytes, 0x080f49b8..0x080f4a04; the next independent
//! function begins at 0x080f4a08).
//!
//! Raw osos.dec decoding finds **8 direct `bl` callers**: seven
//! unconditional at 0x080a774c, 0x080a77c0, 0x080a7850, 0x080a789c,
//! 0x081074a8, 0x08107504, and 0x08107e8c, plus `bleq` at 0x08107c8c. A
//! further unconditional tail `b` at 0x080ae9cc reaches this entry. No data
//! word names this address as a virtual target.
//!
//! The DMA command word is `channel << 6 | 0x20`. Modes other than two write
//! that word; mode one returns immediately. All other modes sample the
//! microsecond timer once, then poll command-register bit 5 until hardware
//! clears it or a 100-us elapsed check succeeds. Mode two is the wait-only
//! form and therefore does not write the command register.
//!
//! # Deviation
//!
//! The original calls the two IRAM timer veneers at 0x08037e20 and
//! 0x08037eb8. Both are already ported, so this port calls those existing
//! veneers instead of adding dispatch seams. Host tests use private operation
//! callbacks to make MMIO state and timer expiry deterministic.

use crate::drivers::timer::{iram_usec_timer_elapsed_veneer, iram_usec_timer_read_veneer};

/// IODMA command/status register used by the retail routine.
const DMA_COMMAND_REGISTER: *mut u32 = 0x3840_0010 as *mut u32;
const DMA_COMMAND_ACTIVE: u32 = 0x20;
const DMA_COMMAND_TIMEOUT_USEC: u32 = 100;

struct DmaCommandOps {
    write_command: unsafe fn(u32),
    read_status: unsafe fn() -> u32,
    timer_read: unsafe fn() -> u32,
    timer_elapsed: unsafe fn(u32, u32) -> bool,
}

#[cfg(target_os = "none")]
unsafe fn write_dma_command(value: u32) {
    DMA_COMMAND_REGISTER.write_volatile(value);
}

#[cfg(target_os = "none")]
unsafe fn read_dma_command_status() -> u32 {
    DMA_COMMAND_REGISTER.read_volatile()
}

#[cfg(target_os = "none")]
unsafe fn read_usec_timer() -> u32 {
    iram_usec_timer_read_veneer()
}

#[cfg(target_os = "none")]
unsafe fn usec_timer_elapsed(start: u32, interval: u32) -> bool {
    iram_usec_timer_elapsed_veneer(start, interval)
}

#[cfg(not(target_os = "none"))]
static mut HOST_DMA_COMMAND_WRITE: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HOST_DMA_COMMAND_STATUS: u32 = 0;

#[cfg(not(target_os = "none"))]
unsafe fn write_dma_command(value: u32) {
    core::ptr::addr_of_mut!(HOST_DMA_COMMAND_WRITE).write_volatile(value);
}

#[cfg(not(target_os = "none"))]
unsafe fn read_dma_command_status() -> u32 {
    core::ptr::addr_of!(HOST_DMA_COMMAND_STATUS).read_volatile()
}

#[cfg(not(target_os = "none"))]
unsafe fn read_usec_timer() -> u32 {
    iram_usec_timer_read_veneer()
}

#[cfg(not(target_os = "none"))]
unsafe fn usec_timer_elapsed(start: u32, interval: u32) -> bool {
    iram_usec_timer_elapsed_veneer(start, interval)
}

const DMA_COMMAND_OPS: DmaCommandOps = DmaCommandOps {
    write_command: write_dma_command,
    read_status: read_dma_command_status,
    timer_read: read_usec_timer,
    timer_elapsed: usec_timer_elapsed,
};

#[inline(always)]
unsafe fn dma_channel_command_with_ops(channel: u32, mode: u32, ops: &DmaCommandOps) {
    if mode != 2 {
        (ops.write_command)(channel.wrapping_shl(6) | DMA_COMMAND_ACTIVE);
        if mode == 1 {
            return;
        }
    }

    let start = (ops.timer_read)();
    loop {
        if (ops.read_status)() & DMA_COMMAND_ACTIVE == 0 {
            return;
        }
        if (ops.timer_elapsed)(start, DMA_COMMAND_TIMEOUT_USEC) {
            return;
        }
    }
}

/// Issues an IODMA channel command and optionally waits for its completion.
///
/// The `mode` word deliberately retains the retailOS numeric contract:
/// `1` issues only, `2` waits only, and every other value issues then waits.
/// The command register and timer pair are volatile hardware interfaces, so
/// callers must only use this on an initialized S5L8702 DMA controller.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dma_channel_command_and_wait(channel: u32, mode: u32) {
    dma_channel_command_with_ops(channel, mode, &DMA_COMMAND_OPS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut WRITES: u32 = 0;
    static mut LAST_WRITE: u32 = 0;
    static mut STATUS: u32 = 0;
    static mut TIMER_READS: u32 = 0;
    static mut START: u32 = 0;
    static mut ELAPSED_CALLS: u32 = 0;
    static mut ELAPSED_START: u32 = 0;
    static mut ELAPSED_INTERVAL: u32 = 0;
    static mut EXPIRED: bool = false;

    unsafe fn record_write(value: u32) {
        let writes = addr_of_mut!(WRITES);
        writes.write_volatile(writes.read_volatile() + 1);
        addr_of_mut!(LAST_WRITE).write_volatile(value);
    }

    unsafe fn read_status() -> u32 {
        addr_of!(STATUS).read_volatile()
    }

    unsafe fn read_timer() -> u32 {
        let reads = addr_of_mut!(TIMER_READS);
        reads.write_volatile(reads.read_volatile() + 1);
        addr_of!(START).read_volatile()
    }

    unsafe fn elapsed(start: u32, interval: u32) -> bool {
        let calls = addr_of_mut!(ELAPSED_CALLS);
        calls.write_volatile(calls.read_volatile() + 1);
        addr_of_mut!(ELAPSED_START).write_volatile(start);
        addr_of_mut!(ELAPSED_INTERVAL).write_volatile(interval);
        addr_of!(EXPIRED).read_volatile()
    }

    const TEST_OPS: DmaCommandOps = DmaCommandOps {
        write_command: record_write,
        read_status,
        timer_read: read_timer,
        timer_elapsed: elapsed,
    };

    unsafe fn reset(status: u32, start: u32, expired: bool) {
        addr_of_mut!(WRITES).write_volatile(0);
        addr_of_mut!(LAST_WRITE).write_volatile(0);
        addr_of_mut!(STATUS).write_volatile(status);
        addr_of_mut!(TIMER_READS).write_volatile(0);
        addr_of_mut!(START).write_volatile(start);
        addr_of_mut!(ELAPSED_CALLS).write_volatile(0);
        addr_of_mut!(ELAPSED_START).write_volatile(0);
        addr_of_mut!(ELAPSED_INTERVAL).write_volatile(0);
        addr_of_mut!(EXPIRED).write_volatile(expired);
    }

    #[test]
    fn issue_only_writes_wrapped_channel_command_without_polling() {
        let _ops_guard = OPS_LOCK.lock();
        unsafe {
            reset(0, 0x1234_5678, false);
            dma_channel_command_with_ops(0xffff_ffff, 1, &TEST_OPS);
            assert_eq!(addr_of!(WRITES).read_volatile(), 1);
            assert_eq!(addr_of!(LAST_WRITE).read_volatile(), 0xffff_ffe0);
            assert_eq!(addr_of!(TIMER_READS).read_volatile(), 0);
            assert_eq!(addr_of!(ELAPSED_CALLS).read_volatile(), 0);
        }
    }

    #[test]
    fn wait_only_times_out_without_writing() {
        let _ops_guard = OPS_LOCK.lock();
        unsafe {
            reset(DMA_COMMAND_ACTIVE, 0xffff_fff0, true);
            dma_channel_command_with_ops(7, 2, &TEST_OPS);
            assert_eq!(addr_of!(WRITES).read_volatile(), 0);
            assert_eq!(addr_of!(TIMER_READS).read_volatile(), 1);
            assert_eq!(addr_of!(ELAPSED_CALLS).read_volatile(), 1);
            assert_eq!(addr_of!(ELAPSED_START).read_volatile(), 0xffff_fff0);
            assert_eq!(addr_of!(ELAPSED_INTERVAL).read_volatile(), DMA_COMMAND_TIMEOUT_USEC);
        }
    }

    #[test]
    fn issue_and_wait_skips_elapsed_check_when_hardware_is_idle() {
        let _ops_guard = OPS_LOCK.lock();
        unsafe {
            reset(0, 12, false);
            dma_channel_command_with_ops(3, 0, &TEST_OPS);
            assert_eq!(addr_of!(WRITES).read_volatile(), 1);
            assert_eq!(addr_of!(LAST_WRITE).read_volatile(), 0xe0);
            assert_eq!(addr_of!(TIMER_READS).read_volatile(), 1);
            assert_eq!(addr_of!(ELAPSED_CALLS).read_volatile(), 0);
        }
    }
}
