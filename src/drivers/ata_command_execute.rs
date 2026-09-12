//! `ata_command_execute` — original: `FUN_080d7b7c` @ `0x080d7b7c`.
//!
//! Raw `osos.dec` extent is **140 bytes**: 136 instruction bytes at
//! `0x080d7b7c..0x080d7bff`, followed by the `10_000`-microsecond literal at
//! `0x080d7c04`; the separately linked next function starts at `0x080d7c08`.
//! Decoding every ARM `B`/`BL` immediate finds exactly **8 inbound direct
//! calls**, all unconditional plain `bl` at `0x0807d7b8`, `0x080b1b04`,
//! `0x080c4b28`, `0x0836bf0c`, `0x0836c3cc`, `0x0836c4a0`, `0x0836c59c`, and
//! `0x0836cf6c`; there are no predicated calls or direct tail branches.
//!
//! # Algorithm
//!
//! Capture the microsecond counter once, then repeatedly read ATA status
//! through the device's `+0x3c` status-source word. Bit 0 aborts with 2.
//! While bit 7 is set, sleep for 10 RTXC ticks after each 10-ms elapsed
//! interval and return 1 once the caller's millisecond timeout expires.
//! When bit 7 clears, bit 3 selects status 4; otherwise return 3.
//!
//! The `+0x3c` status-source field and `FUN_080bb610` are only locally
//! characterized: raw code proves the latter writes a status word but does
//! not identify its object type. Target builds use a literal veneer for that
//! still-unported helper. The Timer E reader/deadline veneers and `task_sleep`
//! are already ported and called directly; no other deliberate deviations.

use core::ptr;

use crate::drivers::timer::{iram_usec_timer_elapsed_veneer, iram_usec_timer_read_veneer};
use crate::kernel::task::task_sleep;

pub const ATA_STATUS_ABORTED: u32 = 2;
pub const ATA_STATUS_COMPLETE: u32 = 3;
pub const ATA_STATUS_DEVICE_ERROR: u32 = 4;
pub const ATA_STATUS_TIMEOUT: u32 = 1;
pub const ATA_STATUS_ABORT: u32 = 1;
pub const ATA_STATUS_BUSY: u32 = 0x80;
pub const ATA_STATUS_ERROR: u32 = 8;
pub const ATA_BUSY_SLEEP_INTERVAL_USEC: u32 = 10_000;
pub const ATA_BUSY_SLEEP_TICKS: u32 = 10;
pub const ATA_STATUS_REGISTER_OFFSET: usize = 0x1c;

/// Target-layout prefix of the opaque `Ide1` ATA object.
///
/// Raw ARM loads the status-source pointer from `device + 0x3c`. The source
/// is a target-width word, not a host pointer, so the surrounding reservation
/// fields preserve both this offset and the later `+0x44` readiness field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AtaCommandDevice {
    pub signature: u32,
    pub _reserved_04_38: [u32; 14],
    pub status_source: u32,
    pub _reserved_40: u32,
    pub ready: u32,
}

pub type AtaStatusRead = unsafe extern "C" fn(status_source: *mut u8, status_out: *mut u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ata_status_read(_status_source: *mut u8, status_out: *mut u32) -> u32 {
    ptr::write_volatile(status_out, ATA_STATUS_ABORT);
    0
}

/// Host-only seam for `FUN_080bb610`, the unported ATA status reader.
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_STATUS_READ: AtaStatusRead = missing_ata_status_read;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_ata_status_read(status_source: *mut u8, status_out: *mut u32) -> u32;
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_ata_status_read(status_source: *mut u8, status_out: *mut u32) -> u32 {
    ptr::read_volatile(ptr::addr_of!(ATA_STATUS_READ))(status_source, status_out)
}

// The original's PC-relative call cannot reach from the patch payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_ata_status_read
    .type retail_ata_status_read, %function
retail_ata_status_read:
    ldr     pc, [pc, #-4]
    .word   0x080bb610
    .size retail_ata_status_read, . - retail_ata_status_read
"#
);

/// `ata_command_execute` — original: `FUN_080d7b7c` @ `0x080d7b7c`
/// (140-byte raw extent: 136 instruction bytes plus a 4-byte literal pool).
///
/// Eight unconditional direct `bl` call sites, verified from every ARM branch
/// immediate in `osos.dec`. Polls the `device + 0x3c` ATA status source until
/// abort, busy-timeout, device error, or completion. `_unused` is r2, which
/// the body never reads; `initial_status` is r3, copied to the stack before
/// `retail_ata_status_read` overwrites it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_command_execute")]
#[inline(never)]
pub unsafe extern "C" fn ata_command_execute(
    device: *mut AtaCommandDevice,
    timeout_ms: u32,
    _unused: u32,
    initial_status: u32,
) -> u32 {
    let start = unsafe { iram_usec_timer_read_veneer() };
    let status_register = unsafe {
        (ptr::read_volatile(ptr::addr_of!((*device).status_source)) as usize as *mut u8)
            .add(ATA_STATUS_REGISTER_OFFSET)
    };
    let mut status = initial_status;

    loop {
        unsafe { retail_ata_status_read(status_register, &mut status) };
        if status & ATA_STATUS_ABORT != 0 {
            return ATA_STATUS_ABORTED;
        }
        if status & ATA_STATUS_BUSY == 0 {
            return if status & ATA_STATUS_ERROR != 0 {
                ATA_STATUS_DEVICE_ERROR
            } else {
                ATA_STATUS_COMPLETE
            };
        }
        if unsafe { iram_usec_timer_elapsed_veneer(start, ATA_BUSY_SLEEP_INTERVAL_USEC) } {
            unsafe { task_sleep(ATA_BUSY_SLEEP_TICKS) };
        }
        if unsafe { iram_usec_timer_elapsed_veneer(start, timeout_ms.wrapping_mul(1_000)) } {
            return ATA_STATUS_TIMEOUT;
        }
    }
}

#[cfg(test)]
pub(crate) static ATA_COMMAND_EXECUTE_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task::{TaskHooks, TASK_HOOKS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TASK_HOOKS_TEST_LOCK};
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::LazyLock;

    static STATUS_SOURCE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ATA_COMMAND_EXECUTE, 0x1000).map(|pointer| pointer as usize)
    });
    static mut DEVICE: AtaCommandDevice = AtaCommandDevice {
        signature: 0,
        _reserved_04_38: [0; 14],
        status_source: 0,
        _reserved_40: 0,
        ready: 0,
    };
    static mut STATUSES: [u32; 2] = [0; 2];
    static mut STATUS_READS: usize = 0;
    static EXPECTED_SOURCE: AtomicU32 = AtomicU32::new(0);
    static SLEEP_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn record_status_read(status_source: *mut u8, status_out: *mut u32) -> u32 {
        assert_eq!(status_source as usize as u32, EXPECTED_SOURCE.load(Ordering::Relaxed));
        let index = STATUS_READS;
        STATUS_READS += 1;
        ptr::write_volatile(status_out, STATUSES[index]);
        0
    }

    unsafe extern "C" fn record_timed_delay(task: usize, ticks: usize) -> usize {
        assert_eq!(task, 0);
        assert_eq!(ticks, ATA_BUSY_SLEEP_TICKS as usize);
        SLEEP_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    struct TaskHooksReset(TaskHooks);

    impl Drop for TaskHooksReset {
        fn drop(&mut self) {
            unsafe { ptr::write_volatile(ptr::addr_of_mut!(TASK_HOOKS), self.0) };
        }
    }

    unsafe fn arrange(statuses: [u32; 2]) -> Option<*mut AtaCommandDevice> {
        let source = (*STATUS_SOURCE)? as *mut u8;
        DEVICE = AtaCommandDevice {
            signature: 0,
            _reserved_04_38: [0; 14],
            status_source: source as usize as u32,
            _reserved_40: 0,
            ready: 0,
        };
        STATUSES = statuses;
        STATUS_READS = 0;
        EXPECTED_SOURCE.store(
            source.add(ATA_STATUS_REGISTER_OFFSET) as usize as u32,
            Ordering::Relaxed,
        );
        ATA_STATUS_READ = record_status_read;
        Some(ptr::addr_of_mut!(DEVICE))
    }

    #[test]
    fn status_bits_select_abort_completion_and_error() {
        let _execute_guard = ATA_COMMAND_EXECUTE_TEST_LOCK.lock();
        let _timer_guard = crate::drivers::timer::configure_usec_timer_for_test(0, 0);
        let Some(device) = (unsafe { arrange([ATA_STATUS_ABORT, 0]) }) else {
            assert!(note_missing_u32_fixture("drivers::ata_command_execute"));
            return;
        };

        assert_eq!(unsafe { ata_command_execute(device, 1, 0x1111_1111, u32::MAX) }, ATA_STATUS_ABORTED);
        unsafe { arrange([0, 0]).unwrap() };
        assert_eq!(unsafe { ata_command_execute(device, 1, 0, 0) }, ATA_STATUS_COMPLETE);
        unsafe { arrange([ATA_STATUS_ERROR, 0]).unwrap() };
        assert_eq!(unsafe { ata_command_execute(device, 1, 0, 0) }, ATA_STATUS_DEVICE_ERROR);
    }

    #[test]
    fn busy_status_sleeps_after_ten_milliseconds_then_times_out() {
        let _execute_guard = ATA_COMMAND_EXECUTE_TEST_LOCK.lock();
        let _timer_guard = crate::drivers::timer::configure_usec_timer_for_test(0, ATA_BUSY_SLEEP_INTERVAL_USEC);
        let _task_guard = TASK_HOOKS_TEST_LOCK.lock();
        let Some(device) = (unsafe { arrange([ATA_STATUS_BUSY, 0]) }) else {
            assert!(note_missing_u32_fixture("drivers::ata_command_execute"));
            return;
        };
        SLEEP_CALLS.store(0, Ordering::Relaxed);
        let saved_hooks = unsafe { ptr::read_volatile(ptr::addr_of!(TASK_HOOKS)) };
        let _restore_hooks = TaskHooksReset(saved_hooks);
        let mut hooks = saved_hooks;
        hooks.rom_timed_delay = record_timed_delay;
        unsafe { ptr::write_volatile(ptr::addr_of_mut!(TASK_HOOKS), hooks) };

        assert_eq!(unsafe { ata_command_execute(device, 15, 0, 0) }, ATA_STATUS_TIMEOUT);
        assert_eq!(SLEEP_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(unsafe { STATUS_READS }, 1);
    }
}
