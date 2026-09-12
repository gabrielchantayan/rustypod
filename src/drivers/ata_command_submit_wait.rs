//! `ata_command_submit_wait` — original: `FUN_0836be8c` @ `0x0836be8c`.
//!
//! Raw osos.dec extent is **156 bytes**: 144 bytes of instructions at
//! `0x0836be8c..0x0836bf1b`, followed by the three literal-pool words at
//! `0x0836bf1c` (`"Ide1"`), `0x0836bf20` (`0x38700000`, ATA MMIO base), and
//! `0x0836bf24` (5000 ms). The distinct next function begins at `0x0836bf28`.
//! Decoding every ARM `B`/`BL` immediate in osos.dec finds exactly **8 inbound
//! direct calls**, all unconditional plain `bl` at `0x0836bd58`, `0x0836bdc8`,
//! `0x0836be58`, `0x0836be74`, `0x0836cd20`, `0x0836cd98`, `0x0836ce28`, and
//! `0x0836ce68`; there are no predicated calls, direct tail branches, or data
//! words containing this entry.
//!
//! # Algorithm
//!
//! Validate an `Ide1` ATA device and its `+0x44` readiness word together with
//! a non-NULL command descriptor. Propagate the device-preparation result;
//! then read and write back ATA MMIO `+0x10`, program the task-file from the
//! descriptor, select operation state 4 (its result is deliberately ignored),
//! and execute with a 5000-ms timeout. Only execution status 3 is success;
//! all other execution statuses map to `0x59`.
//!
//! The three fixed-address callees preparation `0x080b1ae8`, task-file
//! programming `0x0836c6c8`, and operation-state selection `0x0836ce80` are
//! still unported and use literal veneers on target plus volatile callback
//! seams on hosts. Execution `0x080d7b7c` is now the direct
//! [`ata_command_execute`] port. This is the only deliberate
//! code-generation deviation; behavior and call order are retained.

use core::ptr;
use crate::drivers::ata_command_execute::{ata_command_execute, AtaCommandDevice};


pub const ATA_DEVICE_SIGNATURE: u32 = 0x3165_6449;
pub const ATA_DEVICE_NOT_READY: u32 = 7;
pub const ATA_EXECUTION_FAILED: u32 = 0x59;
pub const ATA_EXECUTION_COMPLETE: u32 = 3;
pub const ATA_COMMAND_TIMEOUT_MS: u32 = 5_000;


pub type AtaCommandPrepare = unsafe extern "C" fn(device: *mut AtaCommandDevice) -> u32;
pub type AtaTaskfileProgram =
    unsafe extern "C" fn(device: *mut AtaCommandDevice, command: *mut u8, flags: u32) -> u32;
pub type AtaOperationStateSet = unsafe extern "C" fn(device: *mut AtaCommandDevice, state: u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_prepare(_device: *mut AtaCommandDevice) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_taskfile_program(
    _device: *mut AtaCommandDevice,
    _command: *mut u8,
    _flags: u32,
) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_operation_state_set(_device: *mut AtaCommandDevice, _state: u32) -> u32 {
    0
}


/// Host-only seam for the stock preparation function at `0x080b1ae8`.
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_COMMAND_PREPARE: AtaCommandPrepare = missing_prepare;
/// Host-only seam for the stock task-file programmer at `0x0836c6c8`.
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_TASKFILE_PROGRAM: AtaTaskfileProgram = missing_taskfile_program;
/// Host-only seam for the stock state setter at `0x0836ce80`.
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_OPERATION_STATE_SET: AtaOperationStateSet = missing_operation_state_set;

/// Host replacement for ATA MMIO `0x38700000..0x38700013`.
#[cfg(not(target_os = "none"))]
pub static mut ATA_COMMAND_MMIO_WORDS: [u32; 5] = [0; 5];

#[inline(always)]
fn ata_command_mmio_word() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        0x3870_0010 as *mut u32
    }

    #[cfg(not(target_os = "none"))]
    {
        unsafe { ptr::addr_of_mut!(ATA_COMMAND_MMIO_WORDS).cast::<u32>().add(4) }
    }
}

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_ata_command_prepare(device: *mut AtaCommandDevice) -> u32;
    fn retail_ata_taskfile_program(
        device: *mut AtaCommandDevice,
        command: *mut u8,
        flags: u32,
    ) -> u32;
    fn retail_ata_operation_state_set(device: *mut AtaCommandDevice, state: u32) -> u32;
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_ata_command_prepare(device: *mut AtaCommandDevice) -> u32 {
    ptr::read_volatile(ptr::addr_of!(ATA_COMMAND_PREPARE))(device)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_ata_taskfile_program(
    device: *mut AtaCommandDevice,
    command: *mut u8,
    flags: u32,
) -> u32 {
    ptr::read_volatile(ptr::addr_of!(ATA_TASKFILE_PROGRAM))(device, command, flags)
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_ata_operation_state_set(device: *mut AtaCommandDevice, state: u32) -> u32 {
    ptr::read_volatile(ptr::addr_of!(ATA_OPERATION_STATE_SET))(device, state)
}


// The original's PC-relative calls cannot reach from the patch payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_ata_command_prepare
    .type retail_ata_command_prepare, %function
retail_ata_command_prepare:
    ldr     pc, [pc, #-4]
    .word   0x080b1ae8
    .size retail_ata_command_prepare, . - retail_ata_command_prepare

    .globl retail_ata_taskfile_program
    .type retail_ata_taskfile_program, %function
retail_ata_taskfile_program:
    ldr     pc, [pc, #-4]
    .word   0x0836c6c8
    .size retail_ata_taskfile_program, . - retail_ata_taskfile_program

    .globl retail_ata_operation_state_set
    .type retail_ata_operation_state_set, %function
retail_ata_operation_state_set:
    ldr     pc, [pc, #-4]
    .word   0x0836ce80
    .size retail_ata_operation_state_set, . - retail_ata_operation_state_set

"#
);

/// ata_command_submit_wait — original: `FUN_0836be8c` @ `0x0836be8c`
/// (156-byte raw extent: 144 instruction bytes plus a 12-byte literal pool).
///
/// Eight unconditional direct `bl` call sites, verified by decoding every ARM
/// branch immediate in osos.dec. Validates the `Ide1` device, prepares it,
/// performs the ATA `+0x10` read/write, programs its task-file, selects state
/// 4, then executes with a 5000-ms timeout. Returns the preparation failure,
/// `0x59` for non-3 execution status, or zero for execution status 3.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.ata_command_submit_wait"
)]
#[inline(never)]
pub unsafe extern "C" fn ata_command_submit_wait(
    device: *mut AtaCommandDevice,
    command: *mut u8,
) -> u32 {
    if device.is_null()
        || ptr::read_volatile(ptr::addr_of!((*device).signature)) != ATA_DEVICE_SIGNATURE
        || ptr::read_volatile(ptr::addr_of!((*device).ready)) == 0
        || command.is_null()
    {
        return ATA_DEVICE_NOT_READY;
    }

    let preparation = retail_ata_command_prepare(device);
    if preparation != 0 {
        return preparation;
    }

    let mmio = ata_command_mmio_word();
    let value = ptr::read_volatile(mmio);
    ptr::write_volatile(mmio, value);

    let taskfile_status = retail_ata_taskfile_program(device, command, 0);
    if taskfile_status != 0 {
        return taskfile_status;
    }

    retail_ata_operation_state_set(device, 4);
    if ata_command_execute(device, ATA_COMMAND_TIMEOUT_MS, 0, 0) == ATA_EXECUTION_COMPLETE {
        0
    } else {
        ATA_EXECUTION_FAILED
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::vec::Vec;
    use crate::drivers::ata_command_execute::{
        ATA_COMMAND_EXECUTE_TEST_LOCK, ATA_STATUS_ERROR, ATA_STATUS_READ,
        ATA_STATUS_REGISTER_OFFSET,
    };
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::MutexGuard;
    use std::sync::LazyLock;
    static STATUS_SOURCE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ATA_COMMAND_SUBMIT_WAIT, 0x1000).map(|pointer| pointer as usize)
    });
    static mut DEVICE: AtaCommandDevice = AtaCommandDevice {
        signature: 0,
        _reserved_04_38: [0; 14],
        status_source: 0,
        _reserved_40: 0,
        ready: 0,
    };
    static mut COMMAND: [u8; 12] = [0; 12];
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut PREPARE_RESULT: u32 = 0;
    static mut PROGRAM_RESULT: u32 = 0;
    static mut STATE_RESULT: u32 = 0;
    static mut EXECUTE_STATUS: u32 = 0;

    unsafe extern "C" fn record_prepare(device: *mut AtaCommandDevice) -> u32 {
        assert_eq!(device, addr_of_mut!(DEVICE));
        CALL_LOG.push("prepare");
        PREPARE_RESULT
    }

    unsafe extern "C" fn record_program(
        device: *mut AtaCommandDevice,
        command: *mut u8,
        flags: u32,
    ) -> u32 {
        assert_eq!(device, addr_of_mut!(DEVICE));
        assert_eq!(command, addr_of_mut!(COMMAND).cast::<u8>());
        assert_eq!(flags, 0);
        CALL_LOG.push("program");
        PROGRAM_RESULT
    }

    unsafe extern "C" fn record_state(device: *mut AtaCommandDevice, state: u32) -> u32 {
        assert_eq!(device, addr_of_mut!(DEVICE));
        assert_eq!(state, 4);
        CALL_LOG.push("state");
        STATE_RESULT
    }

    unsafe extern "C" fn record_status_read(status_source: *mut u8, status_out: *mut u32) -> u32 {
        assert_eq!(status_source as usize, (*STATUS_SOURCE).unwrap() + ATA_STATUS_REGISTER_OFFSET);
        CALL_LOG.push("execute");
        ptr::write_volatile(status_out, EXECUTE_STATUS);
        0
    }

    unsafe fn arrange() -> Option<MutexGuard<'static, ()>> {
        let guard = ATA_COMMAND_EXECUTE_TEST_LOCK.lock();
        let source = (*STATUS_SOURCE)? as *mut u8;
        DEVICE = AtaCommandDevice {
            signature: ATA_DEVICE_SIGNATURE,
            _reserved_04_38: [0; 14],
            status_source: source as usize as u32,
            _reserved_40: 0,
            ready: 1,
        };
        COMMAND = [0; 12];
        CALL_LOG.clear();
        PREPARE_RESULT = 0;
        PROGRAM_RESULT = 0;
        STATE_RESULT = 0;
        EXECUTE_STATUS = 0;
        ATA_COMMAND_MMIO_WORDS = [0, 0, 0, 0, 0xa5a5_5a5a];
        ATA_COMMAND_PREPARE = record_prepare;
        ATA_TASKFILE_PROGRAM = record_program;
        ATA_OPERATION_STATE_SET = record_state;
        ATA_STATUS_READ = record_status_read;
        Some(guard)
    }

    #[test]
    fn rejects_invalid_device_or_command_before_any_side_effect() {
        let Some(_guard) = (unsafe { arrange() }) else {
            assert!(note_missing_u32_fixture("drivers::ata_command_submit_wait"));
            return;
        };
        assert_eq!(unsafe { ata_command_submit_wait(ptr::null_mut(), addr_of_mut!(COMMAND).cast()) }, ATA_DEVICE_NOT_READY);
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), ptr::null_mut()) }, ATA_DEVICE_NOT_READY);
        unsafe { DEVICE.ready = 0 };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, ATA_DEVICE_NOT_READY);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, &[] as &[&str]);
        assert_eq!(unsafe { ATA_COMMAND_MMIO_WORDS[4] }, 0xa5a5_5a5a);
    }

    #[test]
    fn propagates_preparation_or_taskfile_failure_without_later_stages() {
        let Some(_guard) = (unsafe { arrange() }) else {
            assert!(note_missing_u32_fixture("drivers::ata_command_submit_wait"));
            return;
        };
        unsafe { PREPARE_RESULT = 0x58 };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, 0x58);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare"]);
        assert_eq!(unsafe { ATA_COMMAND_MMIO_WORDS[4] }, 0xa5a5_5a5a);

        unsafe {
            CALL_LOG.clear();
            PREPARE_RESULT = 0;
            PROGRAM_RESULT = 0x47;
        }
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, 0x47);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program"]);
    }

    #[test]
    fn executes_after_taskfile_programming_and_maps_completion_status() {
        let Some(_guard) = (unsafe { arrange() }) else {
            assert!(note_missing_u32_fixture("drivers::ata_command_submit_wait"));
            return;
        };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, 0);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program", "state", "execute"]);
        assert_eq!(unsafe { ATA_COMMAND_MMIO_WORDS[4] }, 0xa5a5_5a5a);

        unsafe {
            CALL_LOG.clear();
            EXECUTE_STATUS = ATA_STATUS_ERROR;
        }
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, ATA_EXECUTION_FAILED);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program", "state", "execute"]);
    }

    #[test]
    fn ignores_operation_state_result_like_the_original() {
        let Some(_guard) = (unsafe { arrange() }) else {
            assert!(note_missing_u32_fixture("drivers::ata_command_submit_wait"));
            return;
        };
        unsafe { STATE_RESULT = 1 };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, 0);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program", "state", "execute"]);
    }
}
