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
//! The four fixed-address callees are not in the port ledger. Their seam names
//! describe only the roles verified here: preparation `0x080b1ae8`, task-file
//! programming `0x0836c6c8`, operation-state selection `0x0836ce80`, and
//! execution `0x080d7b7c`. Target builds use literal veneers because a Rust
//! payload cannot retain the stock body's PC-relative `bl` reach; host builds
//! use volatile callback seams. This is the only deliberate code-generation
//! deviation; behavior and call order are retained.

use core::ptr;

pub const ATA_DEVICE_SIGNATURE: u32 = 0x3165_6449;
pub const ATA_DEVICE_NOT_READY: u32 = 7;
pub const ATA_EXECUTION_FAILED: u32 = 0x59;
pub const ATA_EXECUTION_COMPLETE: u32 = 3;
pub const ATA_COMMAND_TIMEOUT_MS: u32 = 5_000;

/// The two fields this routine reads from the opaque `Ide1` ATA-device object.
///
/// `u32` reservation words preserve the target's `+0x44` readiness offset on
/// both the 32-bit firmware and 64-bit host test builds.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AtaCommandDevice {
    pub signature: u32,
    pub _reserved_04_40: [u32; 16],
    pub ready: u32,
}

pub type AtaCommandPrepare = unsafe extern "C" fn(device: *mut AtaCommandDevice) -> u32;
pub type AtaTaskfileProgram =
    unsafe extern "C" fn(device: *mut AtaCommandDevice, command: *mut u8, flags: u32) -> u32;
pub type AtaOperationStateSet = unsafe extern "C" fn(device: *mut AtaCommandDevice, state: u32) -> u32;
pub type AtaCommandExecute = unsafe extern "C" fn(device: *mut AtaCommandDevice, timeout_ms: u32) -> u32;

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

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_execute(_device: *mut AtaCommandDevice, _timeout_ms: u32) -> u32 {
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
/// Host-only seam for the stock command executor at `0x080d7b7c`.
#[cfg(not(target_arch = "arm"))]
pub static mut ATA_COMMAND_EXECUTE: AtaCommandExecute = missing_execute;

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
    fn retail_ata_command_execute(device: *mut AtaCommandDevice, timeout_ms: u32) -> u32;
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

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_ata_command_execute(device: *mut AtaCommandDevice, timeout_ms: u32) -> u32 {
    ptr::read_volatile(ptr::addr_of!(ATA_COMMAND_EXECUTE))(device, timeout_ms)
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

    .globl retail_ata_command_execute
    .type retail_ata_command_execute, %function
retail_ata_command_execute:
    ldr     pc, [pc, #-4]
    .word   0x080d7b7c
    .size retail_ata_command_execute, . - retail_ata_command_execute
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
    if retail_ata_command_execute(device, ATA_COMMAND_TIMEOUT_MS) == ATA_EXECUTION_COMPLETE {
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
    use parking_lot::{Mutex, MutexGuard};
    use std::vec::Vec;

    static ATA_COMMAND_LOCK: Mutex<()> = Mutex::new(());
    static mut DEVICE: AtaCommandDevice = AtaCommandDevice {
        signature: 0,
        _reserved_04_40: [0; 16],
        ready: 0,
    };
    static mut COMMAND: [u8; 12] = [0; 12];
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut PREPARE_RESULT: u32 = 0;
    static mut PROGRAM_RESULT: u32 = 0;
    static mut STATE_RESULT: u32 = 0;
    static mut EXECUTE_RESULT: u32 = ATA_EXECUTION_COMPLETE;

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

    unsafe extern "C" fn record_execute(device: *mut AtaCommandDevice, timeout_ms: u32) -> u32 {
        assert_eq!(device, addr_of_mut!(DEVICE));
        assert_eq!(timeout_ms, ATA_COMMAND_TIMEOUT_MS);
        CALL_LOG.push("execute");
        EXECUTE_RESULT
    }

    unsafe fn arrange() -> MutexGuard<'static, ()> {
        let guard = ATA_COMMAND_LOCK.lock();
        DEVICE = AtaCommandDevice {
            signature: ATA_DEVICE_SIGNATURE,
            _reserved_04_40: [0; 16],
            ready: 1,
        };
        COMMAND = [0; 12];
        CALL_LOG.clear();
        PREPARE_RESULT = 0;
        PROGRAM_RESULT = 0;
        STATE_RESULT = 0;
        EXECUTE_RESULT = ATA_EXECUTION_COMPLETE;
        ATA_COMMAND_MMIO_WORDS = [0, 0, 0, 0, 0xa5a5_5a5a];
        ATA_COMMAND_PREPARE = record_prepare;
        ATA_TASKFILE_PROGRAM = record_program;
        ATA_OPERATION_STATE_SET = record_state;
        ATA_COMMAND_EXECUTE = record_execute;
        guard
    }

    #[test]
    fn rejects_invalid_device_or_command_before_any_side_effect() {
        let _guard = unsafe { arrange() };
        assert_eq!(unsafe { ata_command_submit_wait(ptr::null_mut(), addr_of_mut!(COMMAND).cast()) }, ATA_DEVICE_NOT_READY);
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), ptr::null_mut()) }, ATA_DEVICE_NOT_READY);
        unsafe { DEVICE.ready = 0 };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, ATA_DEVICE_NOT_READY);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, &[] as &[&str]);
        assert_eq!(unsafe { ATA_COMMAND_MMIO_WORDS[4] }, 0xa5a5_5a5a);
    }

    #[test]
    fn propagates_preparation_or_taskfile_failure_without_later_stages() {
        let _guard = unsafe { arrange() };
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
        let _guard = unsafe { arrange() };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, 0);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program", "state", "execute"]);
        assert_eq!(unsafe { ATA_COMMAND_MMIO_WORDS[4] }, 0xa5a5_5a5a);

        unsafe {
            CALL_LOG.clear();
            EXECUTE_RESULT = 4;
        }
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, ATA_EXECUTION_FAILED);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program", "state", "execute"]);
    }

    #[test]
    fn ignores_operation_state_result_like_the_original() {
        let _guard = unsafe { arrange() };
        unsafe { STATE_RESULT = 1 };
        assert_eq!(unsafe { ata_command_submit_wait(addr_of_mut!(DEVICE), addr_of_mut!(COMMAND).cast()) }, 0);
        assert_eq!(unsafe { CALL_LOG.as_slice() }, ["prepare", "program", "state", "execute"]);
    }
}
