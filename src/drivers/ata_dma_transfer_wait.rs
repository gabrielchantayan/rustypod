//! ATA DMA start/wait — `FUN_0807d770` @ `0x0807d770`.
//!
//! True extent [0x0807d770, 0x0807d7d0): 96 bytes, comprising 88
//! instruction bytes and literals 0x38700000 and 5000. Next entry starts
//! with push {r4,lr}. Raw A32 decoding finds two plain outbound BLs and
//! zero predicated BLs; inbound BLs are 0x0836c684 and 0x0836d058, both plain.
//! Acknowledge the controller status by writing it back, issue command 1,
//! select operation state 1 (ignoring its wait result), issue command 2,
//! clear control bits 12, 3 and 2, and wait 5000 ms for ATA status 3.
//! Return zero for completion, otherwise 0x59. Callers use this for both
//! DMA reads and writes after ata_dma_configure.
//!
//! Deliberate deviations: hosts use RAM MMIO; execution receives zero for
//! unused r2 and overwritten initial-status r3, as in ata_command_prepare.
//! Existing Rust ports implement both callees; no new retail seams.

use core::ptr;
use crate::drivers::ata_command_execute::{ata_command_execute, AtaCommandDevice};
use crate::drivers::ata_operation_state_set::ata_operation_state_set;

#[cfg(not(target_os = "none"))]
pub static mut ATA_DMA_TRANSFER_MMIO_WORDS: [u32; 7] = [0; 7];

#[inline(always)]
unsafe fn transfer_wait_with(
    registers: *mut u32,
    mut select_state: impl FnMut(),
    mut execute: impl FnMut() -> u32,
) -> u32 {
    let status = registers.add(4);
    status.write_volatile(status.read_volatile());
    registers.add(2).write_volatile(1);
    select_state();
    registers.add(2).write_volatile(2);
    let control = registers.add(6);
    control.write_volatile(control.read_volatile() & !0x100c);
    if execute() == 3 { 0 } else { 0x59 }
}

/// # Safety
/// Requires a live ATA device and serialized access to the ATA controller.
/// As in retailOS, NULL is not rejected before the execution routine.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ata_dma_transfer_wait(device: *mut AtaCommandDevice) -> u32 {
    #[cfg(target_os = "none")]
    let registers = 0x3870_0000 as *mut u32;
    #[cfg(not(target_os = "none"))]
    let registers = ptr::addr_of_mut!(ATA_DMA_TRANSFER_MMIO_WORDS).cast::<u32>();
    transfer_wait_with(registers,
        || { ata_operation_state_set(device, 1); },
        || ata_command_execute(device, 5000, 0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn clears_post_wait_control_and_preserves_other_registers_for_every_result() {
        for initial in [0, u32::MAX, 0xa5a5_5a5a, 0x100c] {
            for result in [0, 1, 2, 3, 4, 5, u32::MAX] {
                let mut words = [0xdead_beef; 7];
                words[4] = 0x1234_5678;
                words[6] = initial;
                let registers = words.as_mut_ptr();
                let stage = Cell::new(0);
                let returned = unsafe { transfer_wait_with(registers,
                    || {
                        assert_eq!(stage.replace(1), 0);
                        assert_eq!(registers.add(2).read(), 1);
                        assert_eq!(registers.add(4).read(), 0x1234_5678);
                        // Waiting may change hardware flags: clear the fresh value.
                        registers.add(6).write(!initial);
                    },
                    || {
                        assert_eq!(stage.replace(2), 1);
                        assert_eq!(registers.add(2).read(), 2);
                        assert_eq!(registers.add(6).read(), !initial & !0x100c);
                        result
                    }) };
                assert_eq!(returned, if result == 3 { 0 } else { 0x59 });
                assert_eq!(stage.get(), 2);
                assert_eq!(words, [0xdead_beef, 0xdead_beef, 2, 0xdead_beef,
                    0x1234_5678, 0xdead_beef, !initial & !0x100c]);
            }
        }
    }
}
