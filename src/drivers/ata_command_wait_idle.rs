//! `ata_command_wait_idle` — original: `FUN_08369c78` @ `0x08369c78`.
//!
//! Raw `osos.dec` contains 32 instruction bytes at
//! `0x08369c78..0x08369c97`, followed by the `0x089d03bc` literal at
//! `0x08369c98..0x08369c9b`; the independently linked next function begins
//! at `0x08369c9c`. Decoding every ARM branch immediate finds four inbound
//! direct calls at `0x080dbbfc`, `0x08369e68`, `0x0836a3d4`, and `0x0836aa60`,
//! all unconditional plain `bl` (zero predicated `bl`). The body makes one
//! unconditional plain `bl`, to `waiter_wait` @ `0x0805695c`.
//!
//! # Algorithm
//!
//! Sleep for one tick on the ATA command-global waiter id, discarding whether
//! the sleep timed out, then store state 3 in the controller object at global
//! `+0x4`, object `+0x38`. Deliberate deviations: the fixed global is a
//! host-replaceable pointer outside target builds; target word offsets and the
//! wait/store order are unchanged.

use core::ptr;

use crate::kernel::kobj::waiter_wait;

/// ATA command-global object at `0x089d03bc`; waiter id is word 10 and the
/// controller-state object is the target-width pointer in word 1.
const ATA_COMMAND_GLOBAL: *mut u32 = 0x089d_03bc as *mut u32;
const ATA_COMMAND_WAITER_ID_WORD: usize = 10;
const ATA_COMMAND_CONTROLLER_WORD: usize = 1;
const ATA_COMMAND_STATE_WORD: usize = 14;
pub const ATA_COMMAND_IDLE_STATE: u32 = 3;

#[cfg(not(target_os = "none"))]
pub static mut HOST_ATA_COMMAND_GLOBAL: *mut u32 = ptr::null_mut();

#[inline(always)]
unsafe fn ata_command_global() -> *mut u32 {
    #[cfg(target_os = "none")]
    { ATA_COMMAND_GLOBAL }

    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(HOST_ATA_COMMAND_GLOBAL)) }
}

/// `ata_command_wait_idle` — original: `FUN_08369c78` @ `0x08369c78` (36-byte
/// raw extent: 32 instruction bytes and one literal word; four plain and zero
/// predicated inbound `bl` calls).
///
/// Waits one tick on the ATA command-global waiter, ignores the wait result,
/// then writes controller state 3 at `controller + 0x38`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_command_wait_idle")]
#[inline(never)]
pub unsafe extern "C" fn ata_command_wait_idle() {
    let global = ata_command_global();
    let waiter_id = ptr::read_volatile(global.add(ATA_COMMAND_WAITER_ID_WORD));
    waiter_wait(waiter_id, 0);
    let controller = ptr::read_volatile(global.add(ATA_COMMAND_CONTROLLER_WORD)) as *mut u32;
    ptr::write_volatile(controller.add(ATA_COMMAND_STATE_WORD), ATA_COMMAND_IDLE_STATE);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use std::sync::LazyLock;

    use super::*;
    use crate::kernel::kobj::{tests::HOOKS_LOCK, DEFAULT_KOBJ_HOOKS, KOBJ_HOOKS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ATA_COMMAND_WAIT_IDLE, 0x1000).map(|pointer| pointer as usize)
    });
    static mut WAIT_ID: u32 = 0;
    static mut WAIT_TIMEOUT: u32 = u32::MAX;
    static mut WAIT_RESULT: u32 = 0;

    unsafe extern "C" fn record_wait(id: u32, timeout: u32) -> u32 {
        WAIT_ID = id;
        WAIT_TIMEOUT = timeout;
        WAIT_RESULT
    }

    unsafe fn install_wait_hook(result: u32) {
        WAIT_ID = 0;
        WAIT_TIMEOUT = u32::MAX;
        WAIT_RESULT = result;
        let mut hooks = DEFAULT_KOBJ_HOOKS;
        hooks.rom_waiter_wait = record_wait;
        ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), hooks);
    }

    #[test]
    fn waits_one_tick_then_sets_controller_idle_state() {
        let _lock = HOOKS_LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("drivers/ata_command_wait_idle"));
            return;
        };
        let global = base as *mut u32;
        let controller = unsafe { global.add(0x100 / 4) };
        unsafe {
            global.write_bytes(0, 0x1000 / 4);
            *global.add(ATA_COMMAND_WAITER_ID_WORD) = 0x1234_5678;
            *global.add(ATA_COMMAND_CONTROLLER_WORD) = controller as u32;
            *controller.add(ATA_COMMAND_STATE_WORD) = u32::MAX;
            HOST_ATA_COMMAND_GLOBAL = global;
            install_wait_hook(5);
            ata_command_wait_idle();
            assert_eq!(WAIT_ID, 0x1234_5678);
            assert_eq!(WAIT_TIMEOUT, 1, "waiter_wait clamps zero to one tick");
            assert_eq!(*controller.add(ATA_COMMAND_STATE_WORD), ATA_COMMAND_IDLE_STATE);
            HOST_ATA_COMMAND_GLOBAL = ptr::null_mut();
            ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }

    #[test]
    fn ignores_a_signaled_wait_before_setting_state() {
        let _lock = HOOKS_LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("drivers/ata_command_wait_idle"));
            return;
        };
        let global = base as *mut u32;
        let controller = unsafe { global.add(0x200 / 4) };
        unsafe {
            global.write_bytes(0, 0x1000 / 4);
            *global.add(ATA_COMMAND_WAITER_ID_WORD) = 0;
            *global.add(ATA_COMMAND_CONTROLLER_WORD) = controller as u32;
            *controller.add(ATA_COMMAND_STATE_WORD) = 0;
            HOST_ATA_COMMAND_GLOBAL = global;
            install_wait_hook(0);
            ata_command_wait_idle();
            assert_eq!(WAIT_ID, 0);
            assert_eq!(*controller.add(ATA_COMMAND_STATE_WORD), ATA_COMMAND_IDLE_STATE);
            HOST_ATA_COMMAND_GLOBAL = ptr::null_mut();
            ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }
}
