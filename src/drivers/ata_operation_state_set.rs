//! `ata_operation_state_set` — original: `FUN_0836ce80` @ `0x0836ce80`.
//!
//! Raw `osos.dec` has **44 instruction bytes** at `0x0836ce80..0x0836cea8`;
//! its three-word literal pool occupies `0x0836ceac..0x0836ceb4`, and the
//! distinct next function begins at `0x0836ceb8`. ARM branch decoding finds
//! zero plain `bl` and zero predicated `bl` calls. Its sole call transfer is
//! the predicated tail `bne 0x0805695c`.
//!
//! # Algorithm
//!
//! Store `state` into ATA MMIO `0x38700014`. A NULL device returns zero;
//! otherwise return its `+0x48` operation word when that word is zero. For a
//! nonzero operation word, wait on the waiter id at `0x089d0448` for the fixed
//! 5000-tick timeout.
//!
//! Deliberate deviation: the stock tail branch to `waiter_wait` becomes a Rust
//! call, preserving its arguments and return value while remaining relocatable
//! from the patch payload.

use core::ptr;

use crate::drivers::ata_command_execute::AtaCommandDevice;
use crate::kernel::kobj::waiter_wait;
/// Fixed waiter timeout literal at `0x0836ceac`.
pub const ATA_OPERATION_WAIT_TIMEOUT_TICKS: u32 = 5_000;
pub const ATA_OPERATION_STATE_MMIO: *mut u32 = 0x3870_0014 as *mut u32;
/// Waiter id slot used by the ATA operation-state wait.
pub const ATA_OPERATION_WAITER_ID_SLOT: *const u32 = 0x089d_0448 as *const u32;

#[cfg(not(target_os = "none"))]
pub static mut ATA_OPERATION_STATE_MMIO_WORD: u32 = 0;
#[cfg(not(target_os = "none"))]
pub static mut ATA_OPERATION_WAITER_ID: u32 = 0;

#[inline(always)]
fn ata_operation_state_mmio() -> *mut u32 {
    #[cfg(target_os = "none")]
    { ATA_OPERATION_STATE_MMIO }

    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(ATA_OPERATION_STATE_MMIO_WORD) }
}

#[inline(always)]
fn ata_operation_waiter_id() -> u32 {
    #[cfg(target_os = "none")]
    unsafe { ptr::read_volatile(ATA_OPERATION_WAITER_ID_SLOT) }

    #[cfg(not(target_os = "none"))]
    unsafe { ptr::read_volatile(core::ptr::addr_of!(ATA_OPERATION_WAITER_ID)) }
}

/// `ata_operation_state_set` — original: `FUN_0836ce80` @ `0x0836ce80`
/// (44 instruction bytes; zero plain and zero predicated `bl` calls).
///
/// Writes the requested ATA operation state, then waits on the controller's
/// waiter when the device's nonzero `+0x48` operation word permits it. NULL
/// and zero-count devices return zero without waiting; other devices wait for
/// the fixed 5000-tick timeout.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_operation_state_set")]
#[inline(never)]
pub unsafe extern "C" fn ata_operation_state_set(
    device: *mut AtaCommandDevice,
    state: u32,
) -> u32 {
    ptr::write_volatile(ata_operation_state_mmio(), state);

    if device.is_null() {
        return 0;
    }

    let operation_count = ptr::read_volatile(ptr::addr_of!((*device).operation_count));
    if operation_count == 0 {
        return 0;
    }

    waiter_wait(ata_operation_waiter_id(), ATA_OPERATION_WAIT_TIMEOUT_TICKS)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;

    use super::*;
    use crate::kernel::kobj::{tests::HOOKS_LOCK, KobjHooks, DEFAULT_KOBJ_HOOKS, KOBJ_HOOKS};
    static mut WAIT_ID: u32 = 0;
    static mut WAIT_TIMEOUT: u32 = 0;
    static mut WAIT_RC: u32 = 0;

    unsafe extern "C" fn record_wait(id: u32, timeout: u32) -> u32 {
        WAIT_ID = id;
        WAIT_TIMEOUT = timeout;
        WAIT_RC
    }

    unsafe fn install_wait_hook(return_code: u32) {
        WAIT_ID = 0;
        WAIT_TIMEOUT = 0;
        WAIT_RC = return_code;
        let mut hooks: KobjHooks = DEFAULT_KOBJ_HOOKS;
        hooks.rom_waiter_wait = record_wait;
        ptr::write(core::ptr::addr_of_mut!(KOBJ_HOOKS), hooks);
    }

    unsafe fn device(operation_count: u32) -> AtaCommandDevice {
        AtaCommandDevice {
            signature: 0,
            _reserved_04_38: [0; 14],
            status_source: 0,
            _reserved_40: 0,
            ready: 0,
            operation_count,
        }
    }

    #[test]
    fn stores_state_before_null_device_return() {
        let _lock = HOOKS_LOCK.lock();
        unsafe {
            ATA_OPERATION_STATE_MMIO_WORD = 0;
            assert_eq!(ata_operation_state_set(ptr::null_mut(), 4), 0);
            assert_eq!(ATA_OPERATION_STATE_MMIO_WORD, 4);
        }
    }

    #[test]
    fn skips_wait_for_zero_operation_count() {
        let _lock = HOOKS_LOCK.lock();
        unsafe {
            install_wait_hook(5);
            ATA_OPERATION_WAITER_ID = 0x55;
            let mut device = device(0);
            assert_eq!(ata_operation_state_set(&mut device, 5), 0);
            assert_eq!(WAIT_TIMEOUT, 0);
            ptr::write(core::ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }

    #[test]
    fn waits_with_controller_id_and_returns_timeout_flag() {
        let _lock = HOOKS_LOCK.lock();
        unsafe {
            install_wait_hook(5);
            ATA_OPERATION_WAITER_ID = 0x1234;
            let mut device = device(0x1388);
            assert_eq!(ata_operation_state_set(&mut device, 1), 1);
            assert_eq!(WAIT_ID, 0x1234);
            assert_eq!(WAIT_TIMEOUT, ATA_OPERATION_WAIT_TIMEOUT_TICKS);
            ptr::write(core::ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }
}
