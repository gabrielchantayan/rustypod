//! `ata_command_wait` — original: `FUN_0836a950` @ `0x0836a950`.
//!
//! Raw `osos.dec` has **56 instruction bytes** at `0x0836a950..0x0836a984`.
//! The two-word literal pool at `0x0836a988..0x0836a98c` is followed by the
//! independently linked next function at `0x0836a990`. Decoding every ARM
//! immediate branch in the image finds exactly four inbound direct calls, all
//! unconditional plain `bl` (no predicated `bl` forms).
//!
//! # Algorithm
//!
//! A NULL device or one whose `+0x48` operation count is zero returns zero.
//! Otherwise sleep on the waiter id at `0x089d03bc + 0x28` for 5000 ticks.
//! Map the ported waiter's timeout result from one to the ATA timeout status
//! `0x1f`; a signaled wait returns zero. Deliberate deviations: none.

use core::ptr;

use crate::drivers::ata_command_execute::AtaCommandDevice;
use crate::kernel::kobj::waiter_wait;

/// Fixed waiter timeout literal at `0x0836a988`.
pub const ATA_COMMAND_WAIT_TIMEOUT_TICKS: u32 = 5_000;
/// Waiter id word at `0x089d03bc + 0x28`.
pub const ATA_COMMAND_WAITER_ID_SLOT: *const u32 = 0x089d_03e4 as *const u32;
/// ATA status returned when the waiter expires.
pub const ATA_COMMAND_WAIT_TIMEOUT: u32 = 0x1f;

#[cfg(not(target_os = "none"))]
pub static mut ATA_COMMAND_WAITER_ID: u32 = 0;

#[inline(always)]
unsafe fn ata_command_waiter_id() -> u32 {
    #[cfg(target_os = "none")]
    { ptr::read_volatile(ATA_COMMAND_WAITER_ID_SLOT) }

    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(ATA_COMMAND_WAITER_ID)) }
}

/// `ata_command_wait` — original: `FUN_0836a950` @ `0x0836a950` (56 bytes;
/// four plain and zero predicated inbound `bl` calls).
///
/// Waits for a nonzero ATA operation count on the controller waiter. NULL and
/// zero-count devices return zero; a waiter timeout maps to `0x1f`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ata_command_wait")]
#[inline(never)]
pub unsafe extern "C" fn ata_command_wait(device: *mut AtaCommandDevice) -> u32 {
    if device.is_null()
        || ptr::read_volatile(ptr::addr_of!((*device).operation_count)) == 0
    {
        return 0;
    }

    if waiter_wait(ata_command_waiter_id(), ATA_COMMAND_WAIT_TIMEOUT_TICKS) != 0 {
        ATA_COMMAND_WAIT_TIMEOUT
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
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
        ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), hooks);
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
    fn skips_null_and_zero_operation_count_devices() {
        let _lock = HOOKS_LOCK.lock();
        unsafe {
            install_wait_hook(5);
            ATA_COMMAND_WAITER_ID = 0x1234;
            assert_eq!(ata_command_wait(ptr::null_mut()), 0);
            let mut zero = device(0);
            assert_eq!(ata_command_wait(&mut zero), 0);
            assert_eq!(WAIT_TIMEOUT, 0);
            ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }

    #[test]
    fn maps_waiter_timeout_to_ata_timeout() {
        let _lock = HOOKS_LOCK.lock();
        unsafe {
            install_wait_hook(5);
            ATA_COMMAND_WAITER_ID = 0x1234;
            let mut active = device(1);
            assert_eq!(ata_command_wait(&mut active), ATA_COMMAND_WAIT_TIMEOUT);
            assert_eq!(WAIT_ID, 0x1234);
            assert_eq!(WAIT_TIMEOUT, ATA_COMMAND_WAIT_TIMEOUT_TICKS);
            ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }

    #[test]
    fn preserves_signaled_result_as_zero() {
        let _lock = HOOKS_LOCK.lock();
        unsafe {
            install_wait_hook(0);
            let mut active = device(u32::MAX);
            assert_eq!(ata_command_wait(&mut active), 0);
            ptr::write(ptr::addr_of_mut!(KOBJ_HOOKS), DEFAULT_KOBJ_HOOKS);
        }
    }
}
