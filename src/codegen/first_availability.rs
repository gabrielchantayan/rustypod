//! `cg_first_availability` — original: `FUN_082bcf38` @ **0x082bcf38**.
//!
//! Raw `osos.dec` words establish the 96-byte body
//! `0x082bcf38..0x082bcf97`; the next independently linked function starts
//! at `0x082bcf98`. Its body contains **4 plain, unconditional `bl` calls**
//! and no predicated calls (Ghidra's three-call report omits the initial
//! `board_version` query). It returns unavailable immediately for first-probe
//! status 2. For status 3, it maps board-version high-halfword values 4, 7,
//! 12, and 20 to limit 6 (all others map to 7), rejects an active mode, then
//! returns unavailable when that limit is not greater than the mode limit.
//!
//! Deliberate deviations: `board_version` is already ported and called
//! directly. The three unported, individually verified callees remain ARM
//! literal veneers and replaceable host seams; their semantic names describe
//! only their observed return roles, not an unproven subsystem identity.

#[cfg(test)]
extern crate std;

#[cfg(not(target_arch = "arm"))]
use core::ptr;

use crate::sysinfo::board_version;

pub type FirstProbeStatus = unsafe extern "C" fn() -> u32;
pub type ModeIsActive = unsafe extern "C" fn() -> u32;
pub type ModeLimit = unsafe extern "C" fn() -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn first_probe_clear() -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn mode_inactive() -> u32 { 0 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn mode_limit_zero() -> i32 { 0 }

#[cfg(not(target_arch = "arm"))]
pub static mut CG_FIRST_PROBE_STATUS: FirstProbeStatus = first_probe_clear;
#[cfg(not(target_arch = "arm"))]
pub static mut CG_MODE_IS_ACTIVE: ModeIsActive = mode_inactive;
#[cfg(not(target_arch = "arm"))]
pub static mut CG_MODE_LIMIT: ModeLimit = mode_limit_zero;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_cg_first_probe_status() -> u32;
    fn retail_cg_mode_is_active() -> u32;
    fn retail_cg_mode_limit() -> i32;
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_first_probe_status() -> u32 {
    ptr::read_volatile(ptr::addr_of!(CG_FIRST_PROBE_STATUS))()
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_mode_is_active() -> u32 {
    ptr::read_volatile(ptr::addr_of!(CG_MODE_IS_ACTIVE))()
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_mode_limit() -> i32 {
    ptr::read_volatile(ptr::addr_of!(CG_MODE_LIMIT))()
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_cg_first_probe_status
retail_cg_first_probe_status:
    ldr pc, [pc, #-4]
    .word 0x082bc5b8
    .globl retail_cg_mode_is_active
retail_cg_mode_is_active:
    ldr pc, [pc, #-4]
    .word 0x080dd2c8
    .globl retail_cg_mode_limit
retail_cg_mode_limit:
    ldr pc, [pc, #-4]
    .word 0x080cc950
"#);

/// First code-generator availability predicate at 0x082bcf38.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_first_availability() -> u32 {
    let version = board_version() >> 16;
    let probe_status = retail_cg_first_probe_status();
    if probe_status == 2 {
        return 1;
    }
    if probe_status == 3 {
        let limit = if version == 4 || version == 7 || version == 12 || version == 20 {
            6
        } else {
            7
        };
        if retail_cg_mode_is_active() != 0 || limit <= retail_cg_mode_limit() {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use crate::sysinfo::install_host_cached_board_version;


    static LOCK: Mutex<()> = Mutex::new(());
    static mut PROBE_STATUS: u32 = 0;
    static mut MODE_ACTIVE: u32 = 0;
    static mut MODE_LIMIT_VALUE: i32 = 0;

    unsafe extern "C" fn probe_status() -> u32 { PROBE_STATUS }
    unsafe extern "C" fn mode_active() -> u32 { MODE_ACTIVE }
    unsafe extern "C" fn mode_limit() -> i32 { MODE_LIMIT_VALUE }

    #[test]
    fn only_status_two_is_unavailable_outside_the_limit_path() {
        let _lock = LOCK.lock();
        let _version = install_host_cached_board_version(0x0004_0000);
        unsafe {
            CG_FIRST_PROBE_STATUS = probe_status;
            CG_MODE_IS_ACTIVE = mode_active;
            CG_MODE_LIMIT = mode_limit;
            MODE_ACTIVE = 1;
            MODE_LIMIT_VALUE = 99;
            PROBE_STATUS = 0;
            assert_eq!(cg_first_availability(), 0);
            PROBE_STATUS = 1;
            assert_eq!(cg_first_availability(), 0);
            PROBE_STATUS = 2;
            assert_eq!(cg_first_availability(), 1);
        }
    }

    #[test]
    fn status_three_selects_the_version_limit_and_checks_activity_first() {
        let _lock = LOCK.lock();
        unsafe {
            CG_FIRST_PROBE_STATUS = probe_status;
            CG_MODE_IS_ACTIVE = mode_active;
            CG_MODE_LIMIT = mode_limit;
            PROBE_STATUS = 3;
            MODE_ACTIVE = 0;
            MODE_LIMIT_VALUE = 6;
        }
        let _special = install_host_cached_board_version(0x000c_0000);
        unsafe { assert_eq!(cg_first_availability(), 1); }
        drop(_special);
        let _other = install_host_cached_board_version(0x0005_0000);
        unsafe {
            assert_eq!(cg_first_availability(), 0);
            MODE_ACTIVE = 1;
            assert_eq!(cg_first_availability(), 1);
        }
    }
}
