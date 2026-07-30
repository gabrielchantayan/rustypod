//! Mutexed PMU I2C register-block read — the entry the RTC wall clock
//! and the time/alarm getters fetch PCF50635 registers through:
//!
//! - `pmu_i2c_read_regs` — original: `FUN_082e58f0` @ 0x082e58f0 (52
//!   bytes; 4 `bl` call sites, binary-verified: 0x08054910 inside
//!   FUN_080548ec, which seeds the PRNG state from the raw RTC bytes;
//!   0x08056164 inside `rtc_read_time` @ 0x08056150 (time/rtc.rs);
//!   0x080641e0 inside FUN_0806418c, the struct-tm time getter, which
//!   maps the status 0x15 apart from other read errors; 0x0806e894
//!   inside FUN_0806e7e4, the time setter's read-back).
//!
//! Algorithm (mirrored from the disassembly):
//! 1. `stmdb sp!, {r4,r5,r6,lr}`; `mov r5, r1` (buf), `mov r4, r0`
//!    (bank).
//! 2. Two fixed-id RTXC kernel-semaphore waits bracket the
//!    transaction: `bl 0x0806a4b0` (`mov r0, #0x11; b 0x08037e08` —
//!    rom_sem_wait(0x11), the outer lock) then `bl 0x0806a4a0`
//!    (`mov r0, #5; b 0x08037e08` — rom_sem_wait(5), the inner lock).
//!    The same pair brackets every PMU I2C transaction of the
//!    0x082e5xxx family (~30 wait sites) — the raw transfer functions
//!    (FUN_0836d3b8 and below) take no lock themselves.
//! 3. `bl 0x0836d698` — `FUN_0836d698(bank, buf)`: bank 0 selects
//!    register block 0x59 (RTC time), bank 1 block 0x60 (alarm), any
//!    other bank returns 9 (bad bank) with the buffer untouched; a
//!    valid bank tail-branches into `FUN_0836d3b8(reg, 7, buf)`, which
//!    writes the register address to I2C slave 0x73 (the PCF50635 PMU)
//!    via FUN_0836bb84 and reads 7 bytes back via FUN_0836b950 — the
//!    S5L8702 I2C hardware.
//! 4. The mirror thunks release in reverse order: `bl 0x080645a8`
//!    (`mov r0, #5; b 0x08037e10` — rom_sem_signal(5)) then
//!    `bl 0x08064604` (`mov r0, #0x11; b 0x08037e10` —
//!    rom_sem_signal(0x11)). Both release unconditionally — there is
//!    no error path that skips them.
//! 5. `mov r0, r4` returns the FUN_0836d698 status verbatim.
//!
//! # Deviation
//!
//! The two semaphore pairs are not ported (they are 8-byte veneers
//! onto the ROM semaphore services 0x22003fd0/0x220042b4 with a fixed
//! id in r0); the port calls the same ROM services through
//! `kernel::sync_mutex::ROM_KERNEL` (`sema_wait`/`sema_signal`), the
//! table every driver already uses — with the default stubs the
//! lock/unlock are harmless no-ops. FUN_0836d698 and the hardware
//! chain under it stay unported: the call dispatches through the
//! [`PMU_READ_REGS`] slot (the house ops-slot pattern, `blx` in place
//! of `bl`), whose default stub fails closed with the driver's own
//! bad-bank code [`PMU_READ_BAD_BANK`]. The port is the shipped
//! default of time/rtc.rs's `RTC_READ_REGS` slot, so the wired
//! defaults reproduce the old fail-closed stub exactly (status 9 ->
//! `rtc_read_time` reports -5 and converts the seeded buffer).

use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};

/// Outer transaction lock: fixed RTXC kernel-semaphore handle 0x11
/// (17), waited first and released last around every PMU I2C
/// transaction (original: `mov r0, #0x11` in the 0x0806a4b0/0x08064604
/// veneers).
pub const PMU_I2C_OUTER_SEM: u32 = 0x11;

/// Inner transaction lock: fixed RTXC kernel-semaphore handle 5,
/// waited second and released first (original: `mov r0, #5` in the
/// 0x0806a4a0/0x080645a8 veneers).
pub const PMU_I2C_INNER_SEM: u32 = 5;

/// FUN_0836d698's own bad-bank code (`movne r0, #9`): what the
/// [`PMU_READ_REGS`] default stub reports for every bank so the chain
/// fails closed without the hardware driver.
pub const PMU_READ_BAD_BANK: i32 = 9;

/// The FUN_0836d698 boundary: `bank` 0 selects PMU register block
/// 0x59 (RTC time), bank 1 block 0x60 (alarm); 7 bytes are read into
/// `buf`; returns 0 on success. Matches time/rtc.rs's `RtcReadFn`.
pub type PmuReadRegsFn = unsafe extern "C" fn(bank: u32, buf: *mut u8) -> i32;

/// Default slot: fail closed with the bad-bank code 9. The real bank
/// mux (FUN_0836d698) and the S5L8702 I2C transfer chain under it
/// (FUN_0836d3b8 -> FUN_0836bb84/FUN_0836b950, slave 0x73) are
/// unported hardware.
pub(crate) unsafe extern "C" fn pmu_read_regs_stub(_bank: u32, _buf: *mut u8) -> i32 {
    PMU_READ_BAD_BANK
}

/// The active PMU register-block read. Host tests install a recording
/// mock; the real driver replaces the stub when the I2C chain lands.
pub static mut PMU_READ_REGS: PmuReadRegsFn = pmu_read_regs_stub;

/// Reads the ROM kernel table and the read slot (volatile — same
/// rationale as every dispatch table: a build in which nothing swaps
/// them must not constant-fold the defaults in).
#[inline(always)]
fn ops() -> (RomKernelOps, PmuReadRegsFn) {
    unsafe {
        (
            core::ptr::read_volatile(core::ptr::addr_of!(ROM_KERNEL)),
            core::ptr::read_volatile(core::ptr::addr_of!(PMU_READ_REGS)),
        )
    }
}

/// pmu_i2c_read_regs — original: `FUN_082e58f0` @ 0x082e58f0 (52
/// bytes).
///
/// Reads a 7-byte PMU register block (`bank` 0 = time @ 0x59, bank 1 =
/// alarm @ 0x60) into `buf` under the outer/inner transaction locks,
/// returning the driver's status (0 on success, 9 for a bad bank).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_i2c_read_regs(bank: u32, buf: *mut u8) -> i32 {
    let (kernel, read_regs) = ops();
    (kernel.sema_wait)(PMU_I2C_OUTER_SEM);
    (kernel.sema_wait)(PMU_I2C_INNER_SEM);
    let status = (read_regs)(bank, buf);
    (kernel.sema_signal)(PMU_I2C_INNER_SEM);
    (kernel.sema_signal)(PMU_I2C_OUTER_SEM);
    status
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the PMU_READ_REGS / ROM_KERNEL swaps; pub(crate) so
    /// time/rtc.rs's shipped-default end-to-end test can hold it (the
    /// kobj.rs HOOKS_LOCK precedent).
    pub(crate) static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Logged semaphore ops: (0 = wait, 1 = signal, handle).
    static mut SEM_LOG: Vec<(u8, u32)> = Vec::new();
    /// Logged reads: (bank, buf address).
    static mut READ_LOG: Vec<(u32, usize)> = Vec::new();
    /// Status the mock read hands back.
    static mut READ_STATUS: i32 = 0;

    unsafe extern "C" fn mock_sema_wait(handle: u32) {
        (*addr_of_mut!(SEM_LOG)).push((0, handle));
    }

    unsafe extern "C" fn mock_sema_signal(handle: u32) {
        (*addr_of_mut!(SEM_LOG)).push((1, handle));
    }

    unsafe extern "C" fn mock_read_regs(bank: u32, buf: *mut u8) -> i32 {
        (*addr_of_mut!(READ_LOG)).push((bank, buf as usize));
        *addr_of!(READ_STATUS)
    }

    /// Installs the recording mocks and returns the guard plus the
    /// saved ROM_KERNEL table (timer.rs's patch-and-restore pattern).
    fn install(status: i32) -> (MutexGuard<'static, ()>, RomKernelOps) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(SEM_LOG)).clear();
            (*addr_of_mut!(READ_LOG)).clear();
            *addr_of_mut!(READ_STATUS) = status;
            let saved = addr_of!(ROM_KERNEL).read_volatile();
            let mut patched = saved;
            patched.sema_wait = mock_sema_wait;
            patched.sema_signal = mock_sema_signal;
            addr_of_mut!(ROM_KERNEL).write(patched);
            addr_of_mut!(PMU_READ_REGS).write(mock_read_regs);
            (guard, saved)
        }
    }

    fn restore(state: (MutexGuard<'static, ()>, RomKernelOps)) {
        unsafe {
            addr_of_mut!(ROM_KERNEL).write(state.1);
            addr_of_mut!(PMU_READ_REGS).write(pmu_read_regs_stub);
        }
        drop(state.0);
    }

    #[test]
    fn locks_bracket_the_read_outer_first_inner_released_first() {
        let state = install(0);
        unsafe {
            let mut buf = [0u8; 7];
            let addr = buf.as_mut_ptr() as usize;
            assert_eq!(pmu_i2c_read_regs(0, buf.as_mut_ptr()), 0);
            assert_eq!(
                (*addr_of!(SEM_LOG)).clone(),
                std::vec![
                    (0, PMU_I2C_OUTER_SEM),
                    (0, PMU_I2C_INNER_SEM),
                    (1, PMU_I2C_INNER_SEM),
                    (1, PMU_I2C_OUTER_SEM),
                ],
                "wait outer, wait inner, read, signal inner, signal outer"
            );
            assert_eq!(
                (*addr_of!(READ_LOG)).clone(),
                std::vec![(0, addr)],
                "bank and buf forwarded untouched"
            );
        }
        restore(state);
    }

    #[test]
    fn status_passes_through_and_locks_release_on_error() {
        let state = install(9);
        unsafe {
            let mut buf = [0u8; 7];
            assert_eq!(pmu_i2c_read_regs(1, buf.as_mut_ptr()), 9);
            assert_eq!(
                (*addr_of!(SEM_LOG)).clone().len(),
                4,
                "the unlock pair runs even when the read fails"
            );
            assert_eq!((*addr_of!(READ_LOG)).clone(), std::vec![(1, buf.as_mut_ptr() as usize)]);
            *addr_of_mut!(READ_STATUS) = 0x15;
            assert_eq!(
                pmu_i2c_read_regs(0, buf.as_mut_ptr()),
                0x15,
                "the getter's special 0x15 passes through verbatim"
            );
            *addr_of_mut!(READ_STATUS) = -5;
            assert_eq!(pmu_i2c_read_regs(7, buf.as_mut_ptr()), -5);
        }
        restore(state);
    }

    #[test]
    fn default_stubs_fail_closed_and_leave_the_buffer_alone() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            addr_of_mut!(PMU_READ_REGS).write(pmu_read_regs_stub);
            let mut buf = [0xaau8; 7];
            assert_eq!(pmu_i2c_read_regs(0, buf.as_mut_ptr()), PMU_READ_BAD_BANK);
            assert_eq!(buf, [0xaau8; 7], "the stub never touches the buffer");
        }
        drop(guard);
    }
}
