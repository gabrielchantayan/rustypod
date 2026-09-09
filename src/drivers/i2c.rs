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
//! 3. `bl 0x0836d698` — `FUN_0836d698(bank, buf)`, now ported as
//!    [`pmu_i2c_read_bank`]: bank 0 selects register block 0x59 (RTC
//!    time), bank 1 block 0x60 (alarm), any other bank returns 9 (bad
//!    bank) with the buffer untouched; a valid bank tail-branches into
//!    `FUN_0836d3b8(reg, 7, buf)`, which writes the register address
//!    to I2C slave 0x73 (the PCF50635 PMU) via FUN_0836bb84 and reads
//!    7 bytes back via FUN_0836b950 — the S5L8702 I2C hardware.
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
//! lock/unlock are harmless no-ops. The callee boundary dispatches
//! through the [`PMU_READ_REGS`] slot (the house ops-slot pattern,
//! `blx` in place of `bl`), whose shipped default is the ported
//! [`pmu_i2c_read_bank`] (the pre-port stub [`pmu_read_regs_stub`] is
//! retained for host tests). The raw PMU transfer is now ported as
//! [`pmu_i2c_read`]; its still-unported S5L8702 I2C primitives
//! (`FUN_0836bb84` and `FUN_0836b950`) are fixed-address calls on
//! target and volatile host test seams.

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

/// FUN_0836d698's own bad-bank code (`movne r0, #9`): what the bank
/// mux returns for every bank but 0/1, and what the pre-port
/// [`PMU_READ_REGS`] stub reports.
pub const PMU_READ_BAD_BANK: i32 = 9;

/// PCF50635 register block selected by bank 0: the RTC time block
/// (sec/min/hour/weekday/day/month/year as 7 BCD bytes starting at
/// register 0x59; original: `moveq r0, #0x59`).
pub const PMU_RTC_TIME_BLOCK: u32 = 0x59;

/// Bank 1: the RTC alarm block at register 0x60 (original: `mov
/// r0, #0x60`).
pub const PMU_RTC_ALARM_BLOCK: u32 = 0x60;

/// Bytes read per register block (original: `mov r1, #0x7`).
pub const PMU_RTC_BLOCK_LEN: u32 = 7;

/// PMU I2C slave address, loaded by `mov r0, #0x73` before both raw
/// S5L8702 transfers in FUN_0836d3b8.
pub const PMU_I2C_SLAVE: u32 = 0x73;

/// ABI of raw S5L8702 I2C write `FUN_0836bb84`.
type I2cWriteFn = unsafe extern "C" fn(slave: u32, len: u32, buf: *const u8) -> i32;
/// ABI of raw S5L8702 I2C read `FUN_0836b950`.
type I2cReadFn = unsafe extern "C" fn(slave: u32, len: u32, buf: *mut u8) -> i32;

const I2C_WRITE_ADDRESS: usize = 0x0836_bb84;
const I2C_READ_ADDRESS: usize = 0x0836_b950;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn i2c_write(slave: u32, len: u32, buf: *const u8) -> i32 {
    let write: I2cWriteFn = core::mem::transmute(I2C_WRITE_ADDRESS);
    write(slave, len, buf)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn i2c_read(slave: u32, len: u32, buf: *mut u8) -> i32 {
    let read: I2cReadFn = core::mem::transmute(I2C_READ_ADDRESS);
    read(slave, len, buf)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2c_write(_slave: u32, _len: u32, _buf: *const u8) -> i32 {
    panic!("pmu_i2c_read requires I2C write 0x0836bb84")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2c_read(_slave: u32, _len: u32, _buf: *mut u8) -> i32 {
    panic!("pmu_i2c_read requires I2C read 0x0836b950")
}

#[cfg(not(target_os = "none"))]
static mut I2C_WRITE: I2cWriteFn = missing_i2c_write;
#[cfg(not(target_os = "none"))]
static mut I2C_READ: I2cReadFn = missing_i2c_read;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn i2c_write(slave: u32, len: u32, buf: *const u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(I2C_WRITE))(slave, len, buf)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn i2c_read(slave: u32, len: u32, buf: *mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(I2C_READ))(slave, len, buf)
}

/// The FUN_0836d698 boundary: `bank` 0 selects PMU register block
/// 0x59 (RTC time), bank 1 block 0x60 (alarm); 7 bytes are read into
/// `buf`; returns 0 on success. Matches time/rtc.rs's `RtcReadFn`.
pub type PmuReadRegsFn = unsafe extern "C" fn(bank: u32, buf: *mut u8) -> i32;

/// Pre-port default slot, retained for host tests: fail closed with
/// the bad-bank code 9 for every bank. The shipped default is the
/// ported [`pmu_i2c_read_bank`].
pub(crate) unsafe extern "C" fn pmu_read_regs_stub(_bank: u32, _buf: *mut u8) -> i32 {
    PMU_READ_BAD_BANK
}

/// The active PMU register-block read. Shipped default: the ported
/// [`pmu_i2c_read_bank`]; host tests install a recording mock.
pub static mut PMU_READ_REGS: PmuReadRegsFn = pmu_i2c_read_bank;

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

/// pmu_i2c_read — original: `FUN_0836d3b8` @ 0x0836d3b8 (84 bytes;
/// 18 plain `bl` call sites, 0 predicated `bl`, binary-verified by
/// decoding every B/BL word in osos.dec).
///
/// Stores `reg` as a native word, writes its low byte to PCF50635
/// slave 0x73 through `FUN_0836bb84`, then, only if that succeeds and
/// `len` is positive, reads exactly `len` bytes through
/// `FUN_0836b950`. The stock loop advances its completed count by the
/// entire remainder, therefore its positive-length path makes exactly
/// one read; zero and negative signed lengths still perform the
/// register write but skip the read. Both raw status words return
/// verbatim. The direct branch references at 0x0836d3ac (`bcc`),
/// 0x0836d690 (`beq`), and 0x0836d6bc (`b`) are not calls.
///
/// # Deviation
///
/// The two raw S5L8702 I2C primitives remain unported. Target builds
/// call their verified load addresses directly; host tests use volatile
/// function-pointer seams. This changes each retail direct `bl` to an
/// indirect `blx` on target.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_i2c_read(reg: u32, len: i32, buf: *mut u8) -> i32 {
    let register = reg;
    let mut status = i2c_write(PMU_I2C_SLAVE, 1, (&register as *const u32).cast());
    if status != 0 {
        return status;
    }
    if len > 0 {
        status = i2c_read(PMU_I2C_SLAVE, len as u32, buf);
    }
    status
}

/// pmu_i2c_write — original: `FUN_0836d524` @ 0x0836d524 (60
/// bytes; 17 plain `bl` call sites, 0 predicated `bl`,
/// binary-verified by decoding every B/BL word in osos.dec).
///
/// The write twin of [`pmu_i2c_read`]: builds a packet on its
/// 16-byte stack frame (`push {r2,r3,r4,lr}`) with the low byte of
/// `reg` first (`strb r0, [sp]`), copies `len` payload bytes after
/// it with a signed byte loop (`cmp r0, r1` / `ldrblt` / `strblt` —
/// non-positive signed lengths copy nothing), then hands
/// `FUN_0836bb84` the PCF50635 slave 0x73, a wrapping count of
/// `len + 1` (`add r1, r1, #1`), and the packet, returning the raw
/// status verbatim. Retail copies into a 16-byte frame, so a
/// payload above 15 bytes would overrun the caller's frame; every
/// caller passes small lengths. The conditional direct branches at
/// 0x0836d474 (`bne`), 0x0836d518 (`bcc`), 0x0836d710 and
/// 0x0836d824 (`beq`) are tail-branch references, not calls.
///
/// # Deviation
///
/// The raw S5L8702 I2C write primitive `FUN_0836bb84` remains
/// unported: target builds call its verified load address directly,
/// host tests use the volatile function-pointer seam (an indirect
/// `blx` in place of retail's `bl`). The payload copy uses volatile
/// byte accesses so LLVM cannot fold the loop into a `memcpy` call
/// that retail never made.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_i2c_write(reg: u32, len: i32, data: *const u8) -> i32 {
    let mut packet = [0u8; 16];
    packet[0] = reg as u8;
    let mut copied: i32 = 0;
    while copied < len {
        let byte = core::ptr::read_volatile(data.offset(copied as isize));
        core::ptr::write_volatile(packet.as_mut_ptr().offset(1 + copied as isize), byte);
        copied += 1;
    }
    i2c_write(PMU_I2C_SLAVE, (len as u32).wrapping_add(1), packet.as_ptr())
}

/// pmu_i2c_read_bank — original: `FUN_0836d698` @ 0x0836d698 (40
/// bytes).
///
/// The bank mux under [`pmu_i2c_read_regs`]: bank 0 selects the
/// PCF50635 RTC time register block 0x59 (`cmp r0, #0 / moveq r0,
/// #0x59`), bank 1 the alarm block 0x60 (`cmp r0, #1 / mov r0,
/// #0x60`), any other bank returns the bad-bank code
/// [`PMU_READ_BAD_BANK`] (`movne r0, #9 / bxne lr`) with the buffer
/// untouched; a valid bank tail-branches (`b 0x0836d3b8`) into
/// [`pmu_i2c_read`].
///
/// # Deviation
///
/// The Rust call replaces the retail tail branch, so it uses `bl` and
/// return rather than `b`; the callee's raw I2C calls are indirect
/// `blx` through its fixed-address boundary.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_i2c_read_bank(bank: u32, buf: *mut u8) -> i32 {
    let reg = if bank == 0 {
        PMU_RTC_TIME_BLOCK
    } else if bank == 1 {
        PMU_RTC_ALARM_BLOCK
    } else {
        return PMU_READ_BAD_BANK;
    };
    pmu_i2c_read(reg, PMU_RTC_BLOCK_LEN as i32, buf)
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

    /// Raw PMU write calls: (slave, len, first byte).
    static mut RAW_WRITE_LOG: Vec<(u32, u32, u8)> = Vec::new();
    /// Full packet bytes handed to each raw PMU write.
    static mut RAW_WRITE_PACKETS: Vec<Vec<u8>> = Vec::new();
    /// Raw PMU read calls: (slave, len, destination address).
    static mut RAW_READ_LOG: Vec<(u32, u32, usize)> = Vec::new();
    static mut RAW_WRITE_STATUS: i32 = 0;
    static mut RAW_READ_STATUS: i32 = 0;
    /// Logged semaphore ops: (0 = wait, 1 = signal, handle).
    static mut SEM_LOG: Vec<(u8, u32)> = Vec::new();
    /// Logged PMU register-block reads: (bank, buf address).
    static mut READ_LOG: Vec<(u32, usize)> = Vec::new();
    /// Status the register-block read mock hands back.
    static mut READ_STATUS: i32 = 0;

    unsafe extern "C" fn mock_i2c_write(slave: u32, len: u32, buf: *const u8) -> i32 {
        (*addr_of_mut!(RAW_WRITE_LOG)).push((slave, len, buf.read()));
        let mut packet = Vec::new();
        for i in 0..len as usize {
            packet.push(buf.add(i).read());
        }
        (*addr_of_mut!(RAW_WRITE_PACKETS)).push(packet);
        *addr_of!(RAW_WRITE_STATUS)
    }

    unsafe extern "C" fn mock_i2c_read(slave: u32, len: u32, buf: *mut u8) -> i32 {
        (*addr_of_mut!(RAW_READ_LOG)).push((slave, len, buf as usize));
        *addr_of!(RAW_READ_STATUS)
    }

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
            addr_of_mut!(PMU_READ_REGS).write(pmu_i2c_read_bank);
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
            addr_of_mut!(PMU_READ_REGS).write(pmu_i2c_read_bank);
        }
        drop(guard);
    }

    fn install_raw(write_status: i32, read_status: i32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(RAW_WRITE_LOG)).clear();
            (*addr_of_mut!(RAW_WRITE_PACKETS)).clear();
            (*addr_of_mut!(RAW_READ_LOG)).clear();
            *addr_of_mut!(RAW_WRITE_STATUS) = write_status;
            *addr_of_mut!(RAW_READ_STATUS) = read_status;
            addr_of_mut!(I2C_WRITE).write(mock_i2c_write);
            addr_of_mut!(I2C_READ).write(mock_i2c_read);
        }
        guard
    }

    fn restore_raw(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(I2C_WRITE).write(missing_i2c_write);
            addr_of_mut!(I2C_READ).write(missing_i2c_read);
        }
        drop(guard);
    }

    #[test]
    fn raw_write_error_skips_read_and_preserves_buffer() {
        let guard = install_raw(-5, 0);
        unsafe {
            let mut buf = [0xaau8; 7];
            assert_eq!(pmu_i2c_read(0x1234_56a7, 7, buf.as_mut_ptr()), -5);
            assert_eq!((*addr_of!(RAW_WRITE_LOG)).clone(), std::vec![(PMU_I2C_SLAVE, 1, 0xa7)]);
            assert!((*addr_of!(RAW_READ_LOG)).is_empty());
            assert_eq!(buf, [0xaau8; 7]);
        }
        restore_raw(guard);
    }

    #[test]
    fn raw_non_positive_lengths_write_register_but_skip_read() {
        let guard = install_raw(0, 0);
        unsafe {
            let mut buf = [0xaau8; 7];
            for len in [i32::MIN, -1, 0] {
                assert_eq!(pmu_i2c_read(0x59, len, buf.as_mut_ptr()), 0);
            }
            assert_eq!(
                (*addr_of!(RAW_WRITE_LOG)).clone(),
                std::vec![
                    (PMU_I2C_SLAVE, 1, 0x59),
                    (PMU_I2C_SLAVE, 1, 0x59),
                    (PMU_I2C_SLAVE, 1, 0x59),
                ]
            );
            assert!((*addr_of!(RAW_READ_LOG)).is_empty());
            assert_eq!(buf, [0xaau8; 7]);
        }
        restore_raw(guard);
    }

    #[test]
    fn raw_positive_read_is_once_and_status_is_verbatim() {
        let guard = install_raw(0, 0x15);
        unsafe {
            let mut buf = [0u8; 7];
            let addr = buf.as_mut_ptr() as usize;
            assert_eq!(pmu_i2c_read(0x60, 7, buf.as_mut_ptr()), 0x15);
            *addr_of_mut!(RAW_READ_STATUS) = -5;
            assert_eq!(pmu_i2c_read(0x60, 1, buf.as_mut_ptr()), -5);
            assert_eq!(
                (*addr_of!(RAW_READ_LOG)).clone(),
                std::vec![
                    (PMU_I2C_SLAVE, 7, addr),
                    (PMU_I2C_SLAVE, 1, addr),
                ],
                "each positive request performs one full read"
            );
        }
        restore_raw(guard);
    }

    #[test]
    fn bank_mux_selects_time_then_alarm_block() {
        let guard = install_raw(0, 0);
        unsafe {
            let mut buf = [0u8; 7];
            let addr = buf.as_mut_ptr() as usize;
            assert_eq!(pmu_i2c_read_bank(0, buf.as_mut_ptr()), 0);
            assert_eq!(pmu_i2c_read_bank(1, buf.as_mut_ptr()), 0);
            assert_eq!(
                (*addr_of!(RAW_WRITE_LOG)).clone(),
                std::vec![
                    (PMU_I2C_SLAVE, 1, PMU_RTC_TIME_BLOCK as u8),
                    (PMU_I2C_SLAVE, 1, PMU_RTC_ALARM_BLOCK as u8),
                ]
            );
            assert_eq!(
                (*addr_of!(RAW_READ_LOG)).clone(),
                std::vec![
                    (PMU_I2C_SLAVE, PMU_RTC_BLOCK_LEN, addr),
                    (PMU_I2C_SLAVE, PMU_RTC_BLOCK_LEN, addr),
                ]
            );
        }
        restore_raw(guard);
    }

    #[test]
    fn write_builds_reg_then_payload_packet() {
        let guard = install_raw(0, 0);
        unsafe {
            let data = [0xde, 0xad, 0xbe, 0xef];
            assert_eq!(pmu_i2c_write(0x59, 4, data.as_ptr()), 0);
            assert_eq!(
                (*addr_of!(RAW_WRITE_LOG)).clone(),
                std::vec![(PMU_I2C_SLAVE, 5, 0x59)],
                "slave 0x73, count len + 1, reg byte first"
            );
            assert_eq!(
                (*addr_of!(RAW_WRITE_PACKETS)).clone(),
                std::vec![std::vec![0x59u8, 0xde, 0xad, 0xbe, 0xef]],
                "packet is the reg byte followed by the payload"
            );
        }
        restore_raw(guard);
    }

    #[test]
    fn write_stores_only_the_low_reg_byte_and_passes_status_through() {
        let guard = install_raw(0x15, 0);
        unsafe {
            let data = [7u8];
            assert_eq!(pmu_i2c_write(0x1234_56a7, 1, data.as_ptr()), 0x15);
            assert_eq!(
                (*addr_of!(RAW_WRITE_PACKETS)).clone(),
                std::vec![std::vec![0xa7u8, 7]],
                "strb keeps only the low byte of the reg argument"
            );
            *addr_of_mut!(RAW_WRITE_STATUS) = -5;
            assert_eq!(pmu_i2c_write(0x60, 1, data.as_ptr()), -5);
        }
        restore_raw(guard);
    }

    #[test]
    fn write_non_positive_lengths_copy_no_payload() {
        let guard = install_raw(0, 0);
        unsafe {
            let data = [0xaau8; 4];
            assert_eq!(pmu_i2c_write(0x2b, 0, data.as_ptr()), 0);
            assert_eq!(pmu_i2c_write(0x2b, -1, data.as_ptr()), 0);
            assert_eq!(
                (*addr_of!(RAW_WRITE_LOG)).clone(),
                std::vec![(PMU_I2C_SLAVE, 1, 0x2b), (PMU_I2C_SLAVE, 0, 0x2b)],
                "len 0 still sends the lone reg byte; len -1 wraps the count to 0"
            );
            assert_eq!(
                (*addr_of!(RAW_WRITE_PACKETS)).clone(),
                std::vec![std::vec![0x2bu8], std::vec![]],
                "the signed copy loop never runs for non-positive lengths"
            );
        }
        restore_raw(guard);
    }

    #[test]
    fn write_max_frame_payload_fits() {
        let guard = install_raw(0, 0);
        unsafe {
            let data: [u8; 15] = core::array::from_fn(|i| i as u8);
            assert_eq!(pmu_i2c_write(0x87, 15, data.as_ptr()), 0);
            let mut expect = std::vec![0x87u8];
            expect.extend_from_slice(&data);
            assert_eq!((*addr_of!(RAW_WRITE_PACKETS)).clone(), std::vec![expect]);
            assert_eq!(
                (*addr_of!(RAW_WRITE_LOG)).clone(),
                std::vec![(PMU_I2C_SLAVE, 16, 0x87)],
                "15 payload bytes fill the retail 16-byte frame exactly"
            );
        }
        restore_raw(guard);
    }

    #[test]
    fn bad_bank_fails_closed_without_transfer() {
        let guard = install_raw(0, 0);
        unsafe {
            let mut buf = [0xaau8; 7];
            for bank in [2u32, 9, 0xffff_ffff] {
                assert_eq!(
                    pmu_i2c_read_bank(bank, buf.as_mut_ptr()),
                    PMU_READ_BAD_BANK,
                    "bank {bank:#x} reports the bad-bank code"
                );
            }
            assert!((*addr_of!(RAW_WRITE_LOG)).is_empty());
            assert!((*addr_of!(RAW_READ_LOG)).is_empty());
            assert_eq!(buf, [0xaau8; 7], "the buffer stays untouched");
        }
        restore_raw(guard);
    }
}
