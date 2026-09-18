//! Best valid clock-source synchronization: `FUN_080e1d18` @ 0x080e1d18.
//!
//! # Verified original
//!
//! The true extent is **152 bytes**, `0x080e1d18..0x080e1db0`: the 38 ARM
//! instructions end in `pop {..., pc}` at 0x080e1dac and are followed by the
//! three literal-pool words consumed by the body. Decoding `osos.dec` finds
//! four unconditional `bl` callers and no predicated `bl` callers. The body
//! contains eight unconditional `bl` instructions and no predicated calls.
//! # Algorithm
//!
//! Select the oldest valid record from the five 20-byte clock-source slots,
//! write it to the RTC, then replace the current clock record only when the
//! selected source is newer. A failed RTC write still refreshes the current
//! record, preserving its zone/DST/status bytes at offsets 6, 7, and 11.
//! The selected slot index is always published, including -1 when no slot is
//! valid.
//!
//! # Deliberate deviations
//!
//! The unported RTC setter (`FUN_0806e7e4`) and change notifier
//! (`FUN_0805caa8`) are fixed-address calls on target and volatile host seams.
//! Selection and comparison inline the small unported helpers (`FUN_080caa28`
//! and `FUN_0808cde4`) rather than adding opaque seams; this preserves their
//! observable ordering and avoids inventing callee identities.

use core::ptr;

use super::clock_state::ClockState;
use crate::kernel::task_lock::{rom_sem_signal, rom_sem_wait};

const CLOCK_SOURCES_ADDRESS: usize = 0x08a6_62ec;
const CURRENT_CLOCK_ADDRESS: usize = 0x08a6_62e0;
const SELECTED_CLOCK_SOURCE_ADDRESS: usize = 0x089c_aa90;
const RTC_WRITE_ADDRESS: usize = 0x0806_e7e4;
const CLOCK_CHANGED_ADDRESS: usize = 0x0805_caa8;
const CLOCK_SOURCE_COUNT: usize = 5;
const CLOCK_SOURCE_SIZE: usize = 20;

type RtcWriteFn = unsafe extern "C" fn(mode: u32, source: *const ClockState) -> i32;
type ClockChangedFn = unsafe extern "C" fn();

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_rtc_write(_mode: u32, _source: *const ClockState) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clock_changed() {}

#[cfg(not(target_os = "none"))]
pub static mut CLOCK_SOURCES: [[u8; CLOCK_SOURCE_SIZE]; CLOCK_SOURCE_COUNT] = [[0; CLOCK_SOURCE_SIZE]; CLOCK_SOURCE_COUNT];
#[cfg(not(target_os = "none"))]
pub static mut CURRENT_CLOCK: ClockState = ClockState { year: 0, month: 0, day: 0, yday: 0, utc_offset_quarters: 0, dst_active: 0, hour: 0, minute: 0, second: 0, status: 0 };
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_CLOCK_SOURCE: i32 = -1;
#[cfg(not(target_os = "none"))]
pub static mut RTC_WRITE: RtcWriteFn = missing_rtc_write;
#[cfg(not(target_os = "none"))]
pub static mut CLOCK_CHANGED: ClockChangedFn = missing_clock_changed;

#[inline(always)]
unsafe fn sources() -> *mut u8 {
    #[cfg(target_os = "none")]
    { CLOCK_SOURCES_ADDRESS as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(CLOCK_SOURCES).cast() }
}
#[inline(always)]
unsafe fn current_clock() -> *mut ClockState {
    #[cfg(target_os = "none")]
    { CURRENT_CLOCK_ADDRESS as *mut ClockState }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(CURRENT_CLOCK) }
}
#[inline(always)]
unsafe fn selected_clock_source() -> *mut i32 {
    #[cfg(target_os = "none")]
    { SELECTED_CLOCK_SOURCE_ADDRESS as *mut i32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(SELECTED_CLOCK_SOURCE) }
}
#[inline(always)]
unsafe fn rtc_write() -> RtcWriteFn {
    #[cfg(target_os = "none")]
    { core::mem::transmute(RTC_WRITE_ADDRESS) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(RTC_WRITE)) }
}
#[inline(always)]
unsafe fn clock_changed() -> ClockChangedFn {
    #[cfg(target_os = "none")]
    { core::mem::transmute(CLOCK_CHANGED_ADDRESS) }
    #[cfg(not(target_os = "none"))]
    { ptr::read_volatile(ptr::addr_of!(CLOCK_CHANGED)) }
}

#[inline(always)]
unsafe fn compare_clock_records(left: *const u8, right: *const u8) -> i32 {
    let left_date = (ptr::read_unaligned(left.cast::<u16>()) as u32) << 16 | ptr::read_unaligned(left.add(4).cast::<u16>()) as u32;
    let right_date = (ptr::read_unaligned(right.cast::<u16>()) as u32) << 16 | ptr::read_unaligned(right.add(4).cast::<u16>()) as u32;
    if left_date != right_date { return if left_date < right_date { -1 } else { 1 }; }
    let left_time = (ptr::read(left.add(8)) as u32) << 16 | (ptr::read(left.add(9)) as u32) << 8 | ptr::read(left.add(10)) as u32;
    let right_time = (ptr::read(right.add(8)) as u32) << 16 | (ptr::read(right.add(9)) as u32) << 8 | ptr::read(right.add(10)) as u32;
    if left_time < right_time { -1 } else if left_time > right_time { 1 } else { 0 }
}

/// sync_best_clock_source — original: `FUN_080e1d18` @ `0x080e1d18`
/// (**152 bytes including its literal pool; four unconditional `bl` callers,
/// no predicated callers; module header records the eight body calls**).
///
/// Returns whether the selected source exactly matches the current record.
/// The source scan, RTC write, conditional 12-byte current-record copy,
/// notification, and index publish follow the ARM order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sync_best_clock_source() -> bool {
    let mut selected = -1i32;
    let source_base = sources();
    for index in 0..CLOCK_SOURCE_COUNT {
        let source = source_base.add(index * CLOCK_SOURCE_SIZE);
        if ptr::read(source.add(14)) != 0 && (selected < 0 || compare_clock_records(source, source_base.add(selected as usize * CLOCK_SOURCE_SIZE)) < 0) {
            selected = index as i32;
        }
    }
    if selected < 0 {
        ptr::write_volatile(selected_clock_source(), selected);
        return false;
    }

    rom_sem_wait(3);
    let source = source_base.add(selected as usize * CLOCK_SOURCE_SIZE);
    rtc_write()(1, source.cast());
    let current = current_clock().cast::<u8>();
    let matches_current = compare_clock_records(source, current) == 0;
    if !matches_current {
        let zone = ptr::read(current.add(6));
        let dst = ptr::read(current.add(7));
        let status = ptr::read(current.add(11));
        for offset in 0..12 { ptr::write(current.add(offset), ptr::read(source.add(offset))); }
        ptr::write(current.add(6), zone);
        ptr::write(current.add(7), dst);
        ptr::write(current.add(11), status);
    }
    clock_changed()();
    rom_sem_signal(3);
    ptr::write_volatile(selected_clock_source(), selected);
    matches_current
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static WRITES: AtomicU32 = AtomicU32::new(0);
    static NOTIFICATIONS: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn record_write(_mode: u32, _source: *const ClockState) -> i32 { WRITES.fetch_add(1, Ordering::Relaxed); 0 }
    unsafe extern "C" fn record_changed() { NOTIFICATIONS.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn no_op_semaphore(_semaphore: usize) -> usize { 0 }


    struct Fixture { _lock: MutexGuard<'static, ()>, write: RtcWriteFn, changed: ClockChangedFn, rom: crate::kernel::task_lock::RomThunkOps, sources: [[u8; CLOCK_SOURCE_SIZE]; CLOCK_SOURCE_COUNT], current: ClockState, selected: i32 }
    unsafe fn install() -> Fixture {
        let lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rom = ptr::read_volatile(ptr::addr_of!(crate::kernel::task_lock::ROM_KERNEL));
        let fixture = Fixture { _lock: lock, write: RTC_WRITE, changed: CLOCK_CHANGED, rom, sources: CLOCK_SOURCES, current: CURRENT_CLOCK, selected: SELECTED_CLOCK_SOURCE };
        let mut installed_rom = rom;
        installed_rom.rom_sem_wait = no_op_semaphore;
        installed_rom.rom_sem_signal = no_op_semaphore;
        ptr::write_volatile(ptr::addr_of_mut!(crate::kernel::task_lock::ROM_KERNEL), installed_rom);
        RTC_WRITE = record_write; CLOCK_CHANGED = record_changed; CLOCK_SOURCES = [[0; CLOCK_SOURCE_SIZE]; CLOCK_SOURCE_COUNT]; WRITES.store(0, Ordering::Relaxed); NOTIFICATIONS.store(0, Ordering::Relaxed);
        fixture
    }
    impl Drop for Fixture { fn drop(&mut self) { unsafe { RTC_WRITE = self.write; CLOCK_CHANGED = self.changed; ptr::write_volatile(ptr::addr_of_mut!(crate::kernel::task_lock::ROM_KERNEL), self.rom); CLOCK_SOURCES = self.sources; CURRENT_CLOCK = self.current; SELECTED_CLOCK_SOURCE = self.selected; } } }
    fn record(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> [u8; CLOCK_SOURCE_SIZE] { let mut r = [0; CLOCK_SOURCE_SIZE]; r[0..2].copy_from_slice(&year.to_le_bytes()); r[2] = month; r[3] = day; r[8] = hour; r[9] = minute; r[10] = second; r[14] = 1; r }

    #[test]
    fn selects_oldest_valid_source_and_updates_different_current_clock() { unsafe { let _fixture = install(); CLOCK_SOURCES[0] = record(2025, 1, 2, 3, 0, 0); CLOCK_SOURCES[1] = record(2024, 12, 31, 23, 59, 59); CURRENT_CLOCK = ClockState { year: 2020, month: 1, day: 1, yday: 0, utc_offset_quarters: -8, dst_active: 1, hour: 0, minute: 0, second: 0, status: 3 }; assert!(!sync_best_clock_source()); assert_eq!(SELECTED_CLOCK_SOURCE, 1); assert_eq!((CURRENT_CLOCK.year, CURRENT_CLOCK.month, CURRENT_CLOCK.day, CURRENT_CLOCK.hour), (2024, 12, 31, 23)); assert_eq!((CURRENT_CLOCK.utc_offset_quarters, CURRENT_CLOCK.dst_active, CURRENT_CLOCK.status), (-8, 1, 3)); assert_eq!(WRITES.load(Ordering::Relaxed), 1); assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), 1); } }

    #[test]
    fn publishes_negative_one_without_calls_when_no_source_is_valid() { unsafe { let _fixture = install(); assert!(!sync_best_clock_source()); assert_eq!(SELECTED_CLOCK_SOURCE, -1); assert_eq!(WRITES.load(Ordering::Relaxed), 0); assert_eq!(NOTIFICATIONS.load(Ordering::Relaxed), 0); } }
}
