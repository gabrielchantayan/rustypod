//! Calendar update field selection: `FUN_08056800` @ 0x08056800.
//!
//! # Raw extent and call sites
//!
//! Raw `osos.dec` decoding establishes the 208-byte extent
//! `0x08056800..0x080568d0`: the following word starts an independent
//! `push {r4, lr}` function. The body has five plain `bl` instructions
//! (to 0x080642a4, 0x0806748c, 0x08031568 twice, and 0x0806ce94), no
//! predicated `bl` instructions. A full raw-image scan finds three inbound
//! plain `bl` calls (0x08098644, 0x080dc460, and 0x0825b704), no predicated
//! `bl` calls, and no tail branches.
//!
//! # Algorithm
//!
//! Initializes a 12-byte calendar-update record through retailOS. When any
//! low seven selection bits are set, it conditionally replaces the record's
//! date bytes from `input` (+2..+6 and +8..+9), marks the record valid, and
//! commits it through retailOS. When bit 0x80 and/or 0x100 is set, it sends
//! the initialized signed field at +6 and unsigned field at +7 to retailOS,
//! replacing them with signed truncating divisions of `input`'s signed
//! halfword +10 by 15 and signed byte +12 by 60 respectively.
//!
//! # Deliberate deviations
//!
//! The three unported callees have no `names.yaml` identities. Target builds
//! call their verified retail addresses directly; host builds expose volatile
//! dispatch seams so the observable selected bytes and arguments can be
//! tested. Rust's signed division has the same truncation-toward-zero result
//! as the ARM ADS signed divider for these nonzero constant divisors.

#[cfg(not(target_os = "none"))]
use core::ptr;
#[cfg(target_os = "none")]
use core::mem;
#[cfg(test)]
extern crate std;

type InitializeRecord = unsafe extern "C" fn(*mut u8);
type CommitRecord = unsafe extern "C" fn(*mut u8);
type ApplyCalendarAdjustment = unsafe extern "C" fn(i8, u8);

const INITIALIZE_RECORD_ADDRESS: usize = 0x0806_42a4;
const COMMIT_RECORD_ADDRESS: usize = 0x0806_748c;
const APPLY_CALENDAR_ADJUSTMENT_ADDRESS: usize = 0x0806_ce94;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn initialize_record(record: *mut u8) {
    unsafe { mem::transmute::<usize, InitializeRecord>(INITIALIZE_RECORD_ADDRESS)(record) }
}
#[cfg(not(target_os = "none"))]
unsafe fn initialize_record(record: *mut u8) {
    unsafe { ptr::read_volatile(ptr::addr_of!(INITIALIZE_RECORD))(record) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn commit_record(record: *mut u8) {
    unsafe { mem::transmute::<usize, CommitRecord>(COMMIT_RECORD_ADDRESS)(record) }
}
#[cfg(not(target_os = "none"))]
unsafe fn commit_record(record: *mut u8) {
    unsafe { ptr::read_volatile(ptr::addr_of!(COMMIT_RECORD))(record) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn apply_calendar_adjustment(first: i8, second: u8) {
    unsafe { mem::transmute::<usize, ApplyCalendarAdjustment>(APPLY_CALENDAR_ADJUSTMENT_ADDRESS)(first, second) }
}
#[cfg(not(target_os = "none"))]
unsafe fn apply_calendar_adjustment(first: i8, second: u8) {
    unsafe { ptr::read_volatile(ptr::addr_of!(APPLY_CALENDAR_ADJUSTMENT))(first, second) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize_record(_record: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_commit_record(_record: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_apply_calendar_adjustment(_first: i8, _second: u8) {}

#[cfg(not(target_os = "none"))]
pub static mut INITIALIZE_RECORD: InitializeRecord = missing_initialize_record;
#[cfg(not(target_os = "none"))]
pub static mut COMMIT_RECORD: CommitRecord = missing_commit_record;
#[cfg(not(target_os = "none"))]
pub static mut APPLY_CALENDAR_ADJUSTMENT: ApplyCalendarAdjustment = missing_apply_calendar_adjustment;

/// calendar_update_fields — original: `FUN_08056800` @ 0x08056800 (208
/// bytes, `0x08056800..0x080568d0`; five plain internal `bl`, no predicated
/// internal `bl`; three inbound plain `bl`, no predicated inbound `bl`).
///
/// # Safety
/// `input` must reference at least 13 readable bytes. The retail initializer,
/// committer, and adjustment handler must accept their respective arguments.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calendar_update_fields(input: *const u8, selection: u32) {
    let mut record = [0u8; 12];
    unsafe { initialize_record(record.as_mut_ptr()) };
    if selection & 0x7f != 0 {
        if selection & 0x70 != 0 {
            record[0] = unsafe { input.add(8).read() };
            record[1] = unsafe { input.add(9).read() };
            record[2] = unsafe { input.add(6).read() };
            record[3] = unsafe { input.add(5).read() };
        }
        if selection & 0x0f != 0 {
            record[8] = unsafe { input.add(4).read() };
            record[9] = unsafe { input.add(3).read() };
            record[10] = unsafe { input.add(2).read() };
        }
        record[11] |= 1;
        unsafe { commit_record(record.as_mut_ptr()) };
    }
    if selection & 0x180 != 0 {
        let mut first = record[6] as i8;
        let mut second = record[7];
        if selection & 0x80 != 0 {
            let value = i16::from_le_bytes([unsafe { input.add(10).read() }, unsafe { input.add(11).read() }]);
            first = (value / 15) as i8;
        }
        if selection & 0x100 != 0 {
            second = (unsafe { input.add(12).read() } as i8 / 60) as u8;
        }
        unsafe { apply_calendar_adjustment(first, second) };
    }
}

#[cfg(test)]
pub static CALENDAR_UPDATE_FIELDS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    static mut INITIAL_RECORD: [u8; 12] = [0; 12];
    static mut COMMITTED_RECORD: [u8; 12] = [0; 12];
    static mut INITIALIZE_CALLS: u32 = 0;
    static mut COMMIT_CALLS: u32 = 0;
    static mut ADJUSTMENT: (i8, u8) = (0, 0);
    static mut ADJUSTMENT_CALLS: u32 = 0;

    unsafe extern "C" fn recording_initialize(record: *mut u8) {
        unsafe { ptr::copy_nonoverlapping(INITIAL_RECORD.as_ptr(), record, 12); INITIALIZE_CALLS += 1 };
    }
    unsafe extern "C" fn recording_commit(record: *mut u8) {
        unsafe { ptr::copy_nonoverlapping(record, COMMITTED_RECORD.as_mut_ptr(), 12); COMMIT_CALLS += 1 };
    }
    unsafe extern "C" fn recording_adjustment(first: i8, second: u8) {
        unsafe { ADJUSTMENT = (first, second); ADJUSTMENT_CALLS += 1 };
    }

    struct Mocks { previous: (InitializeRecord, CommitRecord, ApplyCalendarAdjustment), _lock: MutexGuard<'static, ()> }
    impl Drop for Mocks {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(INITIALIZE_RECORD), self.previous.0);
                ptr::write_volatile(ptr::addr_of_mut!(COMMIT_RECORD), self.previous.1);
                ptr::write_volatile(ptr::addr_of_mut!(APPLY_CALENDAR_ADJUSTMENT), self.previous.2);
            }
        }
    }
    unsafe fn install(initial: [u8; 12]) -> Mocks {
        let lock = CALENDAR_UPDATE_FIELDS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = unsafe {
            (ptr::read_volatile(ptr::addr_of!(INITIALIZE_RECORD)), ptr::read_volatile(ptr::addr_of!(COMMIT_RECORD)), ptr::read_volatile(ptr::addr_of!(APPLY_CALENDAR_ADJUSTMENT)))
        };
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(INITIALIZE_RECORD), recording_initialize);
            ptr::write_volatile(ptr::addr_of_mut!(COMMIT_RECORD), recording_commit);
            ptr::write_volatile(ptr::addr_of_mut!(APPLY_CALENDAR_ADJUSTMENT), recording_adjustment);
            INITIAL_RECORD = initial;
            INITIALIZE_CALLS = 0;
            COMMIT_CALLS = 0;
            ADJUSTMENT_CALLS = 0;
        }
        Mocks { previous, _lock: lock }
    }

    #[test]
    fn commits_selected_date_bytes_and_marks_record_valid() {
        let _mocks = unsafe { install([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0x80]) };
        let input = [0, 1, 0x12, 0x13, 0x14, 0x15, 0x16, 7, 0x18, 0x19, 0, 0, 0];
        unsafe { calendar_update_fields(input.as_ptr(), 0x7f) };
        unsafe {
            assert_eq!(INITIALIZE_CALLS, 1);
            assert_eq!(COMMIT_CALLS, 1);
            assert_eq!(ADJUSTMENT_CALLS, 0);
            assert_eq!(COMMITTED_RECORD, [0x18, 0x19, 0x16, 0x15, 0xa4, 0xa5, 0xa6, 0xa7, 0x14, 0x13, 0x12, 0x81]);
        }
    }

    #[test]
    fn uses_initialized_fields_or_signed_truncating_overrides() {
        let _mocks = unsafe { install([0, 0, 0, 0, 0, 0, 0xfb, 200, 0, 0, 0, 0]) };
        let input = [0; 13];
        unsafe { calendar_update_fields(input.as_ptr(), 0x80) };
        unsafe { assert_eq!(COMMIT_CALLS, 0); assert_eq!(ADJUSTMENT, (0, 200)) };
        unsafe { calendar_update_fields(input.as_ptr(), 0x100) };
        unsafe { assert_eq!(ADJUSTMENT, (-5, 0)) };
        let input = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xe1, 0xff, 0xc3];
        unsafe { calendar_update_fields(input.as_ptr(), 0x180) };
        unsafe {
            assert_eq!(COMMIT_CALLS, 0);
            assert_eq!(ADJUSTMENT, (-2, 255));
            assert_eq!(ADJUSTMENT_CALLS, 3);
        }
    }
}
