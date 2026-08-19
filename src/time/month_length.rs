//! Length of a month for the packed calendar record: `FUN_08076074` @
//! 0x08076074 (52 bytes, 0x08076074..0x080760a8, followed by its one
//! literal-pool word @ 0x080760a8).
//!
//! The record is the ten-byte packed `DateTime` of `time/datetime.rs`
//! (+0x03 day, +0x04 month 1=January, +0x06 u16 year, +0x08 weekday);
//! this helper reads only `month` and `year`. Six `bl` call sites in
//! osos.asm: @ 0x081409b0 / 0x081409c0 in FUN_081408a8 (the month
//! increment/decrement rollover clamp — it compares the stepped month
//! record's length against the record's day), @ 0x081e90c0 / 0x081e9140
//! in FUN_081e8f78 (the alarm/time-offset adjust), and @ 0x082712f0 /
//! 0x08271308 in FUN_082710e0.
//!
//! # The table
//!
//! The literal @ 0x080760a8 holds **0x083e2e48**, the RUNTIME address of
//! the packed-calendar stack's days-in-month table. Under this image's
//! scatterload skew (runtime address = image address - 0xaed8 — see the
//! region survey in names.yaml and the `time/datetime.rs` header) the
//! table's bytes sit at image 0x083edd20 and ARE decrypted:
//!
//! ```text
//! index:  0   1   2   3   4   5   6   7   8   9  10  11  12
//! value:  0  31  29  31  30  31  30  31  31  30  31  30  31
//! ```
//!
//! Index 0 is an unused pad (months are 1-based) and **February is
//! stored as 29** — the function itself subtracts one for a common
//! year. The same table literal is shared by three more calendar
//! helpers (literal pools @ 0x080d6d58, 0x080ff8c8, 0x08158c40). Note
//! the runtime address overlaps dead C++ vector code in the stored
//! image (the middle of FUN_083e2dac); the scatterloader copies the RW
//! block over it at boot, so the code bytes there never execute.
//!
//! # Algorithm
//!
//! ```arm
//! ldrb r1, [r0, #0x4]        ; month
//! ldr  r2, =0x083e2e48       ; table (literal @ 0x080760a8)
//! ldrb r4, [r2, r1]          ; days = table[month]   (unconditional)
//! cmp  r1, #0x2              ; February?
//! bne  done
//! ldrh r0, [r0, #0x6]        ; year
//! bl   0x080aabac            ; is_leap_year(year)
//! cmp  r0, #0x0
//! subeq r0, r4, #0x1         ; common year: 29 -> 28
//! andeq r4, r0, #0xff        ; (byte-resize; wraps 0 -> 0xff)
//! done: mov r0, r4
//! ```
//!
//! The callee `FUN_080aabac` @ 0x080aabac (52 bytes, ported in
//! `time/leap_year.rs`) is the proleptic-Gregorian leap-year test:
//! `year % 4 == 0` and `year % 400` not in {100, 200, 300} — i.e. a
//! century year is common unless it is a 400-year — returning 1 for
//! leap, 0 for common (the `% 400` runs through `__rt_udiv` @
//! 0x08036f14, ported in `runtime/rt_div.rs`). It dispatches through
//! [`IS_LEAP_YEAR`], the house seam for callees reached indirectly
//! (see `time/datetime.rs`'s `DATETIME_OPS`); the wired default is
//! the real port.
//!
//! The return is the raw table byte (`char`, unsigned under ADS), so
//! the February decrement is a wrapping u8 subtraction — exactly the
//! original's `subeq` + `andeq #0xff`.

use super::datetime::DateTime;

/// February, the only month the original special-cases (`cmp r1, #0x2`).
pub const MONTH_FEBRUARY: u8 = 2;

/// The days-in-month table, runtime 0x083e2e48 (module header): index
/// 0 unused, months 1..=12, **February stored as 29** and corrected by
/// [`datetime_days_in_month`] for common years.
///
/// `static mut` after the `DATETIME_FLOOR` precedent: host tests
/// temporarily rewrite an entry (and restore it) to reach the
/// decrement's 0 -> 0xff wrap, which the shipped contents cannot
/// trigger.
pub static mut DAYS_IN_MONTH: [u8; 13] =
    [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Wired default for [`IS_LEAP_YEAR`]: the real port
/// [`leap_year::is_leap_year`], zero-extending the record's u16 year
/// (the original's `ldrh`).
unsafe extern "C" fn leap_year_default(year: u16) -> i32 {
    super::leap_year::is_leap_year(year as u32)
}

/// The active `FUN_080aabac` @ 0x080aabac (leap-year test, ported in
/// `time/leap_year.rs`). Host tests swap in a mock and restore
/// [`DEFAULT_IS_LEAP_YEAR`]; on target the hook wires in the stock
/// function.
pub static mut IS_LEAP_YEAR: unsafe extern "C" fn(year: u16) -> i32 = leap_year_default;

/// The shipped default, exported so tests can restore it.
pub(crate) const DEFAULT_IS_LEAP_YEAR: unsafe extern "C" fn(year: u16) -> i32 =
    leap_year_default;

/// Volatile read so LLVM cannot fold the default in and delete the
/// dispatch (the `alloc_core.rs` rationale).
#[inline(always)]
unsafe fn is_leap_year_fn() -> unsafe extern "C" fn(year: u16) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(IS_LEAP_YEAR))
}

/// datetime_days_in_month — original: `FUN_08076074` @ 0x08076074
/// (52 bytes; 6 `bl` call sites, module header).
///
/// Returns the length of the record's month in its year: the table
/// entry [`DAYS_IN_MONTH`]`[month]`, less one for February of a common
/// (non-leap) year. The table lookup happens for every month value;
/// the leap-year call only for February (`bne` past it otherwise), so
/// out-of-range months never consult [`IS_LEAP_YEAR`].
///
/// The table index is the raw month byte with no bounds check — the
/// original is a bare `ldrb r4, [r2, r1]` — so the port reads through
/// the pointer rather than a checked slice index.
///
/// # Safety
///
/// `dt` must point at a readable [`DateTime`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn datetime_days_in_month(dt: *const DateTime) -> u8 {
    let month = (*dt).month;
    let table = core::ptr::addr_of!(DAYS_IN_MONTH).cast::<u8>();
    let mut days = table.add(month as usize).read();
    if month == MONTH_FEBRUARY {
        let leap = is_leap_year_fn()((*dt).year);
        if leap == 0 {
            days = days.wrapping_sub(1);
        }
    }
    days
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// Serializes the tests that write the shared dispatch slot and the
    /// table.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Call log for the mock.
    static LEAP_CALLS: AtomicU32 = AtomicU32::new(0);
    static LEAP_LAST_YEAR: AtomicU32 = AtomicU32::new(0);

    /// The value the mock returns for "is leap".
    static mut MOCK_LEAP_RESULT: i32 = 1;

    unsafe extern "C" fn leap_year_mock(year: u16) -> i32 {
        LEAP_CALLS.fetch_add(1, Ordering::Relaxed);
        LEAP_LAST_YEAR.store(year as u32, Ordering::Relaxed);
        ptr::read_volatile(ptr::addr_of!(MOCK_LEAP_RESULT))
    }

    fn dt(year: u16, month: u8) -> DateTime {
        DateTime {
            second: 0,
            minute: 0,
            hour: 0,
            day: 15,
            month,
            reserved: 0,
            year,
            weekday: 0,
            reserved2: 0,
        }
    }

    fn call_count() -> u32 {
        LEAP_CALLS.load(Ordering::Relaxed)
    }

    fn last_year() -> u32 {
        LEAP_LAST_YEAR.load(Ordering::Relaxed)
    }

    /// Installs the mock leap-year test with the given result; returns
    /// the guard that restores the default.
    fn install(result: i32) -> std::sync::MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(MOCK_LEAP_RESULT), result);
            ptr::write_volatile(ptr::addr_of_mut!(IS_LEAP_YEAR), leap_year_mock);
        }
        LEAP_CALLS.store(0, Ordering::Relaxed);
        guard
    }

    fn restore(guard: std::sync::MutexGuard<'static, ()>) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(IS_LEAP_YEAR), DEFAULT_IS_LEAP_YEAR);
        }
        drop(guard);
    }

    /// Every table index 0..=12 passes through when the month is not
    /// February, or when February's year is leap (mock returns 1).
    #[test]
    fn every_table_entry() {
        let guard = install(1);
        let expect = [0u8, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for month in 0..=12u8 {
            let record = dt(2001, month);
            assert_eq!(
                unsafe { datetime_days_in_month(&record) },
                expect[month as usize],
                "month {month}"
            );
        }
        restore(guard);
    }

    /// Non-February months never consult the leap-year callee (the
    /// original branches past the `bl`), even for the out-of-range
    /// month 0.
    #[test]
    fn non_february_skips_leap_year() {
        let guard = install(0);
        for month in [0u8, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
            let before = call_count();
            let record = dt(1900, month);
            unsafe { datetime_days_in_month(&record) };
            assert_eq!(call_count(), before, "month {month} called the callee");
        }
        restore(guard);
    }

    /// February with the callee returning nonzero keeps the shipped
    /// table entry: 29.
    #[test]
    fn february_leap_year_is_29() {
        let guard = install(1);
        let record = dt(2000, MONTH_FEBRUARY);
        assert_eq!(unsafe { datetime_days_in_month(&record) }, 29);
        restore(guard);
    }

    /// February with the callee returning 0 is decremented: 29 -> 28.
    #[test]
    fn february_common_year_is_28() {
        let guard = install(0);
        let record = dt(1900, MONTH_FEBRUARY);
        assert_eq!(unsafe { datetime_days_in_month(&record) }, 28);
        restore(guard);
    }

    /// The year argument is the record's 16-bit field at +0x06,
    /// zero-extended (`ldrh`), handed to the callee verbatim.
    #[test]
    fn february_passes_year_through() {
        let guard = install(1);
        let record = dt(0x9abc, MONTH_FEBRUARY);
        unsafe { datetime_days_in_month(&record) };
        assert_eq!(call_count(), 1);
        assert_eq!(last_year(), 0x9abc);
        restore(guard);
    }

    /// The decrement is the original's `subeq` + `andeq #0xff`: a
    /// wrapping byte subtraction. A zero table entry (unreachable with
    /// the shipped contents, where February is 29) wraps to 0xff.
    #[test]
    fn february_decrement_wraps_to_0xff() {
        let guard = install(0);
        unsafe {
            let table = ptr::addr_of_mut!(DAYS_IN_MONTH);
            let saved = (*table)[MONTH_FEBRUARY as usize];
            (*table)[MONTH_FEBRUARY as usize] = 0;
            let record = dt(2001, MONTH_FEBRUARY);
            assert_eq!(datetime_days_in_month(&record), 0xff);
            (*table)[MONTH_FEBRUARY as usize] = saved;
        }
        restore(guard);
    }

    /// With the wired default the real leap-year port drives the
    /// February correction: 2000 is leap (29), 2001 common (28).
    #[test]
    fn wired_default_is_the_real_leap_year_test() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(IS_LEAP_YEAR), DEFAULT_IS_LEAP_YEAR);
        }
        let leap_record = dt(2000, MONTH_FEBRUARY);
        assert_eq!(unsafe { datetime_days_in_month(&leap_record) }, 29);
        let common_record = dt(2001, MONTH_FEBRUARY);
        assert_eq!(unsafe { datetime_days_in_month(&common_record) }, 28);
        let century_record = dt(1900, MONTH_FEBRUARY);
        assert_eq!(unsafe { datetime_days_in_month(&century_record) }, 28);
    }
}
